//! `artoo router setup|status` (SPEC §9.8): the Tailscale subnet router,
//! a small guest tagged `role-router` that advertises the LAN to the
//! tailnet. Configured through the guest agent (root). Enrollment uses a
//! single-use auth key from a hidden prompt, handed to the VM over the
//! agent's stdin into a 0600 file under /run that is removed whatever
//! happens — never argv, never stored. The tailnet itself (policy, DNS,
//! keys) is the operator's console, not artoo.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const exec = @import("../exec.zig");
const prompt = @import("../prompt.zig");
const secrets = @import("../secrets.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const edge = @import("edge.zig");
const vm_cmd = @import("vm.zig");
const vm_new = @import("vm_new.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

pub const role = "router";
pub const tag = "tag:lab-router";
const timeout_ms = 2 * 60 * 1000;

pub const sysctl_path = "/etc/sysctl.d/90-artoo-router.conf";
pub const sysctl =
    \\# Managed by artoo (SPEC 9.8): the Tailscale subnet router forwards.
    \\net.ipv4.ip_forward = 1
    \\net.ipv6.conf.all.forwarding = 1
    \\
;

/// The VM tagged `role-router` (exactly one), running, agent answering.
fn routerVm(ctx: *Context, c: *pve.Client) !vms.Vm {
    var found: ?vms.Vm = null;
    for (try vms.list(c)) |v| {
        const r = vm_cmd.roleOf(v.tags) orelse continue;
        if (!std.mem.eql(u8, r, role) or v.template) continue;
        if (found != null) return ctx.fail(error.Refused, "several VMs carry role-router ({s}, {s}); keep one", .{ found.?.name, v.name });
        found = v;
    }
    const v = found orelse return ctx.fail(error.NotFound, "no VM tagged role-router; create it with 'artoo vm new NAME --role router --size small --cores 1' (SPEC §9.8)", .{});
    if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first", .{ v.name, v.status });
    if (!try agent.ping(c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer", .{v.name});
    return v;
}

/// The LAN the router advertises: the network of `guests.gateway`.
fn lan(ctx: *Context) ![]const u8 {
    const cfg = try ctx.config();
    const gw = config.parseCidr(cfg.guests.gateway) orelse return ctx.fail(error.ConfigInvalid, "guests.gateway is not A/N", .{});
    const mask: u32 = ~@as(u32, 0) << @intCast(32 - @as(u32, gw.prefix));
    return std.fmt.allocPrint(ctx.arena, "{s}/{d}", .{ try vm_new.ip4Text(ctx.arena, gw.address & mask), gw.prefix });
}

// ---------------------------------------------------------------- probe

const probe_script =
    \\h=$(sha256sum /etc/sysctl.d/90-artoo-router.conf 2>/dev/null | cut -d' ' -f1); echo "sysctl ${h:--}"
    \\echo "fwd4 $(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
    \\echo "fwd6 $(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)"
    \\echo '---'
    \\tailscale status --json 2>/dev/null || echo '{}'
    \\echo '---'
    \\tailscale debug prefs 2>/dev/null || echo '{}'
    \\
;

pub const State = struct {
    sysctl_hash: []const u8 = "-",
    forwarding: bool = false,
    /// `Running`, `NeedsLogin`, `Stopped`, …
    backend: []const u8 = "unknown",
    tailnet: []const u8 = "",
    hostname: []const u8 = "",
    version: []const u8 = "",
    tags: []const []const u8 = &.{},
    /// Routes this node serves (approved and primary).
    primary: []const []const u8 = &.{},
    /// Routes it advertises (prefs).
    advertised: []const []const u8 = &.{},
    raw: []const u8 = "",

    pub fn running(s: State) bool {
        return std.mem.eql(u8, s.backend, "Running");
    }
};

fn strings(a: std.mem.Allocator, v: Value) ![]const []const u8 {
    if (v != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (v.array.items) |x| if (x == .string) try out.append(a, x.string);
    return out.items;
}

fn field(v: Value, key: []const u8) Value {
    if (v != .object) return .null;
    return v.object.get(key) orelse .null;
}

pub fn parseState(a: std.mem.Allocator, out: []const u8) !State {
    var st: State = .{ .raw = out };
    var parts = std.mem.splitSequence(u8, out, "---\n");
    var fwd4 = false;
    var fwd6 = false;
    var lines = std.mem.tokenizeScalar(u8, parts.next() orelse "", '\n');
    while (lines.next()) |line| {
        if (std.mem.cutPrefix(u8, line, "sysctl ")) |v| st.sysctl_hash = v;
        if (std.mem.cutPrefix(u8, line, "fwd4 ")) |v| fwd4 = std.mem.eql(u8, v, "1");
        if (std.mem.cutPrefix(u8, line, "fwd6 ")) |v| fwd6 = std.mem.eql(u8, v, "1");
    }
    st.forwarding = fwd4 and fwd6;
    const ts = std.json.parseFromSliceLeaky(Value, a, parts.next() orelse "{}", .{}) catch .null;
    const prefs = std.json.parseFromSliceLeaky(Value, a, parts.next() orelse "{}", .{}) catch .null;
    st.backend = pve.str(ts, "BackendState") orelse "unknown";
    st.version = pve.str(ts, "Version") orelse "";
    st.tailnet = pve.str(field(ts, "CurrentTailnet"), "Name") orelse "";
    const self = field(ts, "Self");
    st.hostname = pve.str(self, "HostName") orelse "";
    st.tags = try strings(a, field(self, "Tags"));
    st.primary = try strings(a, field(self, "PrimaryRoutes"));
    st.advertised = try strings(a, field(prefs, "AdvertiseRoutes"));
    return st;
}

fn has(list: []const []const u8, want: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, want)) return true;
    return false;
}

fn probe(c: *pve.Client, vmid: u32) !State {
    const ctx = c.ctx;
    const r = try agent.sh(c, vmid, probe_script, 60_000);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading the router's state failed: {s}", .{try k.clean(ctx, edge.firstLine(r.err))});
    return parseState(ctx.arena, r.out);
}

// ---------------------------------------------------------------- setup

/// Enrolls with the key on stdin: written to a 0600 file under /run,
/// passed as `file:`, removed on exit. `$1` hostname, `$2` routes, `$3` tag.
const enroll_script =
    \\set -eu
    \\umask 077
    \\key=$(mktemp /run/artoo-tskey.XXXXXX)
    \\trap 'rm -f "$key"' EXIT
    \\cat > "$key"
    \\tailscale up --auth-key="file:$key" --advertise-routes="$2" --advertise-tags="$3" --accept-dns=false --hostname="$1" --timeout=60s
    \\
;

pub const Steps = struct {
    sysctl: bool = false,
    enroll: bool = false,
    routes: bool = false,

    pub fn any(s: Steps) bool {
        return s.sysctl or s.enroll or s.routes;
    }
};

pub fn plannedSteps(a: std.mem.Allocator, st: State, want_route: []const u8) !Steps {
    const sysctl_ok = std.mem.eql(u8, st.sysctl_hash, try edge_files_hash(a, sysctl)) and st.forwarding;
    const routes_ok = st.advertised.len == 1 and std.mem.eql(u8, st.advertised[0], want_route);
    return .{
        .sysctl = !sysctl_ok,
        .enroll = !st.running(),
        .routes = st.running() and !routes_ok,
    };
}

fn edge_files_hash(a: std.mem.Allocator, content: []const u8) ![]const u8 {
    return @import("../edge/files.zig").sha256Hex(a, content);
}

const SetupOp = struct {
    c: *pve.Client,
    /// The single-use auth key; asked only when enrollment is needed.
    key: ?[]const u8 = null,
    from_stdin: bool = false,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: vms.Vm = undefined,
    route: []const u8 = "",
    state: State = .{},
    steps: Steps = .{},
    ledger: exec.Ledger = .{},
    after: State = .{},

    pub fn read(op: *SetupOp, ctx: *Context) !void {
        op.vm = try routerVm(ctx, op.c);
        op.target = op.vm.name;
        op.route = try lan(ctx);
        op.state = try probe(op.c, op.vm.vmid);
        op.steps = try plannedSteps(ctx.arena, op.state, op.route);
        // The key is asked after the plan and the confirmation (send);
        // without a terminal it must come from --stdin — refuse now.
        if (op.steps.enroll and op.key == null and !ctx.globals.dry_run and !op.from_stdin and !try prompt.interactive(ctx.input, ctx.io))
            return ctx.fail(error.NonInteractive, "the router is not enrolled: run in a terminal, or pipe the auth key with --stdin", .{});
    }

    pub fn plan(op: *SetupOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const s = op.steps;
        if (!s.any()) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (s.sysctl) try changes.append(a, .{ .field = "forwarding", .from = if (op.state.forwarding) "on (unmanaged)" else "off", .to = try std.fmt.allocPrint(a, "IPv4 + IPv6 on ({s})", .{sysctl_path}) });
        if (s.enroll) try changes.append(a, .{
            .field = "tailnet",
            .from = op.state.backend,
            .to = try std.fmt.allocPrint(a, "{s} joins as {s}, advertises {s} (single-use key: asked after you confirm)", .{ op.vm.name, tag, op.route }),
        });
        if (s.routes) try changes.append(a, .{ .field = "routes", .from = try std.mem.join(a, ", ", op.state.advertised), .to = op.route });
        return .{
            .action = try std.fmt.allocPrint(a, "Set up subnet router {s} ({d})", .{ op.vm.name, op.vm.vmid }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{
                try std.fmt.allocPrint(a, "Your tailnet devices reach {s} as the tailnet policy allows (Proxmox 22/8006, UniFi 443/53, the guest pool)", .{op.route}),
            }),
            .recovery = try std.fmt.allocPrint(a, "remove the machine in the Tailscale console, then 'artoo vm rm {s}'", .{op.vm.name}),
            .notes = try a.dupe([]const u8, &.{"The key goes over the guest agent's stdin into a 0600 file under /run, removed after use; artoo never stores or prints it."}),
        };
    }

    pub fn fingerprint(op: *SetupOp) []const u8 {
        return op.state.raw;
    }

    pub fn send(op: *SetupOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        const id = op.vm.vmid;
        const l = &op.ledger;
        // Asked after the plan was confirmed and before any step starts
        // (live progress draws once steps are added, SPEC §4.4).
        if (op.steps.enroll and op.key == null) {
            try ctx.out.flush();
            op.key = try askKey(ctx, op.from_stdin);
        }
        const s_sysctl = if (op.steps.sysctl) try l.add(a, "IP forwarding") else null;
        const s_enroll = if (op.steps.enroll) try l.add(a, "join the tailnet") else null;
        const s_routes = if (op.steps.routes) try l.add(a, "advertise the LAN") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (s_sysctl) |i| {
            l.set(i, .unknown, "");
            try edge.writeFile(c, id, .{ .path = sysctl_path, .mode = "0644", .owner = "root:root", .content = sysctl });
            try edge.run(c, id, "applying sysctls", "sysctl -p /etc/sysctl.d/90-artoo-router.conf >/dev/null", timeout_ms);
            l.set(i, .done, sysctl_path);
        }
        if (s_enroll) |i| {
            const key = op.key orelse return ctx.fail(error.Usage, "no auth key", .{});
            l.set(i, .unknown, "");
            const r = try agent.exec(c, id, &.{ "sh", "-c", enroll_script, "sh", op.vm.name, op.route, tag }, key, timeout_ms);
            if (!r.ok()) {
                l.set(i, .failed, "");
                return ctx.fail(error.Partial, "tailscale up failed on {s} (exit {?d}): {s}", .{ op.vm.name, r.code, try k.clean(ctx, edge.firstLine(if (r.err.len > 0) r.err else r.out)) });
            }
            l.set(i, .done, tag);
        }
        if (s_routes) |i| {
            l.set(i, .unknown, "");
            const r = try agent.exec(c, id, &.{ "tailscale", "set", try std.fmt.allocPrint(a, "--advertise-routes={s}", .{op.route}) }, null, timeout_ms);
            if (!r.ok()) {
                l.set(i, .failed, "");
                return ctx.fail(error.Partial, "tailscale set failed on {s}: {s}", .{ op.vm.name, try k.clean(ctx, edge.firstLine(r.err)) });
            }
            l.set(i, .done, op.route);
        }
    }

    /// Running, tagged, forwarding, and the route approved (the policy's
    /// auto-approver; polled briefly).
    pub fn verify(op: *SetupOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        var tries: usize = 0;
        while (true) : (tries += 1) {
            op.after = try probe(op.c, op.vm.vmid);
            if (has(op.after.primary, op.route) or tries >= 10) break;
            try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 2000)), .awake);
        }
        const st = op.after;
        return st.running() and has(st.tags, tag) and st.forwarding and has(st.primary, op.route);
    }

    pub fn done(op: *SetupOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} routes {s} for tailnet {s} — 'artoo router status' to check", .{ op.vm.name, op.route, op.after.tailnet }) catch "done";
    }
};

fn askKey(ctx: *Context, from_stdin: bool) ![]const u8 {
    const value = if (from_stdin)
        try prompt.readAll(ctx.input, ctx.io, ctx.arena, 4096)
    else blk: {
        if (!try prompt.interactive(ctx.input, ctx.io)) return ctx.fail(error.NonInteractive, "the router is not enrolled: run in a terminal, or pipe the auth key with --stdin", .{});
        break :blk try prompt.askHidden(ctx.input, ctx.io, ctx.arena, ctx.err, "Single-use Tailscale auth key, tagged " ++ tag);
    };
    const key = std.mem.trim(u8, value, " \r\n");
    if (!secrets.validSecret(key) or !std.mem.startsWith(u8, key, "tskey-auth-"))
        return ctx.fail(error.Usage, "expected a Tailscale auth key (tskey-auth-…) on one line", .{});
    return key;
}

pub const setup = struct {
    pub const name = "setup";
    pub const summary = "Turn the role-router VM into the tailnet's subnet router (idempotent)";
    pub const details =
        \\IP forwarding, then — when the router is not enrolled — `tailscale up`
        \\with a single-use auth key tagged tag:lab-router (Tailscale console →
        \\Keys → Generate auth key), read from a hidden prompt or --stdin and
        \\removed from the VM right after use. The router advertises the LAN of
        \\guests.gateway; the tailnet policy approves the route (SPEC §9.8).
    ;
    pub const flags = [_]cli.Flag{.{ .long = "stdin", .help = "Read the auth key from standard input" }};
    pub const examples = [_][]const u8{ "artoo router setup -n", "artoo router setup" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SetupOp = .{ .c = &c, .from_stdin = args.has("stdin") };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- status

pub const status = struct {
    pub const name = "status";
    pub const summary = "The subnet router: tailnet state, tag, routes, forwarding (read-only)";
    pub const examples = [_][]const u8{ "artoo router status", "artoo router status -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const h = try health(ctx, &c);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, h, .{ .collected_at = ctx.ui.now });
        try k.header(ctx, &c);
        try vm_new.renderChecks(ctx, h.checks);
        const failed = vm_new.failures(h.checks);
        if (failed > 0) return ctx.fail(error.Partial, "{d} check(s) failed on {s}", .{ failed, h.vm });
    }
};

/// The router's checks (`router status`, `status`).
pub const Health = struct { vm: []const u8, checks: []const vm_new.Check };

pub fn health(ctx: *Context, c: *pve.Client) !Health {
    const a = ctx.arena;
    const v = try routerVm(ctx, c);
    const route = try lan(ctx);
    const st = try probe(c, v.vmid);
    const Check = vm_new.Check;
    var checks: std.ArrayList(Check) = .empty;
    try checks.append(a, .{ .name = "tailnet", .status = if (st.running()) .ok else .failed, .detail = try k.clean(ctx, try std.fmt.allocPrint(a, "{s}{s}{s}", .{ st.backend, if (st.tailnet.len > 0) " on " else "", st.tailnet })) });
    try checks.append(a, .{ .name = "tag", .status = if (has(st.tags, tag)) .ok else .failed, .detail = try k.clean(ctx, if (st.tags.len > 0) try std.mem.join(a, ", ", st.tags) else "none") });
    try checks.append(a, .{ .name = "advertised", .status = if (has(st.advertised, route)) .ok else .failed, .detail = try k.clean(ctx, if (st.advertised.len > 0) try std.mem.join(a, ", ", st.advertised) else "none") });
    try checks.append(a, .{ .name = "approved", .status = if (has(st.primary, route)) .ok else .failed, .detail = if (has(st.primary, route)) route else "not approved — check the policy's autoApprovers" });
    try checks.append(a, .{ .name = "forwarding", .status = if (st.forwarding) .ok else .failed, .detail = if (st.forwarding) "IPv4 + IPv6" else "off — 'artoo router setup'" });
    try checks.append(a, .{ .name = "version", .status = .ok, .detail = try k.clean(ctx, st.version) });
    return .{ .vm = v.name, .checks = checks.items };
}

pub const group = cli.group("router", "The Tailscale subnet router for remote access (SPEC §9.8)", &.{
    cli.leaf(setup),
    cli.leaf(status),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "parseState + plannedSteps: fresh guest needs all; enrolled, approved one nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fresh = try parseState(a, "sysctl -\nfwd4 0\nfwd6 0\n---\n{\"BackendState\":\"NeedsLogin\"}\n---\n{\"AdvertiseRoutes\":null}\n");
    const s = try plannedSteps(a, fresh, "192.168.1.0/24");
    try testing.expect(s.sysctl and s.enroll and !s.routes);

    const hash = try edge_files_hash(a, sysctl);
    const done_out = try std.fmt.allocPrint(a,
        \\sysctl {s}
        \\fwd4 1
        \\fwd6 1
        \\---
        \\{{"BackendState":"Running","Version":"1.90.0","CurrentTailnet":{{"Name":"example.ts.net"}},"Self":{{"HostName":"bespin","Tags":["tag:lab-router"],"PrimaryRoutes":["192.168.1.0/24"]}}}}
        \\---
        \\{{"AdvertiseRoutes":["192.168.1.0/24"]}}
        \\
    , .{hash});
    const st = try parseState(a, done_out);
    try testing.expect(st.running() and st.forwarding and has(st.tags, tag) and has(st.primary, "192.168.1.0/24"));
    try testing.expectEqualStrings("example.ts.net", st.tailnet);
    try testing.expect(!(try plannedSteps(a, st, "192.168.1.0/24")).any());
    try testing.expect((try plannedSteps(a, st, "192.168.2.0/24")).routes);
}

test "router setup -n: plans forwarding and enrollment without asking for the key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const testkit = @import("../testkit.zig");
    const probe_out = try std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = "sysctl -\nfwd4 0\nfwd6 0\n---\n{\"BackendState\":\"NeedsLogin\"}\n---\n{}\n", .@"err-data" = "" } }, .{});
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":202,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-router\"}]}" } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = probe_out } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "router setup -n"));
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Set up subnet router bespin (202)",
        "forwarding  off → IPv4 + IPv6 on (/etc/sysctl.d/90-artoo-router.conf)",
        "tailnet     NeedsLogin → bespin joins as tag:lab-router, advertises 192.168.1.0/24 (single-use key: asked after you confirm)",
        "Dry run: nothing was sent.",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "router setup: a non-terminal without --stdin refuses before anything is sent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const testkit = @import("../testkit.zig");
    const probe_out = try std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = "sysctl -\nfwd4 0\nfwd6 0\n---\n{\"BackendState\":\"NeedsLogin\"}\n---\n{}\n", .@"err-data" = "" } }, .{});
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":202,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-router\"}]}" } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = probe_out } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "router setup -y"));
    try testing.expectEqual(@as(usize, 4), g.sent());
}
