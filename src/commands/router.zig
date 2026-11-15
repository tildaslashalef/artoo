//! `artoo router setup|status` (SPEC §9.8): the Tailscale subnet router,
//! a small guest tagged `role-router` that advertises the LAN to the
//! tailnet. Configured through the guest agent (root). Enrollment uses a
//! single-use auth key from a hidden prompt, handed to the VM over the
//! agent's stdin into a 0600 file under /run that is removed whatever
//! happens — never argv, never stored. With a Tailscale credential
//! (SPEC §19) artoo creates that key itself, approves the LAN route and
//! checks the key expiry; the policy stays the operator's console.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const exec = @import("../exec.zig");
const snapguard = @import("snapguard.zig");
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
const tsapi = @import("../tailscale/client.zig");
const tn = @import("../tailscale/tailnet.zig");

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
    const v = found orelse return ctx.fail(error.NotFound, "no VM tagged role-router; create it with 'artoo vm new NAME --role router --size small --cores 1'", .{});
    if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first", .{ v.name, v.status });
    if (!try agent.ping(c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer", .{v.name});
    return v;
}

/// The LAN the router advertises: the network of `guests.gateway`.
pub fn lan(ctx: *Context) ![]const u8 {
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
    /// `Self.ID`: the stable node ID the API calls `nodeId` — how artoo
    /// finds this node's device (never by name: an old device may keep it).
    node_id: []const u8 = "",
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
    st.node_id = pve.str(self, "ID") orelse "";
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
    /// `--snapshot` (SPEC §9.16).
    guard: ?snapguard.Guard = null,
    /// The Tailscale API, when its credential is set up (SPEC §19).
    tsc: ?*tsapi.Client = null,
    /// The router as the tailnet sees it (null: not joined yet).
    ts_dev: ?tn.Device = null,
    /// The LAN route is to be approved through the API.
    approve: bool = false,
    /// The join key artoo created (its value is `key`), until used.
    key_id: ?[]const u8 = null,
    key_expires: ?i64 = null,
    key_step: ?usize = null,
    key_used: bool = false,

    pub fn read(op: *SetupOp, ctx: *Context) !void {
        op.vm = try routerVm(ctx, op.c);
        op.target = op.vm.name;
        op.route = try lan(ctx);
        op.state = try probe(op.c, op.vm.vmid);
        op.steps = try plannedSteps(ctx.arena, op.state, op.route);
        if (op.tsc) |c| {
            op.ts_dev = if (op.state.running()) try findRouter(c, op.state.node_id) else null;
            op.approve = if (op.ts_dev) |d| !tn.sameSet(d.enabled, &.{op.route}) else true;
            return;
        }
        // The key is asked after the plan and the confirmation (send);
        // without a terminal it must come from --stdin — refuse now.
        if (op.steps.enroll and op.key == null and !ctx.globals.dry_run and !op.from_stdin and !try prompt.interactive(ctx.input, ctx.io))
            return ctx.fail(error.NonInteractive, "the router is not enrolled: run in a terminal, or pipe the auth key with --stdin", .{});
    }

    pub fn plan(op: *SetupOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const s = op.steps;
        if (!s.any() and !op.approve) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        const key_text: []const u8 = if (op.tsc != null) "single-use key created by artoo, 10 min, never shown" else "single-use key: asked after you confirm";
        if (s.sysctl) try changes.append(a, .{ .field = "forwarding", .from = if (op.state.forwarding) "on (unmanaged)" else "off", .to = try std.fmt.allocPrint(a, "IPv4 + IPv6 on ({s})", .{sysctl_path}) });
        if (s.enroll) try changes.append(a, .{
            .field = "tailnet",
            .from = op.state.backend,
            .to = try std.fmt.allocPrint(a, "{s} joins as {s}, advertises {s} ({s})", .{ op.vm.name, tag, op.route, key_text }),
        });
        if (s.routes) try changes.append(a, .{ .field = "routes", .from = try std.mem.join(a, ", ", op.state.advertised), .to = op.route });
        if (op.approve) try changes.append(a, .{
            .field = "approved",
            .from = if (op.ts_dev) |d| (if (d.enabled.len > 0) try k.clean(ctx, try std.mem.join(a, ", ", d.enabled)) else "none") else "not on the tailnet yet",
            .to = try std.fmt.allocPrint(a, "{s} (Tailscale API)", .{op.route}),
        });
        var notes: std.ArrayList([]const u8) = .empty;
        try notes.append(a, "The key goes over the guest agent's stdin into a 0600 file under /run, removed after use; artoo never stores or prints it.");
        if (op.tsc != null) {
            try notes.append(a, "A key left unused by a failed run is deleted; the device's key expiry is checked (off for tagged devices).");
            if (op.ts_dev) |d| if (d.enabled.len > 0 and op.approve)
                try notes.append(a, "Approved routes other than the LAN are withdrawn: artoo approves the LAN only.");
        }
        const pl: exec.Plan = .{
            .action = try std.fmt.allocPrint(a, "Set up subnet router {s} ({d})", .{ op.vm.name, op.vm.vmid }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{
                try std.fmt.allocPrint(a, "Your tailnet devices reach {s} as the tailnet policy allows (Proxmox 22/8006, UniFi 443/53, the guest pool)", .{op.route}),
            }),
            .recovery = try std.fmt.allocPrint(a, "remove the machine in the Tailscale console, then 'artoo vm rm {s}'", .{op.vm.name}),
            .notes = notes.items,
        };
        if (op.guard) |*g| {
            try g.read(ctx, op.c, op.vm);
            return try g.decorate(ctx, pl);
        }
        return pl;
    }

    pub fn fingerprint(op: *SetupOp) []const u8 {
        return op.state.raw;
    }

    pub fn send(op: *SetupOp, ctx: *Context) !void {
        op.sendSteps(ctx) catch |err| {
            op.ledger.settle(err);
            // A key artoo made and the guest did not use is deleted (or,
            // when that fails, listed on the ledger) before it is shown.
            op.dropKey(ctx);
            ctx.out.writeAll("\n") catch {};
            op.ledger.render(ctx.out, &ctx.ui) catch {};
            return err;
        };
    }

    fn sendSteps(op: *SetupOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        const id = op.vm.vmid;
        const l = &op.ledger;
        // Asked after the plan was confirmed and before any step starts
        // (live progress draws once steps are added, SPEC §4.4).
        if (op.steps.enroll and op.key == null and op.tsc == null) {
            try ctx.out.flush();
            op.key = try askKey(ctx, op.from_stdin);
        }
        errdefer if (op.guard) |*g| g.annotate(ctx);
        if (op.guard) |*g| try g.take(ctx, c, l);
        const s_sysctl = if (op.steps.sysctl) try l.add(a, "IP forwarding") else null;
        const s_key = if (op.steps.enroll and op.tsc != null) try l.add(a, "create the join key") else null;
        const s_enroll = if (op.steps.enroll) try l.add(a, "join the tailnet") else null;
        const s_routes = if (op.steps.routes) try l.add(a, "advertise the LAN") else null;
        const s_approve = if (op.approve) try l.add(a, "approve the LAN") else null;
        const s_expiry = if (op.tsc != null) try l.add(a, "key expiry") else null;
        op.key_step = s_key;
        if (s_sysctl) |i| {
            l.set(i, .unknown, "");
            try edge.writeFile(c, id, .{ .path = sysctl_path, .mode = "0644", .owner = "root:root", .content = sysctl });
            try edge.run(c, id, "applying sysctls", "sysctl -p /etc/sysctl.d/90-artoo-router.conf >/dev/null", timeout_ms);
            l.set(i, .done, sysctl_path);
        }
        if (s_key) |i| {
            l.set(i, .unknown, "");
            const nk = try tn.createJoinKey(op.tsc.?, &.{tag}, try tn.keyDescription(a, &.{ "artoo", "router", op.vm.name }));
            op.key = nk.key;
            op.key_id = nk.id;
            op.key_expires = nk.expires;
            l.set(i, .done, try std.fmt.allocPrint(a, "{s}, single-use, 10 min", .{try k.clean(ctx, nk.id)}));
        }
        if (s_enroll) |i| {
            const key = op.key orelse return ctx.fail(error.Usage, "no auth key", .{});
            l.set(i, .unknown, "");
            const r = try agent.exec(c, id, &.{ "sh", "-c", enroll_script, "sh", op.vm.name, op.route, tag }, key, timeout_ms);
            if (!r.ok()) {
                l.set(i, .failed, "");
                const why = try tn.redact(a, edge.firstLine(if (r.err.len > 0) r.err else r.out), key);
                return ctx.fail(error.Partial, "tailscale up failed on {s} (exit {?d}): {s}", .{ op.vm.name, r.code, try k.clean(ctx, why) });
            }
            op.key_used = true;
            l.set(i, .done, tag);
        }
        // The node this guest now is (its new device, whatever an old one
        // of the same name says).
        const node_id = if (op.tsc != null) blk: {
            if (!op.steps.enroll) break :blk op.state.node_id;
            break :blk (try probe(c, id)).node_id;
        } else "";
        if (s_routes) |i| {
            l.set(i, .unknown, "");
            const r = try agent.exec(c, id, &.{ "tailscale", "set", try std.fmt.allocPrint(a, "--advertise-routes={s}", .{op.route}) }, null, timeout_ms);
            if (!r.ok()) {
                l.set(i, .failed, "");
                return ctx.fail(error.Partial, "tailscale set failed on {s}: {s}", .{ op.vm.name, try k.clean(ctx, edge.firstLine(r.err)) });
            }
            l.set(i, .done, op.route);
        }
        if (s_approve) |i| {
            l.set(i, .unknown, "");
            const d = try op.waitAdvertised(ctx, node_id);
            const routes = try tn.routes(op.tsc.?, d.id);
            if (!tn.sameSet(routes.enabled, &.{op.route})) try tn.setRoutes(op.tsc.?, d.id, &.{op.route});
            l.set(i, .done, op.route);
        }
        if (s_expiry) |i| {
            const d = (try findRouter(op.tsc.?, node_id)) orelse {
                l.set(i, .failed, "not on the tailnet");
                return ctx.fail(error.Partial, "{s} is not on the tailnet as {s}", .{ op.vm.name, tag });
            };
            op.ts_dev = d;
            if (!d.key_expiry_disabled) {
                l.set(i, .failed, "on");
                return ctx.fail(error.Partial, "the key of {s} expires ({f}); disable key expiry for it in the Tailscale console (Machines)", .{ op.vm.name, ui.values.absolute(d.expires, &ctx.ui.zone) });
            }
            l.set(i, .done, "off");
        }
    }

    /// Delete the join key artoo created when the guest did not use it;
    /// keeps the error being reported.
    fn dropKey(op: *SetupOp, ctx: *Context) void {
        const id = op.key_id orelse return;
        if (op.key_used) return;
        const diag = ctx.diag;
        defer ctx.diag = diag;
        tn.deleteKey(op.tsc.?, id) catch |err| {
            const why = ctx.diag orelse @errorName(err);
            const detail = tn.strayKey(ctx, id, op.key_expires, why) catch return;
            if (op.key_step) |i| op.ledger.set(i, .failed, detail);
            return;
        };
        op.key_id = null;
    }

    /// The router on the tailnet once it advertises the LAN (polled
    /// briefly after `tailscale up`).
    fn waitAdvertised(op: *SetupOp, ctx: *Context, node_id: []const u8) !tn.Device {
        var tries: usize = 0;
        while (true) : (tries += 1) {
            if (try findRouter(op.tsc.?, node_id)) |d| {
                if (tn.contains(d.advertised, op.route)) return d;
            }
            if (tries >= 10) return ctx.fail(error.Partial, "{s} does not advertise {s} on the tailnet yet; run 'artoo ts routes approve {s}' later", .{ op.vm.name, op.route, op.vm.name });
            try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 2000)), .awake);
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
        const tailnet_ok = if (op.tsc != null) (op.ts_dev != null and op.ts_dev.?.key_expiry_disabled) else true;
        return st.running() and has(st.tags, tag) and st.forwarding and has(st.primary, op.route) and tailnet_ok;
    }

    pub fn done(op: *SetupOp) []const u8 {
        const snap = if (op.guard) |*g| g.doneSuffix(op.c.ctx.arena) else "";
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} routes {s} for tailnet {s} — 'artoo router status' to check{s}", .{ op.vm.name, op.route, op.after.tailnet, snap }) catch "done";
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
        \\guests.gateway; the tailnet policy approves the route.
    ;
    pub const flags = [_]cli.Flag{ .{ .long = "stdin", .help = "Read the auth key from standard input" }, snapguard.flag };
    pub const examples = [_][]const u8{ "artoo router setup -n", "artoo router setup" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SetupOp = .{ .c = &c, .from_stdin = args.has("stdin") };
        if (args.has("snapshot")) op.guard = .{ .action = "router", .command = "router setup" };
        var tsc: tsapi.Client = undefined;
        if (try tsapi.configured(ctx)) {
            if (args.has("stdin")) return ctx.fail(error.Usage, "--stdin is for an entered key; with the Tailscale credential set up artoo creates the key itself", .{});
            tsc = try tsapi.Client.open(ctx, .main);
            op.tsc = &tsc;
        }
        defer if (op.tsc) |t| t.deinit();
        try exec.run(ctx, &op, .{});
    }
};

/// The router's device on the tailnet: the node the guest says it is
/// (`Self.ID`), tagged `tag:lab-router` (SPEC §19). Never matched by
/// name: a stale device of the same name may still be listed.
pub fn findRouter(c: *tsapi.Client, node_id: []const u8) !?tn.Device {
    if (node_id.len == 0) return null;
    const d = (try tn.getDevice(c, node_id)) orelse return null;
    return if (d.hasTag(tag)) d else null;
}

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
        ctx.subject = try k.clean(ctx, h.vm);
        try k.header(ctx, &c);
        try vm_new.renderChecks(ctx, h.checks);
        const failed = vm_new.failures(h.checks);
        if (failed > 0) return ctx.fail(error.Partial, "{f} failed on {s}", .{ ui.values.count(failed, "check"), h.vm });
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
    if (try tsapi.configured(ctx)) try tailnetChecks(ctx, &checks, v.name, st.node_id, route);
    return .{ .vm = v.name, .checks = checks.items };
}

/// The tailnet's view of the router (SPEC §19): tags, approved and
/// primary routes, key expiry and last seen.
fn tailnetChecks(ctx: *Context, checks: *std.ArrayList(vm_new.Check), vm_name: []const u8, node_id: []const u8, route: []const u8) !void {
    const a = ctx.arena;
    var c = tsapi.Client.open(ctx, .main) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            try checks.append(a, .{ .name = "tailnet API", .status = .failed, .detail = try k.clean(ctx, ctx.diag orelse @errorName(err)) });
            ctx.diag = null;
            return;
        },
    };
    defer c.deinit();
    const found = findRouter(&c, node_id) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            try checks.append(a, .{ .name = "tailnet API", .status = .failed, .detail = try k.clean(ctx, ctx.diag orelse @errorName(err)) });
            ctx.diag = null;
            return;
        },
    };
    const d = found orelse {
        try checks.append(a, .{ .name = "tailnet device", .status = .failed, .detail = if (node_id.len == 0) "the router reports no node ID (not joined)" else try std.fmt.allocPrint(a, "no device {s} ({s}) tagged {s}", .{ vm_name, try k.clean(ctx, node_id), tag }) });
        return;
    };
    try checks.append(a, .{ .name = "tailnet device", .status = .ok, .detail = try k.clean(ctx, try std.fmt.allocPrint(a, "{s} ({s}), tags {s}", .{ d.name, d.id, try std.mem.join(a, ", ", d.tags) })) });
    const approved = tn.contains(d.enabled, route);
    try checks.append(a, .{ .name = "API approved", .status = if (approved) .ok else .failed, .detail = if (d.enabled.len > 0) try k.clean(ctx, try std.mem.join(a, ", ", d.enabled)) else "none — 'artoo ts routes approve'" });
    try checks.append(a, .{ .name = "key expiry", .status = if (d.key_expiry_disabled) .ok else .warning, .detail = if (d.key_expiry_disabled) "off" else try std.fmt.allocPrint(a, "on, expires {f}", .{ui.values.absolute(d.expires, &ctx.ui.zone)}) });
    try checks.append(a, .{ .name = "last seen", .status = .ok, .detail = if (d.connected) "connected" else try std.fmt.allocPrint(a, "{f}", .{ui.values.relative(ctx.ui.now, d.last_seen)}) });
}

pub const group = cli.group("router", "The Tailscale subnet router for remote access", &.{
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

test "router setup --snapshot -n: the snapshot comes first and its rollback joins the recovery" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const testkit = @import("../testkit.zig");
    const probe_out = try std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = "sysctl -\nfwd4 0\nfwd6 0\n---\n{\"BackendState\":\"Running\"}\n---\n{}\n", .@"err-data" = "" } }, .{});
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":202,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-router\"}]}" } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = probe_out } },
        .{ .respond = .{ .body = "{\"data\":[{\"name\":\"current\"}]}" } },
        .{ .respond = .{ .body = "{\"data\":{\"scsi0\":\"local-zfs:vm-202-disk-0,size=20G\"}}" } },
        .{ .respond = .{ .body = @import("storage.zig").storage_body } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "router setup --snapshot -n"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    for ([_][]const u8{
        "Change    snapshot    (none) → artoo-router-20",
        "Recovery  artoo vm snap rollback bespin artoo-router-20",
        "(the guest); remove the machine in the Tailscale console, then 'artoo vm rm bespin'",
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

const RouterFixture = struct {
    const testkit = @import("../testkit.zig");
    const R = testkit.Gateway.FakeServer.Route;

    fn r(match: []const u8, body: []const u8) R {
        return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
    }

    fn agentOut(a: std.mem.Allocator, code: i64, out: []const u8, err: []const u8) ![]const u8 {
        return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = code, .@"out-data" = out, .@"err-data" = err } }, .{});
    }

    fn probeOut(a: std.mem.Allocator, backend: []const u8, primary: []const u8) ![]const u8 {
        return probeOutAs(a, backend, primary, "nR");
    }

    fn probeOutAs(a: std.mem.Allocator, backend: []const u8, primary: []const u8, id: []const u8) ![]const u8 {
        return agentOut(a, 0, try std.fmt.allocPrint(a, "sysctl {s}\nfwd4 1\nfwd6 1\n---\n{{\"BackendState\":\"{s}\",\"CurrentTailnet\":{{\"Name\":\"example.ts.net\"}},\"Self\":{{\"ID\":\"{s}\",\"Tags\":[\"tag:lab-router\"],\"PrimaryRoutes\":[{s}]}}}}\n---\n{{\"AdvertiseRoutes\":[\"192.168.1.0/24\"]}}\n", .{ try edge_files_hash(a, sysctl), backend, id, primary }), "");
    }
};

const ts_token = "{\"access_token\":\"tskey-access-xyz\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"devices:core devices:routes auth_keys dns\"}";
const router_vms = "{\"data\":[{\"vmid\":202,\"name\":\"dagobah\",\"status\":\"running\",\"tags\":\"artoo;role-router\"}]}";
const router_new = "{\"nodeId\":\"nNew\",\"name\":\"dagobah.example.ts.net\",\"tags\":[\"tag:lab-router\"],\"keyExpiryDisabled\":true,\"advertisedRoutes\":[\"192.168.1.0/24\"],\"enabledRoutes\":[]}";
const router_dev = "{\"devices\":[{\"nodeId\":\"nR\",\"name\":\"dagobah.example.ts.net\",\"tags\":[\"tag:lab-router\"],\"keyExpiryDisabled\":false,\"connectedToControl\":false,\"advertisedRoutes\":[\"192.168.1.0/24\"],\"enabledRoutes\":[]}]}";

test "router setup with the Tailscale credential: artoo creates the key, joins, approves the LAN, checks key expiry" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const F = RouterFixture;
    var g: F.testkit.Gateway = undefined;
    try g.initRoutes(&.{
        F.r("POST /oauth/token", ts_token),
        F.r("GET /api2/json/nodes/pve/qemu HTTP", router_vms),
        F.r("agent/ping", "{\"data\":{\"result\":{}}}"),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        F.r("exec-status", try F.probeOut(a, "NeedsLogin", "")),
        F.r("POST /tailnet/-/keys", "{\"id\":\"kNew\",\"key\":\"tskey-auth-SECRETVALUE\",\"keyType\":\"auth\"}"),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        F.r("exec-status", try F.agentOut(a, 0, "", "")),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":44}}"),
        F.r("exec-status", try F.probeOutAs(a, "Running", "", "nNew")),
        F.r("GET /device/nNew?", router_new),
        F.r("GET /device/nNew/routes", "{\"advertisedRoutes\":[\"192.168.1.0/24\"],\"enabledRoutes\":[]}"),
        F.r("POST /device/nNew/routes", "{\"advertisedRoutes\":[\"192.168.1.0/24\"],\"enabledRoutes\":[\"192.168.1.0/24\"]}"),
        F.r("GET /device/nNew?", router_new),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":45}}"),
        F.r("exec-status", try F.probeOutAs(a, "Running", "\"192.168.1.0/24\"", "nNew")),
        // A stale, offline device of the same name: never consulted.
        F.r("GET /tailnet/-/devices", router_dev),
    });
    defer g.deinit();
    try g.tailscaleConfig("");
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(F.testkit.Exit.ok, g.h.run(&root, "router setup -y"));
    try testing.expectEqual(@as(usize, 1), g.srv.unused());
    for (g.srv.received) |req| if (req) |q| try testing.expect(std.mem.find(u8, q, "/device/nR") == null);
    const out = g.h.stdout();
    for ([_][]const u8{
        "tailnet   NeedsLogin → dagobah joins as tag:lab-router, advertises 192.168.1.0/24 (single-use key created by artoo, 10 min, never shown)",
        "approved  not on the tailnet yet → 192.168.1.0/24 (Tailscale API)",
        "create the join key  done  kNew, single-use, 10 min",
        "approve the LAN      done  192.168.1.0/24",
        "key expiry           done  off",
    }) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
    // The key: created as SPEC §19 says, only ever in the agent's stdin.
    for (g.srv.received) |req| if (req) |q| {
        if (std.mem.startsWith(u8, q, "POST /tailnet/-/keys")) try testing.expect(std.mem.endsWith(u8, q,
            \\{"keyType":"auth","description":"artoo router dagobah","expirySeconds":600,"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true,"tags":["tag:lab-router"]}}}}
        ));
        if (std.mem.find(u8, q, "SECRETVALUE") != null) try testing.expect(std.mem.find(u8, q, "input-data=tskey-auth-SECRETVALUE") != null);
    };
    try testing.expect(std.mem.find(u8, out, "SECRETVALUE") == null);
    try testing.expect(std.mem.find(u8, g.h.stderr(), "SECRETVALUE") == null);
}

test "router setup with the Tailscale credential: a failed join deletes the unused key; the key never reaches the error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const F = RouterFixture;
    var g: F.testkit.Gateway = undefined;
    try g.initRoutes(&.{
        F.r("POST /oauth/token", ts_token),
        F.r("GET /api2/json/nodes/pve/qemu HTTP", router_vms),
        F.r("agent/ping", "{\"data\":{\"result\":{}}}"),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        F.r("exec-status", try F.probeOut(a, "NeedsLogin", "")),
        F.r("POST /tailnet/-/keys", "{\"id\":\"kNew\",\"key\":\"tskey-auth-SECRETVALUE\",\"keyType\":\"auth\"}"),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        F.r("exec-status", try F.agentOut(a, 1, "", "invalid key tskey-auth-SECRETVALUE: not valid")),
        F.r("DELETE /tailnet/-/keys/kNew", ""),
    });
    defer g.deinit();
    try g.tailscaleConfig("");
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(F.testkit.Exit.partial, g.h.run(&root, "router setup -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expect(std.mem.find(u8, g.h.stderr(), "invalid key [auth key]: not valid") != null);
    try testing.expect(std.mem.find(u8, g.h.stdout(), "SECRETVALUE") == null);
    try testing.expect(std.mem.find(u8, g.h.stderr(), "SECRETVALUE") == null);
    // An entered key has no place when artoo makes it.
    try testing.expectEqual(F.testkit.Exit.usage, g.h.run(&root, "router setup -y --stdin"));
}

test "router setup: an unused key that cannot be deleted is on the ledger with its ID and expiry" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const F = RouterFixture;
    var g: F.testkit.Gateway = undefined;
    try g.initRoutes(&.{
        F.r("POST /oauth/token", ts_token),
        F.r("GET /api2/json/nodes/pve/qemu HTTP", router_vms),
        F.r("agent/ping", "{\"data\":{\"result\":{}}}"),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        F.r("exec-status", try F.probeOut(a, "NeedsLogin", "")),
        F.r("POST /tailnet/-/keys", "{\"id\":\"kNew\",\"key\":\"tskey-auth-SECRETVALUE\",\"keyType\":\"auth\"}"),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        F.r("exec-status", try F.agentOut(a, 1, "", "not valid")),
        .{ .match = "DELETE /tailnet/-/keys/kNew", .behavior = .{ .respond = .{ .status = 500, .body = "{\"message\":\"internal error\"}" } } },
    });
    defer g.deinit();
    try g.tailscaleConfig("");
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(F.testkit.Exit.partial, g.h.run(&root, "router setup -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    // No expiry in the response: about ten minutes from now.
    for ([_][]const u8{ "kNew unused but not deleted", "it expires about ", "Settings → Keys" }) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("--- missing {s} in:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
    try testing.expect(std.mem.find(u8, g.h.stderr(), "tailscale up failed") != null);
}

test "router status with the Tailscale credential adds the tailnet's view" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const F = RouterFixture;
    var g: F.testkit.Gateway = undefined;
    try g.initRoutes(&.{
        F.r("GET /api2/json/nodes/pve/qemu HTTP", router_vms),
        F.r("agent/ping", "{\"data\":{\"result\":{}}}"),
        F.r("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        F.r("exec-status", try F.probeOut(a, "Running", "\"192.168.1.0/24\"")),
        F.r("POST /oauth/token", ts_token),
        F.r("GET /device/nR?", "{\"nodeId\":\"nR\",\"name\":\"dagobah.example.ts.net\",\"tags\":[\"tag:lab-router\"],\"keyExpiryDisabled\":false,\"expires\":\"2027-01-01T00:00:00Z\",\"connectedToControl\":true,\"advertisedRoutes\":[\"192.168.1.0/24\"],\"enabledRoutes\":[\"192.168.1.0/24\"]}"),
    });
    defer g.deinit();
    try g.tailscaleConfig("");
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(F.testkit.Exit.ok, g.h.run(&root, "router status"));
    const out = g.h.stdout();
    for ([_][]const u8{ "tailnet device", "dagobah.example.ts.net (nR), tags tag:lab-router", "API approved", "key expiry", "on, expires 2027-01-01", "connected" }) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
}
