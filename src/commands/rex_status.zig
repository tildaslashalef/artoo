//! `artoo rex status [VM…]`: Rex and the agents on guests
//! tagged `rex`, read through the guest agent. Read-only.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const k = @import("node.zig");
const vm_new = @import("vm_new.zig");
const guest = @import("../rex/guest.zig");
const state = @import("../rex/state.zig");

const Context = app.Context;
const Check = vm_new.Check;

/// One guest's answer.
pub const Report = struct {
    vm: []const u8,
    vmid: u32,
    checks: []const Check,
    agents: []const state.Agent,
};

/// The rows of one guest tagged `rex`: the Rex checks, then the agent rows.
pub fn report(ctx: *Context, c: *pve.Client, v: vms.Vm) !Report {
    const name = try k.clean(ctx, v.name);
    var r: Report = .{ .vm = name, .vmid = v.vmid, .checks = &.{}, .agents = &.{} };
    if (!v.running()) {
        r.checks = try state.notChecked(ctx, try std.fmt.allocPrint(ctx.arena, "VM {s}", .{try k.clean(ctx, v.status)}));
        return r;
    }
    if (!try agent.ping(c, v.vmid)) {
        r.checks = try state.notChecked(ctx, "no guest agent");
        return r;
    }
    const st = state.probe(ctx, c, v.vmid, (try ctx.config()).guests.user) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            defer ctx.diag = null;
            r.checks = try ctx.arena.dupe(Check, &.{.{ .name = "rex", .status = .failed, .detail = try k.clean(ctx, ctx.diag orelse @errorName(err)) }});
            return r;
        },
    };
    var rows: std.ArrayList(Check) = .empty;
    try rows.appendSlice(ctx.arena, try state.checks(ctx, st, v.name));
    if (st.isRex()) try rows.appendSlice(ctx.arena, try state.extraChecks(ctx, c, v, (try ctx.config()).guests.user));
    try rows.appendSlice(ctx.arena, try state.agentChecks(ctx, st));
    r.checks = rows.items;
    r.agents = try st.agents(ctx.arena);
    return r;
}

pub const status = struct {
    pub const name = "status";
    pub const summary = "Show Rex and the agents on guests tagged rex (read-only)";
    pub const details =
        \\Reads, through the guest agent, how Rex is set up on each guest:
        \\the package and where it comes from, the apt pin, linger, the
        \\personal server (and whether it runs an older version than the one
        \\installed), the xterm-rex terminfo, the agent skill for each agent
        \\found, the agy bridge, the agent profile (files changed on the guest
        \\or behind agents.profile) and the permission kind (a warning when an
        \\agent may run unrestricted on a guest that is not sandboxed); then
        \\one row per terminal whose program reports a status (claude-code
        \\working, blocked, …). Nothing on the guest changes and no Rex server
        \\is started.
        \\
        \\Without a VM: every guest tagged rex. A guest not tagged rex is
        \\refused; 'artoo rex setup VM' sets it up. A stopped guest, or one
        \\whose agent does not answer, is not checked. Any failed check exits 8.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name (default: every guest tagged rex)", .required = false, .variadic = true }};
    pub const examples = [_][]const u8{ "artoo rex status", "artoo rex status naboo", "artoo rex status naboo hoth -o json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const a = ctx.arena;
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const all = try vms.list(&c);
        var targets: std.ArrayList(vms.Vm) = .empty;
        const words = args.rest("VM");
        if (words.len == 0) {
            for (all) |v| if (!v.template and guest.tagged(v)) try targets.append(a, v);
        } else for (words) |w| {
            const v = switch (try vms.find(all, a, w)) {
                .vm => |v| v,
                .missing => return ctx.fail(error.NotFound, "no VM '{s}' on {s} (see 'artoo vm ls --all')", .{ w, c.node }),
                .ambiguous => |hits| return ctx.fail(error.Usage, "{d} VMs are named '{s}'; use a VMID", .{ hits.len, w }),
            };
            const vname = try k.clean(ctx, v.name);
            if (!guest.tagged(v) or v.template) return ctx.fail(error.Refused, "{s} is not tagged {s}: Rex is not set up there ('artoo rex setup {s}')", .{ vname, guest.tag, vname });
            for (targets.items) |t| {
                if (t.vmid == v.vmid) break;
            } else try targets.append(a, v);
        }

        const reports = try a.alloc(Report, targets.items.len);
        for (targets.items, reports) |v, *r| r.* = try report(ctx, &c, v);

        var failed_guests: usize = 0;
        var failed: usize = 0;
        var warned_guests: usize = 0;
        for (reports) |r| {
            const f = vm_new.failures(r.checks);
            failed += f;
            if (f > 0) {
                failed_guests += 1;
            } else for (r.checks) |ch| if (ch.status == .warning) {
                warned_guests += 1;
                break;
            };
        }

        if (ctx.json()) {
            const J = struct { check: []const u8, status: []const u8, detail: []const u8 };
            const G = struct { vm: []const u8, vmid: u32, checks: []const J, agents: []const state.Agent };
            const out = try a.alloc(G, reports.len);
            for (reports, out) |r, *g| {
                const js = try a.alloc(J, r.checks.len);
                for (r.checks, js) |ch, *j| j.* = .{ .check = ch.name, .status = ch.status.word(), .detail = ch.detail };
                g.* = .{ .vm = r.vm, .vmid = r.vmid, .checks = js, .agents = r.agents };
            }
            try ui.json.envelope(ctx.out, .pve, out, .{ .collected_at = ctx.ui.now, .failed = failed_guests });
        } else if (reports.len == 1) {
            ctx.subject = reports[0].vm;
            try k.header(ctx, &c);
            try vm_new.renderChecks(ctx, reports[0].checks);
        } else {
            try k.header(ctx, &c);
            const p = ctx.ui.palette;
            if (reports.len == 0) {
                try ctx.out.print("{s}No guest is tagged {s} ('artoo rex setup VM' sets one up).{s}\n", .{ p.on(.muted), guest.tag, p.off(.muted) });
            } else {
                for (reports, 0..) |r, i| {
                    if (i > 0) try ctx.out.writeAll("\n");
                    try ctx.out.print("{s}{s} ({d}){s}\n", .{ p.on(.title), r.vm, r.vmid, p.off(.title) });
                    try vm_new.renderChecks(ctx, r.checks);
                }
                try ctx.out.print("\n{f}: {d} ok, {d} with warnings, {d} failed\n", .{ ui.values.count(reports.len, "guest"), reports.len - failed_guests - warned_guests, warned_guests, failed_guests });
            }
        }
        if (failed > 0) {
            if (reports.len == 1) return ctx.fail(error.Partial, "{f} failed on {s}", .{ ui.values.count(failed, "check"), reports[0].vm });
            return ctx.fail(error.Partial, "{f} failed on {f}", .{ ui.values.count(failed, "check"), ui.values.count(failed_guests, "guest") });
        }
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const B = testkit.Gateway.FakeServer.Behavior;

fn ans(s: []const u8) B {
    return .{ .respond = .{ .body = s } };
}

fn execStatus(a: std.mem.Allocator, code: i64, out: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = code, .@"out-data" = out, .@"err-data" = "" } }, .{});
}

fn expectAll(out: []const u8, wants: []const []const u8) !void {
    for (wants) |want| if (std.mem.find(u8, out, want) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ want, out });
        return error.TestUnexpectedResult;
    };
}

const pid = "{\"data\":{\"pid\":42}}";

/// The two reads behind the agy bridge, profile and permissions rows of a
/// guest with Rex: no agy, no profile, no agents.
fn extras(a: std.mem.Allocator) ![4]B {
    const setup = @import("../rex/setup.zig");
    const profile = @import("../rex/profile.zig");
    return .{ ans(pid), ans(try execStatus(a, 0, try (setup.Fixture{ .a = a }).out())), ans(pid), ans(try execStatus(a, 0, try profile.probeOut(a, .{ .agents = "", .hashes = &.{}, .keys = "" }))) };
}
const ping = "{\"data\":{\"result\":{}}}";
const list = "{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;rex\"},{\"vmid\":207,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":208,\"name\":\"endor\",\"status\":\"stopped\",\"tags\":\"artoo;rex\"}]}";

fn root() cli.Command {
    return cli.group("artoo", "t", &.{@import("rex.zig").group});
}

test "rex status VM: a set-up guest with an agent working is ok" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const user = "{\"server\":{\"running\":true,\"version\":\"0.1.0-snapshot.23\",\"sessions\":1},\"terminfo\":\"Ready: xterm-rex resolves.\",\"skills\":[{\"id\":\"claude\",\"detected\":true,\"items\":[{\"kind\":\"skill\",\"state\":\"current\"}]}],\"agents\":[{\"session\":\"naboo-api\",\"block\":\"block:1\",\"app\":\"claude-code\",\"state\":\"working\",\"title\":\"\",\"updated_at\":\"2026-11-25T01:52:40+01:00\"},{\"session\":\"naboo-api\",\"block\":\"block:1\",\"app\":\"claude-code\",\"state\":\"working\",\"title\":\"fix the tests\",\"updated_at\":\"2026-11-25T01:52:41+01:00\"},{\"session\":\"naboo-web\",\"block\":\"block:2\",\"app\":\"agy\",\"state\":\"blocked\",\"title\":\"\",\"updated_at\":\"\"}],\"errors\":[]}";
    const probe = try execStatus(a, 0, try state.sample(a, .{ .user = user }));
    var g: testkit.Gateway = undefined;
    const x = try extras(a);
    try g.init(&.{ ans(list), ans(ping), ans(pid), ans(probe), x[0], x[1], x[2], x[3], ans(list), ans(ping), ans(pid), ans(probe), x[0], x[1], x[2], x[3] });
    defer g.deinit();
    const r = root();
    try testing.expectEqual(Exit.ok, g.h.run(&r, "rex status naboo"));
    try expectAll(g.h.stdout(), &.{
        "package       ✓ ok           0.1.0~alpha.23 from pkgs.superlogical.com\n",
        "Rex 1001, others −1",
        "0.1.0-snapshot.23, 1 session",
        "skill claude",
        "claude-code working in naboo-api: fix the tests",
        "agy blocked in naboo-web (waiting for the operator)",
        "agy bridge    – not checked  no agy on the user's PATH\n",
        "profile       – not checked  no profile set (agents.profile)\n",
        "permissions   ✓ ok           trusted-reach (not fenced)\n",
    });
    try testing.expect(std.mem.find(u8, g.request(2), "/qemu/205/agent/exec") != null);
    try testing.expectEqual(Exit.ok, g.h.run(&r, "rex status naboo -o json"));
    try expectAll(g.h.stdout(), &.{ "\"vm\": \"naboo\",\n      \"vmid\": 205,\n      \"checks\": [", "\"agents\": [\n        {\n          \"session\": \"naboo-api\",\n          \"block\": \"block:1\",\n          \"app\": \"claude-code\",\n          \"state\": \"working\",\n          \"title\": \"fix the tests\"" });
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "rex status: every guest tagged rex; Ubuntu's rex fails (exit 8); a stale server and linger off warn; a stopped guest is not checked" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const two = "{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;rex\"},{\"vmid\":206,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo;rex\"},{\"vmid\":208,\"name\":\"endor\",\"status\":\"stopped\",\"tags\":\"artoo;rex\"},{\"vmid\":209,\"name\":\"other\",\"status\":\"running\",\"tags\":\"artoo\"}]}";
    const stale = try execStatus(a, 0, try state.sample(a, .{
        .linger = false,
        .pin_file = "other",
        .other_priority = 500,
        .rex_version = "0.1.0-snapshot.24",
        .version = "0.1.0~alpha.24",
        .user = "{\"server\":{\"running\":true,\"version\":\"0.1.0-snapshot.23\",\"sessions\":3},\"terminfo\":\"Not ready: the xterm-rex entry is not installed for this account.\",\"skills\":[{\"id\":\"claude\",\"detected\":true,\"items\":[{\"kind\":\"skill\",\"state\":\"outdated\"},{\"kind\":\"hook\",\"state\":\"current\"}]}],\"agents\":[],\"errors\":[]}",
    }));
    const perl = try execStatus(a, 0, try state.sample(a, .{ .version = "1.16.0-1", .maintainer = "Ubuntu Developers <devel@example.com>", .origin = "other", .rex_priority = null, .other_priority = 500, .pin_file = "missing", .user = null, .rex_version = "" }));
    var g: testkit.Gateway = undefined;
    const x = try extras(a);
    try g.init(&.{ ans(two), ans(ping), ans(pid), ans(stale), x[0], x[1], x[2], x[3], ans(ping), ans(pid), ans(perl) });
    defer g.deinit();
    const r = root();
    try testing.expectEqual(Exit.partial, g.h.run(&r, "rex status"));
    try expectAll(g.h.stdout(), &.{
        "naboo (205)\n",
        "runs 0.1.0-snapshot.23; 0.1.0-snapshot.24 once it stops",
        "off (sessions end at logout) — 'artoo rex setup naboo'",
        "Ubuntu's rex at 500, not −1; /etc/apt/preferences.d/rex is not upstream's",
        "Not ready: the xterm-rex entry is not installed for this account. — 'artoo rex setup naboo'",
        "skill outdated — 'artoo rex setup naboo'",
        "hoth (206)\n",
        "rex 1.16.0-1 is another package (Maintainer Ubuntu Developers <devel@example.com>), not Rex",
        "Rex not installed",
        "endor (208)\n",
        "VM stopped",
        "3 guests: 1 ok, 1 with warnings, 1 failed\n",
    });
    try testing.expect(std.mem.find(u8, g.h.stdout(), "other (") == null);
    try expectAll(g.h.stderr(), &.{"artoo: 1 check failed on 1 guest\n"});
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "rex status VM: a guest not tagged rex is refused with the setup hint; a server not running warns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const off = try execStatus(a, 0, try state.sample(a, .{ .user = "{\"server\":{\"running\":false},\"terminfo\":\"Ready\",\"skills\":[],\"agents\":[],\"errors\":[]}" }));
    var g: testkit.Gateway = undefined;
    const x = try extras(a);
    try g.init(&.{ ans(list), ans(list), ans(ping), ans(pid), ans(off), x[0], x[1], x[2], x[3] });
    defer g.deinit();
    const r = root();
    try testing.expectEqual(Exit.refused, g.h.run(&r, "rex status hoth"));
    try testing.expectEqualStrings("artoo: hoth is not tagged rex: Rex is not set up there ('artoo rex setup hoth')\n", g.h.stderr());
    try testing.expectEqual(Exit.ok, g.h.run(&r, "rex status naboo"));
    try expectAll(g.h.stdout(), &.{ "server       ▲ warning      not running (it starts with the first session)\n", "no agent harness detected" });
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "rex status: the skill row warns on what rex setup repairs and names what it leaves alone" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const user = "{\"server\":{\"running\":false},\"terminfo\":\"Ready\",\"skills\":[{\"id\":\"claude\",\"detected\":true,\"session_naming\":true,\"items\":[{\"kind\":\"skill\",\"state\":\"foreign\"},{\"kind\":\"hook\",\"state\":\"current\"}]},{\"id\":\"pi\",\"detected\":true,\"session_naming\":false,\"items\":[{\"kind\":\"skill\",\"state\":\"current\"}]}],\"agents\":[],\"errors\":[]}";
    const probe = try execStatus(a, 0, try state.sample(a, .{ .user = user }));
    const x = try extras(a);
    var g: testkit.Gateway = undefined;
    try g.init(&.{ ans(list), ans(ping), ans(pid), ans(probe), x[0], x[1], x[2], x[3] });
    defer g.deinit();
    const r = root();
    try testing.expectEqual(Exit.ok, g.h.run(&r, "rex status naboo"));
    try expectAll(g.h.stdout(), &.{
        "skill claude  ✓ ok           current; skill foreign, left alone\n",
        "skill pi      ▲ warning      session naming off — 'artoo rex setup naboo'\n",
    });
}

test "vm verify: a guest tagged rex gets rex status's rows, not checked without its agent" {
    const one = "{\"data\":[{\"vmid\":100,\"name\":\"naboo\",\"status\":\"stopped\",\"tags\":\"artoo;rex\"}]}";
    const R = testkit.Gateway.FakeServer.Route;
    const ok = struct {
        fn r(match: []const u8, body: []const u8) R {
            return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
        }
    }.r;
    const routes = [_]R{
        ok("/nodes/pve/qemu ", one),
        ok("/nodes/pve/qemu ", one),
        ok("/qemu/100/config ", "{\"data\":{\"tags\":\"artoo;rex\"}}"),
        ok("/qemu/100/status/current ", "{\"data\":{\"status\":\"stopped\"}}"),
        ok("/qemu/100/pending ", "{\"data\":[]}"),
        ok("/qemu/100/snapshot ", "{\"data\":[{\"name\":\"current\"}]}"),
    };
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&routes);
    defer g.deinit();
    const r = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.partial, g.h.run(&r, "vm verify --all --full --no-dns"));
    try expectAll(g.h.stdout(), &.{ "package                 – not checked  no guest agent\n", "terminfo                – not checked  no guest agent\n", "skill                   – not checked  no guest agent\n" });
    try testing.expect(std.mem.find(u8, g.h.stdout(), "\nagent ") == null);
}

test {
    _ = state;
}
