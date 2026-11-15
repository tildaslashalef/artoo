//! `artoo vm reboot --pending` (SPEC §9.12): reboot the artoo guests
//! that want it (`/run/reboot-required`), one after another, each back,
//! its agent answering and the request gone before the next — the first
//! that does not come back stops the run. The edge, the router and the
//! watchdog are left to their own `vm reboot`, as with `vm upgrade --all`.

const std = @import("std");
const app = @import("../app.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const template = @import("template.zig");
const vm_new = @import("vm_new.zig");
const vm_upgrade = @import("vm_upgrade.zig");
const k = @import("node.zig");

const Context = app.Context;

const Guest = struct {
    vm: vms.Vm,
    name: []const u8,
    /// `/run/reboot-required.pkgs`, deduplicated.
    pkgs: []const []const u8,
};

/// Whether `vm` wants a reboot: null when it does not, else its packages.
fn wanted(ctx: *Context, c: *pve.Client, vmid: u32) !?[]const []const u8 {
    const a = ctx.arena;
    const r = try agent.sh(c, vmid, vm_new.scripts.reboot, 60_000);
    if (!r.ok()) return ctx.fail(error.TaskFailed, "the reboot check exited {?d}", .{r.code});
    var lines = std.mem.tokenizeAny(u8, r.out, "\r\n");
    if (!std.mem.eql(u8, lines.next() orelse "no", "yes")) return null;
    var pkgs: std.ArrayList([]const u8) = .empty;
    while (lines.next()) |p| {
        for (pkgs.items) |q| {
            if (std.mem.eql(u8, p, q)) break;
        } else try pkgs.append(a, try k.clean(ctx, p));
    }
    return pkgs.items;
}

fn pkgList(a: std.mem.Allocator, pkgs: []const []const u8) ![]const u8 {
    if (pkgs.len == 0) return "no package named";
    const shown = pkgs[0..@min(pkgs.len, 3)];
    const more = if (pkgs.len > 3) try std.fmt.allocPrint(a, " +{d}", .{pkgs.len - 3}) else "";
    return std.fmt.allocPrint(a, "{s}{s}", .{ try std.mem.join(a, ", ", shown), more });
}

pub const RebootPendingOp = struct {
    c: *pve.Client,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "every guest",
    todo: []const Guest = &.{},
    not_needed: []const []const u8 = &.{},
    /// Edge, router, watchdog that want a reboot: named, never rebooted here.
    own_run: []const []const u8 = &.{},
    skipped: []const []const u8 = &.{},
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *RebootPendingOp, ctx: *Context) !void {
        const a = ctx.arena;
        var todo: std.ArrayList(Guest) = .empty;
        var not_needed: std.ArrayList([]const u8) = .empty;
        var own_run: std.ArrayList([]const u8) = .empty;
        var skipped: std.ArrayList([]const u8) = .empty;
        var fp: std.ArrayList(u8) = .empty;
        for (try vms.list(op.c)) |v| {
            if (v.template or !template.taggedWith(v.tags, vm_new.tag)) continue;
            const name = try k.clean(ctx, v.name);
            if (!v.running()) {
                try skipped.append(a, try std.fmt.allocPrint(a, "{s} ({s})", .{ name, try k.clean(ctx, v.status) }));
                continue;
            }
            if (!try agent.ping(op.c, v.vmid)) {
                try skipped.append(a, try std.fmt.allocPrint(a, "{s} (guest agent not answering)", .{name}));
                continue;
            }
            const want = wanted(ctx, op.c, v.vmid) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    const why = ctx.diag orelse @errorName(err);
                    ctx.diag = null;
                    try skipped.append(a, try std.fmt.allocPrint(a, "{s} ({s})", .{ name, try k.clean(ctx, why) }));
                    continue;
                },
            };
            const pkgs = want orelse {
                try not_needed.append(a, name);
                continue;
            };
            if (vm_upgrade.ownRunRole(v.tags)) |r| {
                try own_run.append(a, try std.fmt.allocPrint(a, "{s} (role {s}: 'artoo vm reboot {s}'; {s})", .{ name, r, name, try pkgList(a, pkgs) }));
                continue;
            }
            try fp.print(a, "{s}:{d};", .{ name, pkgs.len });
            try todo.append(a, .{ .vm = v, .name = name, .pkgs = pkgs });
        }
        op.todo = todo.items;
        op.not_needed = not_needed.items;
        op.own_run = own_run.items;
        op.skipped = skipped.items;
        op.fp = fp.items;
    }

    pub fn plan(op: *RebootPendingOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        if (op.todo.len == 0) {
            var parts: std.ArrayList([]const u8) = .empty;
            if (op.not_needed.len > 0) try parts.append(a, try std.fmt.allocPrint(a, "not needed: {s}", .{try std.mem.join(a, ", ", op.not_needed)}));
            if (op.own_run.len > 0) try parts.append(a, try std.fmt.allocPrint(a, "on their own: {s}", .{try std.mem.join(a, "; ", op.own_run)}));
            if (op.skipped.len > 0) try parts.append(a, try std.fmt.allocPrint(a, "skipped: {s}", .{try std.mem.join(a, "; ", op.skipped)}));
            if (parts.items.len == 0) try parts.append(a, "no artoo guests");
            return ctx.fail(error.NoChange, "no guest to reboot ({s})", .{try std.mem.join(a, "; ", parts.items)});
        }
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        for (op.todo) |g| try changes.append(a, .{
            .field = g.name,
            .from = "running",
            .to = try std.fmt.allocPrint(a, "rebooted ({s})", .{try pkgList(a, g.pkgs)}),
        });
        var notes: std.ArrayList([]const u8) = .empty;
        for (op.own_run) |o| try notes.append(a, try std.fmt.allocPrint(a, "Wants a reboot, on its own: {s}.", .{o}));
        if (op.not_needed.len > 0) try notes.append(a, try std.fmt.allocPrint(a, "Not needed: {s}.", .{try std.mem.join(a, ", ", op.not_needed)}));
        for (op.skipped) |s| try notes.append(a, try std.fmt.allocPrint(a, "Skipped: {s}.", .{s}));
        return .{
            .action = try std.fmt.allocPrint(a, "Reboot {f} that want it", .{ui.values.count(op.todo.len, "guest")}),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{
                "One guest after another; each guest's services are briefly unavailable",
                "Each guest must run again, its agent answer and its reboot request be gone before the next starts",
                "The first guest that does not come back stops the run; the rest are not rebooted",
            }),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *RebootPendingOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *RebootPendingOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const first = l.steps.items.len;
        for (op.todo) |g| _ = try l.add(a, try std.fmt.allocPrint(a, "reboot {s}", .{g.name}));
        for (op.todo, first..) |g, i| {
            // Checks the request again right before the write: a guest that
            // no longer wants a reboot is skipped, not rebooted.
            vm_new.rebootForUpdates(op.c, g.vm.vmid, l, i) catch |err| {
                l.settle(err);
                if (l.steps.items[i].detail.len == 0) l.set(i, l.steps.items[i].state, try k.clean(ctx, ctx.diag orelse @errorName(err)));
                ctx.out.writeAll("\n") catch {};
                l.render(ctx.out, &ctx.ui) catch {};
                const rest = op.todo.len - (i - first) - 1;
                const why = ctx.diag orelse @errorName(err);
                return ctx.fail(err, "{s} did not come back as expected ({s}); {s}", .{
                    g.name,                                                                                                                try k.clean(ctx, why),
                    if (rest > 0) try std.fmt.allocPrint(a, "{f} not rebooted", .{ui.values.count(rest, "guest")}) else "it was the last",
                });
            };
        }
    }

    pub fn verify(op: *RebootPendingOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        return op.ledger.complete();
    }

    pub fn done(op: *RebootPendingOp) []const u8 {
        const a = op.c.ctx.arena;
        var n: usize = 0;
        for (op.ledger.steps.items) |st| n += @intFromBool(st.state == .done);
        return std.fmt.allocPrint(a, "{f} rebooted and back; no reboot request left on them", .{ui.values.count(n, "guest")}) catch "rebooted";
    }
};

pub fn runPending(ctx: *Context) !void {
    var c = try pve.Client.open(ctx);
    defer c.deinit();
    var op: RebootPendingOp = .{ .c = &c };
    try exec.run(ctx, &op, .{});
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const cli = @import("../cli.zig");
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
const ping = "{\"data\":{\"result\":{}}}";
const upid = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:qmreboot:205:artoo@pve!cli:\"}";
const task_ok = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}";
const list = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"},{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;role-dev\"},{\"vmid\":207,\"name\":\"tatooine\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":206,\"name\":\"endor\",\"status\":\"stopped\",\"tags\":\"artoo\"},{\"vmid\":150,\"name\":\"other\",\"status\":\"running\"}]}";

test "vm reboot --pending: only guests that want it, the edge named but left alone; checked back before the end" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const yes_edge = try execStatus(a, 0, "yes\nlinux-base\n");
    const yes = try execStatus(a, 0, "yes\nlinux-image-7.0.0-45-generic\nlinux-base\nlinux-base\n");
    const no = try execStatus(a, 0, "no\n");
    const read = [_]B{
        ans(list),
        ans(ping), ans(pid), ans(yes_edge), // bespin
        ans(ping), ans(pid), ans(yes), // naboo
        ans(ping), ans(pid), ans(no), // tatooine
    };
    var g: testkit.Gateway = undefined;
    try g.init(&(read ++ read ++ [_]B{
        ans(pid), ans(yes), ans(upid), ans(task_ok), ans(ping), ans(pid), ans(try execStatus(a, 0, "7.0.0-45-generic\n")),
    }));
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm reboot --pending -n"));
    const plan = g.h.stdout();
    try expectAll(plan, &.{
        "Plan · Reboot 1 guest that want it\n",
        "Change    naboo  running → rebooted (linux-image-7.0.0-45-generic, linux-base)\n",
        "The first guest that does not come back stops the run; the rest are not rebooted",
        "Wants a reboot, on its own: bespin (role edge: 'artoo vm reboot bespin'; linux-base).",
        "Not needed: tatooine.",
        "Skipped: endor (stopped).",
        "Dry run: nothing was sent.\n",
    });
    try testing.expect(std.mem.find(u8, plan, "other (") == null and std.mem.find(u8, plan, "other.") == null and std.mem.find(u8, plan, "other,") == null);
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm reboot --pending -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/205/status/reboot HTTP/1.1", g.request(22));
    try expectAll(g.h.stdout(), &.{ "✓ reboot naboo  done  kernel 7.0.0-45-generic\n", "✓ 1 guest rebooted and back; no reboot request left on them\n" });
}

test "vm reboot --pending: the first guest still wanting a reboot stops the run" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const yes = try execStatus(a, 0, "yes\nlinux-base\n");
    const two = "{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":207,\"name\":\"tatooine\",\"status\":\"running\",\"tags\":\"artoo\"}]}";
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans(two),
        ans(ping),
        ans(pid),
        ans(yes),
        ans(ping),
        ans(pid),
        ans(yes),
        ans(pid),
        ans(yes),
        ans(upid),
        ans(task_ok),
        ans(ping),
        ans(pid),
        ans(try execStatus(a, 0, "7.0.0-45-generic\nstill\n")),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm reboot --pending -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try expectAll(g.h.stdout(), &.{ "✗ reboot naboo     failed  still pending after the reboot (kernel 7.0.0-45-generic)\n", "reboot tatooine" });
    try expectAll(g.h.stderr(), &.{"artoo: naboo did not come back as expected (VM 205 still wants a reboot after rebooting; check with 'artoo vm verify'); 1 guest not rebooted\n"});
}

test "vm reboot --pending: none wanted names why; usage" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const no = try execStatus(a, 0, "no\n");
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans(list),
        ans(ping),
        ans(pid),
        ans(no),
        ans(ping),
        ans(pid),
        ans(no),
        ans(ping),
        ans(pid),
        ans(no),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm reboot --pending -y"));
    try testing.expectEqualStrings("artoo: no guest to reboot (not needed: bespin, naboo, tatooine; skipped: endor (stopped))\n", g.h.stderr());
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm reboot naboo --pending"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm reboot --pending --no-wait -y"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm reboot"));
}
