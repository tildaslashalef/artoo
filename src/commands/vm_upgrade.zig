//! `artoo vm upgrade VM` (SPEC §9.12): install a guest's pending package
//! updates through the guest agent, on the one pipeline — the plan lists
//! every package from a simulated upgrade on the guest's current lists,
//! apt runs once, and a fresh simulation verifies. Never a reboot.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const apt = @import("../guest/apt.zig");
const template = @import("template.zig");
const vm_new = @import("vm_new.zig");
const k = @import("node.zig");

const Context = app.Context;

/// apt's own deadline; past it the outcome is unknown (SPEC §9.12).
const deadline_ms: u64 = 30 * 60 * 1000;
const log_file = "/var/log/artoo-upgrade.log";

const UpgradeOp = struct {
    c: *pve.Client,
    word: []const u8,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: ?vms.Vm = null,
    pending: apt.Pending = .{},
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},
    /// `/run/reboot-required.pkgs` after the run; null when no reboot is wanted.
    reboot: ?[]const []const u8 = null,

    pub fn read(op: *UpgradeOp, ctx: *Context) !void {
        const a = ctx.arena;
        const v = try vms.resolve(op.c, op.word);
        op.vm = v;
        op.target = try k.clean(ctx, v.name);
        if (v.template) return ctx.fail(error.Refused, "{s} is a template; templates are not upgraded (a new image pin is, SPEC §9.2)", .{op.target});
        if (!template.taggedWith(v.tags, vm_new.tag)) return ctx.fail(error.Refused, "{s} is not an artoo guest (no '{s}' tag)", .{ op.target, vm_new.tag });
        if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first ('artoo vm start {s}')", .{ op.target, try k.clean(ctx, v.status), op.target });
        if (!try agent.ping(op.c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer", .{op.target});
        op.pending = try simulate(ctx, op.c, v.vmid, op.target);
        var fp: std.ArrayList(u8) = .empty;
        try fp.print(a, "{?d}", .{op.pending.lists});
        for (op.pending.packages) |p| try fp.print(a, " {s}={s}", .{ p.name, p.to });
        op.fp = fp.items;
    }

    pub fn plan(op: *UpgradeOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const p = op.pending;
        if (p.packages.len == 0) return null;
        const v = op.vm.?;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        for (p.packages) |pk| try changes.append(a, .{
            .field = try k.clean(ctx, pk.name),
            .from = if (pk.from) |f| try k.clean(ctx, f) else null,
            .to = try std.fmt.allocPrint(a, "{s}{s}", .{ try k.clean(ctx, pk.to), if (pk.security) " (security)" else "" }),
        });
        var notes: std.ArrayList([]const u8) = .empty;
        try notes.append(a, if (p.listsAge()) |age|
            try std.fmt.allocPrint(a, "Package lists from {f} ago (apt's daily refresh); artoo does not refresh them.", .{ui.values.duration(age)})
        else
            "Package lists of unknown age (no update-success stamp); artoo does not refresh them.");
        if (p.deferred > 0) try notes.append(a, try std.fmt.allocPrint(a, "{d} update(s) deferred by Ubuntu's phased rollout stay for now.", .{p.deferred}));
        if (p.kept_back > 0) try notes.append(a, try std.fmt.allocPrint(a, "{d} package(s) kept back (they would need a removal) are not touched.", .{p.kept_back}));
        try notes.append(a, "Pinned packages (Alloy, the watchdog's stack) stay at their pins.");
        const sec = p.security();
        return .{
            .action = try std.fmt.allocPrint(a, "Upgrade {d} package(s) on {s} ({d}){s}", .{
                p.packages.len,                                                           op.target, v.vmid,
                if (sec > 0) try std.fmt.allocPrint(a, ", {d} security", .{sec}) else "",
            }),
            .target = try std.fmt.allocPrint(a, "the guest agent of {s} on {s}", .{ op.target, try k.nodeTarget(ctx, op.c) }),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{
                "Installed with apt as listed, new dependencies too (a new kernel); nothing is removed",
                "Services that use an upgraded library are restarted (needrestart); configuration files keep local changes",
                try std.fmt.allocPrint(a, "No reboot: a kernel or core library update leaves 'reboot pending' ('artoo vm reboot {s}')", .{op.target}),
                try std.fmt.allocPrint(a, "No undo: a snapshot taken first ('artoo vm snap add {s} pre-upgrade') is the way back", .{op.target}),
            }),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *UpgradeOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *UpgradeOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const vmid = op.vm.?.vmid;
        const i = try l.add(a, "apt-get upgrade");
        const argv: []const []const u8 = &.{ "sh", "-c", apt.upgrade_script };
        const pid = agent.start(op.c, vmid, argv, null) catch |err| {
            l.set(i, if (err == error.OutcomeUnknown) .unknown else .failed, "");
            return err;
        };
        if (ctx.globals.no_wait) {
            l.set(i, .unknown, try std.fmt.allocPrint(a, "started (pid {d}); 'artoo vm verify {s}' shows the result", .{ pid, op.target }));
            return;
        }
        const r = agent.wait(op.c, vmid, pid, "apt-get upgrade", deadline_ms, .{ .file = apt.stage_file, .note = l.noter(i) }) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => {
                const why = ctx.diag orelse @errorName(err);
                l.set(i, .unknown, "");
                return ctx.fail(error.OutcomeUnknown, "the upgrade of {s} was started, outcome unknown ({s}); apt may still be running — its log is {s}, 'artoo vm verify {s}' shows what is pending", .{ op.target, try k.clean(ctx, why), log_file, op.target });
            },
        };
        if (!r.ok()) {
            l.set(i, .failed, if (r.code) |c| try std.fmt.allocPrint(a, "exit {d}", .{c}) else "");
            return ctx.fail(error.TaskFailed, "apt-get upgrade failed on {s} (exit {?d}): {s} (log: {s})", .{ op.target, r.code, try k.clean(ctx, lastLine(r.err)), log_file });
        }
        l.set(i, .done, try std.fmt.allocPrint(a, "{d} package(s)", .{op.pending.packages.len}));
    }

    pub fn verify(op: *UpgradeOp, ctx: *Context) !bool {
        const a = ctx.arena;
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const vmid = op.vm.?.vmid;
        const now = try simulate(ctx, op.c, vmid, op.target);
        var left: std.ArrayList([]const u8) = .empty;
        for (op.pending.packages) |pk| if (now.has(pk)) try left.append(a, try k.clean(ctx, pk.name));
        if (left.items.len > 0) return ctx.fail(error.Partial, "{d} planned package(s) still pending on {s}: {s} (log: {s})", .{ left.items.len, op.target, try std.mem.join(a, ", ", left.items), log_file });
        const r = try agent.sh(op.c, vmid, vm_new.scripts.reboot, 60_000);
        var lines = std.mem.tokenizeAny(u8, r.out, "\r\n");
        if (std.mem.eql(u8, lines.next() orelse "no", "yes")) {
            var pkgs: std.ArrayList([]const u8) = .empty;
            while (lines.next()) |p| {
                for (pkgs.items) |q| {
                    if (std.mem.eql(u8, p, q)) break;
                } else try pkgs.append(a, try k.clean(ctx, p));
            }
            op.reboot = pkgs.items;
        }
        return true;
    }

    pub fn done(op: *UpgradeOp) []const u8 {
        const a = op.c.ctx.arena;
        const n = op.pending.packages.len;
        const rest = if (op.reboot) |pkgs| blk: {
            const shown = pkgs[0..@min(pkgs.len, 3)];
            const more = if (pkgs.len > 3) std.fmt.allocPrint(a, " +{d}", .{pkgs.len - 3}) catch "" else "";
            const list = std.mem.join(a, ", ", shown) catch "";
            break :blk std.fmt.allocPrint(a, "; reboot pending{s}{s}{s}{s} — 'artoo vm reboot {s}' when convenient", .{
                if (shown.len > 0) " (" else "", list, more, if (shown.len > 0) ")" else "", op.target,
            }) catch "; reboot pending";
        } else "; no reboot needed";
        return std.fmt.allocPrint(a, "{d} package(s) upgraded on {s}{s}", .{ n, op.target, rest }) catch "upgraded";
    }
};

/// The simulated upgrade (SPEC §9.12); a failing `apt-get -s` refuses.
fn simulate(ctx: *Context, c: *pve.Client, vmid: u32, target: []const u8) !apt.Pending {
    const r = try agent.sh(c, vmid, apt.simulate_script, 120_000);
    if (!r.ok()) return ctx.fail(error.TaskFailed, "apt-get -s failed on {s} (exit {?d}): {s}", .{ target, r.code, try k.clean(ctx, lastLine(r.err)) });
    return apt.parse(ctx.arena, r.out);
}

fn lastLine(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \t\r\n");
    return t[if (std.mem.findScalarLast(u8, t, '\n')) |i| i + 1 else 0..];
}

pub const upgrade = struct {
    pub const name = "upgrade";
    pub const summary = "Install a guest's pending package updates (apt, through the guest agent; never a reboot)";
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name" }};
    pub const examples = [_][]const u8{ "artoo vm upgrade naboo -n", "artoo vm upgrade naboo", "artoo vm upgrade naboo -y" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: UpgradeOp = .{ .c = &c, .word = args.pos("VM") };
        try exec.run(ctx, &op, .{});
    }
};

pub const commands = [_]cli.Command{cli.leaf(upgrade)};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;

const list_body = "{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":150,\"name\":\"other\",\"status\":\"running\"},{\"vmid\":101,\"name\":\"hoth\",\"status\":\"stopped\",\"tags\":\"artoo\"}]}";
const pid_body = "{\"data\":{\"pid\":42}}";
const ping_body = "{\"data\":{\"result\":{}}}";

fn execStatus(a: std.mem.Allocator, code: i64, out: []const u8, err: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = code, .@"out-data" = out, .@"err-data" = err } }, .{});
}

const B = testkit.Gateway.FakeServer.Behavior;
fn ans(s: []const u8) B {
    return .{ .respond = .{ .body = s } };
}

fn expectAll(out: []const u8, wants: []const []const u8) !void {
    for (wants) |want| if (std.mem.find(u8, out, want) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ want, out });
        return error.TestUnexpectedResult;
    };
}

test "vm upgrade: plan from the simulation, apt once with its live stage, verified, reboot named" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans(list_body),
        ans(ping_body),
        ans(pid_body), ans(try execStatus(a, 0, apt.sample, "")), // simulate
        ans(pid_body), ans("{\"data\":{\"exited\":0}}"), ans("{\"data\":{\"content\":\"42% Unpacking tmux (amd64)\\n\"}}"), ans(try execStatus(a, 0, "", "")), // upgrade
        ans(pid_body), ans(try execStatus(a, 0, "lists 4700\nnow 4800\nInst tmux [3.6a-2ubuntu0.2] (3.6a-2ubuntu0.3 Ubuntu:26.04/resolute-updates [amd64])\n", "")), // verify
        ans(pid_body), ans(try execStatus(a, 0, "yes\nlinux-image-7.0.0-40-generic\nlinux-base\n", "")), // reboot wanted
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm upgrade naboo -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/205/agent/ping HTTP/1.1", g.request(1));
    try testing.expect(std.mem.startsWith(u8, g.body(2), "command=sh&command=-c&command=echo%20%22lists%20"));
    try testing.expect(std.mem.startsWith(u8, g.body(4), "command=sh&command=-c&command=export%20DEBIAN_FRONTEND%3Dnoninteractive%20NEEDRESTART_MODE%3Da"));
    try testing.expect(std.mem.find(u8, g.request(6), "file-read?file=%2Frun%2Fartoo-upgrade.stage") != null);
    try expectAll(g.h.stdout(), &.{
        "Plan · Upgrade 3 package(s) on naboo (205), 1 security\n",
        "libssl3t64                    3.5.3-1ubuntu1 → 3.5.3-1ubuntu1.1 (security)\n",
        "linux-image-7.0.0-40-generic  (none) → 7.0.0-40.40\n",
        "Package lists from 1h ago (apt's daily refresh); artoo does not refresh them.",
        "4 update(s) deferred by Ubuntu's phased rollout stay for now.",
        "1 package(s) kept back",
        "✓ apt-get upgrade  done",
        // tmux has a newer version now: the planned one is installed.
        "✓ 3 package(s) upgraded on naboo; reboot pending (linux-image-7.0.0-40-generic, linux-base) — 'artoo vm reboot naboo' when convenient\n",
    });
    // Not a terminal: the stage is one dated line while apt runs.
    try expectAll(g.h.stderr(), &.{"  · apt-get upgrade  42% Unpacking tmux (amd64)\n"});
}

test "vm upgrade: nothing pending, dry run, refusals, apt failing, a package left" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const none = try execStatus(a, 0, "lists 1000\nnow 1100\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", "");
    const one = try execStatus(a, 0, "lists 1000\nnow 1100\nInst tmux [1] (2 Ubuntu:26.04/resolute-updates [amd64])\n", "");
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans(list_body), ans(ping_body), ans(pid_body), ans(none), // nothing pending
        ans(list_body), ans(ping_body), ans(pid_body), ans(one), // dry run
        ans(list_body), // not an artoo guest
        ans(list_body), // stopped
        ans(list_body), ans(ping_body), ans(pid_body), ans(one), ans(pid_body), ans(try execStatus(a, 100, "", "Reading package lists...\nE: Sub-process /usr/bin/dpkg returned an error code (1)\n")), // apt fails
        ans(list_body), ans(ping_body), ans(pid_body), ans(one), ans(pid_body), ans(try execStatus(a, 0, "", "")), ans(pid_body), ans(one), // still pending
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm upgrade naboo -y"));
    try testing.expectEqualStrings("artoo: nothing to change: naboo already has the requested state\n", g.h.stderr());
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm upgrade naboo -n"));
    try expectAll(g.h.stdout(), &.{ "tmux  1 → 2\n", "Dry run: nothing was sent.\n" });
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm upgrade other -y"));
    try testing.expectEqualStrings("artoo: other is not an artoo guest (no 'artoo' tag)\n", g.h.stderr());
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm upgrade hoth -y"));
    try testing.expectEqualStrings("artoo: hoth is stopped; start it first ('artoo vm start hoth')\n", g.h.stderr());
    try testing.expectEqual(Exit.task_failed, g.h.run(&root, "vm upgrade naboo -y"));
    try expectAll(g.h.stderr(), &.{"artoo: apt-get upgrade failed on naboo (exit 100): E: Sub-process /usr/bin/dpkg returned an error code (1) (log: /var/log/artoo-upgrade.log)\n"});
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm upgrade naboo -y"));
    try expectAll(g.h.stderr(), &.{"artoo: 1 planned package(s) still pending on naboo: tmux (log: /var/log/artoo-upgrade.log)\n"});
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}
