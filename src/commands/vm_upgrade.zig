//! `artoo vm upgrade VM` (SPEC §9.12): install a guest's pending package
//! updates through the guest agent, on the one pipeline — the plan lists
//! every package from a simulated upgrade on the guest's current lists,
//! apt runs once, and a fresh simulation verifies. Never a reboot.
//! `--all` does the same for every ordinary artoo guest in one plan, one
//! guest after another; the edge, the router and the watchdog are left
//! to their own runs.

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
const snapguard = @import("snapguard.zig");
const vm_cmd = @import("vm.zig");
const edge = @import("edge.zig");
const router = @import("router.zig");
const watch = @import("watch.zig");

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
    /// `--snapshot` (SPEC §9.16).
    guard: ?snapguard.Guard = null,

    pub fn read(op: *UpgradeOp, ctx: *Context) !void {
        const a = ctx.arena;
        const v = try vms.resolve(op.c, op.word);
        op.vm = v;
        op.target = try k.clean(ctx, v.name);
        if (v.template) return ctx.fail(error.Refused, "{s} is a template; templates are not upgraded (a new image pin is)", .{op.target});
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
        if (p.deferred > 0) try notes.append(a, try std.fmt.allocPrint(a, "{f} deferred by Ubuntu's phased rollout stay for now.", .{ui.values.count(p.deferred, "update")}));
        if (p.kept_back > 0) try notes.append(a, try std.fmt.allocPrint(a, "{f} kept back (they would need a removal) are not touched.", .{ui.values.count(p.kept_back, "package")}));
        try notes.append(a, "Pinned packages (Alloy, the watchdog's stack) stay at their pins.");
        const sec = p.security();
        const pl: exec.Plan = .{
            .action = try std.fmt.allocPrint(a, "Upgrade {f} on {s} ({d}){s}", .{
                ui.values.count(p.packages.len, "package"),                               op.target, v.vmid,
                if (sec > 0) try std.fmt.allocPrint(a, ", {d} security", .{sec}) else "",
            }),
            .target = try std.fmt.allocPrint(a, "the guest agent of {s} on {s}", .{ op.target, try k.nodeTarget(ctx, op.c) }),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{
                "Installed with apt as listed, new dependencies too (a new kernel); nothing is removed",
                "Services that use an upgraded library are restarted (needrestart); configuration files keep local changes",
                try std.fmt.allocPrint(a, "No reboot: a kernel or core library update leaves 'reboot pending' ('artoo vm reboot {s}')", .{op.target}),
                if (op.guard != null) "apt has no undo: the snapshot taken first is the way back" else "No undo: run with --snapshot to take a snapshot first",
            }),
            .notes = notes.items,
        };
        if (op.guard) |*g| {
            try g.read(ctx, op.c, v);
            return try g.decorate(ctx, pl);
        }
        return pl;
    }

    pub fn fingerprint(op: *UpgradeOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *UpgradeOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const vmid = op.vm.?.vmid;
        errdefer if (op.guard) |*g| g.annotate(ctx);
        if (op.guard) |*g| try g.take(ctx, op.c, l);
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
        l.set(i, .done, try std.fmt.allocPrint(a, "{f}", .{ui.values.count(op.pending.packages.len, "package")}));
    }

    pub fn verify(op: *UpgradeOp, ctx: *Context) !bool {
        const a = ctx.arena;
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const vmid = op.vm.?.vmid;
        const now = try simulate(ctx, op.c, vmid, op.target);
        var left: std.ArrayList([]const u8) = .empty;
        for (op.pending.packages) |pk| if (now.has(pk)) try left.append(a, try k.clean(ctx, pk.name));
        if (left.items.len > 0) return ctx.fail(error.Partial, "{f} still pending on {s}: {s} (log: {s})", .{ ui.values.count(left.items.len, "planned package"), op.target, try std.mem.join(a, ", ", left.items), log_file });
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
        const snap = if (op.guard) |*g| g.doneSuffix(a) else "";
        return std.fmt.allocPrint(a, "{f} upgraded on {s}{s}{s}", .{ ui.values.count(n, "package"), op.target, rest, snap }) catch "upgraded";
    }
};

/// Roles `vm upgrade --all` leaves out (SPEC §9.12): the guests needed to
/// reach, serve and watch the rest — the same set `vm fence` refuses.
const own_run_roles = [_][]const u8{ edge.role, router.role, watch.role };

pub fn ownRunRole(tags: []const u8) ?[]const u8 {
    const r = vm_cmd.roleOf(tags) orelse return null;
    for (own_run_roles) |o| if (std.mem.eql(u8, r, o)) return o;
    return null;
}

/// One guest of `vm upgrade --all`.
const Guest = struct {
    vm: vms.Vm,
    name: []const u8,
    pending: apt.Pending,
    /// Ledger step; set by `send`.
    step: usize = 0,
    /// apt finished with exit 0 (`send`).
    upgraded: bool = false,
    /// Planned packages a fresh simulation still shows (`verify`).
    left: []const []const u8 = &.{},
    reboot: bool = false,
    /// The reboot check itself failed: neither "pending" nor "not needed".
    reboot_unknown: bool = false,
};

const UpgradeAllOp = struct {
    c: *pve.Client,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "every guest",
    todo: []Guest = &.{},
    current: []const []const u8 = &.{},
    skipped: []const []const u8 = &.{},
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *UpgradeAllOp, ctx: *Context) !void {
        const a = ctx.arena;
        var todo: std.ArrayList(Guest) = .empty;
        var current: std.ArrayList([]const u8) = .empty;
        var skipped: std.ArrayList([]const u8) = .empty;
        var fp: std.ArrayList(u8) = .empty;
        for (try vms.list(op.c)) |v| {
            if (v.template or !template.taggedWith(v.tags, vm_new.tag)) continue;
            const name = try k.clean(ctx, v.name);
            if (ownRunRole(v.tags)) |r| {
                try skipped.append(a, try std.fmt.allocPrint(a, "{s} (role {s}: 'artoo vm upgrade {s}')", .{ name, r, name }));
                continue;
            }
            if (!v.running()) {
                try skipped.append(a, try std.fmt.allocPrint(a, "{s} ({s})", .{ name, try k.clean(ctx, v.status) }));
                continue;
            }
            if (!try agent.ping(op.c, v.vmid)) {
                try skipped.append(a, try std.fmt.allocPrint(a, "{s} (guest agent not answering)", .{name}));
                continue;
            }
            const p = simulate(ctx, op.c, v.vmid, name) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    const why = ctx.diag orelse @errorName(err);
                    ctx.diag = null;
                    try skipped.append(a, try std.fmt.allocPrint(a, "{s} ({s})", .{ name, why }));
                    continue;
                },
            };
            try fp.print(a, "{s}:{?d}", .{ name, p.lists });
            for (p.packages) |pk| try fp.print(a, " {s}={s}", .{ pk.name, pk.to });
            try fp.append(a, ';');
            if (p.packages.len == 0) {
                try current.append(a, name);
            } else try todo.append(a, .{ .vm = v, .name = name, .pending = p });
        }
        op.todo = todo.items;
        op.current = current.items;
        op.skipped = skipped.items;
        op.fp = fp.items;
    }

    fn packages(op: *const UpgradeAllOp) usize {
        var n: usize = 0;
        for (op.todo) |g| n += g.pending.packages.len;
        return n;
    }

    pub fn plan(op: *UpgradeAllOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        if (op.todo.len == 0) {
            // Not exec's generic no-op line: it would hide the skipped guests.
            const up = if (op.current.len > 0) try std.fmt.allocPrint(a, "up to date: {s}", .{try std.mem.join(a, ", ", op.current)}) else "no guest was read";
            if (op.skipped.len == 0) return ctx.fail(error.NoChange, "nothing to upgrade ({s})", .{up});
            return ctx.fail(error.NoChange, "nothing to upgrade ({s}); skipped: {s}", .{ up, try std.mem.join(a, "; ", op.skipped) });
        }
        var name_w: usize = 0;
        for (op.todo) |g| name_w = @max(name_w, ui.text.width(g.name));
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        var sec: usize = 0;
        var deferred: usize = 0;
        var kept_back: usize = 0;
        var oldest: ?u64 = null;
        var unknown_age = false;
        for (op.todo) |g| {
            sec += g.pending.security();
            deferred += g.pending.deferred;
            kept_back += g.pending.kept_back;
            if (g.pending.listsAge()) |age| oldest = @max(oldest orelse 0, age) else unknown_age = true;
            for (g.pending.packages, 0..) |pk, i| {
                const who = if (i == 0) g.name else "";
                try changes.append(a, .{
                    .field = try std.fmt.allocPrint(a, "{s}{s}  {s}", .{ who, try pad(a, name_w - ui.text.width(who)), try k.clean(ctx, pk.name) }),
                    .from = if (pk.from) |f| try k.clean(ctx, f) else null,
                    .to = try std.fmt.allocPrint(a, "{s}{s}", .{ try k.clean(ctx, pk.to), if (pk.security) " (security)" else "" }),
                });
            }
        }
        var notes: std.ArrayList([]const u8) = .empty;
        if (oldest) |age| try notes.append(a, try std.fmt.allocPrint(a, "Package lists up to {f} old (apt's daily refresh){s}; artoo does not refresh them.", .{ ui.values.duration(age), if (unknown_age) ", some of unknown age" else "" })) else try notes.append(a, "Package lists of unknown age (no update-success stamp); artoo does not refresh them.");
        if (deferred > 0) try notes.append(a, try std.fmt.allocPrint(a, "{f} deferred by Ubuntu's phased rollout stay for now.", .{ui.values.count(deferred, "update")}));
        if (kept_back > 0) try notes.append(a, try std.fmt.allocPrint(a, "{f} kept back (they would need a removal) are not touched.", .{ui.values.count(kept_back, "package")}));
        try notes.append(a, "Pinned packages (Alloy) stay at their pins.");
        if (op.current.len > 0) try notes.append(a, try std.fmt.allocPrint(a, "Up to date: {s}.", .{try std.mem.join(a, ", ", op.current)}));
        for (op.skipped) |sk| try notes.append(a, try std.fmt.allocPrint(a, "Skipped: {s}.", .{sk}));
        return .{
            .action = try std.fmt.allocPrint(a, "Upgrade {f} on {f}{s}", .{
                ui.values.count(op.packages(), "package"),                                ui.values.count(op.todo.len, "guest"),
                if (sec > 0) try std.fmt.allocPrint(a, ", {d} security", .{sec}) else "",
            }),
            .target = try std.fmt.allocPrint(a, "the guest agents on {s}", .{try k.nodeTarget(ctx, op.c)}),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{
                "One guest after another; a guest whose upgrade fails does not stop the others",
                "Installed with apt as listed, new dependencies too (a new kernel); nothing is removed",
                "Services that use an upgraded library are restarted (needrestart); configuration files keep local changes",
                "No reboot: the result names the guests that want one ('artoo vm reboot VM')",
                "No undo: for a way back, upgrade a guest on its own with --snapshot",
            }),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *UpgradeAllOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *UpgradeAllOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        for (op.todo) |*g| g.step = try l.add(a, try std.fmt.allocPrint(a, "upgrade {s}", .{g.name}));
        for (op.todo) |*g| {
            const vmid = g.vm.vmid;
            const argv: []const []const u8 = &.{ "sh", "-c", apt.upgrade_script };
            const pid = agent.start(op.c, vmid, argv, null) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    // A 2xx without a pid may still have started apt.
                    l.set(g.step, if (err == error.OutcomeUnknown or err == error.Protocol) .unknown else .failed, try k.clean(ctx, ctx.diag orelse @errorName(err)));
                    ctx.diag = null;
                    continue;
                },
            };
            const r = agent.wait(op.c, vmid, pid, "apt-get upgrade", deadline_ms, .{ .file = apt.stage_file, .note = l.noter(g.step) }) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| {
                    l.set(g.step, .unknown, try std.fmt.allocPrint(a, "started (pid {d}); apt may still be running, log {s}", .{ pid, log_file }));
                    return e;
                },
                else => {
                    const why = ctx.diag orelse @errorName(err);
                    ctx.diag = null;
                    l.set(g.step, .unknown, try std.fmt.allocPrint(a, "outcome unknown ({s}); apt may still be running, log {s}", .{ try k.clean(ctx, why), log_file }));
                    continue;
                },
            };
            if (!r.ok()) {
                l.set(g.step, .failed, try std.fmt.allocPrint(a, "exit {?d}: {s} (log {s})", .{ r.code, try k.clean(ctx, lastLine(r.err)), log_file }));
                continue;
            }
            g.upgraded = true;
            l.set(g.step, .done, try std.fmt.allocPrint(a, "{f}", .{ui.values.count(g.pending.packages.len, "package")}));
        }
    }

    pub fn verify(op: *UpgradeAllOp, ctx: *Context) !bool {
        const a = ctx.arena;
        const l = &op.ledger;
        // The live display has ended: steps changed from here on must not
        // restart it, and the ledger is printed again when one changes.
        const live = l.progress;
        l.progress = null;
        var changed = false;
        for (op.todo) |*g| {
            if (!g.upgraded) continue;
            const now = simulate(ctx, op.c, g.vm.vmid, g.name) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    const why = ctx.diag orelse @errorName(err);
                    ctx.diag = null;
                    g.upgraded = false;
                    changed = true;
                    l.set(g.step, .unknown, try std.fmt.allocPrint(a, "upgraded, not verified: {s}", .{why}));
                    continue;
                },
            };
            var left: std.ArrayList([]const u8) = .empty;
            for (g.pending.packages) |pk| if (now.has(pk)) try left.append(a, try k.clean(ctx, pk.name));
            if (left.items.len > 0) {
                g.left = left.items;
                changed = true;
                l.set(g.step, .failed, try std.fmt.allocPrint(a, "{f} still pending: {s} (log {s})", .{ ui.values.count(left.items.len, "planned package"), try std.mem.join(a, ", ", left.items), log_file }));
                continue;
            }
            const r = agent.sh(op.c, g.vm.vmid, vm_new.scripts.reboot, 60_000) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => blk: {
                    ctx.diag = null;
                    break :blk null;
                },
            };
            if (r == null or !r.?.ok()) {
                g.reboot_unknown = true;
                changed = true;
                l.set(g.step, .done, try std.fmt.allocPrint(a, "{s}; reboot state unknown ('artoo vm verify {s}')", .{ l.steps.items[g.step].detail, g.name }));
                continue;
            }
            var lines = std.mem.tokenizeAny(u8, r.?.out, "\r\n");
            g.reboot = std.mem.eql(u8, lines.next() orelse "no", "yes");
            if (g.reboot) {
                changed = true;
                l.set(g.step, .done, try std.fmt.allocPrint(a, "{s}; reboot pending", .{l.steps.items[g.step].detail}));
            }
        }
        if (live == null or !live.?.replaces or changed) {
            try ctx.out.writeAll("\n");
            try l.render(ctx.out, &ctx.ui);
        }
        var unknown: usize = 0;
        var failed: usize = 0;
        for (l.steps.items) |st| switch (st.state) {
            .unknown => unknown += 1,
            .failed => failed += 1,
            else => {},
        };
        if (unknown > 0) return ctx.fail(error.OutcomeUnknown, "the outcome on {f} is unknown{s}; 'artoo vm verify --all' shows what is pending", .{
            ui.values.count(unknown, "guest"), if (failed > 0) try std.fmt.allocPrint(a, " and {d} failed", .{failed}) else "",
        });
        if (failed > 0) return ctx.fail(error.Partial, "{d} of {f} not upgraded (see above); the others are", .{ failed, ui.values.count(op.todo.len, "guest") });
        return true;
    }

    pub fn done(op: *UpgradeAllOp) []const u8 {
        const a = op.c.ctx.arena;
        var want: std.ArrayList([]const u8) = .empty;
        var unsure: std.ArrayList([]const u8) = .empty;
        for (op.todo) |g| {
            if (g.reboot) want.append(a, g.name) catch {};
            if (g.reboot_unknown) unsure.append(a, g.name) catch {};
        }
        const pending = if (want.items.len > 0)
            std.fmt.allocPrint(a, "; reboot pending on {s} — 'artoo vm reboot VM' when convenient", .{std.mem.join(a, ", ", want.items) catch ""}) catch "; reboot pending"
        else if (unsure.items.len == 0) "; no reboot needed" else "";
        const rest = if (unsure.items.len > 0)
            std.fmt.allocPrint(a, "{s}; reboot state unknown on {s}", .{ pending, std.mem.join(a, ", ", unsure.items) catch "" }) catch pending
        else
            pending;
        return std.fmt.allocPrint(a, "{f} upgraded on {f}{s}", .{ ui.values.count(op.packages(), "package"), ui.values.count(op.todo.len, "guest"), rest }) catch "upgraded";
    }
};

fn pad(a: std.mem.Allocator, n: usize) ![]const u8 {
    const b = try a.alloc(u8, n);
    @memset(b, ' ');
    return b;
}

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
    pub const summary = "Install a guest's pending package updates";
    pub const details =
        \\Installs the updates apt has pending on a running artoo guest,
        \\through its guest agent. The plan lists every package with its old
        \\and new version and marks security updates.
        \\
        \\Packages are upgraded as listed, with new dependencies (such as a
        \\new kernel); nothing is removed. Services that use an upgraded
        \\library are restarted, and configuration files keep local changes.
        \\Package lists are not refreshed (apt does that daily), and pinned
        \\packages stay at their pins.
        \\
        \\There is never a reboot: if one is needed, the result says so and
        \\'artoo vm reboot VM' does it when convenient. apt has no undo, so
        \\--snapshot takes a snapshot first as the way back.
        \\
        \\--all upgrades every running artoo guest in one plan, one guest
        \\after another; a guest that fails does not stop the others. The
        \\edge, the router and the watchdog (roles edge, router, watch) are
        \\left out: they are what reaches, serves and watches the rest, so
        \\each gets its own run. Guests that are stopped, whose agent does
        \\not answer or with nothing pending are named in the plan.
        \\
        \\Refused: templates, VMs artoo did not create, stopped VMs, and
        \\guests whose agent does not answer.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name", .required = false }};
    pub const flags = [_]cli.Flag{
        .{ .long = "all", .short = 'a', .help = "Every running artoo guest except the edge, router and watchdog" },
        snapguard.flag,
    };
    pub const examples = [_][]const u8{ "artoo vm upgrade naboo -n", "artoo vm upgrade naboo --snapshot", "artoo vm upgrade naboo -y", "artoo vm upgrade --all -n" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        if (args.has("all")) {
            if (args.optPos("VM") != null) return ctx.fail(error.Usage, "give a VM or --all, not both", .{});
            if (args.has("snapshot")) return ctx.fail(error.Usage, "--snapshot goes with one VM: upgrade a guest on its own for a way back", .{});
            if (ctx.globals.no_wait) return ctx.fail(error.Usage, "--no-wait goes with one VM: --all upgrades one guest after another and waits for each", .{});
            var c = try pve.Client.open(ctx);
            defer c.deinit();
            var op: UpgradeAllOp = .{ .c = &c };
            return exec.run(ctx, &op, .{});
        }
        const word = args.optPos("VM") orelse return ctx.fail(error.Usage, "missing VM (or --all)", .{});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: UpgradeOp = .{ .c = &c, .word = word };
        if (args.has("snapshot")) op.guard = .{ .action = "upgrade", .command = "vm upgrade" };
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
        "Plan · Upgrade 3 packages on naboo (205), 1 security\n",
        "libssl3t64                    3.5.3-1ubuntu1 → 3.5.3-1ubuntu1.1 (security)\n",
        "linux-image-7.0.0-40-generic  (none) → 7.0.0-40.40\n",
        "Package lists from 1h ago (apt's daily refresh); artoo does not refresh them.",
        "4 updates deferred by Ubuntu's phased rollout stay for now.",
        "1 package kept back",
        "✓ apt-get upgrade  done",
        // tmux has a newer version now: the planned one is installed.
        "✓ 3 packages upgraded on naboo; reboot pending (linux-image-7.0.0-40-generic, linux-base) — 'artoo vm reboot naboo' when convenient\n",
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
    try expectAll(g.h.stderr(), &.{"artoo: 1 planned package still pending on naboo: tmux (log: /var/log/artoo-upgrade.log)\n"});
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

const snap_upid = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:qmsnapshot:205:artoo@pve!cli:\"}";
const task_ok = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}";
const naboo_config = "{\"data\":{\"scsi0\":\"local-zfs:vm-205-disk-0,size=20G\"}}";

/// The listing after the snapshot step: the names for this minute and
/// the next, so the run's own name is in it whenever it starts.
fn listingWithOwnName(a: std.mem.Allocator) ![]const u8 {
    const now: i64 = @intCast(@divFloor(std.Io.Clock.real.now(testing.io).nanoseconds, std.time.ns_per_s));
    return std.fmt.allocPrint(a, "{{\"data\":[{{\"name\":\"current\"}},{{\"name\":\"{s}\"}},{{\"name\":\"{s}\"}}]}}", .{
        try snapguard.snapName(a, "upgrade", now), try snapguard.snapName(a, "upgrade", now + 60),
    });
}

test "vm upgrade --snapshot: the snapshot is planned, taken first and named in the result" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans(list_body), ans(ping_body), ans(pid_body), ans(try execStatus(a, 0, apt.sample, "")), // read
        ans("{\"data\":[{\"name\":\"current\"},{\"name\":\"mine\",\"snaptime\":1}]}"), ans(naboo_config), ans(@import("storage.zig").storage_body), // guard
        ans(snap_upid), ans(task_ok), ans(try listingWithOwnName(a)), // snapshot step
        ans(pid_body), ans("{\"data\":{\"exited\":0}}"), ans("{\"data\":{\"content\":\"\"}}"), ans(try execStatus(a, 0, "", "")), // upgrade
        ans(pid_body), ans(try execStatus(a, 0, "lists 4700\nnow 4800\n", "")), // verify
        ans(pid_body), ans(try execStatus(a, 0, "no\n", "")), // no reboot
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm upgrade naboo --snapshot -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/205/snapshot HTTP/1.1", g.request(7));
    try testing.expect(std.mem.startsWith(u8, g.body(7), "snapname=artoo-upgrade-20"));
    try testing.expect(std.mem.find(u8, g.body(7), "&description=artoo%20") != null);
    try testing.expect(std.mem.find(u8, g.body(7), "vmstate") == null);
    try expectAll(g.h.stdout(), &.{
        "snapshot                      (none) → artoo-upgrade-20",
        "(no RAM), taken first",
        "Recovery  artoo vm snap rollback naboo artoo-upgrade-20",
        "apt has no undo: the snapshot taken first is the way back",
        "not its Proxmox firewall rules",
        "kept ('artoo vm snap prune naboo' when no longer needed)",
    });
}

test "vm upgrade --snapshot: refused at the cap and above the storage headroom, nothing sent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sim = try execStatus(a, 0, apt.sample, "");
    const full = "{\"data\":[{\"active\":1,\"enabled\":1,\"storage\":\"local-zfs\",\"type\":\"zfspool\",\"total\":1000,\"used\":900}]}";
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans(list_body),                                                                                                                                                ans(ping_body),                             ans(pid_body),     ans(sim),
        ans("{\"data\":[{\"name\":\"current\"},{\"name\":\"artoo-upgrade-20261101T0100Z\",\"snaptime\":1},{\"name\":\"artoo-edge-20261102T0100Z\",\"snaptime\":2}]}"), ans(list_body),                             ans(ping_body),    ans(pid_body),
        ans(sim),                                                                                                                                                      ans("{\"data\":[{\"name\":\"current\"}]}"), ans(naboo_config), ans(full),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm upgrade naboo --snapshot -y"));
    try testing.expectEqualStrings("artoo: naboo holds 2 artoo snapshots (keep 2): 'artoo vm snap prune naboo' first, or run without --snapshot\n", g.h.stderr());
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm upgrade naboo --snapshot -y"));
    try testing.expectEqualStrings("artoo: storage local-zfs is 90% used (above 80%): no snapshot is taken there; free space first, or run without --snapshot\n", g.h.stderr());
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "vm upgrade --snapshot: a failing apt names the rollback" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans(list_body),                             ans(ping_body),                 ans(pid_body),                            ans(try execStatus(a, 0, apt.sample, "")),
        ans("{\"data\":[{\"name\":\"current\"}]}"), ans(naboo_config),              ans(@import("storage.zig").storage_body), ans(snap_upid),
        ans(task_ok),                               ans(try listingWithOwnName(a)), ans(pid_body),                            ans(try execStatus(a, 100, "", "E: dpkg was interrupted\n")),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.task_failed, g.h.run(&root, "vm upgrade naboo --snapshot -y"));
    try expectAll(g.h.stderr(), &.{ "apt-get upgrade failed on naboo (exit 100): E: dpkg was interrupted", " — the snapshot taken first is the way back: artoo vm snap rollback naboo artoo-upgrade-20" });
}

const all_list = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"},{\"vmid\":201,\"name\":\"dagobah\",\"status\":\"running\",\"tags\":\"artoo;role-router\"},{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"},{\"vmid\":204,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo;role-search\"},{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;role-dev\"},{\"vmid\":206,\"name\":\"endor\",\"status\":\"stopped\",\"tags\":\"artoo;role-app\"},{\"vmid\":207,\"name\":\"tatooine\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":150,\"name\":\"other\",\"status\":\"running\"},{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"status\":\"stopped\",\"template\":1,\"tags\":\"artoo-template\"}]}";

test "vm upgrade --all: one plan without the edge, router and watchdog; a failing guest does not stop the next" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const hoth_sim = try execStatus(a, 0, "lists 1000\nnow 4600\nInst tmux [1] (2 Ubuntu:26.04/resolute-updates [amd64])\nInst libssl3t64 [3.5.3-1ubuntu1] (3.5.3-1ubuntu1.1 Ubuntu:26.04/resolute-security [amd64])\n", "");
    const naboo_sim = try execStatus(a, 0, "lists 1000\nnow 8200\nInst curl [8.1] (8.2 Ubuntu:26.04/resolute-updates [amd64])\n", "");
    const none = try execStatus(a, 0, "lists 1000\nnow 1100\n", "");
    const read = [_]B{
        ans(all_list),
        ans(ping_body), ans(pid_body), ans(hoth_sim), // hoth: role search is upgraded
        ans(ping_body), ans(pid_body), ans(naboo_sim), // naboo
        ans(ping_body), ans(pid_body), ans(none), // tatooine: up to date
    };
    var g: testkit.Gateway = undefined;
    try g.init(&(read ++ read ++ [_]B{
        ans(pid_body), ans(try execStatus(a, 100, "", "Reading package lists...\nE: dpkg was interrupted\n")), // hoth fails
        ans(pid_body), ans(try execStatus(a, 0, "", "")), // naboo upgraded
        ans(pid_body), ans(try execStatus(a, 0, "lists 1000\nnow 8300\n", "")), // naboo verified
        ans(pid_body), ans(try execStatus(a, 0, "yes\nlinux-base\n", "")), // reboot wanted
    }));
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm upgrade --all -n"));
    const plan = g.h.stdout();
    try expectAll(plan, &.{
        "Plan · Upgrade 3 packages on 2 guests, 1 security\n",
        "Change    hoth   tmux        1 → 2\n",
        "          ",
        "       libssl3t64  3.5.3-1ubuntu1 → 3.5.3-1ubuntu1.1 (security)\n",
        "          naboo  curl        8.1 → 8.2\n",
        "One guest after another; a guest whose upgrade fails does not stop the others",
        "Package lists up to 2h old",
        "Up to date: tatooine.",
        "Skipped: bespin (role edge: 'artoo vm upgrade bespin').",
        "Skipped: dagobah (role router: 'artoo vm upgrade dagobah').",
        "Skipped: scarif (role watch: 'artoo vm upgrade scarif').",
        "Skipped: endor (stopped).",
        "Dry run: nothing was sent.\n",
    });
    for ([_][]const u8{ "other (", "other.", "ubuntu-2604" }) |gone| try testing.expect(std.mem.find(u8, plan, gone) == null);

    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm upgrade --all -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try expectAll(g.h.stdout(), &.{
        "✗ upgrade hoth   failed  exit 100: E: dpkg was interrupted (log /var/log/artoo-upgrade.log)\n",
        "✓ upgrade naboo  done  1 package; reboot pending\n",
    });
    try expectAll(g.h.stderr(), &.{ "✗ upgrade hoth  failed", "✓ upgrade naboo  done", "artoo: 1 of 2 guests not upgraded (see above); the others are\n" });
}

test "vm upgrade --all: nothing pending is a no-op; usage" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const none = try execStatus(a, 0, "lists 1000\nnow 1100\n", "");
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans(all_list),
        ans(ping_body),
        ans(pid_body),
        ans(none),
        ans(ping_body),
        ans(pid_body),
        ans(none),
        ans(ping_body),
        ans(pid_body),
        ans(none),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm upgrade --all -y"));
    // The skipped guests are named, not hidden behind a generic no-op line.
    try testing.expectEqualStrings("artoo: nothing to upgrade (up to date: hoth, naboo, tatooine); skipped: bespin (role edge: 'artoo vm upgrade bespin'); dagobah (role router: 'artoo vm upgrade dagobah'); scarif (role watch: 'artoo vm upgrade scarif'); endor (stopped)\n", g.h.stderr());
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm upgrade naboo --all"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm upgrade --all --snapshot"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm upgrade --all -y --no-wait"));
    try expectAll(g.h.stderr(), &.{"artoo: --no-wait goes with one VM: --all upgrades one guest after another and waits for each\n"});
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm upgrade"));
}

test "vm upgrade --all: a failing apt-get -s is a named skip; no pid is unknown (exit 7); a package left fails its guest; an unanswered reboot check claims nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const one = try execStatus(a, 0, "lists 1000\nnow 1100\nInst tmux [1] (2 Ubuntu:26.04/resolute-updates [amd64])\n", "");
    const broken = try execStatus(a, 100, "", "E: dpkg was interrupted, you must manually run 'dpkg --configure -a'\n");
    const read = [_]B{
        ans(all_list),
        ans(ping_body), ans(pid_body), ans(broken), // hoth: simulation fails → skipped
        ans(ping_body), ans(pid_body), ans(one), // naboo
        ans(ping_body), ans(pid_body), ans(one), // tatooine
    };
    var g: testkit.Gateway = undefined;
    try g.init(&(read ++ [_]B{
        ans("{\"data\":{}}"), // naboo: accepted, no pid
        ans(pid_body), ans(try execStatus(a, 0, "", "")), // tatooine upgraded
        ans(pid_body), ans(one), // tmux still pending
    } ++ read ++ [_]B{
        ans(pid_body), ans(try execStatus(a, 0, "", "")), // naboo upgraded
        ans(pid_body), ans(try execStatus(a, 0, "", "")), // tatooine upgraded
        ans(pid_body), ans(try execStatus(a, 0, "lists 1000\nnow 1200\n", "")), // naboo verified
        ans(pid_body), ans(try execStatus(a, 1, "", "")), // its reboot check fails
        ans(pid_body), ans(try execStatus(a, 0, "lists 1000\nnow 1200\n", "")), // tatooine verified
        ans(pid_body), ans(try execStatus(a, 0, "no\n", "")),
    }));
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.unknown, g.h.run(&root, "vm upgrade --all -y"));
    try expectAll(g.h.stdout(), &.{
        "Skipped: hoth (apt-get -s failed on hoth (exit 100): E: dpkg was interrupted, you must manually run 'dpkg --configure -a').",
        "? upgrade naboo     unknown  the guest agent of VM 205 returned no pid\n",
        "✗ upgrade tatooine  failed  1 planned package still pending: tmux (log /var/log/artoo-upgrade.log)\n",
    });
    try expectAll(g.h.stderr(), &.{"artoo: the outcome on 1 guest is unknown and 1 failed; 'artoo vm verify --all' shows what is pending\n"});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm upgrade --all -y"));
    try expectAll(g.h.stdout(), &.{
        "✓ upgrade naboo     done  1 package; reboot state unknown ('artoo vm verify naboo')\n",
        "✓ 2 packages upgraded on 2 guests; reboot state unknown on naboo\n",
    });
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}
