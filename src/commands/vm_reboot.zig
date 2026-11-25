//! `artoo vm reboot --pending`: reboot the artoo guests
//! that want it (`/run/reboot-required`), one after another, each back,
//! its agent answering and the request gone before the next — the first
//! that does not come back stops the run. The edge, the router and the
//! watchdog are left to their own `vm reboot`, as with `vm upgrade --all`.
//! On guests tagged `rex` the agents are read first: a guest
//! where one is working or blocked is skipped unless `--force-agents`.

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
const tasks = @import("../pve/task.zig");
const rex_guest = @import("../rex/guest.zig");
const rex_state = @import("../rex/state.zig");

const Context = app.Context;

const Guest = struct {
    vm: vms.Vm,
    name: []const u8,
    /// `/run/reboot-required.pkgs`, deduplicated.
    pkgs: []const []const u8,
    /// Tagged `rex`: its agents are read again before the reboot.
    rex: bool = false,
    /// With `--force-agents`: the agents busy there (or why they could not
    /// be read), named in the plan; null when none is.
    agents: ?[]const u8 = null,
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
    if (pkgs.len == 0) return "packages not named";
    const shown = pkgs[0..@min(pkgs.len, 3)];
    const more = if (pkgs.len > 3) try std.fmt.allocPrint(a, " +{d}", .{pkgs.len - 3}) else "";
    return std.fmt.allocPrint(a, "{s}{s}", .{ try std.mem.join(a, ", ", shown), more });
}

/// The typed confirmation when `--force-agents` reboots a guest whose
/// agents are busy.
pub const forced_target = "every-guest";

pub const RebootPendingOp = struct {
    c: *pve.Client,
    /// `.destructive` when `--force-agents` includes a busy guest.
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "every guest",
    /// `--force-agents`: guests whose agents are busy (or unreadable) are rebooted too.
    force_agents: bool = false,
    /// `guests.user`, as whom the agents are read.
    user: []const u8 = "",
    /// Guests skipped in `send` because an agent was busy by then.
    agent_skips: usize = 0,
    todo: []const Guest = &.{},
    not_needed: []const []const u8 = &.{},
    /// Edge, router, watchdog that want a reboot: named, never rebooted here.
    own_run: []const []const u8 = &.{},
    skipped: []const []const u8 = &.{},
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *RebootPendingOp, ctx: *Context) !void {
        const a = ctx.arena;
        var host_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
        const here = shortName(std.posix.gethostname(&host_buf) catch "");
        var todo: std.ArrayList(Guest) = .empty;
        var not_needed: std.ArrayList([]const u8) = .empty;
        var own_run: std.ArrayList([]const u8) = .empty;
        var skipped: std.ArrayList([]const u8) = .empty;
        var fp: std.ArrayList(u8) = .empty;
        op.risk = .normal;
        op.target = "every guest";
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
            // Rebooting the machine artoo runs on would end the run midway.
            if (here.len > 0 and std.ascii.eqlIgnoreCase(here, v.name)) {
                try own_run.append(a, try std.fmt.allocPrint(a, "{s} (artoo runs here: reboot it last, on its own; {s})", .{ name, try pkgList(a, pkgs) }));
                continue;
            }
            // an agent working or blocked holds the reboot back.
            var busy: ?[]const u8 = null;
            if (rex_guest.tagged(v)) {
                busy = try busyAgents(ctx, op.c, v.vmid, op.user);
                if (busy) |b| {
                    if (!op.force_agents) {
                        try skipped.append(a, try std.fmt.allocPrint(a, "{s} ({s}; --force-agents to reboot anyway)", .{ name, b }));
                        continue;
                    }
                    op.risk = .destructive;
                    op.target = forced_target;
                }
            }
            try fp.print(a, "{d}:{s}:{s}{s};", .{ v.vmid, name, try std.mem.join(a, ",", pkgs), if (busy != null) ":agents" else "" });
            try todo.append(a, .{ .vm = v, .name = name, .pkgs = pkgs, .rex = rex_guest.tagged(v), .agents = busy });
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
        var impact: std.ArrayList([]const u8) = .empty;
        try impact.appendSlice(a, &.{
            "One guest after another; each guest's services are briefly unavailable",
            "Each guest must run again, its agent answer and its reboot request be gone before the next starts",
            "The first guest that does not come back stops the run; the rest are not rebooted",
        });
        var forced: std.ArrayList([]const u8) = .empty;
        for (op.todo) |g| if (g.agents) |b| try forced.append(a, try std.fmt.allocPrint(a, "{s} ({s})", .{ g.name, b }));
        if (forced.items.len > 0) {
            try impact.append(a, try std.fmt.allocPrint(a, "--force-agents: the reboot cuts off the agents at work on {s}; their sessions end", .{try std.mem.join(a, "; ", forced.items)}));
        } else if (op.force_agents) {
            try notes.append(a, "--force-agents: no agent is busy on these guests now, so only y/N is asked; one busy by its turn is skipped (run again to confirm it).");
        }
        for (op.todo) |g| if (g.rex and !(op.force_agents and op.risk == .destructive))
            try notes.append(a, try std.fmt.allocPrint(a, "{s} runs Rex: its agents are read again right before its reboot; one busy by then skips it.", .{g.name}));
        return .{
            .action = try std.fmt.allocPrint(a, "Reboot {f} that want it", .{ui.values.count(op.todo.len, "guest")}),
            .risk = op.risk,
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = impact.items,
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
            var sent = false;
            // Read again right before the write: an agent busy by now skips
            // the guest — with --force-agents too, unless the
            // typed confirmation covered busy guests (nothing was busy at
            // the plan, so only y/N was asked).
            if (g.rex and !(op.force_agents and op.risk == .destructive)) {
                if (try busyAgents(ctx, op.c, g.vm.vmid, op.user)) |b| {
                    l.set(i, .skipped, if (op.force_agents)
                        try std.fmt.allocPrint(a, "{s} since the confirmation; run again to confirm it", .{b})
                    else
                        try std.fmt.allocPrint(a, "{s}; --force-agents to reboot anyway", .{b}));
                    op.agent_skips += 1;
                    continue;
                }
            }
            rebootOne(ctx, op.c, g, l, i, &sent) catch |err| {
                if (err == error.OutOfMemory) return err;
                if (!ctx.json()) {
                    ctx.out.writeAll("\n") catch {};
                    l.render(ctx.out, &ctx.ui) catch {};
                }
                const why = try k.clean(ctx, ctx.diag orelse @errorName(err));
                const after = op.todo.len - (i - first) - 1;
                const st = l.steps.items[i].state;
                if (!sent) return ctx.fail(err, "{s} was not rebooted ({s}); the run stopped, {f} not rebooted", .{ g.name, why, ui.values.count(after + 1, "guest") });
                const rest = if (after > 0) try std.fmt.allocPrint(a, "{f} after it not rebooted", .{ui.values.count(after, "guest")}) else "it was the last";
                if (st == .unknown) return ctx.fail(if (err == error.Canceled) err else error.OutcomeUnknown, "the reboot of {s} was sent, outcome unknown ({s}); check 'artoo vm verify {s}' before running again; {s}", .{ g.name, why, g.name, rest });
                return ctx.fail(error.Partial, "{s} did not come back as expected ({s}); {s}", .{ g.name, why, rest });
            };
        }
    }

    pub fn verify(op: *RebootPendingOp, ctx: *Context) !bool {
        if (!ctx.json()) {
            try ctx.out.writeAll("\n");
            try op.ledger.render(ctx.out, &ctx.ui);
        }
        var n: usize = 0;
        for (op.ledger.steps.items) |st| n += @intFromBool(st.state == .done);
        if (n == 0 and op.agent_skips > 0) return ctx.fail(error.NoChange, "no guest was rebooted: when its turn came, an agent was busy on {f} and the rest no longer wanted it", .{ui.values.count(op.agent_skips, "guest")});
        if (n == 0) return ctx.fail(error.NoChange, "no guest was rebooted: none wanted it any more when its turn came", .{});
        return op.ledger.complete();
    }

    pub fn done(op: *RebootPendingOp) []const u8 {
        const a = op.c.ctx.arena;
        var n: usize = 0;
        for (op.ledger.steps.items) |st| n += @intFromBool(st.state == .done);
        return std.fmt.allocPrint(a, "{f} rebooted and back; no reboot request left on them", .{ui.values.count(n, "guest")}) catch "rebooted";
    }
};

/// The busy agents of a guest tagged `rex`, described ("claude-code
/// working in naboo-api"), or why they could not be read ("agents
/// unreadable: …") — both hold its reboot back; null when none is busy.
fn busyAgents(ctx: *Context, c: *pve.Client, vmid: u32, user: []const u8) !?[]const u8 {
    const found = rex_state.agents(ctx, c, vmid, user) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return try std.fmt.allocPrint(ctx.arena, "agents unreadable: {s}", .{try reason(ctx, err)}),
    };
    return rex_state.busyText(ctx, found);
}

/// The host name without its domain.
fn shortName(h: []const u8) []const u8 {
    return h[0 .. std.mem.indexOfScalar(u8, h, '.') orelse h.len];
}

fn reason(ctx: *Context, err: anyerror) ![]const u8 {
    defer ctx.diag = null;
    return k.clean(ctx, ctx.diag orelse @errorName(err));
}

/// One guest's reboot. Every return sets the guest's step to its final
/// state first — done, skipped, failed, or unknown when the reboot was
/// (or may have been) sent and its end is not known — and `sent` says
/// whether the write went out (or may have).
fn rebootOne(ctx: *Context, c: *pve.Client, g: Guest, l: *exec.Ledger, i: usize, sent: *bool) !void {
    const a = ctx.arena;
    const vmid = g.vm.vmid;
    // The request is read again right before the write: a guest that no
    // longer wants a reboot is skipped, not rebooted.
    const want = wanted(ctx, c, vmid) catch |err| {
        if (err == error.OutOfMemory or err == error.Canceled) return err;
        const why = try reason(ctx, err);
        l.set(i, .failed, try std.fmt.allocPrint(a, "reboot check failed: {s}", .{why}));
        return ctx.fail(err, "its reboot check failed: {s}", .{why});
    };
    if (want == null) {
        l.set(i, .skipped, "no longer wanted");
        return;
    }
    sent.* = true;
    l.set(i, .unknown, "");
    const data = c.send(.POST, try c.nodePath("/qemu/{d}/status/reboot", .{vmid}), &.{}) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        // No definite answer: the reboot may have been sent.
        error.OutcomeUnknown, error.Network, error.Timeout, error.Protocol, error.Canceled => {
            const why = try reason(ctx, err);
            l.set(i, .unknown, try std.fmt.allocPrint(a, "may have been sent: {s}", .{why}));
            return ctx.fail(err, "{s}", .{why});
        },
        else => {
            sent.* = false;
            const why = try reason(ctx, err);
            l.set(i, .failed, try std.fmt.allocPrint(a, "refused, not rebooted: {s}", .{why}));
            return ctx.fail(err, "Proxmox refused it: {s}", .{why});
        },
    };
    const upid = tasks.upidOf(c, data, "the reboot") catch |err| {
        const why = try reason(ctx, err);
        l.set(i, .unknown, try std.fmt.allocPrint(a, "sent, no task ID: {s}", .{why}));
        return ctx.fail(err, "{s}", .{why});
    };
    _ = k.waitTaskNoted(c, upid, 240, l.noter(i)) catch |err| {
        if (err == error.OutOfMemory) return err;
        const why = try reason(ctx, err);
        if (err == error.TaskFailed) {
            l.set(i, .failed, try std.fmt.allocPrint(a, "reboot task failed: {s}", .{why}));
            return ctx.fail(err, "its reboot task failed: {s}", .{why});
        }
        l.set(i, .unknown, try std.fmt.allocPrint(a, "sent, its task not followed to the end: {s}", .{why}));
        return ctx.fail(err, "{s}", .{why});
    };
    l.note(i, "waiting for the guest agent");
    agent.waitReady(c, vmid, 600_000) catch |err| {
        if (err == error.OutOfMemory) return err;
        const why = try reason(ctx, err);
        if (err == error.WaitTimeout) {
            l.set(i, .failed, try std.fmt.allocPrint(a, "not back: {s}", .{why}));
            return ctx.fail(err, "{s}", .{why});
        }
        l.set(i, .unknown, try std.fmt.allocPrint(a, "rebooted, not seen back: {s}", .{why}));
        return ctx.fail(err, "{s}", .{why});
    };
    const r = agent.sh(c, vmid, "uname -r; test -f /run/reboot-required && echo still || true", 60_000) catch |err| {
        if (err == error.OutOfMemory) return err;
        const why = try reason(ctx, err);
        l.set(i, .unknown, try std.fmt.allocPrint(a, "back, its reboot state unread: {s}", .{why}));
        return ctx.fail(err, "{s}", .{why});
    };
    var out = std.mem.tokenizeAny(u8, r.out, "\r\n");
    const kernel = out.next() orelse "";
    if (!r.ok() or kernel.len == 0) {
        l.set(i, .unknown, "back, its reboot state unread");
        return ctx.fail(error.OutcomeUnknown, "it is back, but its reboot state could not be read (exit {?d})", .{r.code});
    }
    const kern = try k.clean(ctx, kernel);
    if (std.mem.eql(u8, out.next() orelse "", "still")) {
        l.set(i, .failed, try std.fmt.allocPrint(a, "still pending after the reboot (kernel {s})", .{kern}));
        return ctx.fail(error.Partial, "it still wants a reboot after rebooting (kernel {s})", .{kern});
    }
    l.set(i, .done, try std.fmt.allocPrint(a, "kernel {s}", .{kern}));
}

/// `force_agents`: `--force-agents`; `confirm`: `--confirm TARGET`.
pub fn runPending(ctx: *Context, force_agents: bool, confirm: ?[]const u8) !void {
    var c = try pve.Client.open(ctx);
    defer c.deinit();
    var op: RebootPendingOp = .{ .c = &c, .force_agents = force_agents, .user = (try ctx.config()).guests.user };
    try exec.run(ctx, &op, .{ .confirm = confirm });
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
const upid_body = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:qmreboot:205:artoo@pve!cli:\"}";
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
        ans(pid), ans(yes), ans(upid_body), ans(task_ok), ans(ping), ans(pid), ans(try execStatus(a, 0, "7.0.0-45-generic\n")),
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
        ans(upid_body),
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
    try expectAll(g.h.stderr(), &.{"artoo: naboo did not come back as expected (it still wants a reboot after rebooting (kernel 7.0.0-45-generic)); 1 guest after it not rebooted\n"});
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

test "vm reboot --pending: a refused reboot was not sent and counts itself; an ambiguous one is unknown (exit 7); no .pkgs still wants it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // `/run/reboot-required` without `.pkgs`: still a guest that wants it.
    const yes = try execStatus(a, 0, "yes\n");
    const two = "{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":207,\"name\":\"tatooine\",\"status\":\"running\",\"tags\":\"artoo\"}]}";
    const read = [_]B{ ans(two), ans(ping), ans(pid), ans(yes), ans(ping), ans(pid), ans(yes) };
    var g: testkit.Gateway = undefined;
    try g.init(&(read ++ [_]B{
        ans(pid), ans(yes), .{ .respond = .{ .status = 500, .body = "{\"message\":\"VM is locked (backup)\"}" } },
    } ++ read ++ [_]B{
        ans(pid), ans(yes), .{ .respond = .{ .status = 502, .body = "{\"message\":\"bad gateway\"}" } },
    }));
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expect(g.h.run(&root, "vm reboot --pending -y") != Exit.ok);
    try expectAll(g.h.stdout(), &.{ "✗ reboot naboo     failed  refused, not rebooted: Proxmox refused POST", "naboo     running → rebooted (packages not named)\n", "– reboot tatooine  not run" });
    try expectAll(g.h.stderr(), &.{"artoo: naboo was not rebooted (Proxmox refused it: Proxmox refused POST /nodes/pve/qemu/205/status/reboot (500): VM is locked (backup)); the run stopped, 2 guests not rebooted\n"});
    try testing.expectEqual(Exit.unknown, g.h.run(&root, "vm reboot --pending -y"));
    try expectAll(g.h.stdout(), &.{"reboot naboo     unknown  may have been sent: Proxmox answered 502"});
    try expectAll(g.h.stderr(), &.{ "artoo: the reboot of naboo was sent, outcome unknown (Proxmox answered 502", "check 'artoo vm verify naboo' before running again; 1 guest after it not rebooted\n" });
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "vm reboot VM: one VM still reboots as before" {
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        ans("{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"}]}"),
        ans(upid_body),
        ans(task_ok),
        ans("{\"data\":{\"status\":\"running\"}}"),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm reboot naboo -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/205/status/reboot HTTP/1.1", g.request(1));
    try expectAll(g.h.stdout(), &.{ "Plan · Reboot VM naboo (205)\n", "✓ naboo is running (" });
}

const rex_two = "{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;rex\"},{\"vmid\":207,\"name\":\"tatooine\",\"status\":\"running\",\"tags\":\"artoo\"}]}";
const agents_working = "{\"server\":{\"running\":true,\"version\":\"0.1.0-snapshot.23\",\"sessions\":1},\"agents\":[{\"session\":\"naboo-api\",\"block\":\"block:1\",\"app\":\"claude-code\",\"state\":\"working\",\"title\":\"\",\"updated_at\":\"2026-11-25T01:52:40+01:00\"}],\"errors\":[]}";
const agents_idle = "{\"server\":{\"running\":true,\"version\":\"0.1.0-snapshot.23\",\"sessions\":1},\"agents\":[{\"session\":\"naboo-api\",\"block\":\"block:1\",\"app\":\"claude-code\",\"state\":\"idle\",\"title\":\"\",\"updated_at\":\"\"}],\"errors\":[]}";

test "vm reboot --pending: a rex guest with an agent working is skipped; --force-agents includes it behind the typed target" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const yes = try execStatus(a, 0, "yes\nlinux-base\n");
    const working = try execStatus(a, 0, agents_working);
    const read = [_]B{ ans(rex_two), ans(ping), ans(pid), ans(yes), ans(pid), ans(working), ans(ping), ans(pid), ans(yes) };
    const back = [_]B{ ans(pid), ans(yes), ans(upid_body), ans(task_ok), ans(ping), ans(pid), ans(try execStatus(a, 0, "7.0.0-45-generic\n")) };
    var g: testkit.Gateway = undefined;
    try g.init(&(read ++ read ++ read ++ back ++ back));
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm reboot --pending -n"));
    try expectAll(g.h.stdout(), &.{
        "Plan · Reboot 1 guest that want it\n",
        "Change    tatooine  running → rebooted (linux-base)\n",
        "Skipped: naboo (claude-code working in naboo-api; --force-agents to reboot anyway).",
    });
    try testing.expect(std.mem.find(u8, g.h.stdout(), "destructive") == null);
    // --force-agents: destructive, the typed target is every-guest.
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm reboot --pending --force-agents -y"));
    try expectAll(g.h.stdout(), &.{ "destructive", "Change    naboo     running → rebooted (linux-base)\n", "--force-agents: the reboot cuts off the agents at work on naboo (claude-code working in naboo-api); their sessions end" });
    try expectAll(g.h.stderr(), &.{"add --confirm every-guest to proceed with --yes"});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm reboot --pending --force-agents -y --confirm every-guest"));
    try expectAll(g.h.stdout(), &.{ "✓ reboot naboo     done  kernel 7.0.0-45-generic\n", "✓ 2 guests rebooted and back" });
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm reboot naboo --force-agents"));
}

test "vm reboot --pending: the agents are read again before each rex guest's reboot; busy by then, or unreadable, skips it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const yes = try execStatus(a, 0, "yes\nlinux-base\n");
    const read = [_]B{ ans(rex_two), ans(ping), ans(pid), ans(yes), ans(pid), ans(try execStatus(a, 0, agents_idle)), ans(ping), ans(pid), ans(yes) };
    const back = [_]B{ ans(pid), ans(yes), ans(upid_body), ans(task_ok), ans(ping), ans(pid), ans(try execStatus(a, 0, "7.0.0-45-generic\n")) };
    const unreadable = [_]B{ ans(rex_two), ans(ping), ans(pid), ans(yes), ans(pid), ans(try execStatus(a, 1, "")), ans(ping), ans(pid), ans(yes) };
    var g: testkit.Gateway = undefined;
    try g.init(&(read ++ [_]B{ ans(pid), ans(try execStatus(a, 0, agents_working)) } ++ back ++ unreadable));
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm reboot --pending -y"));
    try expectAll(g.h.stdout(), &.{
        "naboo runs Rex: its agents are read again right before its reboot; one busy by then skips it.",
        "reboot naboo     skipped  claude-code working in naboo-api; --force-agents to reboot anyway\n",
        "✓ reboot tatooine  done",
        "✓ 1 guest rebooted and back",
    });
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm reboot --pending -n"));
    try expectAll(g.h.stdout(), &.{"Skipped: naboo (agents unreadable: the read exited 1; --force-agents to reboot anyway)."});
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}
