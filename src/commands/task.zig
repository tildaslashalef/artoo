//! `artoo task ls | show TASK | log TASK | wait TASK` (SPEC §3.3): Proxmox
//! tasks. TASK is a UPID, a handle as printed (`qmstart:100@14:32`) or a
//! unique fragment of a UPID.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const tasks = @import("../pve/task.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

pub const Task = struct {
    upid: []const u8,
    handle: []const u8,
    type: []const u8,
    id: []const u8,
    user: []const u8,
    start: ?i64,
    end: ?i64,
    /// null while running; else the exit status (`OK`, `WARNINGS: n`, error).
    exitstatus: ?[]const u8,

    pub fn state(t: Task) ui.style.Status {
        const es = t.exitstatus orelse return .running;
        return if (tasks.succeeded(es)) |warn| (if (warn) .warning else .ok) else .failed;
    }
};

pub const Filter = enum { all, running, failed };

/// Recent tasks on the node, newest first.
pub fn list(c: *pve.Client, limit: u32, filter: Filter) ![]Task {
    const ctx = c.ctx;
    const path = try c.nodePath("/tasks?limit={d}&source={s}{s}", .{
        limit,
        if (filter == .running) "active" else "all",
        if (filter == .failed) "&errors=1" else "",
    });
    var out: std.ArrayList(Task) = .empty;
    for (pve.items(try c.get(path))) |t| {
        const upid = pve.str(t, "upid") orelse continue;
        const end = pve.int(t, "endtime");
        try out.append(ctx.arena, .{
            .upid = upid,
            .handle = try tasks.handle(ctx.arena, upid, &ctx.ui.zone),
            .type = pve.str(t, "type") orelse "",
            .id = pve.str(t, "id") orelse "",
            .user = pve.str(t, "user") orelse "",
            .start = pve.int(t, "starttime"),
            .end = end,
            .exitstatus = if (end != null) (pve.str(t, "status") orelse "unknown") else null,
        });
    }
    return out.items;
}

/// Resolve TASK against the recent tasks (500, all sources).
fn resolve(c: *pve.Client, word: []const u8) ![]const u8 {
    const ctx = c.ctx;
    if (tasks.parse(word) != null) return word;
    const recent = try list(c, 500, .all);
    const upids = try ctx.arena.alloc([]const u8, recent.len);
    for (recent, upids) |t, *u| u.* = t.upid;
    const r = tasks.resolve(ctx.arena, upids, word, &ctx.ui.zone) catch |err| switch (err) {
        error.NotFound => return ctx.fail(error.NotFound, "no recent task matches '{s}' (see 'artoo task ls')", .{word}),
        else => |e| return e,
    };
    if (r.matches > 1) return ctx.fail(error.Usage, "'{s}' matches {d} tasks; use more of the handle or the UPID (see 'artoo task ls')", .{ word, r.matches });
    return r.upid;
}

fn upidPath(c: *pve.Client, upid: []const u8, comptime suffix: []const u8) ![]const u8 {
    const node = if (tasks.parse(upid)) |u| u.node else c.node;
    const esc = try @import("storage.zig").escapeSegment(c.ctx, upid);
    return std.fmt.allocPrint(c.ctx.arena, "/nodes/{s}/tasks/{s}" ++ suffix, .{ node, esc });
}

fn statusCell(ctx: *Context, t: Task) !ui.table.Cell {
    const s = t.state();
    return k.statusCell(ctx, s, switch (s) {
        .running => "running",
        .ok => "ok",
        .warning => try k.clean(ctx, t.exitstatus.?),
        else => "failed",
    });
}

fn durationOf(ctx: *Context, t: Task) ![]const u8 {
    const start = t.start orelse return "--";
    const end = t.end orelse ctx.ui.now;
    return k.fmt(ctx, ui.values.duration(@intCast(@max(end - start, 0))));
}

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "Recent Proxmox tasks";
    pub const flags = [_]cli.Flag{
        .{ .long = "running", .help = "Only running tasks" },
        .{ .long = "failed", .help = "Only failed tasks" },
        .{ .long = "limit", .short = 'l', .kind = .int, .metavar = "N", .default = "20", .help = "Number of tasks (1-500)" },
    };
    pub const examples = [_][]const u8{ "artoo task ls", "artoo task ls --failed -l 50" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        if (args.has("running") and args.has("failed")) return ctx.fail(error.Usage, "--running and --failed are mutually exclusive", .{});
        const limit = args.int("limit") orelse 20;
        if (limit < 1 or limit > 500) return ctx.fail(error.Usage, "--limit must be 1-500, got {d}", .{limit});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const filter: Filter = if (args.has("running")) .running else if (args.has("failed")) .failed else .all;
        const all = try list(&c, @intCast(limit), filter);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, all, .{ .collected_at = ctx.ui.now, .node = c.node });
        try k.header(ctx, &c);
        if (all.len == 0) {
            try ctx.out.print("{s}No tasks.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
            return;
        }
        const rows = try ctx.arena.alloc([]const ui.table.Cell, all.len);
        for (all, rows) |t, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 5);
            cells[0] = .{ .text = try k.clean(ctx, t.handle) };
            cells[1] = .{ .text = try k.clean(ctx, t.user) };
            cells[2] = .{ .text = try k.fmt(ctx, ui.values.relative(ctx.ui.now, t.start)) };
            cells[3] = .{ .text = try durationOf(ctx, t) };
            cells[4] = try statusCell(ctx, t);
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "TASK", .truncate = false },
            .{ .title = "USER", .drop = 2 },
            .{ .title = "STARTED" },
            .{ .title = "DURATION", .alignment = .right, .drop = 1 },
            .{ .title = "STATUS" },
        }, rows);
    }
};

const task_arg = [_]cli.Positional{.{ .name = "TASK", .help = "UPID, handle (qmstart:100@14:32) or unique fragment" }};

pub const show = struct {
    pub const name = "show";
    pub const summary = "One task: type, target, user, times, exit status";
    pub const positionals = task_arg;
    pub const examples = [_][]const u8{"artoo task show qmstart:100@14:32"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const upid = try resolve(&c, args.pos("TASK"));
        const st = try c.get(try upidPath(&c, upid, "/status"));
        const running = !std.mem.eql(u8, pve.str(st, "status") orelse "", "stopped");
        const u = tasks.parse(upid);
        const t: Task = .{
            .upid = upid,
            .handle = try tasks.handle(ctx.arena, upid, &ctx.ui.zone),
            .type = pve.str(st, "type") orelse if (u) |x| x.type else "",
            .id = pve.str(st, "id") orelse if (u) |x| x.id else "",
            .user = pve.str(st, "user") orelse if (u) |x| x.user else "",
            .start = pve.int(st, "starttime") orelse if (u) |x| x.start else null,
            .end = null,
            .exitstatus = if (running) null else (pve.str(st, "exitstatus") orelse "unknown"),
        };
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, t, .{ .collected_at = ctx.ui.now, .node = c.node });
        try k.header(ctx, &c);
        const cell = try statusCell(ctx, t);
        try ui.blocks.detail(ctx.out, &ctx.ui, &.{.{ .title = try std.fmt.allocPrint(ctx.arena, "Task {s}", .{try k.clean(ctx, t.handle)}), .fields = &.{
            .{ .key = "UPID", .value = try k.clean(ctx, t.upid) },
            .{ .key = "Type", .value = try k.clean(ctx, t.type) },
            .{ .key = "Target", .value = if (t.id.len > 0) try k.clean(ctx, t.id) else "--" },
            .{ .key = "User", .value = try k.clean(ctx, t.user) },
            .{ .key = "Started", .value = try std.fmt.allocPrint(ctx.arena, "{f} ({f})", .{ ui.values.absolute(t.start, &ctx.ui.zone), ui.values.relative(ctx.ui.now, t.start) }) },
            .{ .key = "Status", .value = if (t.exitstatus) |es| try k.clean(ctx, es) else "running", .role = cell.role },
        } }});
    }
};

pub const log = struct {
    pub const name = "log";
    pub const summary = "A task's log (last 50 lines; --all for everything)";
    pub const positionals = task_arg;
    pub const flags = [_]cli.Flag{.{ .long = "all", .short = 'a', .help = "Print the whole log" }};
    pub const examples = [_][]const u8{ "artoo task log qmstart:100@14:32", "artoo task log qmclone --all" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const upid = try resolve(&c, args.pos("TASK"));
        var lines: std.ArrayList([]const u8) = .empty;
        var start: usize = 0;
        const page = 1000;
        while (lines.items.len < 100_000) {
            const base = try upidPath(&c, upid, "/log");
            const got = pve.items(try c.get(try std.fmt.allocPrint(ctx.arena, "{s}?start={d}&limit={d}", .{ base, start, page })));
            for (got) |l| try lines.append(ctx.arena, try k.clean(ctx, pve.str(l, "t") orelse ""));
            if (got.len < page) break;
            start += got.len;
        }
        const shown = if (args.has("all") or lines.items.len <= 50) lines.items else lines.items[lines.items.len - 50 ..];
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, shown, .{ .collected_at = ctx.ui.now, .total_lines = lines.items.len, .upid = upid });
        if (shown.len < lines.items.len) {
            try ctx.err.print("{s}… {d} earlier line(s); --all prints everything{s}\n", .{ ctx.err_ui.palette.on(.muted), lines.items.len - shown.len, ctx.err_ui.palette.off(.muted) });
        }
        for (shown) |l| try ctx.out.print("{s}\n", .{l});
    }
};

pub const wait = struct {
    pub const name = "wait";
    pub const summary = "Wait for a task to finish; exit 6 if it failed";
    pub const positionals = task_arg;
    pub const flags = [_]cli.Flag{.{ .long = "max-wait", .kind = .int, .metavar = "SECONDS", .default = "900", .help = "Give up after this long (exit 7)" }};
    pub const examples = [_][]const u8{"artoo task wait qmclone:9010@14:32"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const max = args.int("max-wait") orelse 900;
        if (max < 1 or max > 86400) return ctx.fail(error.Usage, "--max-wait must be 1-86400 seconds, got {d}", .{max});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const upid = try resolve(&c, args.pos("TASK"));
        const done = try tasks.wait(&c, upid, @as(u64, @intCast(max)) * 1000);
        const h = try tasks.handle(ctx.arena, upid, &ctx.ui.zone);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, .{ .upid = upid, .exitstatus = done.exitstatus }, .{});
        const p = ctx.ui.palette;
        const role: ui.style.Role = if (done.warnings) .warn else .ok;
        try ctx.out.print("{s}{s}{s} {s}: {s}\n", .{ p.on(role), if (done.warnings) ctx.ui.glyphs.warn else ctx.ui.glyphs.ok, p.off(role), h, done.exitstatus });
    }
};

pub const group = cli.group("task", "Proxmox tasks", &.{ cli.leaf(ls), cli.leaf(show), cli.leaf(log), cli.leaf(wait) });

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");

const upid_ok = "UPID:pve:0006B482:00B442ED:6ACA1C3A:qmdestroy:9000:artoo@pve!cli:";
const tasks_body =
    \\{"data":[{"upid":"UPID:pve:0006B483:00B442EE:6ACA1C40:qmstart:100:artoo@pve!cli:","type":"qmstart","id":"100","user":"artoo@pve","starttime":1791630400,"endtime":1791630402,"status":"start failed: no OS"},
    \\ {"upid":"UPID:pve:0006B482:00B442ED:6ACA1C3A:qmdestroy:9000:artoo@pve!cli:","type":"qmdestroy","id":"9000","user":"artoo@pve","starttime":1791630394,"endtime":1791630394,"status":"OK"}]}
;

test "task ls: handles, states; filters reach the API" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{ .{ .respond = .{ .body = tasks_body } }, .{ .respond = .{ .body = "{\"data\":[]}" } } });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "task ls"));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/tasks?limit=20&source=all HTTP/1.1", g.request(0));
    const out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "✗ failed") != null);
    try testing.expect(std.mem.find(u8, out, "✓ ok") != null);
    try testing.expect(std.mem.find(u8, out, "qmdestroy:9000@") != null);
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "task ls --failed -l 5"));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/tasks?limit=5&source=all&errors=1 HTTP/1.1", g.request(1));
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "task ls --failed --running"));
}

test "task wait: polls until stopped; failure exits 6, OK exits 0" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":{\"status\":\"running\"}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}" } },
        .{ .respond = .{ .body = tasks_body } },
        .{ .respond = .{ .body = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"start failed: no OS\"}}" } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "task wait " ++ upid_ok));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/tasks/UPID%3Apve%3A0006B482%3A00B442ED%3A6ACA1C3A%3Aqmdestroy%3A9000%3Aartoo%40pve%21cli%3A/status HTTP/1.1", g.request(0));
    try testing.expect(std.mem.endsWith(u8, g.h.stdout(), ": OK\n"));
    try testing.expectEqual(testkit.Exit.task_failed, g.h.run(&root, "task wait qmstart"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "failed: start failed: no OS") != null);
}

test "task log: tail by default" {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    try body.appendSlice(testing.allocator, "{\"data\":[");
    for (0..60) |i| try body.print(testing.allocator, "{s}{{\"n\":{d},\"t\":\"line {d}\"}}", .{ if (i > 0) "," else "", i + 1, i + 1 });
    try body.appendSlice(testing.allocator, "]}");
    var g: testkit.Gateway = undefined;
    try g.init(&.{.{ .respond = .{ .body = body.items } }});
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "task log " ++ upid_ok));
    try testing.expect(std.mem.startsWith(u8, g.h.stdout(), "line 11\n"));
    try testing.expect(std.mem.endsWith(u8, g.h.stdout(), "line 60\n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "10 earlier line(s)") != null);
}
