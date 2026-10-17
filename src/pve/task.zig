//! Proxmox tasks (SPEC §3.2, §8.2): UPID parsing, short handles
//! (`qmstart:100@14:32`) that `artoo task …` accepts back, resolution of a
//! TASK word, and waiting for completion. `stopped` alone is not success:
//! only exit status `OK` or `WARNINGS: n` is.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const pve = @import("client.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");

pub const Upid = struct {
    node: []const u8,
    /// Start time, epoch seconds.
    start: i64,
    type: []const u8,
    id: []const u8,
    user: []const u8,
};

/// `UPID:node:pid:pstart:starttime:type:id:user:` (hex numbers).
pub fn parse(upid: []const u8) ?Upid {
    var it = std.mem.splitScalar(u8, upid, ':');
    if (!std.mem.eql(u8, it.next() orelse return null, "UPID")) return null;
    const node = it.next() orelse return null;
    _ = it.next() orelse return null; // pid
    _ = it.next() orelse return null; // pstart
    const start = std.fmt.parseInt(i64, it.next() orelse return null, 16) catch return null;
    const typ = it.next() orelse return null;
    const id = it.next() orelse return null;
    const user = it.next() orelse return null;
    if (node.len == 0 or typ.len == 0) return null;
    return .{ .node = node, .start = start, .type = typ, .id = id, .user = user };
}

/// `qmstart:100@14:32` (local time); the UPID itself if unparseable.
pub fn handle(arena: Allocator, upid: []const u8, zone: *const ui.values.Zone) ![]const u8 {
    const u = parse(upid) orelse return upid;
    return std.fmt.allocPrint(arena, "{s}{s}{s}@{f}", .{ u.type, if (u.id.len > 0) ":" else "", u.id, ui.values.clock(u.start, zone) });
}

/// The UPID in `list` that `word` names: an exact UPID, a handle, or a
/// unique substring of one UPID. `error.NotFound`/`error.Ambiguous`.
pub fn resolve(arena: Allocator, list: []const []const u8, word: []const u8, zone: *const ui.values.Zone) !struct { upid: []const u8, matches: usize } {
    for (list) |u| {
        if (std.mem.eql(u8, u, word)) return .{ .upid = u, .matches = 1 };
    }
    var hit: ?[]const u8 = null;
    var n: usize = 0;
    for (list) |u| {
        if (std.mem.eql(u8, try handle(arena, u, zone), word) or std.mem.find(u8, u, word) != null) {
            n += 1;
            if (hit == null) hit = u;
        }
    }
    if (hit == null) return error.NotFound;
    return .{ .upid = hit.?, .matches = n };
}

pub const Done = struct {
    exitstatus: []const u8,
    warnings: bool,
};

/// Classify a finished task's exit status.
pub fn succeeded(exitstatus: []const u8) ?bool {
    if (std.mem.eql(u8, exitstatus, "OK")) return false;
    if (std.mem.startsWith(u8, exitstatus, "WARNINGS")) return true;
    return null;
}

/// Poll `upid` until it stops or `timeout_ms` passes. Failure → TaskFailed
/// (exit 6); deadline → WaitTimeout (7); unreadable status after
/// submission → OutcomeUnknown (7). Messages name the task handle.
pub fn wait(c: *pve.Client, upid: []const u8, timeout_ms: u64) !Done {
    return waitNoted(c, upid, timeout_ms, null);
}

/// `wait`, reporting the task log's newest line to `note` while the task
/// runs (download progress, disk import, …; SPEC §4.4).
pub fn waitNoted(c: *pve.Client, upid: []const u8, timeout_ms: u64, note: ?exec.Note) !Done {
    const ctx = c.ctx;
    const h = try handle(ctx.arena, upid, &ctx.ui.zone);
    const node = if (parse(upid)) |u| u.node else c.node;
    var path: std.ArrayList(u8) = .empty;
    try path.print(ctx.arena, "/nodes/{s}/tasks/", .{node});
    try escapeInto(ctx.arena, &path, upid);
    const base_len = path.items.len;
    try path.appendSlice(ctx.arena, "/status");
    const log_base = path.items[0..base_len];
    var log_next: usize = 0;
    const interval = ctx.test_hooks.poll_ms orelse 1000;
    const started = Io.Clock.awake.now(ctx.io);
    while (true) {
        const st = c.get(path.items) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => {
                const why = ctx.diag orelse @errorName(err);
                return ctx.fail(error.OutcomeUnknown, "submitted as {s}, but its status could not be read ({s}); check 'artoo task show {s}'", .{ h, why, h });
            },
        };
        if (std.mem.eql(u8, pve.str(st, "status") orelse "", "stopped")) {
            const es = try ui.text.sanitize(ctx.arena, pve.str(st, "exitstatus") orelse "unknown", .line);
            const warn = succeeded(es) orelse return ctx.fail(error.TaskFailed, "task {s} failed: {s} (see 'artoo task log {s}')", .{ h, es, h });
            return .{ .exitstatus = es, .warnings = warn };
        }
        if (note) |n| if (try logTail(c, log_base, &log_next)) |line| n.say(line);
        const waited: u64 = @intCast(@divTrunc(started.durationTo(Io.Clock.awake.now(ctx.io)).nanoseconds, std.time.ns_per_ms));
        if (waited >= timeout_ms) {
            return ctx.fail(error.WaitTimeout, "task {s} still running after {d} s; follow it with 'artoo task wait {s}'", .{ h, timeout_ms / 1000, h });
        }
        try ctx.io.sleep(.fromMilliseconds(@intCast(interval)), .awake);
    }
}

/// The newest non-empty log line after line `next.*` (advanced), or null.
/// A failed read is no reason to stop waiting: it reports nothing.
fn logTail(c: *pve.Client, base: []const u8, next: *usize) !?[]const u8 {
    const ctx = c.ctx;
    const got = c.get(try std.fmt.allocPrint(ctx.arena, "{s}/log?start={d}&limit=500", .{ base, next.* })) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            ctx.diag = null;
            return null;
        },
    };
    var newest: ?[]const u8 = null;
    for (pve.items(got)) |l| {
        if (pve.uint(l, "n")) |n| next.* = @max(next.*, @as(usize, @intCast(n)));
        const t = std.mem.trim(u8, pve.str(l, "t") orelse "", " \t\r\n");
        if (t.len > 0 and !std.mem.eql(u8, t, "no content")) newest = t;
    }
    return if (newest) |t| try ui.text.sanitize(ctx.arena, t, .line) else null;
}

fn escapeInto(arena: Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try out.append(arena, ch);
        } else try out.print(arena, "%{X:0>2}", .{ch});
    }
}

/// The UPID a write returned (`data` string), or a protocol error.
pub fn upidOf(c: *pve.Client, v: Value, what: []const u8) ![]const u8 {
    if (v == .string and parse(v.string) != null) return v.string;
    return c.ctx.fail(error.OutcomeUnknown, "{s} was sent, but Proxmox did not return a task ID; check 'artoo task ls'", .{what});
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const sample = "UPID:pve:0003A1B2:0123ABCD:66F8A1B0:qmstart:100:artoo@pve!cli:";

test "parse and handle" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const u = parse(sample).?;
    try testing.expectEqualStrings("pve", u.node);
    try testing.expectEqualStrings("qmstart", u.type);
    try testing.expectEqualStrings("100", u.id);
    try testing.expectEqualStrings("artoo@pve!cli", u.user);
    try testing.expectEqual(@as(i64, 0x66F8A1B0), u.start);
    const utc: ui.values.Zone = .utc;
    try testing.expectEqualStrings("qmstart:100@00:39", try handle(a.allocator(), sample, &utc));
    try testing.expect(parse("UPID:x") == null);
    try testing.expect(parse("nope") == null);
}

test "resolve: exact, handle, unique substring, ambiguity" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const utc: ui.values.Zone = .utc;
    const other = "UPID:pve:0003A1B3:0123ABCE:66F8A1C0:qmstop:101:root@pam:";
    const list = [_][]const u8{ sample, other };
    try testing.expectEqualStrings(sample, (try resolve(ar, &list, sample, &utc)).upid);
    try testing.expectEqualStrings(sample, (try resolve(ar, &list, "qmstart:100@00:39", &utc)).upid);
    try testing.expectEqualStrings(other, (try resolve(ar, &list, "qmstop", &utc)).upid);
    try testing.expectEqual(@as(usize, 2), (try resolve(ar, &list, "pve", &utc)).matches);
    try testing.expectError(error.NotFound, resolve(ar, &list, "vzdump", &utc));
}

test "succeeded" {
    try testing.expectEqual(@as(?bool, false), succeeded("OK"));
    try testing.expectEqual(@as(?bool, true), succeeded("WARNINGS: 2"));
    try testing.expectEqual(@as(?bool, null), succeeded("command 'qm start' failed"));
}
