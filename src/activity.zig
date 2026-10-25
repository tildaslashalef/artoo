//! The activity line (SPEC §4.5): while a command reads before it prints,
//! one line on stderr — spinner, command path, elapsed time, latest
//! detail — erased for good at the first output. Dispatch starts it for
//! every command; commands only add details (`Context.busy`, `Tally`).

const std = @import("std");
const Io = std.Io;
const ui = @import("ui.zig");
const exec = @import("exec.zig");

/// Nothing is drawn before this, so quick commands never flicker.
pub const delay_ms = 400;

pub const Activity = struct {
    io: Io,
    /// The real stderr. The line is drawn here, never through a `Gate`.
    w: *Io.Writer,
    u: *const ui.Ui,
    /// The command path ("vm verify").
    name: []const u8,
    /// Guards everything below; the ticker and concurrent notes take it.
    mutex: Io.Mutex = .init,
    started: Io.Timestamp = .zero,
    frame: usize = 0,
    drawn: bool = false,
    ended: bool = false,
    detail_buf: [256]u8 = undefined,
    detail_len: usize = 0,
    ticker: ?Io.Future(Io.Cancelable!void) = null,

    /// Starts the ticker; without concurrency nothing is ever drawn.
    pub fn start(a: *Activity) void {
        a.started = Io.Clock.awake.now(a.io);
        a.ticker = a.io.concurrent(tick, .{a}) catch null;
    }

    fn tick(a: *Activity) Io.Cancelable!void {
        try a.io.sleep(.fromMilliseconds(delay_ms), .awake);
        while (true) {
            {
                try a.mutex.lock(a.io);
                defer a.mutex.unlock(a.io);
                if (a.ended) return;
                a.draw() catch {};
                a.frame +%= 1;
            }
            try a.io.sleep(.fromMilliseconds(100), .awake);
        }
    }

    /// New detail, sanitized (it may carry server-supplied names); shown
    /// from the next frame. Safe from concurrent tasks.
    pub fn note(a: *Activity, comptime fmt: []const u8, args: anytype) void {
        var raw: [256]u8 = undefined;
        var rw: Io.Writer = .fixed(&raw);
        rw.print(fmt, args) catch {}; // cut at the buffer; the line is cut anyway
        var scratch: [1024]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&scratch);
        const clean = ui.text.sanitize(fba.allocator(), rw.buffered(), .line) catch return;
        a.mutex.lockUncancelable(a.io);
        defer a.mutex.unlock(a.io);
        if (a.ended) return;
        a.detail_len = @min(clean.len, a.detail_buf.len);
        @memcpy(a.detail_buf[0..a.detail_len], clean[0..a.detail_len]);
    }

    /// Ends the line for good: erases what was drawn and stops the
    /// ticker. Idempotent; the first caller does the work.
    pub fn end(a: *Activity) void {
        {
            a.mutex.lockUncancelable(a.io);
            defer a.mutex.unlock(a.io);
            if (a.ended) return;
            a.ended = true;
            if (a.drawn) {
                a.w.writeAll("\r\x1b[2K") catch {};
                a.w.flush() catch {};
            }
        }
        if (a.ticker) |*t| {
            t.cancel(a.io) catch {};
            a.ticker = null;
        }
    }

    fn draw(a: *Activity) !void {
        const ns = a.started.durationTo(Io.Clock.awake.now(a.io)).nanoseconds;
        const seconds: u64 = if (ns <= 0) 0 else @intCast(@divTrunc(ns, std.time.ns_per_s));
        try a.w.writeAll("\r\x1b[2K");
        try line(a.w, a.u, a.name, a.detail_buf[0..a.detail_len], seconds, a.frame);
        try a.w.flush();
        a.drawn = true;
    }
};

/// The drawn line (no newline): §4.4's live line for a single step named
/// after the command, cut to the terminal width.
pub fn line(w: *Io.Writer, u: *const ui.Ui, name: []const u8, detail: []const u8, seconds: u64, frame: usize) !void {
    try exec.liveLine(w, u, .{ .name = name, .detail = detail }, ui.text.width(name), seconds, frame, u.width);
}

/// A pass-through writer in front of stdout or stderr that ends the
/// activity line at the first output: the first bytes that reach the
/// real writer, or any flush.
pub const Gate = struct {
    activity: *Activity,
    inner: *Io.Writer,
    writer: Io.Writer,

    pub fn init(activity: *Activity, inner: *Io.Writer, buffer: []u8) Gate {
        return .{
            .activity = activity,
            .inner = inner,
            .writer = .{ .buffer = buffer, .vtable = &.{ .drain = drain, .flush = flush } },
        };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const g: *Gate = @alignCast(@fieldParentPtr("writer", w));
        g.activity.end();
        const n = try g.inner.writeSplatHeader(w.buffered(), data, splat);
        return w.consume(n);
    }

    fn flush(w: *Io.Writer) Io.Writer.Error!void {
        const g: *Gate = @alignCast(@fieldParentPtr("writer", w));
        g.activity.end();
        while (w.end != 0) _ = try drain(w, &.{""}, 1);
        try g.inner.flush();
    }
};

/// Counts finished concurrent parts (guests, sections) and keeps the
/// activity detail current: `3/5 done, waiting on edge, tunnel`.
pub const Tally = struct {
    activity: ?*Activity,
    names: []const []const u8,
    done: []bool,
    mutex: Io.Mutex = .init,

    pub fn init(arena: std.mem.Allocator, activity: ?*Activity, names: []const []const u8) !Tally {
        const done = try arena.alloc(bool, names.len);
        @memset(done, false);
        var t: Tally = .{ .activity = activity, .names = names, .done = done };
        t.show();
        return t;
    }

    /// Part `i` finished. Safe from concurrent tasks.
    pub fn finish(t: *Tally, io: Io, i: usize) void {
        t.mutex.lockUncancelable(io);
        defer t.mutex.unlock(io);
        t.done[i] = true;
        t.show();
    }

    fn show(t: *const Tally) void {
        const a = t.activity orelse return;
        var buf: [256]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        tallyText(&w, t.names, t.done) catch {}; // cut at the buffer
        a.note("{s}", .{w.buffered()});
    }
};

/// `N/M done, waiting on a, b` (all done: `M/M done`).
pub fn tallyText(w: *Io.Writer, names: []const []const u8, done: []const bool) !void {
    var n: usize = 0;
    for (done) |d| n += @intFromBool(d);
    try w.print("{d}/{d} done", .{ n, names.len });
    var first = true;
    for (names, done) |name, d| {
        if (d) continue;
        try w.writeAll(if (first) ", waiting on " else ", ");
        try w.writeAll(name);
        first = false;
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn testActivity(err: *Io.Writer, u: *const ui.Ui) Activity {
    return .{ .io = testing.io, .w = err, .u = u, .name = "vm verify", .started = Io.Clock.awake.now(testing.io) };
}

test "line: spinner, path, elapsed, detail; cut to the terminal width" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const wide: ui.Ui = .{ .width = 80 };
    try line(&buf.writer, &wide, "vm verify", "4/7 done, waiting on naboo, hoth", 12, 2);
    try testing.expectEqualStrings("  ⠹ vm verify  12s  4/7 done, waiting on naboo, hoth", buf.written());

    buf.clearRetainingCapacity();
    const narrow: ui.Ui = .{ .width = 24 };
    try line(&buf.writer, &narrow, "vm verify", "4/7 done, waiting on naboo, hoth", 12, 0);
    try testing.expectEqualStrings("  ⠋ vm verify  12s  4/…", buf.written());
}

test "tallyText: counts finished parts and names the rest" {
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const names = [_][]const u8{ "pve", "unifi", "edge", "router", "tunnel" };
    try tallyText(&w, &names, &.{ true, true, false, true, false });
    try testing.expectEqualStrings("3/5 done, waiting on edge, tunnel", w.buffered());
    w = .fixed(&buf);
    try tallyText(&w, names[0..2], &.{ true, true });
    try testing.expectEqualStrings("2/2 done", w.buffered());
}

test "Gate: erases a drawn line before the first output, once" {
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    const u: ui.Ui = .{ .width = 80 };
    var a = testActivity(&err.writer, &u);
    a.note("{d}/{d} done", .{ 0, 2 });
    try a.draw();
    try testing.expect(std.mem.endsWith(u8, err.written(), "vm verify  0s  0/2 done"));
    err.clearRetainingCapacity();

    var buf: [64]u8 = undefined;
    var gate: Gate = .init(&a, &out.writer, &buf);
    try gate.writer.writeAll("NAME  STATUS\n");
    try testing.expectEqualStrings("", err.written()); // still buffered
    try gate.writer.flush();
    try testing.expectEqualStrings("\r\x1b[2K", err.written());
    try testing.expectEqualStrings("NAME  STATUS\n", out.written());

    // Ended for good: later output and notes leave stderr alone.
    a.note("late", .{});
    const xs: [100]u8 = @splat('x');
    try gate.writer.writeAll(&xs);
    try gate.writer.flush();
    try testing.expectEqualStrings("\r\x1b[2K", err.written());
    try testing.expectEqualStrings("NAME  STATUS\n" ++ xs, out.written());
}

test "Gate: nothing on stderr when the line was never drawn" {
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    const u: ui.Ui = .{ .width = 80 };
    var a = testActivity(&err.writer, &u);
    var buf: [8]u8 = undefined;
    var gate: Gate = .init(&a, &out.writer, &buf);
    try gate.writer.print("{s} ({d})\n", .{ "naboo", 101 }); // larger than the buffer: drains
    try testing.expect(a.ended);
    try gate.writer.flush();
    try testing.expectEqualStrings("naboo (101)\n", out.written());
    try testing.expectEqualStrings("", err.written());
}

test "note: server-supplied text is sanitized" {
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    const u: ui.Ui = .{ .width = 80 };
    var a = testActivity(&err.writer, &u);
    a.note("waiting on {s}", .{"na\x1b[2Jboo"});
    try testing.expect(std.mem.indexOfScalar(u8, a.detail_buf[0..a.detail_len], 0x1b) == null);
}

test "Tally: details follow finished parts" {
    var err: Io.Writer.Allocating = .init(testing.allocator);
    defer err.deinit();
    const u: ui.Ui = .{ .width = 80 };
    var a = testActivity(&err.writer, &u);
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var t: Tally = try .init(arena.allocator(), &a, &.{ "naboo", "hoth" });
    try testing.expectEqualStrings("0/2 done, waiting on naboo, hoth", a.detail_buf[0..a.detail_len]);
    t.finish(testing.io, 0);
    try testing.expectEqualStrings("1/2 done, waiting on hoth", a.detail_buf[0..a.detail_len]);
}
