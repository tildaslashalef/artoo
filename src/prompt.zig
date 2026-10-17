//! Terminal input: confirmations and hidden secret entry (SPEC §3.4, §6).
//! Prompts go to stderr; answers come from stdin only when it is a TTY.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// Where answers come from. Tests use `script`.
pub const Input = union(enum) {
    stdin,
    script: *Script,
};

pub const Script = struct {
    interactive: bool = true,
    lines: []const []const u8 = &.{},
    /// Bytes returned by `readAll` (for `--stdin`).
    piped: []const u8 = "",
    next: usize = 0,
};

pub const Error = error{ ReadFailed, NonInteractive } || Allocator.Error || Io.Cancelable;

pub fn interactive(input: Input, io: Io) Io.Cancelable!bool {
    return switch (input) {
        .stdin => Io.File.stdin().isTty(io),
        .script => |s| s.interactive,
    };
}

/// One line without its newline; null at end of input.
pub fn readLine(input: Input, io: Io, arena: Allocator, hidden: bool) Error!?[]const u8 {
    switch (input) {
        .script => |s| {
            if (s.next >= s.lines.len) return null;
            s.next += 1;
            return s.lines[s.next - 1];
        },
        .stdin => {
            const file = Io.File.stdin();
            var restore: ?std.posix.termios = null;
            if (hidden and builtin.os.tag != .windows) {
                if (std.posix.tcgetattr(file.handle)) |t| {
                    var quiet = t;
                    quiet.lflag.ECHO = false;
                    std.posix.tcsetattr(file.handle, .FLUSH, quiet) catch {};
                    restore = t;
                } else |_| {}
            }
            defer if (restore) |t| std.posix.tcsetattr(file.handle, .FLUSH, t) catch {};
            var buf: [4096]u8 = undefined;
            var r = file.readerStreaming(io, &buf);
            const line = r.interface.takeDelimiter('\n') catch return error.ReadFailed;
            const got = line orelse return null;
            return try arena.dupe(u8, std.mem.trimEnd(u8, got, "\r"));
        },
    }
}

/// All of stdin (bounded), trailing newline removed.
pub fn readAll(input: Input, io: Io, arena: Allocator, limit: usize) Error![]const u8 {
    const raw = switch (input) {
        .script => |s| s.piped,
        .stdin => blk: {
            var buf: [4096]u8 = undefined;
            var r = Io.File.stdin().readerStreaming(io, &buf);
            break :blk r.interface.allocRemaining(arena, .limited(limit + 2)) catch return error.ReadFailed;
        },
    };
    return std.mem.trimEnd(u8, raw, "\r\n");
}

pub const Answer = enum { yes, no };

/// `question [y/N] ` → yes only for y/yes. Non-interactive → NonInteractive.
pub fn ask(input: Input, io: Io, arena: Allocator, w: *Io.Writer, question: []const u8) Error!Answer {
    if (!try interactive(input, io)) return error.NonInteractive;
    w.print("{s} [y/N] ", .{question}) catch return error.ReadFailed;
    w.flush() catch return error.ReadFailed;
    const line = (try readLine(input, io, arena, false)) orelse return .no;
    const a = std.mem.trim(u8, line, " \t");
    return if (std.ascii.eqlIgnoreCase(a, "y") or std.ascii.eqlIgnoreCase(a, "yes")) .yes else .no;
}

/// Typed-name confirmation for destructive actions (SPEC §3.4).
pub fn askTyped(input: Input, io: Io, arena: Allocator, w: *Io.Writer, target: []const u8) Error!Answer {
    if (!try interactive(input, io)) return error.NonInteractive;
    w.print("Type '{s}' to confirm: ", .{target}) catch return error.ReadFailed;
    w.flush() catch return error.ReadFailed;
    const line = (try readLine(input, io, arena, false)) orelse return .no;
    return if (std.mem.eql(u8, std.mem.trim(u8, line, " \t"), target)) .yes else .no;
}

/// `label (input hidden): ` → one hidden line ("" at end of input). The
/// line is ended and flushed, so whatever is printed next (a plan on
/// stdout) starts on its own line.
pub fn askHidden(input: Input, io: Io, arena: Allocator, w: *Io.Writer, label: []const u8) Error![]const u8 {
    if (!try interactive(input, io)) return error.NonInteractive;
    w.print("{s} (input hidden): ", .{label}) catch return error.ReadFailed;
    w.flush() catch return error.ReadFailed;
    const line = try readLine(input, io, arena, true);
    w.writeByte('\n') catch return error.ReadFailed;
    w.flush() catch return error.ReadFailed;
    return line orelse "";
}

const testing = std.testing;

test "askHidden ends its line before anything else is printed" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var s: Script = .{ .lines = &.{ "s3cret", "again" } };
    const in: Input = .{ .script = &s };
    try testing.expectEqualStrings("s3cret", try askHidden(in, testing.io, a.allocator(), &out.writer, "New password"));
    try testing.expectEqualStrings("again", try askHidden(in, testing.io, a.allocator(), &out.writer, "Repeat"));
    try testing.expectEqualStrings("New password (input hidden): \nRepeat (input hidden): \n", out.written());
    var batch: Script = .{ .interactive = false };
    try testing.expectError(error.NonInteractive, askHidden(.{ .script = &batch }, testing.io, a.allocator(), &out.writer, "x"));
}

test "ask and askTyped with a script" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var s: Script = .{ .lines = &.{ "y", "", "web-01", "web-1" } };
    const in: Input = .{ .script = &s };
    try testing.expectEqual(Answer.yes, try ask(in, testing.io, a.allocator(), &out.writer, "Proceed?"));
    try testing.expectEqual(Answer.no, try ask(in, testing.io, a.allocator(), &out.writer, "Proceed?"));
    try testing.expectEqual(Answer.yes, try askTyped(in, testing.io, a.allocator(), &out.writer, "web-01"));
    try testing.expectEqual(Answer.no, try askTyped(in, testing.io, a.allocator(), &out.writer, "web-01"));
    try testing.expectEqual(Answer.no, try ask(in, testing.io, a.allocator(), &out.writer, "Proceed?")); // EOF
    try testing.expectEqualStrings("Proceed? [y/N] Proceed? [y/N] Type 'web-01' to confirm: Type 'web-01' to confirm: Proceed? [y/N] ", out.written());
    var batch: Script = .{ .interactive = false };
    try testing.expectError(error.NonInteractive, ask(.{ .script = &batch }, testing.io, a.allocator(), &out.writer, "x"));
}
