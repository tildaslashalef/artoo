//! Run a helper process with optional stdin bytes, capturing bounded
//! stdout/stderr. Secrets travel only through these pipes, never argv or
//! the environment (SPEC §6).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Result = struct {
    /// Exit status; null when killed by a signal.
    code: ?u8,
    stdout: []const u8,
    stderr: []const u8,
};

pub const Error = error{ NotFound, Failed } || Allocator.Error || Io.Cancelable;

/// A seam so stores can be tested without spawning anything.
pub const Runner = struct {
    ctx: ?*anyopaque = null,
    runFn: *const fn (ctx: ?*anyopaque, io: Io, arena: Allocator, argv: []const []const u8, stdin: ?[]const u8) Error!Result = runReal,

    pub fn run(r: Runner, io: Io, arena: Allocator, argv: []const []const u8, stdin: ?[]const u8) Error!Result {
        return r.runFn(r.ctx, io, arena, argv, stdin);
    }
};

const max_output = 1 << 20;

fn runReal(_: ?*anyopaque, io: Io, arena: Allocator, argv: []const []const u8, stdin: ?[]const u8) Error!Result {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = if (stdin != null) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        error.Canceled => return error.Canceled,
        else => return error.Failed,
    };
    defer child.kill(io);

    if (stdin) |bytes| {
        // Inputs are small (one secret or command line); write all, then
        // close so the child sees EOF before we read its output.
        const in = child.stdin.?;
        in.writeStreamingAll(io, bytes) catch {};
        in.close(io);
        child.stdin = null;
    }

    var buf: Io.File.MultiReader.Buffer(2) = undefined;
    var mr: Io.File.MultiReader = undefined;
    mr.init(arena, io, buf.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer mr.deinit();
    while (mr.fill(64, .none)) |_| {
        if (mr.reader(0).buffered().len > max_output or mr.reader(1).buffered().len > max_output) return error.Failed;
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.Canceled => return error.Canceled,
        else => return error.Failed,
    }
    mr.checkAnyError() catch return error.Failed;
    const term = child.wait(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.Failed,
    };
    const out = mr.toOwnedSlice(0) catch return error.OutOfMemory;
    const errout = mr.toOwnedSlice(1) catch return error.OutOfMemory;
    return .{
        .code = switch (term) {
            .exited => |c| c,
            else => null,
        },
        .stdout = out,
        .stderr = errout,
    };
}

/// Run `argv` on the terminal (stdin, stdout and stderr inherited) and
/// wait: for helpers the operator watches, such as scp's progress meter.
/// Exit status; null when killed by a signal.
pub fn runInherited(io: Io, argv: []const []const u8) Error!?u8 {
    var child = std.process.spawn(io, .{ .argv = argv }) catch |err| switch (err) {
        error.FileNotFound => return error.NotFound,
        error.Canceled => return error.Canceled,
        else => return error.Failed,
    };
    const term = child.wait(io) catch |err| switch (err) {
        error.Canceled => {
            child.kill(io);
            return error.Canceled;
        },
        else => return error.Failed,
    };
    return switch (term) {
        .exited => |c| c,
        else => null,
    };
}

const testing = std.testing;

test "runReal: stdin in, stdout/stderr out, exit codes" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const r: Runner = .{};
    const cat = try r.run(testing.io, a.allocator(), &.{"cat"}, "secret\n");
    try testing.expectEqual(@as(?u8, 0), cat.code);
    try testing.expectEqualStrings("secret\n", cat.stdout);
    const sh = try r.run(testing.io, a.allocator(), &.{ "sh", "-c", "echo oops >&2; exit 44" }, null);
    try testing.expectEqual(@as(?u8, 44), sh.code);
    try testing.expectEqualStrings("oops\n", sh.stderr);
    try testing.expectError(error.NotFound, r.run(testing.io, a.allocator(), &.{"/nonexistent/artoo-helper"}, null));
}
