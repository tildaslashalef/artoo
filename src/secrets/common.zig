//! Shared names, errors and the fake process runner for store tests.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const proc = @import("../proc.zig");

pub const service = "artoo";

pub const Error = error{ SecretStoreUnavailable, UnsafePath } || Allocator.Error || Io.Cancelable;

/// `pve`, `unifi`, `guest/<name>`: lowercase letters, digits, `-`, `_`, `.`
/// and one `/` after `guest`.
pub fn validName(name: []const u8) bool {
    const rest = if (std.mem.cutPrefix(u8, name, "guest/")) |r| r else name;
    if (rest.len == 0 or rest.len > 64) return false;
    for (rest) |c| {
        if (!(std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '-' or c == '_' or c == '.')) return false;
    }
    return true;
}

/// Secrets must fit one line: no control characters.
pub fn validSecret(secret: []const u8) bool {
    if (secret.len == 0 or secret.len > 4096) return false;
    for (secret) |c| {
        if (c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// Scripted process runner: each call must match the next expectation.
pub const FakeRunner = struct {
    arena: Allocator,
    script: std.ArrayList(Step) = .empty,
    next: usize = 0,
    seen: std.ArrayList([]const []const u8) = .empty,

    const Step = struct { argv: []const []const u8, stdin: ?[]const u8, result: proc.Result };

    pub fn expect(f: *FakeRunner, argv: []const []const u8, stdin: ?[]const u8, result: struct { code: ?u8 = 0, stdout: []const u8 = "", stderr: []const u8 = "" }) !void {
        try f.script.append(f.arena, .{ .argv = argv, .stdin = stdin, .result = .{ .code = result.code, .stdout = result.stdout, .stderr = result.stderr } });
    }

    pub fn runner(f: *FakeRunner) proc.Runner {
        return .{ .ctx = f, .runFn = run };
    }

    pub fn done(f: *FakeRunner) !void {
        try std.testing.expectEqual(f.script.items.len, f.next);
    }

    fn run(ctx: ?*anyopaque, _: Io, _: Allocator, argv: []const []const u8, stdin: ?[]const u8) proc.Error!proc.Result {
        const f: *FakeRunner = @ptrCast(@alignCast(ctx.?));
        // argv usually lives in the caller's frame: keep a copy.
        const copy = f.arena.alloc([]const u8, argv.len) catch return error.OutOfMemory;
        for (argv, copy) |w, *c| c.* = f.arena.dupe(u8, w) catch return error.OutOfMemory;
        f.seen.append(f.arena, copy) catch return error.OutOfMemory;
        if (f.next >= f.script.items.len) {
            std.debug.print("unexpected call: {any}\n", .{argv});
            return error.Failed;
        }
        const step = f.script.items[f.next];
        f.next += 1;
        const same = step.argv.len == argv.len and for (step.argv, argv) |x, y| {
            if (!std.mem.eql(u8, x, y)) break false;
        } else true;
        const same_in = if (step.stdin) |want| (stdin != null and std.mem.eql(u8, want, stdin.?)) else true;
        if (!same or !same_in) {
            std.debug.print("call mismatch:\n  want {any} stdin={?s}\n  got  {any} stdin={?s}\n", .{ step.argv, step.stdin, argv, stdin });
            return error.Failed;
        }
        return step.result;
    }
};

test "names and secrets" {
    try std.testing.expect(validName("pve"));
    try std.testing.expect(validName("guest/web-01"));
    try std.testing.expect(!validName("Guest/x"));
    try std.testing.expect(!validName("guest/"));
    try std.testing.expect(!validName("a b"));
    try std.testing.expect(validSecret("abc-DEF_123=+/"));
    try std.testing.expect(!validSecret("line\nbreak"));
    try std.testing.expect(!validSecret(""));
}
