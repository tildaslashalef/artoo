//! macOS login Keychain through Apple's `/usr/bin/security` (SPEC §6).
//!
//! Items: service `artoo`, account = secret name, trusted app
//! `/usr/bin/security`, so rebuilding artoo never causes prompts. The secret
//! is read from `-w` output and written as a `security -i` command on stdin.
//! Replacing deletes and re-adds: updating an existing item's access list
//! (`-U -T`) makes macOS ask for the keychain password.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const proc = @import("../proc.zig");
const common = @import("common.zig");

pub const exe = "/usr/bin/security";
const not_found = 44;

runner: proc.Runner = .{},

const Keychain = @This();

pub fn get(k: Keychain, io: Io, arena: Allocator, name: []const u8) common.Error!?[]const u8 {
    const r = try k.call(io, arena, &.{ exe, "find-generic-password", "-s", common.service, "-a", name, "-w" }, null);
    if (r.code == not_found) return null;
    if (r.code != 0) return error.SecretStoreUnavailable;
    return std.mem.trimEnd(u8, r.stdout, "\n");
}

pub fn exists(k: Keychain, io: Io, arena: Allocator, name: []const u8) common.Error!bool {
    // Without -w: attributes only, the secret is not printed.
    const r = try k.call(io, arena, &.{ exe, "find-generic-password", "-s", common.service, "-a", name }, null);
    if (r.code == not_found) return false;
    if (r.code != 0) return error.SecretStoreUnavailable;
    return true;
}

pub fn delete(k: Keychain, io: Io, arena: Allocator, name: []const u8) common.Error!bool {
    const r = try k.call(io, arena, &.{ exe, "delete-generic-password", "-s", common.service, "-a", name }, null);
    if (r.code == not_found) return false;
    if (r.code != 0) return error.SecretStoreUnavailable;
    return true;
}

pub fn set(k: Keychain, io: Io, arena: Allocator, name: []const u8, secret: []const u8) common.Error!void {
    _ = try k.delete(io, arena, name);
    const script = try addCommand(arena, name, secret);
    // `security -i` reports command failures on stderr, not in its status.
    const r = try k.call(io, arena, &.{ exe, "-i" }, script);
    if (r.code != 0 or r.stderr.len > 0) return error.SecretStoreUnavailable;
    const back = (try k.get(io, arena, name)) orelse return error.SecretStoreUnavailable;
    if (!std.mem.eql(u8, back, secret)) return error.SecretStoreUnavailable;
}

/// The `security -i` line; the secret is double-quoted with `\` escapes.
fn addCommand(arena: Allocator, name: []const u8, secret: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(arena, "add-generic-password -s {s} -a {s} -l \"artoo {s}\" -T {s} -w \"", .{ common.service, name, name, exe });
    for (secret) |c| {
        if (c == '"' or c == '\\') try out.append(arena, '\\');
        try out.append(arena, c);
    }
    try out.appendSlice(arena, "\"\n");
    return out.items;
}

fn call(k: Keychain, io: Io, arena: Allocator, argv: []const []const u8, stdin: ?[]const u8) common.Error!proc.Result {
    return k.runner.run(io, arena, argv, stdin) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        else => error.SecretStoreUnavailable,
    };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Fake = @import("common.zig").FakeRunner;

test "keychain: argv never carries the secret; replace = delete + add" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var fake: Fake = .{ .arena = ar };
    const k: Keychain = .{ .runner = fake.runner() };

    // delete (44: absent) → add via -i → read back
    try fake.expect(&.{ exe, "delete-generic-password", "-s", "artoo", "-a", "unifi" }, null, .{ .code = 44 });
    try fake.expect(&.{ exe, "-i" }, "add-generic-password -s artoo -a unifi -l \"artoo unifi\" -T /usr/bin/security -w \"k\\\"e\\\\y\"\n", .{ .code = 0 });
    try fake.expect(&.{ exe, "find-generic-password", "-s", "artoo", "-a", "unifi", "-w" }, null, .{ .code = 0, .stdout = "k\"e\\y\n" });
    try k.set(testing.io, ar, "unifi", "k\"e\\y");
    try fake.done();
    for (fake.seen.items) |argv| {
        for (argv) |w| try testing.expect(std.mem.find(u8, w, "k\"e") == null);
    }
}

test "keychain: get/exists/delete status mapping" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var fake: Fake = .{ .arena = ar };
    const k: Keychain = .{ .runner = fake.runner() };
    try fake.expect(&.{ exe, "find-generic-password", "-s", "artoo", "-a", "pve", "-w" }, null, .{ .code = 44 });
    try testing.expectEqual(@as(?[]const u8, null), try k.get(testing.io, ar, "pve"));
    try fake.expect(&.{ exe, "find-generic-password", "-s", "artoo", "-a", "pve" }, null, .{ .code = 0 });
    try testing.expect(try k.exists(testing.io, ar, "pve"));
    try fake.expect(&.{ exe, "delete-generic-password", "-s", "artoo", "-a", "pve" }, null, .{ .code = 0 });
    try testing.expect(try k.delete(testing.io, ar, "pve"));
    try fake.expect(&.{ exe, "find-generic-password", "-s", "artoo", "-a", "pve", "-w" }, null, .{ .code = 51 });
    try testing.expectError(error.SecretStoreUnavailable, k.get(testing.io, ar, "pve"));
    // A failing `security -i` add (stderr) is an error even with status 0.
    try fake.expect(&.{ exe, "delete-generic-password", "-s", "artoo", "-a", "pve" }, null, .{ .code = 44 });
    try fake.expect(&.{ exe, "-i" }, null, .{ .code = 0, .stderr = "add-generic-password: returned -25299\n" });
    try testing.expectError(error.SecretStoreUnavailable, k.set(testing.io, ar, "pve", "x"));
    try fake.done();
}
