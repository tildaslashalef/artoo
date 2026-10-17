//! Linux Secret Service (GNOME Keyring / KWallet) through `secret-tool`,
//! attributes `service=artoo account=<name>`; `store` reads the secret
//! from stdin (SPEC §6).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const proc = @import("../proc.zig");
const common = @import("common.zig");

pub const exe = "secret-tool";

runner: proc.Runner = .{},

const SecretService = @This();

/// `lookup` of an absent item exits 1 with empty stderr when the service is
/// reachable; any stderr means no usable Secret Service.
fn absent(r: proc.Result) bool {
    return r.code == 1 and std.mem.trim(u8, r.stderr, " \n").len == 0;
}

pub fn available(s: SecretService, io: Io, arena: Allocator) Io.Cancelable!bool {
    const r = s.runner.run(io, arena, &.{ exe, "lookup", "service", common.service, "account", "__artoo_probe__" }, null) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return false,
    };
    return r.code == 0 or absent(r);
}

pub fn get(s: SecretService, io: Io, arena: Allocator, name: []const u8) common.Error!?[]const u8 {
    const r = try s.call(io, arena, &.{ exe, "lookup", "service", common.service, "account", name }, null);
    if (absent(r)) return null;
    if (r.code != 0) return error.SecretStoreUnavailable;
    return std.mem.trimEnd(u8, r.stdout, "\n");
}

pub fn exists(s: SecretService, io: Io, arena: Allocator, name: []const u8) common.Error!bool {
    return (try s.get(io, arena, name)) != null;
}

pub fn set(s: SecretService, io: Io, arena: Allocator, name: []const u8, secret: []const u8) common.Error!void {
    const label = try std.fmt.allocPrint(arena, "--label=artoo {s}", .{name});
    const r = try s.call(io, arena, &.{ exe, "store", label, "service", common.service, "account", name }, secret);
    if (r.code != 0) return error.SecretStoreUnavailable;
}

pub fn delete(s: SecretService, io: Io, arena: Allocator, name: []const u8) common.Error!bool {
    if (!try s.exists(io, arena, name)) return false;
    const r = try s.call(io, arena, &.{ exe, "clear", "service", common.service, "account", name }, null);
    if (r.code != 0) return error.SecretStoreUnavailable;
    return true;
}

fn call(s: SecretService, io: Io, arena: Allocator, argv: []const []const u8, stdin: ?[]const u8) common.Error!proc.Result {
    return s.runner.run(io, arena, argv, stdin) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        else => error.SecretStoreUnavailable,
    };
}

const testing = std.testing;

test "secret-service: store via stdin, lookup, clear, availability" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var fake: common.FakeRunner = .{ .arena = ar };
    const s: SecretService = .{ .runner = fake.runner() };
    try fake.expect(&.{ exe, "lookup", "service", "artoo", "account", "__artoo_probe__" }, null, .{ .code = 1 });
    try testing.expect(try s.available(testing.io, ar));
    try fake.expect(&.{ exe, "lookup", "service", "artoo", "account", "__artoo_probe__" }, null, .{ .code = 1, .stderr = "Cannot autolaunch D-Bus without X11 $DISPLAY\n" });
    try testing.expect(!try s.available(testing.io, ar));
    try fake.expect(&.{ exe, "store", "--label=artoo unifi", "service", "artoo", "account", "unifi" }, "s3cret", .{});
    try s.set(testing.io, ar, "unifi", "s3cret");
    try fake.expect(&.{ exe, "lookup", "service", "artoo", "account", "unifi" }, null, .{ .stdout = "s3cret" });
    try testing.expectEqualStrings("s3cret", (try s.get(testing.io, ar, "unifi")).?);
    try fake.expect(&.{ exe, "lookup", "service", "artoo", "account", "unifi" }, null, .{ .stdout = "s3cret" });
    try fake.expect(&.{ exe, "clear", "service", "artoo", "account", "unifi" }, null, .{});
    try testing.expect(try s.delete(testing.io, ar, "unifi"));
    try fake.done();
}
