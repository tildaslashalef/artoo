//! SecretStore (SPEC §6): `get`, `set`, `delete`, `exists` over the
//! Keychain, Secret Service, a 0600 file, or memory (tests). Secrets are
//! fetched only right before use and never printed, logged or put in
//! error text.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const config = @import("config.zig");
const proc = @import("proc.zig");

pub const common = @import("secrets/common.zig");
pub const Keychain = @import("secrets/keychain.zig");
pub const SecretService = @import("secrets/secret_service.zig");
pub const FileStore = @import("secrets/file.zig");

pub const Error = common.Error || error{SecretMissing};
pub const validName = common.validName;
pub const validSecret = common.validSecret;

pub const Memory = struct {
    map: std.StringArrayHashMapUnmanaged([]const u8) = .empty,
    gpa: Allocator,
};

pub const Store = union(enum) {
    keychain: Keychain,
    secret_service: SecretService,
    file: FileStore,
    memory: *Memory,

    pub fn describe(s: Store, arena: Allocator) []const u8 {
        return switch (s) {
            .keychain => "macOS Keychain (service artoo)",
            .secret_service => "Secret Service via secret-tool (service artoo)",
            .file => |f| std.fmt.allocPrint(arena, "file {s} (0600)", .{f.path}) catch "file",
            .memory => "memory (test)",
        };
    }

    pub fn kind(s: Store) []const u8 {
        return switch (s) {
            .keychain => "keychain",
            .secret_service => "secret-service",
            .file => "file",
            .memory => "memory",
        };
    }

    pub fn get(s: Store, io: Io, arena: Allocator, name: []const u8) common.Error!?[]const u8 {
        return switch (s) {
            .memory => |m| m.map.get(name),
            inline else => |b| b.get(io, arena, name),
        };
    }

    /// The secret, or `error.SecretMissing`.
    pub fn require(s: Store, io: Io, arena: Allocator, name: []const u8) Error![]const u8 {
        return (try s.get(io, arena, name)) orelse error.SecretMissing;
    }

    pub fn exists(s: Store, io: Io, arena: Allocator, name: []const u8) common.Error!bool {
        return switch (s) {
            .memory => |m| m.map.contains(name),
            inline else => |b| b.exists(io, arena, name),
        };
    }

    pub fn set(s: Store, io: Io, arena: Allocator, name: []const u8, secret: []const u8) common.Error!void {
        return switch (s) {
            .memory => |m| m.map.put(m.gpa, name, secret),
            inline else => |b| b.set(io, arena, name, secret),
        };
    }

    pub fn delete(s: Store, io: Io, arena: Allocator, name: []const u8) common.Error!bool {
        return switch (s) {
            .memory => |m| m.map.orderedRemove(name),
            inline else => |b| b.delete(io, arena, name),
        };
    }
};

pub const OpenError = error{ SecretStoreUnavailable, HomeUnknown } || Allocator.Error || Io.Cancelable;

/// Choose the backend for `credentials.store` (`auto`: Keychain on macOS;
/// Secret Service on Linux when it answers; else the file).
pub fn open(io: Io, arena: Allocator, env: *const std.process.Environ.Map, choice: config.Store, runner: proc.Runner) OpenError!Store {
    const is_mac = builtin.os.tag.isDarwin();
    switch (choice) {
        .keychain => return if (is_mac) .{ .keychain = .{ .runner = runner } } else error.SecretStoreUnavailable,
        .@"secret-service" => {
            const s: SecretService = .{ .runner = runner };
            return if (try s.available(io, arena)) .{ .secret_service = s } else error.SecretStoreUnavailable;
        },
        .file => return .{ .file = .{ .path = try FileStore.defaultPath(arena, env) } },
        .auto => {
            if (is_mac) return .{ .keychain = .{ .runner = runner } };
            const s: SecretService = .{ .runner = runner };
            if (try s.available(io, arena)) return .{ .secret_service = s };
            return .{ .file = .{ .path = try FileStore.defaultPath(arena, env) } };
        },
    }
}

test {
    _ = common;
    _ = Keychain;
    _ = SecretService;
    _ = FileStore;
}

test "open: explicit file, auto per platform" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("HOME", "/home/me");
    const f = try open(std.testing.io, a.allocator(), &env, .file, .{});
    try std.testing.expectEqualStrings("/home/me/.config/artoo/secrets.json", f.file.path);
    if (builtin.os.tag.isDarwin()) {
        try std.testing.expect((try open(std.testing.io, a.allocator(), &env, .auto, .{})) == .keychain);
    }
}
