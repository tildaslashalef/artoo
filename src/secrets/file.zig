//! Headless fallback: `$XDG_CONFIG_HOME/artoo/secrets.json` (default
//! `~/.config/artoo/`), dir 0700 + file 0600. Like ssh with private keys,
//! a secrets file that is a symlink, owned by someone else, or readable by
//! group/others is refused (SPEC §6).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const common = @import("common.zig");
const files = @import("../files.zig");

/// Absolute path of secrets.json.
path: []const u8,

const FileStore = @This();

pub fn defaultPath(arena: Allocator, env: *const std.process.Environ.Map) error{ HomeUnknown, OutOfMemory }![]const u8 {
    if (env.get("XDG_CONFIG_HOME")) |x| {
        if (x.len > 0 and x[0] == '/') return std.fs.path.join(arena, &.{ x, "artoo", "secrets.json" });
    }
    const home = env.get("HOME") orelse return error.HomeUnknown;
    return std.fs.path.join(arena, &.{ home, ".config", "artoo", "secrets.json" });
}

const Doc = struct {
    schema_version: u32 = 1,
    secrets: std.json.ArrayHashMap([]const u8) = .{},
};

pub const Reason = enum { ok, missing, symlink, foreign_owner, too_open, not_file };

/// Ownership/permission check without following symlinks.
pub fn inspect(path: []const u8) Reason {
    var z: [std.fs.max_path_bytes:0]u8 = undefined;
    if (path.len >= z.len) return .not_file;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const p: [*:0]const u8 = &z;
    const uid: u32, const mode: u32 = switch (builtin.os.tag) {
        .linux => blk: {
            const linux = std.os.linux;
            var sx: linux.Statx = undefined;
            const rc = linux.statx(linux.AT.FDCWD, p, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true, .UID = true }, &sx);
            if (linux.errno(rc) != .SUCCESS) return .missing;
            if (linux.getuid() != sx.uid) break :blk .{ std.math.maxInt(u32), sx.mode };
            break :blk .{ sx.uid, sx.mode };
        },
        else => blk: {
            var st: std.c.Stat = undefined;
            if (std.c.fstatat(std.c.AT.FDCWD, p, &st, std.c.AT.SYMLINK_NOFOLLOW) != 0) return .missing;
            if (std.c.getuid() != st.uid) break :blk .{ std.math.maxInt(u32), @intCast(st.mode) };
            break :blk .{ st.uid, @intCast(st.mode) };
        },
    };
    const fmt = mode & 0o170000;
    if (fmt == 0o120000) return .symlink;
    if (fmt != 0o100000) return .not_file;
    if (uid == std.math.maxInt(u32)) return .foreign_owner;
    if (mode & 0o077 != 0) return .too_open;
    return .ok;
}

fn read(f: FileStore, io: Io, arena: Allocator) common.Error!Doc {
    switch (inspect(f.path)) {
        .missing => return .{},
        .ok => {},
        else => return error.UnsafePath,
    }
    const bytes = Io.Dir.cwd().readFileAlloc(io, f.path, arena, .limited(1 << 20)) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Canceled => return error.Canceled,
        else => return error.SecretStoreUnavailable,
    };
    return std.json.parseFromSliceLeaky(Doc, arena, bytes, .{}) catch error.SecretStoreUnavailable;
}

fn write(f: FileStore, io: Io, arena: Allocator, doc: Doc) common.Error!void {
    const dir = std.fs.path.dirname(f.path).?;
    if (std.fs.path.dirname(dir)) |parent| {
        Io.Dir.cwd().createDirPath(io, parent) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return error.SecretStoreUnavailable,
        };
    }
    files.ensurePrivateDir(io, dir) catch |err| return mapFiles(err);
    var out: Io.Writer.Allocating = .init(arena);
    std.json.Stringify.value(doc, .{ .whitespace = .indent_2 }, &out.writer) catch return error.OutOfMemory;
    files.atomicWrite(io, arena, f.path, out.written()) catch |err| return mapFiles(err);
}

fn mapFiles(err: files.Error) common.Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.UnsafePath => error.UnsafePath,
        else => error.SecretStoreUnavailable,
    };
}

pub fn get(f: FileStore, io: Io, arena: Allocator, name: []const u8) common.Error!?[]const u8 {
    const doc = try f.read(io, arena);
    return doc.secrets.map.get(name);
}

pub fn exists(f: FileStore, io: Io, arena: Allocator, name: []const u8) common.Error!bool {
    return (try f.get(io, arena, name)) != null;
}

pub fn set(f: FileStore, io: Io, arena: Allocator, name: []const u8, secret: []const u8) common.Error!void {
    var doc = try f.read(io, arena);
    try doc.secrets.map.put(arena, name, secret);
    try f.write(io, arena, doc);
}

pub fn delete(f: FileStore, io: Io, arena: Allocator, name: []const u8) common.Error!bool {
    var doc = try f.read(io, arena);
    if (!doc.secrets.map.orderedRemove(name)) return false;
    try f.write(io, arena, doc);
    return true;
}

const testing = std.testing;

test "file store: round trip, 0600, refusal of open/symlinked files" {
    const io = testing.io;
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try tmp.dir.realPathFileAlloc(io, ".", ar);
    const f: FileStore = .{ .path = try std.fs.path.join(ar, &.{ base, "cfg", "artoo", "secrets.json" }) };

    try testing.expectEqual(@as(?[]const u8, null), try f.get(io, ar, "unifi"));
    try f.set(io, ar, "unifi", "key-1");
    try f.set(io, ar, "guest/web-01", "pw");
    try testing.expectEqualStrings("key-1", (try f.get(io, ar, "unifi")).?);
    try testing.expect(try f.exists(io, ar, "guest/web-01"));
    try testing.expectEqual(Reason.ok, inspect(f.path));
    const dir_st = try Io.Dir.cwd().statFile(io, std.fs.path.dirname(f.path).?, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o700), dir_st.permissions.toMode() & 0o777);
    try testing.expect(try f.delete(io, ar, "unifi"));
    try testing.expect(!try f.delete(io, ar, "unifi"));

    const file = try Io.Dir.cwd().openFile(io, f.path, .{ .mode = .read_write });
    try file.setPermissions(io, .fromMode(0o644));
    file.close(io);
    try testing.expectEqual(Reason.too_open, inspect(f.path));
    try testing.expectError(error.UnsafePath, f.get(io, ar, "guest/web-01"));

    const link: FileStore = .{ .path = try std.fs.path.join(ar, &.{ base, "link.json" }) };
    try Io.Dir.cwd().symLink(io, f.path, link.path, .{});
    try testing.expectEqual(Reason.symlink, inspect(link.path));
    try testing.expectError(error.UnsafePath, link.get(io, ar, "x"));
}

test "defaultPath honors XDG_CONFIG_HOME" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("HOME", "/home/me");
    try testing.expectEqualStrings("/home/me/.config/artoo/secrets.json", try defaultPath(a.allocator(), &env));
    try env.put("XDG_CONFIG_HOME", "/xdg");
    try testing.expectEqualStrings("/xdg/artoo/secrets.json", try defaultPath(a.allocator(), &env));
}
