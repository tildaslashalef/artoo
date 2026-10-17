//! Local file helpers shared by config and the file secret store:
//! `~` expansion, private directories, and locked atomic replacement that
//! refuses symlinked destinations (SPEC §5, §6).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Error = error{ UnsafePath, HomeUnknown, Io } || Allocator.Error || Io.Cancelable;

/// `~/x` → `$HOME/x`; other paths unchanged.
pub fn expandHome(arena: Allocator, env: *const std.process.Environ.Map, path: []const u8) error{ HomeUnknown, OutOfMemory }![]const u8 {
    if (std.mem.eql(u8, path, "~")) return env.get("HOME") orelse error.HomeUnknown;
    const rest = std.mem.cutPrefix(u8, path, "~/") orelse return path;
    const home = env.get("HOME") orelse return error.HomeUnknown;
    return std.fs.path.join(arena, &.{ home, rest });
}

/// Create `dir_path` (one level) with 0700 if it does not exist.
pub fn ensurePrivateDir(io: Io, dir_path: []const u8) Error!void {
    const st = Io.Dir.cwd().statFile(io, dir_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => {
            Io.Dir.cwd().createDir(io, dir_path, .fromMode(0o700)) catch |e| switch (e) {
                error.PathAlreadyExists => return,
                error.Canceled => return error.Canceled,
                else => return error.Io,
            };
            return;
        },
        error.Canceled => return error.Canceled,
        else => return error.Io,
    };
    if (st.kind != .directory) return error.UnsafePath;
}

/// `error.UnsafePath` when `path` is a symlink; missing is fine.
pub fn refuseSymlink(io: Io, path: []const u8) Error!void {
    const st = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        error.Canceled => return error.Canceled,
        else => return error.Io,
    };
    if (st.kind == .sym_link) return error.UnsafePath;
}

pub fn exists(io: Io, path: []const u8) Io.Cancelable!bool {
    _ = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return false,
    };
    return true;
}

/// Replace `path` with `bytes` (mode 0600): exclusive lock on `<path>.lock`,
/// unique temp file in the same directory, fsync, rename. Never follows a
/// symlink at `path`.
pub fn atomicWrite(io: Io, arena: Allocator, path: []const u8, bytes: []const u8) Error!void {
    const dir = std.fs.path.dirname(path) orelse ".";
    const base = std.fs.path.basename(path);
    try refuseSymlink(io, path);

    const lock_path = try std.fmt.allocPrint(arena, "{s}.lock", .{path});
    try refuseSymlink(io, lock_path);
    const lock = Io.Dir.cwd().createFile(io, lock_path, .{
        .truncate = false,
        .lock = .exclusive,
        .permissions = .fromMode(0o600),
    }) catch |err| return mapIo(err);
    defer lock.close(io);
    // Re-check under the lock: another writer may have swapped the target.
    try refuseSymlink(io, path);

    var rnd: [8]u8 = undefined;
    io.random(&rnd);
    const tmp = try std.fmt.allocPrint(arena, "{s}/.{s}.{x}.tmp", .{ dir, base, rnd });
    const file = Io.Dir.cwd().createFile(io, tmp, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    }) catch |err| return mapIo(err);
    var keep_tmp = true;
    defer if (keep_tmp) Io.Dir.cwd().deleteFile(io, tmp) catch {};
    {
        defer file.close(io);
        file.writeStreamingAll(io, bytes) catch return error.Io;
        file.sync(io) catch return error.Io;
    }
    Io.Dir.rename(Io.Dir.cwd(), tmp, Io.Dir.cwd(), path, io) catch |err| return mapIo(err);
    keep_tmp = false;
}

fn mapIo(err: anyerror) Error {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        error.SymLinkLoop, error.IsDir, error.NotDir => error.UnsafePath,
        else => error.Io,
    };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

pub fn tmpPath(arena: Allocator, tmp: *testing.TmpDir, name: []const u8) ![]const u8 {
    const dir = try tmp.dir.realPathFileAlloc(testing.io, ".", arena);
    return std.fs.path.join(arena, &.{ dir, name });
}

test "expandHome" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("HOME", "/home/me");
    try testing.expectEqualStrings("/home/me/.artoo/x", try expandHome(a.allocator(), &env, "~/.artoo/x"));
    try testing.expectEqualStrings("/etc/x", try expandHome(a.allocator(), &env, "/etc/x"));
    try testing.expectEqualStrings("/home/me", try expandHome(a.allocator(), &env, "~"));
    var empty: std.process.Environ.Map = .init(testing.allocator);
    defer empty.deinit();
    try testing.expectError(error.HomeUnknown, expandHome(a.allocator(), &empty, "~/x"));
}

test "atomicWrite: create, replace, 0600, no temp left, symlink refused" {
    const io = testing.io;
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Listable: on Linux a default handle is O_PATH and cannot be read.
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    const path = try tmpPath(ar, &tmp, "config.json");
    try atomicWrite(io, ar, path, "one\n");
    try atomicWrite(io, ar, path, "two\n");
    const got = try Io.Dir.cwd().readFileAlloc(io, path, ar, .limited(1024));
    try testing.expectEqualStrings("two\n", got);
    const st = try Io.Dir.cwd().statFile(io, path, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);

    var it = tmp.dir.iterate();
    while (try it.next(io)) |e| try testing.expect(!std.mem.endsWith(u8, e.name, ".tmp"));

    const link = try tmpPath(ar, &tmp, "link.json");
    try Io.Dir.cwd().symLink(io, path, link, .{});
    try testing.expectError(error.UnsafePath, atomicWrite(io, ar, link, "x"));
    try testing.expectEqualStrings("two\n", try Io.Dir.cwd().readFileAlloc(io, path, ar, .limited(1024)));
}

test "ensurePrivateDir: creates 0700, accepts existing, rejects files" {
    const io = testing.io;
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const d = try tmpPath(ar, &tmp, "artoo");
    try ensurePrivateDir(io, d);
    try ensurePrivateDir(io, d);
    const st = try Io.Dir.cwd().statFile(io, d, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o700), st.permissions.toMode() & 0o777);
    const f = try tmpPath(ar, &tmp, "plain");
    try atomicWrite(io, ar, f, "x");
    try testing.expectError(error.UnsafePath, ensurePrivateDir(io, f));
}
