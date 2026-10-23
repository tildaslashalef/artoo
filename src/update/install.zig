//! Where `artoo update` installs and how (SPEC §18): the running
//! executable, refused when it was reached through a symbolic link or its
//! directory is not writable; the new binary staged beside it, the old one
//! copied to `.<name>.previous`, then one atomic rename.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const app = @import("../app.zig");
const proc = @import("../proc.zig");
const archive = @import("archive.zig");
const release = @import("release.zig");

const Context = app.Context;

pub const Install = struct {
    /// The running executable, links resolved.
    path: []const u8,
    dir: []const u8,
    /// `<dir>/.<name>.previous`.
    backup: []const u8,
    stat: Io.File.Stat,

    /// Identity of the installed file, to notice a change during the prompt.
    pub fn fingerprint(i: Install, arena: Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "{d}:{d}:{d}", .{ i.stat.inode, i.stat.size, i.stat.mtime.nanoseconds });
    }
};

/// The installation this process runs from, checked for replacement.
pub fn locate(ctx: *Context) !Install {
    const hooks = ctx.test_hooks.update;
    const path: []const u8 = if (hooks) |h| h.exe_path else std.process.executablePathAlloc(ctx.io, ctx.arena) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return ctx.fail(error.Refused, "cannot find the running executable ({s}); install a release by hand", .{@errorName(err)}),
    };
    if (std.mem.endsWith(u8, path, " (deleted)")) {
        return ctx.fail(error.Refused, "the running executable was deleted or replaced ({s}); run the installed artoo again", .{path});
    }
    const invoked = if (hooks) |h| h.invoked orelse h.exe_path else try findInvoked(ctx.io, ctx.arena, ctx.env, ctx.argv0);
    if (invoked) |inv| {
        const st = Io.Dir.cwd().statFile(ctx.io, inv, .{ .follow_symlinks = false }) catch null;
        if (st != null and st.?.kind == .sym_link) {
            return ctx.fail(error.Refused, "{s} is a symbolic link to {s}; update what owns that file (a package manager, a checkout), or replace the link with the binary itself", .{ ctx.tilde(inv), ctx.tilde(path) });
        }
    }
    const st = Io.Dir.cwd().statFile(ctx.io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return ctx.fail(error.Refused, "cannot read {s} ({s})", .{ ctx.tilde(path), @errorName(err) }),
    };
    if (st.kind != .file) return ctx.fail(error.Refused, "{s} is not a regular file; install a release by hand", .{ctx.tilde(path)});
    const dir = std.fs.path.dirname(path) orelse ".";
    Io.Dir.cwd().access(ctx.io, dir, .{ .write = true }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return ctx.fail(error.PermissionDenied, "cannot write {s}: run artoo update as a user who can (artoo never runs sudo)", .{ctx.tilde(dir)}),
    };
    return .{
        .path = path,
        .dir = dir,
        .backup = try std.fmt.allocPrint(ctx.arena, "{s}/.{s}.previous", .{ dir, std.fs.path.basename(path) }),
        .stat = st,
    };
}

/// The path the shell ran: argv[0] when it names a path, else the first
/// `PATH` entry holding that name; null when it cannot be told.
pub fn findInvoked(io: Io, arena: Allocator, env: *const std.process.Environ.Map, argv0: []const u8) !?[]const u8 {
    if (argv0.len == 0) return null;
    if (std.mem.findScalar(u8, argv0, '/') != null) return argv0;
    var dirs = std.mem.tokenizeScalar(u8, env.get("PATH") orelse return null, ':');
    while (dirs.next()) |d| {
        const candidate = try std.fs.path.join(arena, &.{ d, argv0 });
        const st = Io.Dir.cwd().statFile(io, candidate, .{}) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => continue,
        };
        if (st.kind == .file) return candidate;
    }
    return null;
}

/// Write `entry` of the verified archive to `<dir>/.<name>.update-<random>`
/// (exclusive, 0755, synced); returns its path. The caller removes it on
/// every path that does not install it.
pub fn stage(ctx: *Context, inst: Install, data: []const u8, entry: []const u8) ![]const u8 {
    var rnd: [6]u8 = undefined;
    ctx.io.random(&rnd);
    const staged = try std.fmt.allocPrint(ctx.arena, "{s}/.{s}.update-{x}", .{ inst.dir, std.fs.path.basename(inst.path), rnd });
    const file = Io.Dir.cwd().createFile(ctx.io, staged, .{ .exclusive = true, .permissions = .fromMode(0o755) }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.AccessDenied, error.PermissionDenied, error.ReadOnlyFileSystem => return ctx.fail(error.PermissionDenied, "cannot write {s}: run artoo update as a user who can (artoo never runs sudo)", .{ctx.tilde(inst.dir)}),
        else => return ctx.fail(error.Refused, "cannot create {s} ({s}); nothing was replaced", .{ ctx.tilde(staged), @errorName(err) }),
    };
    var keep = false;
    defer if (!keep) Io.Dir.cwd().deleteFile(ctx.io, staged) catch {};
    {
        defer file.close(ctx.io);
        var buf: [64 * 1024]u8 = undefined;
        var fw: Io.File.Writer = .initStreaming(file, ctx.io, &buf);
        _ = archive.extract(data, entry, &fw.interface, release.limits.binary) catch |err| return switch (err) {
            error.WriteFailed => ctx.fail(error.Refused, "writing {s} failed; nothing was replaced", .{ctx.tilde(staged)}),
            error.EntryMissing => ctx.fail(error.Refused, "the archive has no {s}; nothing was replaced", .{entry}),
            error.EntryDuplicate => ctx.fail(error.Refused, "the archive holds {s} more than once; nothing was replaced", .{entry}),
            error.EntryNotFile => ctx.fail(error.Refused, "{s} in the archive is not a regular file; nothing was replaced", .{entry}),
            error.EntryTooLarge => ctx.fail(error.Refused, "{s} in the archive is larger than {d} MiB; nothing was replaced", .{ entry, release.limits.binary >> 20 }),
            error.ArchiveMalformed => ctx.fail(error.Refused, "the archive is not a readable gzip tar; nothing was replaced", .{}),
        };
        fw.interface.flush() catch return ctx.fail(error.Refused, "writing {s} failed; nothing was replaced", .{ctx.tilde(staged)});
        // The umask may have narrowed the create mode.
        file.setPermissions(ctx.io, .fromMode(0o755)) catch {};
        file.sync(ctx.io) catch return ctx.fail(error.Refused, "syncing {s} failed; nothing was replaced", .{ctx.tilde(staged)});
    }
    keep = true;
    return staged;
}

/// What `<path> --version` prints (trimmed), or null when it did not run
/// or exited non-zero.
pub fn reportedVersion(ctx: *Context, path: []const u8) !?[]const u8 {
    const runner = ctx.test_hooks.runner orelse proc.Runner{};
    const r = runner.run(ctx.io, ctx.arena, &.{ path, "--version" }, null) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return null,
    };
    if (r.code != 0) return null;
    return std.mem.trim(u8, r.stdout, " \t\r\n");
}

/// Copy the installed binary to `inst.backup` (temp file, sync, rename;
/// 0755). A copy, not a hard link (Linux's protected_hardlinks) and not a
/// rename (the target never goes missing).
pub fn backup(ctx: *Context, inst: Install) !void {
    const fail_msg = "cannot back up {s} to {s} ({s}); nothing was replaced";
    const bytes = Io.Dir.cwd().readFileAlloc(ctx.io, inst.path, ctx.arena, .limited(release.limits.binary * 2)) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return ctx.fail(error.Refused, fail_msg, .{ ctx.tilde(inst.path), ctx.tilde(inst.backup), @errorName(err) }),
    };
    var rnd: [6]u8 = undefined;
    ctx.io.random(&rnd);
    const tmp = try std.fmt.allocPrint(ctx.arena, "{s}.{x}.tmp", .{ inst.backup, rnd });
    const file = Io.Dir.cwd().createFile(ctx.io, tmp, .{ .exclusive = true, .permissions = .fromMode(0o755) }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return ctx.fail(error.Refused, fail_msg, .{ ctx.tilde(inst.path), ctx.tilde(inst.backup), @errorName(err) }),
    };
    var keep_tmp = true;
    defer if (keep_tmp) Io.Dir.cwd().deleteFile(ctx.io, tmp) catch {};
    {
        defer file.close(ctx.io);
        file.writeStreamingAll(ctx.io, bytes) catch |err| return ctx.fail(error.Refused, fail_msg, .{ ctx.tilde(inst.path), ctx.tilde(inst.backup), @errorName(err) });
        file.setPermissions(ctx.io, .fromMode(0o755)) catch {};
        file.sync(ctx.io) catch |err| return ctx.fail(error.Refused, fail_msg, .{ ctx.tilde(inst.path), ctx.tilde(inst.backup), @errorName(err) });
    }
    Io.Dir.rename(Io.Dir.cwd(), tmp, Io.Dir.cwd(), inst.backup, ctx.io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return ctx.fail(error.Refused, fail_msg, .{ ctx.tilde(inst.path), ctx.tilde(inst.backup), @errorName(err) }),
    };
    keep_tmp = false;
}

/// Rename `staged` over the installed binary (atomic: a new inode; the
/// running process keeps the old one), then sync the directory.
pub fn swap(ctx: *Context, inst: Install, staged: []const u8) !void {
    Io.Dir.rename(Io.Dir.cwd(), staged, Io.Dir.cwd(), inst.path, ctx.io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return ctx.fail(error.Refused, "cannot rename the new binary over {s} ({s}); nothing was replaced", .{ ctx.tilde(inst.path), @errorName(err) }),
    };
    // Best effort: the rename itself is what matters; a directory handle
    // that is listable is a real descriptor on Linux (not O_PATH).
    var d = Io.Dir.cwd().openDir(ctx.io, inst.dir, .{ .iterate = true }) catch return;
    defer d.close(ctx.io);
    const as_file: Io.File = .{ .handle = d.handle, .flags = .{ .nonblocking = false } };
    as_file.sync(ctx.io) catch {};
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "findInvoked: a path as given, a bare name through PATH" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "artoo", .data = "x" });
    const dir = try tmp.dir.realPathFileAlloc(testing.io, ".", ar);
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("PATH", try std.fmt.allocPrint(ar, "/nonexistent:{s}", .{dir}));
    try testing.expectEqualStrings("./bin/artoo", (try findInvoked(testing.io, ar, &env, "./bin/artoo")).?);
    try testing.expectEqualStrings(try std.fs.path.join(ar, &.{ dir, "artoo" }), (try findInvoked(testing.io, ar, &env, "artoo")).?);
    try testing.expectEqual(@as(?[]const u8, null), try findInvoked(testing.io, ar, &env, "not-here"));
    try testing.expectEqual(@as(?[]const u8, null), try findInvoked(testing.io, ar, &env, ""));
}
