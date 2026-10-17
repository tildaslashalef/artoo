//! Guest SSH host keys (SPEC §9.3, §9.4): `vm new` reads the guest's
//! ed25519 host key through the guest agent (an authenticated channel)
//! and records it in `~/.artoo/known_hosts` under the VM name
//! (`HostKeyAlias`), so the first SSH connection is already strict — no
//! trust-on-first-use, and an address reused by another guest cannot
//! impersonate this one.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const app = @import("../app.zig");
const files = @import("../files.zig");

const Context = app.Context;

pub const default_path = "~/.artoo/known_hosts";
pub const host_key_file = "/etc/ssh/ssh_host_ed25519_key.pub";

/// `ssh-ed25519 AAAA… root@x` → `ssh-ed25519 AAAA…` (null if malformed).
pub fn keyOf(arena: Allocator, pub_line: []const u8) !?[]const u8 {
    var it = std.mem.tokenizeAny(u8, pub_line, " \t\r\n");
    const kind = it.next() orelse return null;
    const blob = it.next() orelse return null;
    if (!std.mem.eql(u8, kind, "ssh-ed25519")) return null;
    if (blob.len < 60 or blob.len > 200) return null;
    for (blob) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '+' and ch != '/' and ch != '=') return null;
    return try std.fmt.allocPrint(arena, "{s} {s}", .{ kind, blob });
}

/// `existing` with every line for `alias` replaced by one new line
/// (`alias` null: only removed).
pub fn update(arena: Allocator, existing: []const u8, alias: []const u8, key: ?[]const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, existing, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const first = line[0 .. std.mem.findScalar(u8, line, ' ') orelse line.len];
        if (std.mem.eql(u8, first, alias)) continue;
        try out.appendSlice(arena, line);
        try out.append(arena, '\n');
    }
    if (key) |k| try out.print(arena, "{s} {s}\n", .{ alias, k });
    return out.items;
}

pub fn path(ctx: *Context) ![]const u8 {
    return files.expandHome(ctx.arena, ctx.env, default_path) catch
        ctx.fail(error.ConfigInvalid, "HOME is not set; cannot locate {s}", .{default_path});
}

/// Record (`key` set) or forget (`key` null) the host key of `alias`.
pub fn record(ctx: *Context, alias: []const u8, key: ?[]const u8) !void {
    const p = try path(ctx);
    files.ensurePrivateDir(ctx.io, std.fs.path.dirname(p).?) catch |err| return switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        else => ctx.fail(error.Io, "cannot create {s}", .{std.fs.path.dirname(p).?}),
    };
    const existing = Io.Dir.cwd().readFileAlloc(ctx.io, p, ctx.arena, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => "",
        error.Canceled => return error.Canceled,
        error.OutOfMemory => return error.OutOfMemory,
        else => return ctx.fail(error.Io, "cannot read {s}", .{ctx.tilde(p)}),
    };
    files.atomicWrite(ctx.io, ctx.arena, p, try update(ctx.arena, existing, alias, key)) catch |err| return switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        else => ctx.fail(error.Io, "cannot write {s}", .{ctx.tilde(p)}),
    };
}

/// `ssh` to `<guests.user>@address`, host key checked strictly against the
/// recorded key of `alias`.
pub fn sshArgv(ctx: *Context, alias: []const u8, address: []const u8, batch: bool, jump: bool, command: []const []const u8) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    const a = ctx.arena;
    try argv.appendSlice(a, &.{
        "/usr/bin/ssh",
        "-o",
        try std.fmt.allocPrint(a, "HostKeyAlias={s}", .{alias}),
        "-o",
        try std.fmt.allocPrint(a, "UserKnownHostsFile={s}", .{try path(ctx)}),
        "-o",
        "StrictHostKeyChecking=yes",
    });
    if (jump) try argv.appendSlice(a, &.{ "-o", try std.fmt.allocPrint(a, "ProxyCommand={s}", .{try proxyCommand(ctx)}) });
    if (batch) try argv.appendSlice(a, &.{ "-o", "BatchMode=yes", "-o", "ConnectTimeout=10" });
    try argv.append(a, try std.fmt.allocPrint(a, "{s}@{s}", .{ (try ctx.config()).guests.user, address }));
    if (command.len > 0) {
        try argv.append(a, "--");
        try argv.appendSlice(a, command);
    }
    return argv.items;
}

/// Tag of guests reachable over SSH only from Proxmox (SPEC §9.7.3).
pub const jump_tag = "ssh-jump";

/// The `ProxyCommand` through root on Proxmox with artoo's Proxmox SSH settings
/// (identity, strict host key from the default known_hosts, no prompts):
/// `-J` would not carry them to the jump hop. Proxmox only forwards; the
/// guest is authenticated end to end.
pub fn proxyCommand(ctx: *Context) ![]const u8 {
    const cfg = try ctx.config();
    const identity = files.expandHome(ctx.arena, ctx.env, cfg.pve.ssh_identity) catch
        return ctx.fail(error.ConfigInvalid, "cannot expand pve.ssh_identity: HOME is not set", .{});
    // The value is run by a shell: refuse anything that would need quoting.
    for ([_][]const u8{ identity, cfg.pve.ssh_host }) |word| {
        for (word) |ch| if (!(std.ascii.isAlphanumeric(ch) or std.mem.findScalar(u8, "/._-~@:", ch) != null))
            return ctx.fail(error.ConfigInvalid, "'{s}' cannot be used in an SSH jump (only letters, digits and /._-~@:)", .{word});
    }
    return std.fmt.allocPrint(ctx.arena, "/usr/bin/ssh -i {s} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -W %h:%p root@{s}", .{ identity, cfg.pve.ssh_host });
}

/// Whether a VM's tags ask for the Proxmox jump.
pub fn wantsJump(tags: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, tags, ";, ");
    while (it.next()) |t| if (std.mem.eql(u8, t, jump_tag)) return true;
    return false;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "wantsJump" {
    try testing.expect(wantsJump("artoo;role-edge;ssh-jump"));
    try testing.expect(!wantsJump("artoo;role-edge"));
    try testing.expect(!wantsJump("ssh-jumpy"));
}

test "keyOf and update" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIGb8kQvYwZp1n0Xo3m2cJ6d0n8wY1u5wQ7q8zT3kQ2rS";
    const key = (try keyOf(ar, "ssh-ed25519 " ++ blob ++ " root@web-01\n")).?;
    try testing.expectEqualStrings("ssh-ed25519 " ++ blob, key);
    try testing.expect(try keyOf(ar, "ssh-rsa " ++ blob) == null);
    try testing.expect(try keyOf(ar, "ssh-ed25519 a;b") == null);
    const before = "web-01 ssh-ed25519 OLD\ndb-01 ssh-ed25519 X\n";
    try testing.expectEqualStrings("db-01 ssh-ed25519 X\nweb-01 ssh-ed25519 " ++ blob ++ "\n", try update(ar, before, "web-01", key));
    try testing.expectEqualStrings("db-01 ssh-ed25519 X\n", try update(ar, before, "web-01", null));
    try testing.expectEqualStrings("web-02 k\n", try update(ar, "", "web-02", "k"));
}

test "sshArgv: the jump runs through root on Proxmox with artoo's Proxmox SSH settings" {
    var h = try @import("../testkit.zig").Harness.init();
    defer h.deinit();
    try h.env.put("HOME", "/home/me");
    var ctx: Context = .{ .arena = h.arena.allocator(), .gpa = testing.allocator, .io = testing.io, .out = &h.out.writer, .err = &h.err.writer, .env = &h.env };
    ctx.loaded = .{ .ok = .{ .path = "", .exists = false, .config = .{}, .tree = .empty } };
    const argv = try sshArgv(&ctx, "bespin", "192.168.1.200", true, true, &.{"true"});
    try testing.expectEqualStrings(
        "ProxyCommand=/usr/bin/ssh -i /home/me/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -W %h:%p root@192.168.1.10",
        argv[8],
    );
    try testing.expectEqualStrings("artoo@192.168.1.200", argv[argv.len - 3]);
    const direct = try sshArgv(&ctx, "naboo", "192.168.1.201", true, false, &.{});
    for (direct) |w| try testing.expect(std.mem.find(u8, w, "ProxyCommand") == null);
}
