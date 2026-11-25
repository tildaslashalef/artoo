//! Shared facts of Rex on guests (SPEC §20, §17.5): the tag, which
//! guests may have Rex, and how a command runs as the guest user.

const std = @import("std");
const vms = @import("../pve/vm.zig");
const template = @import("../commands/template.zig");
const vm_cmd = @import("../commands/vm.zig");
const vm_new = @import("../commands/vm_new.zig");

/// The Proxmox tag of a guest with Rex (SPEC §20.1).
pub const tag = "rex";

/// Roles that never get Rex (SPEC §20.1).
pub const refused_roles = [_][]const u8{ "edge", "router", "watch" };

/// Why `v` may not have Rex, or null (state checks — running, agent —
/// are the caller's).
pub fn refusal(v: vms.Vm) ?[]const u8 {
    if (v.template) return "a template";
    if (!template.taggedWith(v.tags, vm_new.tag)) return "not an artoo guest (no tag artoo)";
    if (vm_cmd.roleOf(v.tags)) |r| for (refused_roles) |x| {
        if (std.mem.eql(u8, r, x)) return "the edge, the router or the watchdog (they run nothing interactive)";
    };
    return null;
}

pub fn tagged(v: vms.Vm) bool {
    return template.taggedWith(v.tags, tag);
}

/// A shell script that runs `script` as `user` with Rex's environment
/// and no Rex server started (SPEC §20.3): never a login shell (the
/// user's shell is fish). `user` is a validated Linux name (SPEC §5);
/// `script` is passed as one single-quoted word.
pub fn asUser(a: std.mem.Allocator, user: []const u8, script: []const u8) ![]const u8 {
    var q: std.ArrayList(u8) = .empty;
    try q.append(a, '\'');
    for (script) |ch| {
        if (ch == '\'') try q.appendSlice(a, "'\\''") else try q.append(a, ch);
    }
    try q.append(a, '\'');
    return std.fmt.allocPrint(a,
        \\u={s}; uid=$(id -u "$u") || exit 1; h=$(getent passwd "$u" | cut -d: -f6)
        \\runuser -u "$u" -- env HOME="$h" USER="$u" XDG_RUNTIME_DIR=/run/user/$uid REX_AUTOSTART=0 PATH="$h/.local/bin:/usr/local/bin:/usr/bin:/bin" sh -c {s}
    , .{ user, q.items });
}

test "asUser quotes the script as one word" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const s = try asUser(arena.allocator(), "artoo", "echo 'hi'");
    try std.testing.expect(std.mem.endsWith(u8, s, "sh -c 'echo '\\''hi'\\'''"));
}

test "refusal" {
    const base: vms.Vm = .{ .vmid = 200, .name = "naboo", .status = "running", .tags = "artoo", .template = false, .cpus = null, .cpu = null, .mem = null, .maxmem = null, .maxdisk = null, .uptime = null, .lock = null };
    try std.testing.expect(refusal(base) == null);
    var e = base;
    e.tags = "artoo;role-edge";
    try std.testing.expect(refusal(e) != null);
    e.tags = "";
    try std.testing.expect(refusal(e) != null);
}
