//! Permission kinds of the coding agents on a guest (SPEC §20.6): how
//! freely Claude Code and `agy` act depends on what the guest can reach.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;

pub const Kind = enum {
    /// Fenced (tag `fenced`, §9.11) and no private key in `~/.ssh`.
    sandboxed,
    /// Every other guest.
    trusted_reach,

    pub fn word(k: Kind) []const u8 {
        return switch (k) {
            .sandboxed => "sandboxed",
            .trusted_reach => "trusted-reach",
        };
    }
};

/// The kind of a guest: `fenced` from its tags, `keys` the names of the
/// private keys in the guest user's `~/.ssh` (SPEC §20.6).
pub fn kindOf(fenced: bool, keys: []const []const u8) Kind {
    return if (fenced and keys.len == 0) .sandboxed else .trusted_reach;
}

/// Why the guest has its kind, for plans and `rex status`: "sandboxed",
/// "trusted-reach (not fenced)", "trusted-reach (fenced, but holds
/// ~/.ssh/id_ed25519)".
pub fn reason(a: Allocator, fenced: bool, keys: []const []const u8) ![]const u8 {
    if (kindOf(fenced, keys) == .sandboxed) return "sandboxed (fenced, no private key in ~/.ssh)";
    if (!fenced) return "trusted-reach (not fenced)";
    var list: std.ArrayList(u8) = .empty;
    for (keys, 0..) |k, i| {
        if (i > 0) try list.appendSlice(a, ", ");
        try list.print(a, "~/.ssh/{s}", .{k});
    }
    return std.fmt.allocPrint(a, "trusted-reach (fenced, but holds {s})", .{list.items});
}

/// The guest's fish file that wraps `agy` (SPEC §20.6), home-relative.
pub const fish_path = ".config/fish/conf.d/artoo-agents.fish";

pub const agy_flag = "--dangerously-skip-permissions";

/// The fish file's content for `kind`.
pub fn fishFile(kind: Kind) []const u8 {
    return switch (kind) {
        .sandboxed =>
        \\# Managed by artoo (SPEC §20.6): this guest is sandboxed (fenced, no
        \\# private key in ~/.ssh), so agy runs without asking. 'artoo rex setup'
        \\# rewrites this file.
        \\function agy; command agy --dangerously-skip-permissions $argv; end
        \\
        ,
        .trusted_reach =>
        \\# Managed by artoo (SPEC §20.6): this guest is trusted-reach (not fenced,
        \\# or it holds a private key), so agy keeps asking before it acts.
        \\# 'artoo rex setup' rewrites this file.
        \\
        ,
    };
}

/// True when a fish file's non-comment lines pass `agy_flag`.
pub fn fishUnrestricted(content: []const u8) bool {
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        const t = std.mem.trim(u8, line, " \t\r");
        if (t.len == 0 or t[0] == '#') continue;
        if (std.mem.find(u8, t, agy_flag) != null) return true;
    }
    return false;
}

/// Claude's `permissions.defaultMode` in a settings object, or null.
pub fn defaultMode(settings: Value) ?[]const u8 {
    if (settings != .object) return null;
    const p = settings.object.get("permissions") orelse return null;
    if (p != .object) return null;
    const m = p.object.get("defaultMode") orelse return null;
    return if (m == .string) m.string else null;
}

/// True when Claude may run unrestricted with these settings.
pub fn claudeUnrestricted(settings: Value) bool {
    const m = defaultMode(settings) orelse return false;
    return std.mem.eql(u8, m, "bypassPermissions");
}

/// Apply `kind` to Claude's (merged) settings object in place (SPEC
/// §20.6). Sandboxed: `defaultMode` `bypassPermissions` and no
/// `disableBypassPermissionsMode` (the kind decides). Trusted-reach:
/// `defaultMode` kept unless `bypassPermissions` (then `default`) and
/// `disableBypassPermissionsMode` `"disable"`.
pub fn applyClaude(a: Allocator, settings: *std.json.ObjectMap, kind: Kind) !void {
    const existing = settings.get("permissions");
    var perms: std.json.ObjectMap = .empty;
    if (existing) |e| if (e == .object) {
        var it = e.object.iterator();
        while (it.next()) |kv| try perms.put(a, kv.key_ptr.*, kv.value_ptr.*);
    };
    switch (kind) {
        .sandboxed => {
            try perms.put(a, "defaultMode", .{ .string = "bypassPermissions" });
            _ = perms.orderedRemove("disableBypassPermissionsMode");
        },
        .trusted_reach => {
            if (perms.get("defaultMode")) |m| if (m == .string and std.mem.eql(u8, m.string, "bypassPermissions"))
                try perms.put(a, "defaultMode", .{ .string = "default" });
            try perms.put(a, "disableBypassPermissionsMode", .{ .string = "disable" });
        },
    }
    try settings.put(a, "permissions", .{ .object = perms });
}

const testing = std.testing;

test "kindOf: fenced without keys is sandboxed; keys or no fence is trusted-reach" {
    try testing.expectEqual(Kind.sandboxed, kindOf(true, &.{}));
    try testing.expectEqual(Kind.trusted_reach, kindOf(true, &.{"id_ed25519"}));
    try testing.expectEqual(Kind.trusted_reach, kindOf(false, &.{}));
    try testing.expectEqual(Kind.trusted_reach, kindOf(false, &.{"id_ed25519"}));
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("trusted-reach (fenced, but holds ~/.ssh/id_ed25519, ~/.ssh/deploy)", try reason(arena.allocator(), true, &.{ "id_ed25519", "deploy" }));
    try testing.expectEqualStrings("trusted-reach (not fenced)", try reason(arena.allocator(), false, &.{}));
}

test "fish file: sandboxed passes the flag, trusted-reach defines nothing" {
    try testing.expect(fishUnrestricted(fishFile(.sandboxed)));
    try testing.expect(!fishUnrestricted(fishFile(.trusted_reach)));
    try testing.expect(!fishUnrestricted("# agy --dangerously-skip-permissions\n"));
}

test "applyClaude: sandboxed bypasses; trusted-reach downgrades bypass and disables it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const parse = struct {
        fn f(al: Allocator, s: []const u8) !Value {
            return std.json.parseFromSliceLeaky(Value, al, s, .{});
        }
    }.f;

    var v = try parse(a, "{\"model\":\"x\",\"permissions\":{\"allow\":[\"Bash(ls)\"],\"defaultMode\":\"bypassPermissions\"}}");
    try applyClaude(a, &v.object, .trusted_reach);
    try testing.expectEqualStrings(
        "{\"model\":\"x\",\"permissions\":{\"allow\":[\"Bash(ls)\"],\"defaultMode\":\"default\",\"disableBypassPermissionsMode\":\"disable\"}}",
        try std.json.Stringify.valueAlloc(a, v, .{}),
    );
    try testing.expect(!claudeUnrestricted(v));

    try applyClaude(a, &v.object, .sandboxed);
    try testing.expectEqualStrings(
        "{\"model\":\"x\",\"permissions\":{\"allow\":[\"Bash(ls)\"],\"defaultMode\":\"bypassPermissions\"}}",
        try std.json.Stringify.valueAlloc(a, v, .{}),
    );
    try testing.expect(claudeUnrestricted(v));

    var plan_mode = try parse(a, "{\"permissions\":{\"defaultMode\":\"plan\"}}");
    try applyClaude(a, &plan_mode.object, .trusted_reach);
    try testing.expectEqualStrings("plan", defaultMode(plan_mode).?);

    var empty = try parse(a, "{}");
    try applyClaude(a, &empty.object, .trusted_reach);
    try testing.expectEqualStrings("{\"permissions\":{\"disableBypassPermissionsMode\":\"disable\"}}", try std.json.Stringify.valueAlloc(a, empty, .{}));
}
