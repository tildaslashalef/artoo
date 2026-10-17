//! UniFi client records through the classic, undocumented API
//! (SPEC §9.5, §17.1): the only place artoo uses it. A record ties a MAC to
//! a name (the UI alias) and optionally a Fixed IP (a DHCP reservation);
//! `vm new` creates one per guest before its first start and `vm rm`
//! forgets it. Request shapes verified 2026-10-10
//! (`scripts/live/unifi-reservation-probe.sh`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const unifi = @import("client.zig");
const view = @import("view.zig");
const Value = std.json.Value;

pub const Record = struct {
    id: []const u8,
    /// Lowercase `aa:bb:cc:dd:ee:ff`.
    mac: []const u8,
    name: []const u8,
    hostname: []const u8,
    /// Set only while the record's Fixed IP is enabled.
    fixed_ip: ?[]const u8,
};

/// Every client record UniFi knows, offline ones included.
pub fn records(c: *unifi.Client) ![]Record {
    var out: std.ArrayList(Record) = .empty;
    for (try c.classic(.GET, "rest/user", null)) |r| {
        const fixed = view.lookup(r, "use_fixedip");
        try out.append(c.ctx.arena, .{
            .id = view.string(r, "_id") orelse continue,
            .mac = try lower(c.ctx.arena, view.string(r, "mac") orelse continue),
            .name = view.string(r, "name") orelse "",
            .hostname = view.string(r, "hostname") orelse "",
            .fixed_ip = if (fixed != null and fixed.? == .bool and fixed.?.bool) view.string(r, "fixed_ip") else null,
        });
    }
    return out.items;
}

/// The record for `mac` (case-insensitive).
pub fn find(list: []const Record, mac: []const u8) ?Record {
    for (list) |r| if (std.ascii.eqlIgnoreCase(r.mac, mac)) return r;
    return null;
}

/// The classic `_id` of the network whose `ip_subnet` is `subnet`
/// (`192.168.1.1/24`, i.e. `guests.gateway`).
pub fn networkId(c: *unifi.Client, subnet: []const u8) ![]const u8 {
    for (try c.classic(.GET, "rest/networkconf", null)) |n| {
        if (std.mem.eql(u8, view.string(n, "ip_subnet") orelse "", subnet)) {
            if (view.string(n, "_id")) |id| return id;
        }
    }
    return c.ctx.fail(error.Refused, "no network {s} on UniFi (guests.gateway)", .{subnet});
}

/// Create the record for a MAC UniFi has not seen: name and Fixed IP
/// in one request.
pub fn reserve(c: *unifi.Client, mac: []const u8, name: []const u8, network_id: []const u8, ip: []const u8) !void {
    const body = try std.json.Stringify.valueAlloc(c.ctx.arena, .{ .objects = .{.{ .data = .{
        .mac = mac,
        .name = name,
        .use_fixedip = true,
        .network_id = network_id,
        .fixed_ip = ip,
    } }} }, .{});
    _ = try c.classic(.POST, "group/user", body);
}

/// Forget the record for `mac` (gone at once unless the client is connected).
pub fn forget(c: *unifi.Client, mac: []const u8) !void {
    const body = try std.json.Stringify.valueAlloc(c.ctx.arena, .{ .cmd = "forget-sta", .macs = .{mac} }, .{});
    _ = try c.classic(.POST, "cmd/stamgr", body);
}

/// `virtio=BC:24:11:AB:CD:EF,bridge=vmbr0` → `bc:24:11:ab:cd:ef`.
pub fn netMac(arena: Allocator, net0: []const u8) !?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, net0, ',');
    const first = it.next() orelse return null;
    const eq = std.mem.findScalar(u8, first, '=') orelse return null;
    const mac = first[eq + 1 ..];
    if (!validMac(mac)) return null;
    return try lower(arena, mac);
}

pub fn validMac(s: []const u8) bool {
    if (s.len != 17) return false;
    for (s, 0..) |ch, i| {
        if (i % 3 == 2) {
            if (ch != ':') return false;
        } else if (!std.ascii.isHex(ch)) return false;
    }
    return true;
}

fn lower(arena: Allocator, s: []const u8) ![]const u8 {
    const out = try arena.dupe(u8, s);
    for (out) |*ch| ch.* = std.ascii.toLower(ch.*);
    return out;
}

const testing = std.testing;

test "netMac" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    try testing.expectEqualStrings("bc:24:11:ab:cd:ef", (try netMac(a.allocator(), "virtio=BC:24:11:AB:CD:EF,bridge=vmbr0")).?);
    try testing.expectEqualStrings("bc:24:11:ab:cd:ef", (try netMac(a.allocator(), "virtio=bc:24:11:ab:cd:ef")).?);
    try testing.expect((try netMac(a.allocator(), "virtio,bridge=vmbr0")) == null);
    try testing.expect((try netMac(a.allocator(), "virtio=BC:24:11:AB:CD,bridge=vmbr0")) == null);
}
