//! A records on UniFi (SPEC §10.3): DNS policies of type `A_RECORD`
//! (`domain`, `ipv4Address`, `ttlSeconds`, `enabled`), typed for `artoo
//! dns` and, later, `vm new`/`vm rm`. Names are validated locally before
//! anything is sent.

const std = @import("std");
const Allocator = std.mem.Allocator;
const unifi = @import("client.zig");
const catalog = @import("catalog.zig");
const view = @import("view.zig");

pub const ARecord = struct {
    id: []const u8,
    domain: []const u8,
    ipv4: []const u8,
    ttl: ?i64,
    enabled: bool,
};

/// API limit for `domain` (OpenAPI `maxLength`).
pub const max_domain = 127;
pub const max_ttl = 86400;
pub const default_ttl = 300;

const policies = catalog.find("dns-policies").?;
const collection = "/v1/sites/{siteId}/dns/policies";
const item_path = "/v1/sites/{siteId}/dns/policies/{dnsPolicyId}";

/// Every A record (all pages; other policy types are skipped).
pub fn list(c: *unifi.Client) ![]ARecord {
    const page = try unifi.list(c, policies, .{ .all = true });
    var out: std.ArrayList(ARecord) = .empty;
    for (page.items) |it| {
        if (!std.mem.eql(u8, view.string(it, "type") orelse "", "A_RECORD")) continue;
        const ttl = view.lookup(it, "ttlSeconds");
        const enabled = view.lookup(it, "enabled");
        try out.append(c.ctx.arena, .{
            .id = view.string(it, "id") orelse continue,
            .domain = view.string(it, "domain") orelse continue,
            .ipv4 = view.string(it, "ipv4Address") orelse "",
            .ttl = if (ttl != null and ttl.? == .integer) ttl.?.integer else null,
            .enabled = enabled != null and enabled.? == .bool and enabled.?.bool,
        });
    }
    return out.items;
}

/// Records for `domain` (case-insensitive; normally zero or one).
pub fn find(records: []const ARecord, domain: []const u8) ?ARecord {
    for (records) |r| {
        if (std.ascii.eqlIgnoreCase(r.domain, domain)) return r;
    }
    return null;
}

pub fn create(c: *unifi.Client, domain: []const u8, ipv4: []const u8, ttl: u32) !void {
    const body = try std.json.Stringify.valueAlloc(c.ctx.arena, .{
        .type = "A_RECORD",
        .enabled = true,
        .domain = domain,
        .ipv4Address = ipv4,
        .ttlSeconds = ttl,
    }, .{});
    _ = try c.request(.POST, try unifi.expandPath(c, collection, null), body);
}

pub fn delete(c: *unifi.Client, id: []const u8) !void {
    _ = try c.request(.DELETE, try unifi.expandPath(c, item_path, id), null);
}

pub const NameError = error{ InvalidName, OutOfMemory };

/// `web-01` → `web-01.<domain>`; a dotted name is taken as the FQDN.
/// Lowercased, trailing dot removed, validated (RFC 1123 labels).
pub fn fqdn(arena: Allocator, name: []const u8, domain: []const u8) NameError![]const u8 {
    const n = std.mem.trimEnd(u8, name, ".");
    const full = if (std.mem.findScalar(u8, n, '.') == null)
        try std.fmt.allocPrint(arena, "{s}.{s}", .{ n, domain })
    else
        try arena.dupe(u8, n);
    for (full) |*ch| ch.* = std.ascii.toLower(ch.*);
    if (!validName(full)) return error.InvalidName;
    return full;
}

pub fn validName(n: []const u8) bool {
    if (n.len == 0 or n.len > max_domain) return false;
    var labels = std.mem.splitScalar(u8, n, '.');
    var count: usize = 0;
    while (labels.next()) |l| {
        count += 1;
        if (l.len == 0 or l.len > 63 or l[0] == '-' or l[l.len - 1] == '-') return false;
        for (l) |ch| {
            if (!std.ascii.isAlphanumeric(ch) and ch != '-') return false;
        }
    }
    return count >= 2;
}

/// Dotted-quad IPv4, no leading zeros.
pub fn validIpv4(s: []const u8) bool {
    var parts = std.mem.splitScalar(u8, s, '.');
    var count: usize = 0;
    while (parts.next()) |p| {
        count += 1;
        if (p.len == 0 or p.len > 3 or (p.len > 1 and p[0] == '0')) return false;
        const v = std.fmt.parseInt(u16, p, 10) catch return false;
        if (v > 255) return false;
    }
    return count == 4;
}

const testing = std.testing;

test "fqdn: short names get the guest domain; validation" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expectEqualStrings("web-01.lab.example.com", try fqdn(ar, "Web-01", "lab.example.com"));
    try testing.expectEqualStrings("pve.home.arpa", try fqdn(ar, "pve.home.arpa.", "lab.example.com"));
    try testing.expectError(error.InvalidName, fqdn(ar, "-web", "lab.example.com"));
    try testing.expectError(error.InvalidName, fqdn(ar, "web_01", "lab.example.com"));
    try testing.expectError(error.InvalidName, fqdn(ar, "a..b", "lab.example.com"));
    try testing.expectError(error.InvalidName, fqdn(ar, "", "lab.example.com"));
}

test "validIpv4" {
    try testing.expect(validIpv4("192.168.1.201"));
    try testing.expect(!validIpv4("192.168.1"));
    try testing.expect(!validIpv4("192.168.1.256"));
    try testing.expect(!validIpv4("192.168.01.1"));
    try testing.expect(!validIpv4("::1"));
}
