//! DNS records of the Cloudflare zone (SPEC §15). artoo marks what it
//! creates with a comment and changes nothing else.

const std = @import("std");
const cf = @import("client.zig");
const Value = std.json.Value;

/// Comment prefix that marks an artoo-owned record.
pub const marker = "artoo";
/// Record types `cf dns add` writes.
pub const Type = enum { A, AAAA, CNAME, TXT };

pub const Record = struct {
    id: []const u8,
    name: []const u8,
    type: []const u8,
    content: []const u8,
    proxied: bool,
    /// 1 = automatic.
    ttl: ?i64,
    comment: []const u8,

    pub fn owned(r: Record) bool {
        return isMarked(r.comment);
    }
};

/// `artoo` or `artoo: …`.
pub fn isMarked(comment: []const u8) bool {
    return std.mem.eql(u8, comment, marker) or std.mem.startsWith(u8, comment, marker ++ ":");
}

pub const ttl_auto = 1;
pub const ttl_min = 60;
pub const ttl_max = 86400;

/// Every record of the zone, optionally filtered by exact name and type.
pub fn list(c: *cf.Client, name: ?[]const u8, rtype: ?[]const u8) ![]Record {
    const a = c.ctx.arena;
    var q: std.ArrayList(u8) = .empty;
    try q.print(a, "/zones/{s}/dns_records", .{try c.zoneId()});
    var sep: u8 = '?';
    if (name) |n| {
        try q.print(a, "{c}name.exact={s}", .{ sep, n });
        sep = '&';
    }
    if (rtype) |t| try q.print(a, "{c}type={s}", .{ sep, t });
    var out: std.ArrayList(Record) = .empty;
    for (try c.list(q.items)) |v| try out.append(a, of(v) orelse continue);
    return out.items;
}

/// One record by ID; null when Cloudflare answers 404.
pub fn get(c: *cf.Client, id: []const u8) !?Record {
    const path = try std.fmt.allocPrint(c.ctx.arena, "/zones/{s}/dns_records/{s}", .{ try c.zoneId(), id });
    const v = c.get(path) catch |err| switch (err) {
        error.NotFound => {
            c.ctx.diag = null;
            return null;
        },
        else => return err,
    };
    return of(v);
}

pub const New = struct {
    name: []const u8,
    type: Type,
    content: []const u8,
    proxied: bool,
    ttl: u32,
    comment: []const u8,
};

/// `POST /zones/{id}/dns_records`; the created record's ID.
pub fn create(c: *cf.Client, r: New) ![]const u8 {
    const a = c.ctx.arena;
    const body = try std.json.Stringify.valueAlloc(a, .{
        .name = r.name,
        .type = @tagName(r.type),
        .content = r.content,
        .proxied = r.proxied,
        .ttl = r.ttl,
        .comment = r.comment,
    }, .{});
    const path = try std.fmt.allocPrint(a, "/zones/{s}/dns_records", .{try c.zoneId()});
    const v = try c.request(.POST, path, body);
    const result = v.object.get("result") orelse .null;
    return cf.str(result, "id") orelse c.ctx.fail(error.OutcomeUnknown, "Cloudflare accepted the record but sent no ID; check 'artoo cf dns ls'", .{});
}

pub fn delete(c: *cf.Client, id: []const u8) !void {
    const path = try std.fmt.allocPrint(c.ctx.arena, "/zones/{s}/dns_records/{s}", .{ try c.zoneId(), id });
    _ = try c.request(.DELETE, path, null);
}

fn of(v: Value) ?Record {
    const ttl = if (v == .object) v.object.get("ttl") else null;
    return .{
        .id = cf.str(v, "id") orelse return null,
        .name = cf.str(v, "name") orelse return null,
        .type = cf.str(v, "type") orelse "",
        .content = cf.str(v, "content") orelse "",
        .proxied = cf.isTrue(if (v == .object) v.object.get("proxied") else null),
        .ttl = if (ttl != null and ttl.? == .integer) ttl.?.integer else null,
        .comment = cf.str(v, "comment") orelse "",
    };
}

/// Addresses that must never appear in public DNS: private (RFC 1918),
/// shared/CGNAT incl. Tailscale (100.64/10), loopback, link-local,
/// unspecified; IPv6 loopback, link-local and unique-local.
pub fn nonPublic(content: []const u8) bool {
    if (std.Io.net.Ip4Address.parse(content, 0)) |a| {
        const b = a.bytes;
        return b[0] == 10 or b[0] == 127 or b[0] == 0 or
            (b[0] == 172 and b[1] >= 16 and b[1] <= 31) or
            (b[0] == 192 and b[1] == 168) or
            (b[0] == 169 and b[1] == 254) or
            (b[0] == 100 and b[1] >= 64 and b[1] <= 127);
    } else |_| {}
    if (std.Io.net.Ip6Address.parse(content, 0)) |a| {
        const b = a.bytes;
        const loopback = std.mem.allEqual(u8, b[0..15], 0) and b[15] == 1;
        return loopback or std.mem.allEqual(u8, &b, 0) or
            (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) or (b[0] & 0xfe) == 0xfc;
    } else |_| {}
    return false;
}

pub fn validIpv6(s: []const u8) bool {
    _ = std.Io.net.Ip6Address.parse(s, 0) catch return false;
    return std.mem.findScalar(u8, s, ':') != null;
}

const testing = std.testing;

test "nonPublic" {
    for ([_][]const u8{ "192.168.1.200", "10.0.0.1", "172.20.1.1", "127.0.0.1", "169.254.1.1", "100.100.100.100", "0.0.0.0", "::1", "fe80::1", "fd7a:115c:a1e0::1", "::" }) |s| {
        if (!nonPublic(s)) {
            std.debug.print("{s} should be non-public\n", .{s});
            return error.TestUnexpectedResult;
        }
    }
    for ([_][]const u8{ "1.1.1.1", "172.32.0.1", "100.128.0.1", "2606:4700::1111", "example.com" }) |s| {
        if (nonPublic(s)) {
            std.debug.print("{s} should be public\n", .{s});
            return error.TestUnexpectedResult;
        }
    }
}

test "isMarked" {
    try testing.expect(isMarked("artoo"));
    try testing.expect(isMarked("artoo: web-01 public name"));
    try testing.expect(!isMarked("artoos"));
    try testing.expect(!isMarked(""));
}
