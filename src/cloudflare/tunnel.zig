//! The lab's Cloudflare Tunnel (SPEC §15): remotely managed, its ingress
//! list lives in Cloudflare and `cloudflared` on the edge VM fetches it.
//! Configurations are handled as JSON values so rules and settings artoo
//! did not write survive a `PUT` unchanged.

const std = @import("std");
const cf = @import("client.zig");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;

/// Where every public route lands: Caddy on the edge VM itself.
pub const origin = "https://localhost:443";
pub const catch_all = "http_status:404";

pub const Tunnel = struct {
    id: []const u8,
    name: []const u8,
    /// `healthy`, `degraded`, `down`, `inactive`.
    status: []const u8,
    connections: usize,
};

fn account(c: *cf.Client) ![]const u8 {
    _ = try c.zoneId();
    return c.account_id orelse c.ctx.fail(error.Protocol, "Cloudflare sent zone {s} without its account", .{c.zone_name});
}

fn of(v: Value) ?Tunnel {
    const conns = if (v == .object) v.object.get("connections") else null;
    return .{
        .id = cf.str(v, "id") orelse return null,
        .name = cf.str(v, "name") orelse "",
        .status = cf.str(v, "status") orelse "unknown",
        .connections = if (conns != null and conns.? == .array) conns.?.array.items.len else 0,
    };
}

/// Tunnels of the account that are not deleted.
pub fn list(c: *cf.Client) ![]Tunnel {
    const path = try std.fmt.allocPrint(c.ctx.arena, "/accounts/{s}/cfd_tunnel?is_deleted=false", .{try account(c)});
    var out: std.ArrayList(Tunnel) = .empty;
    for (try c.list(path)) |v| try out.append(c.ctx.arena, of(v) orelse continue);
    return out.items;
}

pub fn find(c: *cf.Client, name: []const u8) !?Tunnel {
    for (try list(c)) |t| if (std.mem.eql(u8, t.name, name)) return t;
    return null;
}

pub fn get(c: *cf.Client, id: []const u8) !Tunnel {
    const v = try c.get(try std.fmt.allocPrint(c.ctx.arena, "/accounts/{s}/cfd_tunnel/{s}", .{ try account(c), id }));
    return of(v) orelse c.ctx.fail(error.Protocol, "Cloudflare sent an unexpected tunnel {s}", .{id});
}

/// A remotely managed tunnel (`config_src: cloudflare`).
pub fn create(c: *cf.Client, name: []const u8) !Tunnel {
    const a = c.ctx.arena;
    const body = try std.json.Stringify.valueAlloc(a, .{ .name = name, .config_src = "cloudflare" }, .{});
    const v = try c.request(.POST, try std.fmt.allocPrint(a, "/accounts/{s}/cfd_tunnel", .{try account(c)}), body);
    return of(v.object.get("result") orelse .null) orelse c.ctx.fail(error.OutcomeUnknown, "Cloudflare accepted tunnel {s} but sent no ID; check 'artoo cf tunnel ls'", .{name});
}

/// The connector token. A secret: the caller hands it to the edge VM and
/// drops it; it is never printed, logged or stored (SPEC §9.7).
pub fn token(c: *cf.Client, id: []const u8) ![]const u8 {
    const v = try c.get(try std.fmt.allocPrint(c.ctx.arena, "/accounts/{s}/cfd_tunnel/{s}/token", .{ try account(c), id }));
    if (v != .string or v.string.len == 0) return c.ctx.fail(error.Protocol, "Cloudflare sent no token for tunnel {s}", .{id});
    return v.string;
}

pub const Config = struct {
    version: i64,
    /// The `config` object (empty for a tunnel never configured).
    config: Value,
};

pub fn getConfig(c: *cf.Client, id: []const u8) !Config {
    const v = try c.get(try std.fmt.allocPrint(c.ctx.arena, "/accounts/{s}/cfd_tunnel/{s}/configurations", .{ try account(c), id }));
    const ver = if (v == .object) v.object.get("version") else null;
    const cfg = if (v == .object) v.object.get("config") else null;
    return .{
        .version = if (ver != null and ver.? == .integer) ver.?.integer else 0,
        .config = if (cfg != null and cfg.? == .object) cfg.? else .{ .object = .empty },
    };
}

pub fn putConfig(c: *cf.Client, id: []const u8, config: Value) !void {
    const a = c.ctx.arena;
    const body = try std.json.Stringify.valueAlloc(a, .{ .config = config }, .{});
    _ = try c.request(.PUT, try std.fmt.allocPrint(a, "/accounts/{s}/cfd_tunnel/{s}/configurations", .{ try account(c), id }), body);
}

/// One ingress rule with a hostname.
pub const Route = struct {
    hostname: []const u8,
    service: []const u8,
    /// `originRequest.originServerName`: the service name for artoo's routes.
    server_name: ?[]const u8,

    /// The service name artoo's rule points at, or null.
    pub fn serviceHost(r: Route) ?[]const u8 {
        return if (std.mem.eql(u8, r.service, origin)) r.server_name else null;
    }
};

fn ingress(config: Value) []const Value {
    const v = config.object.get("ingress") orelse return &.{};
    return if (v == .array) v.array.items else &.{};
}

pub fn routes(a: Allocator, config: Value) ![]const Route {
    var out: std.ArrayList(Route) = .empty;
    for (ingress(config)) |r| {
        const host = cf.str(r, "hostname") orelse continue;
        const req = if (r == .object) r.object.get("originRequest") orelse .null else .null;
        try out.append(a, .{ .hostname = host, .service = cf.str(r, "service") orelse "", .server_name = cf.str(req, "originServerName") });
    }
    return out.items;
}

pub fn findRoute(rs: []const Route, host: []const u8) ?Route {
    for (rs) |r| if (std.ascii.eqlIgnoreCase(r.hostname, host)) return r;
    return null;
}

/// `config` with a rule `host` → Caddy (as `service_host`), inserted before
/// the catch-all (added when missing); other rules and keys unchanged.
pub fn withRoute(a: Allocator, config: Value, host: []const u8, service_host: []const u8) !Value {
    const rule_json = try std.json.Stringify.valueAlloc(a, .{
        .hostname = host,
        .service = origin,
        .originRequest = .{ .originServerName = service_host, .httpHostHeader = service_host },
    }, .{});
    const rule = try std.json.parseFromSliceLeaky(Value, a, rule_json, .{});
    var rules = std.json.Array.init(a);
    var tail: ?Value = null;
    for (ingress(config)) |r| {
        if (cf.str(r, "hostname") == null) {
            tail = r;
            continue;
        }
        try rules.append(r);
    }
    try rules.append(rule);
    try rules.append(tail orelse try std.json.parseFromSliceLeaky(Value, a, "{\"service\":\"" ++ catch_all ++ "\"}", .{}));
    return replaceIngress(a, config, rules);
}

/// `config` without the rule for `host`.
pub fn withoutRoute(a: Allocator, config: Value, host: []const u8) !Value {
    var rules = std.json.Array.init(a);
    for (ingress(config)) |r| {
        if (cf.str(r, "hostname")) |h| if (std.ascii.eqlIgnoreCase(h, host)) continue;
        try rules.append(r);
    }
    return replaceIngress(a, config, rules);
}

fn replaceIngress(a: Allocator, config: Value, rules: std.json.Array) !Value {
    var obj: std.json.ObjectMap = .empty;
    var it = config.object.iterator();
    while (it.next()) |e| if (!std.mem.eql(u8, e.key_ptr.*, "ingress")) try obj.put(a, e.key_ptr.*, e.value_ptr.*);
    try obj.put(a, "ingress", .{ .array = rules });
    return .{ .object = obj };
}

const testing = std.testing;

test "withRoute / withoutRoute: catch-all last, foreign rules and keys kept" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cfg = try std.json.parseFromSliceLeaky(Value, a,
        \\{"ingress":[{"hostname":"x.example.com","service":"http://other:80"},{"service":"http_status:404"}],"warp-routing":{"enabled":false}}
    , .{});
    const added = try withRoute(a, cfg, "blog.example.com", "grafana.apps.lab.example.com");
    const text = try std.json.Stringify.valueAlloc(a, added, .{});
    try testing.expectEqualStrings(
        \\{"warp-routing":{"enabled":false},"ingress":[{"hostname":"x.example.com","service":"http://other:80"},{"hostname":"blog.example.com","service":"https://localhost:443","originRequest":{"originServerName":"grafana.apps.lab.example.com","httpHostHeader":"grafana.apps.lab.example.com"}},{"service":"http_status:404"}]}
    , text);
    const rs = try routes(a, added);
    try testing.expectEqual(@as(usize, 2), rs.len);
    try testing.expectEqualStrings("grafana.apps.lab.example.com", findRoute(rs, "BLOG.example.com").?.serviceHost().?);
    try testing.expect(findRoute(rs, "x.example.com").?.serviceHost() == null);
    const removed = try withoutRoute(a, added, "blog.example.com");
    try testing.expectEqualStrings(
        \\{"warp-routing":{"enabled":false},"ingress":[{"hostname":"x.example.com","service":"http://other:80"},{"service":"http_status:404"}]}
    , try std.json.Stringify.valueAlloc(a, removed, .{}));
}

test "withRoute on a never-configured tunnel adds the catch-all" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const empty: Value = .{ .object = .empty };
    try testing.expectEqualStrings(
        \\{"ingress":[{"hostname":"blog.example.com","service":"https://localhost:443","originRequest":{"originServerName":"g.apps.lab.example.com","httpHostHeader":"g.apps.lab.example.com"}},{"service":"http_status:404"}]}
    , try std.json.Stringify.valueAlloc(a, try withRoute(a, empty, "blog.example.com", "g.apps.lab.example.com"), .{}));
}
