//! UniFi Network Integration API client (SPEC §10, §17.1).
//! `X-API-KEY` from the SecretStore at request time; JSON responses.

const std = @import("std");
const Allocator = std.mem.Allocator;
const app = @import("../app.zig");
const api = @import("../api.zig");
const http = @import("../http.zig");

const catalog = @import("catalog.zig");
const view = @import("view.zig");
const Value = std.json.Value;

const Context = app.Context;

pub const Client = struct {
    ctx: *Context,
    http: *http.Client,
    base: []const u8,
    site: []const u8,
    key: []const u8,
    /// Resolved site UUID (cached).
    site_id: ?[]const u8 = null,
    site_name: ?[]const u8 = null,

    pub fn open(ctx: *Context) !Client {
        const cfg = try ctx.config();
        const store = try ctx.secretStore();
        const key = (store.get(ctx.io, ctx.arena, "unifi") catch |err| return switch (err) {
            error.OutOfMemory, error.Canceled => err,
            else => ctx.fail(error.SecretStoreUnavailable, "cannot read the UniFi API key from {s}", .{store.describe(ctx.arena)}),
        }) orelse return ctx.fail(error.SecretMissing, "no UniFi API key stored; run 'artoo auth set unifi'", .{});
        if (ctx.test_hooks.unifi_base) |base| {
            const hc = try ctx.arena.create(http.Client);
            hc.init(ctx.gpa, ctx.io, .{ .ca_bundle = null, .timeout_ms = 2000, .retries = 0 }) catch return error.Tls;
            return .{ .ctx = ctx, .http = hc, .base = base, .site = cfg.unifi.site, .key = key };
        }
        return .{
            .ctx = ctx,
            .http = try api.httpClient(ctx, .{ .base = cfg.unifi.endpoint, .ca_bundle = cfg.unifi.ca_bundle, .timeout_seconds = cfg.unifi.timeout_seconds }),
            .base = api.trimSlash(cfg.unifi.endpoint),
            .site = cfg.unifi.site,
            .key = key,
        };
    }

    pub fn deinit(c: *Client) void {
        c.http.deinit();
    }

    /// GET `path` (starting with /v1/) and return the raw 2xx body.
    pub fn getRaw(c: *Client, path: []const u8) ![]const u8 {
        const r = try c.request(.GET, path, null);
        return r.body;
    }

    /// One request; non-2xx statuses become errors with the API's message.
    pub fn request(c: *Client, method: http.Method, path: []const u8, body: ?[]const u8) !http.Response {
        return c.send(method, try std.fmt.allocPrint(c.ctx.arena, "{s}{s}", .{ c.base, path }), path, body);
    }

    /// The gateway's own OpenAPI document (SPEC §17.1), served beside the
    /// Integration API, not under it.
    pub fn getSpec(c: *Client) ![]const u8 {
        const url = try std.fmt.allocPrint(c.ctx.arena, "{s}{s}", .{ origin(c.base), spec_path });
        return (try c.send(.GET, url, spec_path, null)).body;
    }

    /// One request to the classic API of this site (SPEC §17.1):
    /// `sub` like `rest/user`; the `data` array of a `meta.rc == "ok"`
    /// envelope.
    pub fn classic(c: *Client, method: http.Method, sub: []const u8, body: ?[]const u8) ![]Value {
        const path = try std.fmt.allocPrint(c.ctx.arena, "{s}{s}/{s}", .{ classic_prefix, c.site, sub });
        const r = try c.send(method, try std.fmt.allocPrint(c.ctx.arena, "{s}{s}", .{ origin(c.base), path }), path, body);
        const v = std.json.parseFromSliceLeaky(Value, c.ctx.arena, r.body, .{}) catch
            return c.ctx.fail(error.Protocol, "UniFi sent invalid JSON for {s}", .{path});
        const rc = view.string(v, "meta.rc") orelse "";
        const data = view.lookup(v, "data");
        if (!std.mem.eql(u8, rc, "ok") or data == null or data.? != .array)
            return c.ctx.fail(error.Protocol, "UniFi sent an unexpected answer for {s} {s}", .{ @tagName(method), path });
        return data.?.array.items;
    }

    fn send(c: *Client, method: http.Method, url: []const u8, path: []const u8, body: ?[]const u8) !http.Response {
        const ctx = c.ctx;
        var diag: http.Diag = .{};
        const r = c.http.send(ctx.arena, .{
            .method = method,
            .url = url,
            .headers = &.{ .{ .name = "X-API-KEY", .value = c.key }, .{ .name = "Accept", .value = "application/json" } },
            .body = body,
        }, &diag) catch |err| return api.transportError(ctx, err, diag, "UniFi");
        if (r.status >= 200 and r.status < 300) return r;
        const msg = errorMessage(ctx.arena, r.body);
        if (r.status == 400 and std.mem.eql(u8, errorCode(ctx.arena, r.body), "api.request.invalid-filter")) {
            return ctx.fail(error.Usage, "invalid --filter: {s}", .{msg});
        }
        if (method != .GET and r.status >= 500) {
            return ctx.fail(error.OutcomeUnknown, "UniFi answered {d} to {s} {s}{s}{s}; the write may or may not have applied — check before retrying", .{ r.status, @tagName(method), path, sep(msg), msg });
        }
        return switch (r.status) {
            401 => ctx.fail(error.AuthFailed, "UniFi rejected the API key (401); replace it with 'artoo auth set unifi'", .{}),
            403 => ctx.fail(error.PermissionDenied, "UniFi denied {s} {s} (403){s}{s}", .{ @tagName(method), path, sep(msg), msg }),
            404 => ctx.fail(error.NotFound, "not found on UniFi: {s}{s}{s}", .{ path, sep(msg), msg }),
            else => ctx.fail(error.HttpStatus, "UniFi answered {d} for {s} {s}{s}{s}", .{ r.status, @tagName(method), path, sep(msg), msg }),
        };
    }
};

pub const spec_path = "/proxy/network/api-docs/integration.json";
/// The classic (undocumented) API beside the Integration API.
pub const classic_prefix = "/proxy/network/api/s/";

/// `https://host[:port]/a/b` → `https://host[:port]`.
fn origin(url: []const u8) []const u8 {
    const authority = (std.mem.find(u8, url, "://") orelse return url) + 3;
    const slash = std.mem.findScalarPos(u8, url, authority, '/') orelse return url;
    return url[0..slash];
}

test "origin" {
    try std.testing.expectEqualStrings("https://unifi.home.arpa", origin("https://unifi.home.arpa/proxy/network/integration"));
    try std.testing.expectEqualStrings("http://127.0.0.1:8080", origin("http://127.0.0.1:8080"));
}

fn sep(msg: []const u8) []const u8 {
    return if (msg.len > 0) ": " else "";
}

pub fn errorCode(arena: Allocator, body: []const u8) []const u8 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch return "";
    if (v != .object) return "";
    const m = v.object.get("code") orelse return "";
    return if (m == .string) m.string else "";
}

/// The `message` of a UniFi error body (`{statusCode, statusName, code,
/// message, …}`), sanitized; empty when absent.
pub fn errorMessage(arena: Allocator, body: []const u8) []const u8 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch return "";
    if (v != .object) return "";
    // Classic API errors: `{"meta":{"rc":"error","msg":"api.err.…"}}`.
    const m = v.object.get("message") orelse view.lookup(v, "meta.msg") orelse return "";
    if (m != .string) return "";
    return @import("../ui.zig").text.sanitize(arena, m.string, .line) catch "";
}

pub const ListOptions = struct {
    filter: ?[]const u8 = null,
    offset: u32 = 0,
    limit: u32 = 200,
    /// Fetch every page (pages of 200; not a snapshot).
    all: bool = false,
};

pub const Page = struct {
    items: []Value,
    offset: i64 = 0,
    total: ?i64 = null,
};

pub const max_page = 200;

/// The site UUID for `unifi.site` (internal reference, name or UUID).
pub fn siteId(c: *Client) ![]const u8 {
    if (c.site_id) |id| return id;
    const ctx = c.ctx;
    const page = try listPath(c, "/v1/sites", .{ .all = true });
    for (page.items) |s| {
        const id = view.string(s, "id") orelse continue;
        if (std.mem.eql(u8, id, c.site) or
            std.mem.eql(u8, view.string(s, "internalReference") orelse "", c.site) or
            std.mem.eql(u8, view.string(s, "name") orelse "", c.site))
        {
            c.site_id = id;
            c.site_name = view.string(s, "name");
            return id;
        }
    }
    return ctx.fail(error.ConfigInvalid, "site '{s}' (unifi.site) not found on UniFi; see 'artoo gw sites ls'", .{c.site});
}

/// Expand a catalog path template for this site.
pub fn expandPath(c: *Client, template: []const u8, id: ?[]const u8) ![]const u8 {
    const site: ?[]const u8 = if (std.mem.find(u8, template, "{siteId}") != null) try siteId(c) else null;
    return catalog.expand(c.ctx.arena, template, site, id) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => c.ctx.fail(error.Usage, "missing identifier for {s}", .{template}),
    };
}

/// GET a JSON object (redacted).
pub fn getJson(c: *Client, p: []const u8) !Value {
    const body = try c.getRaw(p);
    var v = std.json.parseFromSliceLeaky(Value, c.ctx.arena, body, .{}) catch
        return c.ctx.fail(error.Protocol, "UniFi sent invalid JSON for {s}", .{p});
    view.redact(&v);
    return v;
}

/// One page or every page of a paginated list (items redacted).
pub fn listPath(c: *Client, p: []const u8, opts: ListOptions) !Page {
    const ctx = c.ctx;
    var items: std.ArrayList(Value) = .empty;
    var offset: u32 = opts.offset;
    var total: ?i64 = null;
    const limit: u32 = if (opts.all) max_page else @min(opts.limit, max_page);
    while (true) {
        var q: std.ArrayList(u8) = .empty;
        try q.print(ctx.arena, "{s}?offset={d}&limit={d}", .{ p, offset, limit });
        if (opts.filter) |f| {
            try q.appendSlice(ctx.arena, "&filter=");
            try catalog.appendEscaped(ctx.arena, &q, f);
        }
        const v = try getJson(c, q.items);
        const data = if (v == .object) v.object.get("data") else null;
        if (data == null or data.? != .array) return ctx.fail(error.Protocol, "UniFi sent an unexpected page for {s}", .{p});
        try items.appendSlice(ctx.arena, data.?.array.items);
        if (v.object.get("totalCount")) |t| {
            if (t == .integer) total = t.integer;
        }
        const got: u32 = @intCast(data.?.array.items.len);
        offset += got;
        if (!opts.all or got == 0) break;
        if (total) |t| {
            if (offset >= t) break;
        } else if (got < limit) break;
    }
    return .{ .items = items.items, .offset = opts.offset, .total = total };
}

pub fn list(c: *Client, r: *const catalog.Resource, opts: ListOptions) !Page {
    return listPath(c, try expandPath(c, r.list.path, null), opts);
}

pub const Resolved = struct {
    id: []const u8,
    /// The list item when the object was found by listing.
    item: ?Value = null,
};

fn looksLikeId(r: *const catalog.Resource, word: []const u8) bool {
    if (r.columns.len > 0 and std.mem.eql(u8, r.columns[0].path, "id")) {
        // Integer-keyed (DPI): numeric words are IDs.
        _ = std.fmt.parseInt(u32, word, 10) catch return false;
        return true;
    }
    if (word.len != 36) return false;
    for (word, 0..) |ch, i| {
        const dash = i == 8 or i == 13 or i == 18 or i == 23;
        if (dash != (ch == '-')) return false;
        if (!dash and !std.ascii.isHex(ch)) return false;
    }
    return true;
}

fn idText(arena: Allocator, v: Value) ![]const u8 {
    return switch (v) {
        .string => |s| s,
        .integer => |n| try std.fmt.allocPrint(arena, "{d}", .{n}),
        else => "",
    };
}

/// Resolve an ID or unique name (exact, then case-insensitive) to an ID.
pub fn resolve(c: *Client, r: *const catalog.Resource, word: []const u8) !Resolved {
    const ctx = c.ctx;
    if (looksLikeId(r, word) and r.show != null) return .{ .id = word };
    const page = try list(c, r, .{ .all = true });
    var hits: std.ArrayList(Value) = .empty;
    for ([_]bool{ false, true }) |loose| {
        for (page.items) |item| {
            const id = try idText(ctx.arena, item.object.get("id") orelse .null);
            var hit = std.mem.eql(u8, id, word);
            for (r.match) |m| {
                const s = view.string(item, m) orelse continue;
                if (if (loose) std.ascii.eqlIgnoreCase(s, word) else std.mem.eql(u8, s, word)) hit = true;
            }
            if (hit) try hits.append(ctx.arena, item);
        }
        if (hits.items.len > 0) break;
    }
    if (hits.items.len == 0) return ctx.fail(error.NotFound, "no {s} '{s}' on UniFi (see 'artoo gw {s} ls')", .{ r.label, word, r.name });
    if (hits.items.len > 1) {
        var ids: std.ArrayList(u8) = .empty;
        for (hits.items, 0..) |h, i| {
            if (i > 0) try ids.appendSlice(ctx.arena, ", ");
            try ids.appendSlice(ctx.arena, try idText(ctx.arena, h.object.get("id") orelse .null));
        }
        return ctx.fail(error.Usage, "'{s}' matches {d} {s}s; use an ID: {s}", .{ word, hits.items.len, r.label, ids.items });
    }
    const item = hits.items[0];
    return .{ .id = try idText(ctx.arena, item.object.get("id") orelse .null), .item = item };
}

pub const Info = struct {
    applicationVersion: []const u8,
};

pub fn info(c: *Client) !Info {
    const body = try c.getRaw("/v1/info");
    return std.json.parseFromSliceLeaky(Info, c.ctx.arena, body, .{ .ignore_unknown_fields = true }) catch
        c.ctx.fail(error.Protocol, "unexpected /v1/info response from UniFi", .{});
}

test "errorMessage" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    try std.testing.expectEqualStrings("Invalid filter\x3f", errorMessage(a.allocator(), "{\"statusCode\":400,\"message\":\"Invalid filter\\u001b\"}"));
    try std.testing.expectEqualStrings("", errorMessage(a.allocator(), "<html>"));
    try std.testing.expectEqualStrings("api.err.InvalidFixedIP", errorMessage(a.allocator(), "{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.InvalidFixedIP\"},\"data\":[]}"));
}
