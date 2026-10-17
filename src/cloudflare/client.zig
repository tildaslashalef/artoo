//! Cloudflare API client (SPEC §15): `Authorization: Bearer` from the
//! SecretStore at request time, TLS against the system root store, the
//! `{success, errors, result, result_info}` envelope, page/per_page lists.

const std = @import("std");
const app = @import("../app.zig");
const api = @import("../api.zig");
const http = @import("../http.zig");
const ui = @import("../ui.zig");
const Value = std.json.Value;

const Context = app.Context;

pub const default_base = "https://api.cloudflare.com/client/v4";
pub const per_page = 100;

pub const Client = struct {
    ctx: *Context,
    http: *http.Client,
    base: []const u8,
    /// `Bearer <token>`.
    authorization: []const u8,
    zone_name: []const u8,
    zone_id: ?[]const u8 = null,
    /// The zone's account (`account.id`), known after `zoneId`.
    account_id: ?[]const u8 = null,

    pub fn open(ctx: *Context) !Client {
        const cfg = try ctx.config();
        const store = try ctx.secretStore();
        const token = (store.get(ctx.io, ctx.arena, "cloudflare") catch |err| return switch (err) {
            error.OutOfMemory, error.Canceled => err,
            else => ctx.fail(error.SecretStoreUnavailable, "cannot read the Cloudflare token from {s}", .{store.describe(ctx.arena)}),
        }) orelse return ctx.fail(error.SecretMissing, "no Cloudflare token stored; run 'artoo auth set cloudflare'", .{});
        const authorization = try std.fmt.allocPrint(ctx.arena, "Bearer {s}", .{token});
        if (ctx.test_hooks.cloudflare_base) |base| {
            const hc = try ctx.arena.create(http.Client);
            hc.init(ctx.gpa, ctx.io, .{ .ca_bundle = null, .timeout_ms = 2000, .retries = 0 }) catch return error.Tls;
            return .{ .ctx = ctx, .http = hc, .base = base, .authorization = authorization, .zone_name = cfg.cloudflare.zone };
        }
        return .{
            .ctx = ctx,
            .http = try api.httpClient(ctx, .{ .base = default_base, .ca_bundle = null, .timeout_seconds = cfg.cloudflare.timeout_seconds }),
            .base = default_base,
            .authorization = authorization,
            .zone_name = cfg.cloudflare.zone,
        };
    }

    pub fn deinit(c: *Client) void {
        c.http.deinit();
    }

    /// One request; the parsed envelope of a successful answer. Non-2xx
    /// or `success: false` become errors carrying Cloudflare's messages.
    pub fn request(c: *Client, method: http.Method, path: []const u8, body: ?[]const u8) !Value {
        const ctx = c.ctx;
        var diag: http.Diag = .{};
        const r = c.http.send(ctx.arena, .{
            .method = method,
            .url = try std.fmt.allocPrint(ctx.arena, "{s}{s}", .{ c.base, path }),
            .authorization = c.authorization,
            .headers = &.{.{ .name = "Accept", .value = "application/json" }},
            .body = body,
        }, &diag) catch |err| return api.transportError(ctx, err, diag, "Cloudflare");
        const v = std.json.parseFromSliceLeaky(Value, ctx.arena, r.body, .{}) catch null;
        const ok = v != null and v.? == .object and isTrue(v.?.object.get("success"));
        if (r.status >= 200 and r.status < 300 and ok) return v.?;
        const msg = try errorMessage(ctx.arena, v);
        const s = if (msg.len > 0) ": " else "";
        if (method != .GET and (r.status >= 500 or (r.status >= 200 and r.status < 300))) {
            return ctx.fail(error.OutcomeUnknown, "Cloudflare answered {d} to {s} {s}{s}{s}; the write may or may not have applied — check before retrying", .{ r.status, @tagName(method), path, s, msg });
        }
        return switch (r.status) {
            400 => ctx.fail(error.Refused, "Cloudflare refused {s} {s}{s}{s}", .{ @tagName(method), path, s, msg }),
            401 => ctx.fail(error.AuthFailed, "Cloudflare rejected the token (401){s}{s}; replace it with 'artoo auth set cloudflare'", .{ s, msg }),
            403 => ctx.fail(error.PermissionDenied, "the Cloudflare token may not {s} {s} (403){s}{s}; see SPEC §15 for its permissions", .{ @tagName(method), path, s, msg }),
            404 => ctx.fail(error.NotFound, "not found on Cloudflare: {s}{s}{s}", .{ path, s, msg }),
            else => ctx.fail(error.HttpStatus, "Cloudflare answered {d} for {s} {s}{s}{s}", .{ r.status, @tagName(method), path, s, msg }),
        };
    }

    /// The `result` of a GET.
    pub fn get(c: *Client, path: []const u8) !Value {
        return (try c.request(.GET, path, null)).object.get("result") orelse .null;
    }

    /// Every item of a paged list (`path` may carry a query already).
    pub fn list(c: *Client, path: []const u8) ![]Value {
        const ctx = c.ctx;
        var items: std.ArrayList(Value) = .empty;
        const sep: u8 = if (std.mem.findScalar(u8, path, '?') == null) '?' else '&';
        var page: u32 = 1;
        while (true) : (page += 1) {
            const v = try c.request(.GET, try std.fmt.allocPrint(ctx.arena, "{s}{c}page={d}&per_page={d}", .{ path, sep, page, per_page }), null);
            const result = v.object.get("result") orelse .null;
            if (result != .array) return ctx.fail(error.Protocol, "Cloudflare sent an unexpected list for {s}", .{path});
            try items.appendSlice(ctx.arena, result.array.items);
            const total = intAt(v, "result_info", "total_count");
            if (result.array.items.len == 0 or result.array.items.len < per_page) break;
            if (total) |t| {
                if (items.items.len >= t) break;
            }
        }
        return items.items;
    }

    /// The configured zone's ID (`GET /zones?name=`), cached.
    pub fn zoneId(c: *Client) ![]const u8 {
        if (c.zone_id) |id| return id;
        const ctx = c.ctx;
        const zones = try c.list(try std.fmt.allocPrint(ctx.arena, "/zones?name={s}", .{c.zone_name}));
        for (zones) |z| {
            if (std.ascii.eqlIgnoreCase(str(z, "name") orelse "", c.zone_name)) {
                c.zone_id = str(z, "id") orelse continue;
                c.account_id = if (z.object.get("account")) |acc| str(acc, "id") else null;
                return c.zone_id.?;
            }
        }
        return ctx.fail(error.NotFound, "zone {s} (cloudflare.zone) is not visible to the token; it needs Zone → Zone → Read on that zone", .{c.zone_name});
    }
};

pub const TokenStatus = struct {
    status: []const u8,
    /// `expires_on` as sent (RFC 3339), when the token has an expiry.
    expires_on: ?[]const u8,
};

/// The token is account-owned (SPEC §15): `GET /accounts/{id}/tokens/verify`
/// (needs no permission), the account taken from the zone.
pub fn verifyToken(c: *Client) !TokenStatus {
    _ = try c.zoneId();
    const account = c.account_id orelse return c.ctx.fail(error.Protocol, "Cloudflare sent zone {s} without its account", .{c.zone_name});
    const r = try c.get(try std.fmt.allocPrint(c.ctx.arena, "/accounts/{s}/tokens/verify", .{account}));
    return .{ .status = str(r, "status") orelse "unknown", .expires_on = str(r, "expires_on") };
}

pub fn str(v: Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const x = v.object.get(key) orelse return null;
    return if (x == .string) x.string else null;
}

pub fn isTrue(v: ?Value) bool {
    return v != null and v.? == .bool and v.?.bool;
}

fn intAt(v: Value, a: []const u8, b: []const u8) ?usize {
    if (v != .object) return null;
    const o = v.object.get(a) orelse return null;
    if (o != .object) return null;
    const x = o.object.get(b) orelse return null;
    return if (x == .integer and x.integer >= 0) @intCast(x.integer) else null;
}

/// `errors[].message` joined, sanitized; empty when absent.
pub fn errorMessage(arena: std.mem.Allocator, v: ?Value) ![]const u8 {
    const root = v orelse return "";
    if (root != .object) return "";
    const errs = root.object.get("errors") orelse return "";
    if (errs != .array) return "";
    var out: std.ArrayList(u8) = .empty;
    for (errs.array.items) |e| {
        const m = str(e, "message") orelse continue;
        if (out.items.len > 0) try out.appendSlice(arena, "; ");
        try out.appendSlice(arena, m);
    }
    return ui.text.sanitize(arena, out.items, .line);
}

test "errorMessage" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const v = try std.json.parseFromSliceLeaky(Value, ar,
        \\{"success":false,"errors":[{"code":1001,"message":"Missing \"Authorization\" header"},{"code":2,"message":"bad\u001b"}],"result":null}
    , .{});
    try std.testing.expectEqualStrings("Missing \"Authorization\" header; bad?", try errorMessage(ar, v));
    try std.testing.expectEqualStrings("", try errorMessage(ar, null));
}
