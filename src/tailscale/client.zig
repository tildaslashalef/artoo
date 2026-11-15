//! Tailscale API client (SPEC §19, §17.4): an OAuth client's secret from
//! the SecretStore is exchanged once per invocation for an access token
//! (`POST /oauth/token`, client-credentials grant, form-encoded) that
//! lives in memory only; requests carry it as `Authorization: Bearer`.
//! TLS against the system root store; errors are a status plus
//! `{"message": …}`; no pagination; writes are sent once.

const std = @import("std");
const app = @import("../app.zig");
const api = @import("../api.zig");
const http = @import("../http.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const Value = std.json.Value;

const Context = app.Context;

pub const default_base = "https://api.tailscale.com/api/v2";

/// Which OAuth client: `main` (secret `tailscale`).
pub const Credential = enum {
    main,

    pub fn secretName(c: Credential) []const u8 {
        return switch (c) {
            .main => "tailscale",
        };
    }

    fn clientId(c: Credential, ctx: *Context) ![]const u8 {
        const cfg = try ctx.config();
        return switch (c) {
            .main => cfg.tailscale.client_id,
        };
    }

    fn idKey(c: Credential) []const u8 {
        return switch (c) {
            .main => "tailscale.client_id",
        };
    }
};

/// True when the integrations are on (SPEC §19): the client ID is set
/// and its secret is stored. A store that cannot answer counts as off.
pub fn configured(ctx: *Context) !bool {
    const cfg = ctx.config() catch return false;
    if (cfg.tailscale.client_id.len == 0) return false;
    const store = ctx.secretStore() catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => return err,
        else => {
            ctx.diag = null;
            return false;
        },
    };
    return store.exists(ctx.io, ctx.arena, "tailscale") catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => err,
        else => false,
    };
}

pub const Options = struct {
    accept: []const u8 = "application/json",
    content_type: []const u8 = "application/json",
    /// `If-Match` (the policy's ETag, as received).
    if_match: ?[]const u8 = null,
};

pub const Client = struct {
    ctx: *Context,
    http: *http.Client,
    base: []const u8,
    /// The tailnet path segment (`-` = the client's own).
    tailnet: []const u8,
    credential: Credential,
    /// `Bearer <access token>`, for this invocation only.
    authorization: []const u8,
    /// The scopes the token was granted (the token response's `scope`).
    scopes: []const u8 = "",
    /// Seconds the token is valid.
    expires_in: ?i64 = null,

    /// Exchange the stored secret for an access token.
    pub fn open(ctx: *Context, cred: Credential) !Client {
        const cfg = try ctx.config();
        const id = try cred.clientId(ctx);
        if (id.len == 0) return ctx.fail(error.ConfigInvalid, "{s} is not set; 'artoo config set {s} ID' (the OAuth client's ID, SPEC §19)", .{ cred.idKey(), cred.idKey() });
        const store = try ctx.secretStore();
        const secret = (store.get(ctx.io, ctx.arena, cred.secretName()) catch |err| return switch (err) {
            error.OutOfMemory, error.Canceled => err,
            else => ctx.fail(error.SecretStoreUnavailable, "cannot read the {s} secret from {s}", .{ cred.secretName(), store.describe(ctx.arena) }),
        }) orelse return ctx.fail(error.SecretMissing, "no {s} secret stored; run 'artoo auth set {s}'", .{ cred.secretName(), cred.secretName() });
        var c: Client = .{
            .ctx = ctx,
            .http = undefined,
            .base = default_base,
            .tailnet = cfg.tailscale.tailnet,
            .credential = cred,
            .authorization = "",
        };
        if (ctx.test_hooks.tailscale_base) |base| {
            const hc = try ctx.arena.create(http.Client);
            hc.init(ctx.gpa, ctx.io, .{ .ca_bundle = null, .timeout_ms = 2000, .retries = 0 }) catch return error.Tls;
            c.http = hc;
            c.base = base;
        } else {
            c.http = try api.httpClient(ctx, .{ .base = default_base, .ca_bundle = null, .timeout_seconds = cfg.tailscale.timeout_seconds });
        }
        errdefer c.http.deinit();
        try c.exchange(id, secret);
        return c;
    }

    pub fn deinit(c: *Client) void {
        c.http.deinit();
    }

    /// `POST /oauth/token` (client-credentials grant). The secret travels
    /// only in this body; it never reaches an error message.
    fn exchange(c: *Client, id: []const u8, secret: []const u8) !void {
        const ctx = c.ctx;
        const body = try pve.form(ctx.arena, &.{
            .{ .name = "grant_type", .value = "client_credentials" },
            .{ .name = "client_id", .value = id },
            .{ .name = "client_secret", .value = secret },
        });
        var diag: http.Diag = .{};
        const r = c.http.send(ctx.arena, .{
            .method = .POST,
            .url = try std.fmt.allocPrint(ctx.arena, "{s}/oauth/token", .{c.base}),
            .headers = &.{.{ .name = "Accept", .value = "application/json" }},
            .body = body,
            .content_type = "application/x-www-form-urlencoded",
        }, &diag) catch |err| return switch (err) {
            error.OutOfMemory, error.Canceled => err,
            // No state changes on a token exchange: an unanswered one is
            // a network failure, not an unknown outcome.
            else => ctx.fail(if (err == error.OutcomeUnknown) error.Network else err, "Tailscale token exchange: {s}", .{if (diag.message.len > 0) diag.message else @errorName(err)}),
        };
        const v = std.json.parseFromSliceLeaky(Value, ctx.arena, r.body, .{}) catch null;
        if (r.status >= 200 and r.status < 300) {
            const token = if (v) |x| str(x, "access_token") else null;
            if (token == null or token.?.len == 0) return ctx.fail(error.Protocol, "Tailscale's token exchange answered without an access token", .{});
            c.authorization = try std.fmt.allocPrint(ctx.arena, "Bearer {s}", .{token.?});
            c.scopes = try ui.text.sanitize(ctx.arena, if (v) |x| str(x, "scope") orelse "" else "", .line);
            c.expires_in = if (v) |x| int(x, "expires_in") else null;
            return;
        }
        const msg = try errorMessage(ctx.arena, r.body);
        const s = if (msg.len > 0) ": " else "";
        return switch (r.status) {
            400, 401, 403 => ctx.fail(error.AuthFailed, "Tailscale rejected the OAuth client ({d}){s}{s}; check {s} and replace the secret with 'artoo auth set {s}'", .{ r.status, s, msg, c.credential.idKey(), c.credential.secretName() }),
            429 => ctx.fail(error.RateLimited, "Tailscale rate limited the token exchange (429){s}{s}; try again later", .{ s, msg }),
            else => ctx.fail(error.HttpStatus, "Tailscale answered {d} to the token exchange{s}{s}", .{ r.status, s, msg }),
        };
    }

    /// `/tailnet/<tailnet><rest>`.
    pub fn tailnetPath(c: *Client, comptime fmt: []const u8, args: anytype) ![]const u8 {
        return std.fmt.allocPrint(c.ctx.arena, "/tailnet/{s}" ++ fmt, .{c.tailnet} ++ args);
    }

    /// One request; the 2xx response. Other statuses become errors with
    /// Tailscale's sanitized message. A write that may have reached the
    /// server without a clear answer is `OutcomeUnknown`.
    pub fn raw(c: *Client, method: http.Method, path: []const u8, body: ?[]const u8, opts: Options) !http.Response {
        const ctx = c.ctx;
        var diag: http.Diag = .{};
        var headers: [2]std.http.Header = undefined;
        var n: usize = 0;
        headers[n] = .{ .name = "Accept", .value = opts.accept };
        n += 1;
        if (opts.if_match) |m| {
            headers[n] = .{ .name = "If-Match", .value = m };
            n += 1;
        }
        const r = c.http.send(ctx.arena, .{
            .method = method,
            .url = try std.fmt.allocPrint(ctx.arena, "{s}{s}", .{ c.base, path }),
            .authorization = c.authorization,
            .headers = try ctx.arena.dupe(std.http.Header, headers[0..n]),
            .body = body,
            .content_type = opts.content_type,
        }, &diag) catch |err| return api.transportError(ctx, err, diag, "Tailscale");
        if (r.status >= 200 and r.status < 300) return r;
        const msg = try errorMessage(ctx.arena, r.body);
        const s = if (msg.len > 0) ": " else "";
        const verb = @tagName(method);
        if (method != .GET and r.status >= 500) {
            return ctx.fail(error.OutcomeUnknown, "Tailscale answered {d} to {s} {s}{s}{s}; the write may or may not have applied — check before retrying", .{ r.status, verb, path, s, msg });
        }
        return switch (r.status) {
            400 => ctx.fail(error.Refused, "Tailscale refused {s} {s}{s}{s}", .{ verb, path, s, msg }),
            401 => ctx.fail(error.AuthFailed, "Tailscale rejected the access token (401){s}{s}", .{ s, msg }),
            403 => ctx.fail(error.PermissionDenied, "the Tailscale OAuth client may not {s} {s} (403){s}{s}; see SPEC §19 for its scopes", .{ verb, path, s, msg }),
            404 => ctx.fail(error.NotFound, "not found on Tailscale: {s}{s}{s}", .{ path, s, msg }),
            412 => ctx.fail(error.Changed, "Tailscale refused {s} {s}: it changed since it was read (412){s}{s}; nothing was applied — review and run again", .{ verb, path, s, msg }),
            429 => ctx.fail(error.RateLimited, "Tailscale rate limited {s} {s} (429){s}{s}; nothing is retried — try again later", .{ verb, path, s, msg }),
            else => ctx.fail(error.HttpStatus, "Tailscale answered {d} for {s} {s}{s}{s}", .{ r.status, verb, path, s, msg }),
        };
    }

    /// A JSON request; the parsed answer (`.null` for an empty body).
    pub fn json(c: *Client, method: http.Method, path: []const u8, body: ?[]const u8) !Value {
        const r = try c.raw(method, path, body, .{});
        if (std.mem.trim(u8, r.body, " \r\n\t").len == 0) return .null;
        return std.json.parseFromSliceLeaky(Value, c.ctx.arena, r.body, .{}) catch {
            if (method != .GET) return c.ctx.fail(error.OutcomeUnknown, "Tailscale answered {s} {s} with invalid JSON; the write may or may not have applied — check before retrying", .{ @tagName(method), path });
            return c.ctx.fail(error.Protocol, "Tailscale sent invalid JSON for {s}", .{path});
        };
    }

    pub fn get(c: *Client, path: []const u8) !Value {
        return c.json(.GET, path, null);
    }

    /// A typed value as the JSON body.
    pub fn send(c: *Client, method: http.Method, path: []const u8, body: anytype) !Value {
        const text = try std.json.Stringify.valueAlloc(c.ctx.arena, body, .{});
        return c.json(method, path, text);
    }
};

pub fn str(v: Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const x = v.object.get(key) orelse return null;
    return if (x == .string) x.string else null;
}

pub fn int(v: Value, key: []const u8) ?i64 {
    if (v != .object) return null;
    const x = v.object.get(key) orelse return null;
    return if (x == .integer) x.integer else null;
}

pub fn boolean(v: Value, key: []const u8) bool {
    if (v != .object) return false;
    const x = v.object.get(key) orelse return false;
    return x == .bool and x.bool;
}

pub fn field(v: Value, key: []const u8) Value {
    if (v != .object) return .null;
    return v.object.get(key) orelse .null;
}

/// The string items of an array member (others skipped).
pub fn strings(arena: std.mem.Allocator, v: Value, key: []const u8) ![]const []const u8 {
    const x = field(v, key);
    if (x != .array) return &.{};
    var out: std.ArrayList([]const u8) = .empty;
    for (x.array.items) |it| if (it == .string) try out.append(arena, it.string);
    return out.items;
}

/// `message`, sanitized to one line; empty when absent.
pub fn errorMessage(arena: std.mem.Allocator, body: []const u8) ![]const u8 {
    const v = std.json.parseFromSliceLeaky(Value, arena, body, .{}) catch return "";
    const m = str(v, "message") orelse return "";
    return ui.text.sanitize(arena, std.mem.trim(u8, m, " \r\n"), .line);
}

/// The granted scopes as a list (`a b` or `a,b`).
pub fn scopeList(arena: std.mem.Allocator, scopes: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeAny(u8, scopes, " ,");
    while (it.next()) |s| try out.append(arena, s);
    return out.items;
}

/// True when `have` grants `want`: the scope itself, its write form for a
/// `:read` scope, or `all` / `all:read` (read scopes only).
pub fn grants(have: []const []const u8, want: []const u8) bool {
    const read_base = std.mem.cutSuffix(u8, want, ":read");
    for (have) |h| {
        if (std.mem.eql(u8, h, want) or std.mem.eql(u8, h, "all")) return true;
        if (read_base) |b| if (std.mem.eql(u8, h, b) or std.mem.eql(u8, h, "all:read")) return true;
    }
    return false;
}

test "errorMessage and scopes" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try std.testing.expectEqualStrings("bad\x3f", try errorMessage(ar, "{\"message\":\"bad\\u001b\"}"));
    try std.testing.expectEqualStrings("", try errorMessage(ar, "not json"));
    const have = try scopeList(ar, "devices:core auth_keys dns:read");
    try std.testing.expect(grants(have, "devices:core"));
    try std.testing.expect(grants(have, "devices:core:read"));
    try std.testing.expect(grants(have, "dns:read"));
    try std.testing.expect(!grants(have, "dns"));
    try std.testing.expect(!grants(have, "policy_file:read"));
}
