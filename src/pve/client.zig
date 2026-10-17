//! Proxmox VE API client (SPEC §7, §8). Token `artoo@pve!cli` from the
//! SecretStore at request time; responses are `{"data": …}`, writes are
//! form-encoded. pveproxy reports errors in the status line's reason
//! phrase (and sometimes a JSON `message`/`errors`); both are surfaced.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const app = @import("../app.zig");
const api = @import("../api.zig");
const http = @import("../http.zig");
const ui = @import("../ui.zig");

const Context = app.Context;

pub const Param = struct {
    name: []const u8,
    value: []const u8,
};

pub const Client = struct {
    ctx: *Context,
    http: *http.Client,
    base: []const u8,
    node: []const u8,
    authorization: []const u8,

    pub fn open(ctx: *Context) !Client {
        const cfg = try ctx.config();
        const store = try ctx.secretStore();
        const secret = (store.get(ctx.io, ctx.arena, "pve") catch |err| return switch (err) {
            error.OutOfMemory, error.Canceled => err,
            else => ctx.fail(error.SecretStoreUnavailable, "cannot read the Proxmox token from {s}", .{store.describe(ctx.arena)}),
        }) orelse return ctx.fail(error.SecretMissing, "no Proxmox token stored; run 'artoo auth set pve'", .{});
        const authorization = try std.fmt.allocPrint(ctx.arena, "PVEAPIToken={s}={s}", .{ cfg.pve.token_id, secret });
        if (ctx.test_hooks.pve_base) |base| {
            const hc = try ctx.arena.create(http.Client);
            hc.init(ctx.gpa, ctx.io, .{ .ca_bundle = null, .timeout_ms = 2000, .retries = 0 }) catch return error.Tls;
            return .{ .ctx = ctx, .http = hc, .base = base, .node = cfg.pve.node, .authorization = authorization };
        }
        return .{
            .ctx = ctx,
            .http = try api.httpClient(ctx, .{ .base = cfg.pve.endpoint, .ca_bundle = cfg.pve.ca_bundle, .timeout_seconds = cfg.pve.timeout_seconds }),
            .base = api.trimSlash(cfg.pve.endpoint),
            .node = cfg.pve.node,
            .authorization = authorization,
        };
    }

    pub fn deinit(c: *Client) void {
        c.http.deinit();
    }

    /// `/nodes/<node><rest>` with the configured node.
    pub fn nodePath(c: *Client, comptime fmt: []const u8, args: anytype) ![]const u8 {
        return std.fmt.allocPrint(c.ctx.arena, "/nodes/{s}" ++ fmt, .{c.node} ++ args);
    }

    /// GET `path` (below /api2/json); the raw 2xx body.
    pub fn getRaw(c: *Client, path: []const u8) ![]const u8 {
        return (try c.request(.GET, path, &.{})).body;
    }

    /// GET `path` and return its `data` member.
    pub fn get(c: *Client, path: []const u8) !Value {
        return data(c.ctx, try c.getRaw(path), path);
    }

    pub const Version = struct { version: []const u8, release: ?[]const u8 = null };

    pub fn version(c: *Client) !Version {
        const v = try c.get("/version");
        return .{
            .version = str(v, "version") orelse return c.ctx.fail(error.Protocol, "unexpected /version response from Proxmox", .{}),
            .release = str(v, "release"),
        };
    }

    /// One write (sent once; SPEC §8.1); returns `data` (often a UPID).
    pub fn send(c: *Client, method: http.Method, path: []const u8, params: []const Param) !Value {
        const r = try c.request(method, path, params);
        return data(c.ctx, r.body, path);
    }

    fn request(c: *Client, method: http.Method, path: []const u8, params: []const Param) !http.Response {
        const ctx = c.ctx;
        // GET and DELETE carry parameters in the query string, never a body.
        const in_query = method == .GET or method == .DELETE;
        const query: []const u8 = if (in_query and params.len > 0)
            try std.fmt.allocPrint(ctx.arena, "{s}{s}", .{ if (std.mem.findScalar(u8, path, '?') == null) "?" else "&", try form(ctx.arena, params) })
        else
            "";
        const url = try std.fmt.allocPrint(ctx.arena, "{s}/api2/json{s}{s}", .{ c.base, path, query });
        const body: ?[]const u8 = if (in_query) null else try form(ctx.arena, params);
        var diag: http.Diag = .{};
        const r = c.http.send(ctx.arena, .{
            .method = method,
            .url = url,
            .authorization = c.authorization,
            .body = body,
            .content_type = "application/x-www-form-urlencoded",
        }, &diag) catch |err| return api.transportError(ctx, err, diag, "Proxmox");
        if (r.status >= 200 and r.status < 300) return r;
        const msg = try errorMessage(ctx.arena, r);
        const verb = @tagName(method);
        return switch (r.status) {
            400 => ctx.fail(error.Usage, "Proxmox rejected {s} {s}: {s}", .{ verb, path, msg }),
            401 => ctx.fail(error.AuthFailed, "Proxmox rejected the API token (401); check pve.token_id and 'artoo auth set pve'", .{}),
            403 => ctx.fail(error.PermissionDenied, "Proxmox denied {s} {s} (403): {s}", .{ verb, path, msg }),
            404 => ctx.fail(error.NotFound, "not found on Proxmox: {s}", .{path}),
            // pveproxy itself failed: a write may have reached pvedaemon.
            502, 503, 504 => if (method != .GET)
                ctx.fail(error.OutcomeUnknown, "Proxmox answered {d} to {s} {s}: {s}; the write may or may not have applied — check before retrying", .{ r.status, verb, path, msg })
            else
                ctx.fail(error.HttpStatus, "Proxmox answered {d} for GET {s}: {s}", .{ r.status, path, msg }),
            // pvedaemon refused the request (nothing was done), or the
            // object is missing: "Configuration file … does not exist".
            else => if (std.mem.find(u8, msg, "does not exist") != null)
                ctx.fail(error.NotFound, "not found on Proxmox: {s}", .{msg})
            else
                ctx.fail(error.HttpStatus, "Proxmox refused {s} {s} ({d}): {s}", .{ verb, path, r.status, msg }),
        };
    }
};

/// `a=1&b=x%20y`.
pub fn form(arena: Allocator, params: []const Param) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (params, 0..) |p, i| {
        if (i > 0) try out.append(arena, '&');
        try escape(arena, &out, p.name);
        try out.append(arena, '=');
        try escape(arena, &out, p.value);
    }
    return out.items;
}

fn escape(arena: Allocator, out: *std.ArrayList(u8), s: []const u8) !void {
    for (s) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try out.append(arena, ch);
        } else try out.print(arena, "%{X:0>2}", .{ch});
    }
}

fn data(ctx: *Context, body: []const u8, path: []const u8) !Value {
    const v = std.json.parseFromSliceLeaky(Value, ctx.arena, body, .{}) catch
        return ctx.fail(error.Protocol, "Proxmox sent invalid JSON for {s}", .{path});
    if (v != .object) return ctx.fail(error.Protocol, "Proxmox sent an unexpected response for {s}", .{path});
    return v.object.get("data") orelse .null;
}

/// JSON `message` + `errors` (per-parameter), else the reason phrase;
/// sanitized, one line.
pub fn errorMessage(arena: Allocator, r: http.Response) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    if (std.json.parseFromSliceLeaky(Value, arena, r.body, .{})) |v| {
        if (v == .object) {
            if (v.object.get("message")) |m| if (m == .string) try out.appendSlice(arena, std.mem.trim(u8, m.string, " \n"));
            if (v.object.get("errors")) |e| if (e == .object) {
                var it = e.object.iterator();
                while (it.next()) |x| {
                    if (out.items.len > 0) try out.appendSlice(arena, "; ");
                    try out.print(arena, "{s}: {s}", .{ x.key_ptr.*, if (x.value_ptr.* == .string) std.mem.trim(u8, x.value_ptr.string, " \n") else "invalid" });
                }
            };
        }
    } else |_| {}
    if (out.items.len == 0) try out.appendSlice(arena, std.mem.trim(u8, r.reason, " "));
    if (out.items.len == 0) try out.appendSlice(arena, "no message");
    return ui.text.sanitize(arena, out.items, .line);
}

// ---------------------------------------------------------------- values
// PVE serializes many numbers as strings (`loadavg`, sometimes `cpu`);
// these accessors accept both and return null when absent.

pub fn str(v: Value, key: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const x = v.object.get(key) orelse return null;
    return if (x == .string) x.string else null;
}

pub fn num(v: Value, key: []const u8) ?f64 {
    if (v != .object) return null;
    return numberOf(v.object.get(key) orelse return null);
}

pub fn numberOf(x: Value) ?f64 {
    return switch (x) {
        .integer => |n| @floatFromInt(n),
        .float => |f| f,
        .number_string, .string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

pub fn int(v: Value, key: []const u8) ?i64 {
    const f = num(v, key) orelse return null;
    if (!std.math.isFinite(f)) return null;
    return @intFromFloat(@trunc(f));
}

pub fn uint(v: Value, key: []const u8) ?u64 {
    const n = int(v, key) orelse return null;
    return if (n < 0) null else @intCast(n);
}

pub fn flag(v: Value, key: []const u8) bool {
    return (int(v, key) orelse 0) != 0;
}

/// Nested object member.
pub fn obj(v: Value, key: []const u8) Value {
    if (v != .object) return .null;
    return v.object.get(key) orelse .null;
}

pub fn items(v: Value) []const Value {
    return if (v == .array) v.array.items else &.{};
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "form encoding" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    try testing.expectEqualStrings("name=web-01&description=a%20b%2Fc&net0=virtio%2Cbridge%3Dvmbr0", try form(a.allocator(), &.{
        .{ .name = "name", .value = "web-01" },
        .{ .name = "description", .value = "a b/c" },
        .{ .name = "net0", .value = "virtio,bridge=vmbr0" },
    }));
}

test "errorMessage: JSON message and errors, else reason" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expectEqualStrings("Parameter verification failed.; memory: value must have a minimum value of 16", try errorMessage(ar, .{
        .status = 400,
        .body = "{\"message\":\"Parameter verification failed.\\n\",\"errors\":{\"memory\":\"value must have a minimum value of 16\\n\"},\"data\":null}",
    }));
    try testing.expectEqualStrings("Configuration file 'nodes/pve/qemu-server/999.conf' does not exist", try errorMessage(ar, .{
        .status = 500,
        .body = "{\"data\":null}",
        .reason = "Configuration file 'nodes/pve/qemu-server/999.conf' does not exist",
    }));
}

test "number-tolerant accessors" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const v = try std.json.parseFromSliceLeaky(Value, a.allocator(), "{\"cpu\":0.25,\"load\":\"0.53\",\"mem\":1024,\"template\":1,\"name\":\"x\"}", .{});
    try testing.expectEqual(@as(?f64, 0.25), num(v, "cpu"));
    try testing.expectEqual(@as(?f64, 0.53), num(v, "load"));
    try testing.expectEqual(@as(?u64, 1024), uint(v, "mem"));
    try testing.expect(flag(v, "template"));
    try testing.expect(num(v, "absent") == null);
    try testing.expectEqualStrings("x", str(v, "name").?);
}
