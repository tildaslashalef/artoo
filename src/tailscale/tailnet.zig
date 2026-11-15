//! Tailnet resources (SPEC §19, §17.4): devices and their routes, auth
//! key metadata, DNS, the policy — typed views of the API's JSON, and the
//! ownership rule that decides which devices artoo may change. Resource
//! functions never print.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const ts = @import("client.zig");
const parseTime = @import("../unifi/view.zig").parseTime;
const ui = @import("../ui.zig");
const Context = @import("../app.zig").Context;

pub const router_tag = "tag:lab-router";

pub const Device = struct {
    /// `nodeId` (preferred), else the legacy `id`.
    id: []const u8,
    /// The MagicDNS name (`naboo.example.ts.net`).
    name: []const u8,
    /// Its first label: the machine name artoo matches against VM names.
    machine: []const u8,
    hostname: []const u8,
    os: []const u8,
    client_version: []const u8,
    addresses: []const []const u8,
    tags: []const []const u8,
    /// Epoch seconds; null when connected or never seen.
    last_seen: ?i64,
    connected: bool,
    key_expiry_disabled: bool,
    expires: ?i64,
    authorized: bool,
    external: bool,
    advertised: []const []const u8,
    enabled: []const []const u8,

    pub fn hasTag(d: Device, tag: []const u8) bool {
        return contains(d.tags, tag);
    }
};

pub fn contains(list: []const []const u8, want: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, want)) return true;
    return false;
}

fn time(v: Value, key: []const u8) ?i64 {
    const s = ts.str(v, key) orelse return null;
    // Tailscale writes the zero time for "never".
    if (std.mem.startsWith(u8, s, "0001-")) return null;
    return parseTime(s);
}

pub fn device(a: Allocator, v: Value) !?Device {
    if (v != .object) return null;
    const id = ts.str(v, "nodeId") orelse ts.str(v, "id") orelse return null;
    const name = std.mem.trimEnd(u8, ts.str(v, "name") orelse "", ".");
    const hostname = ts.str(v, "hostname") orelse "";
    const machine = if (name.len > 0) name[0 .. std.mem.findScalar(u8, name, '.') orelse name.len] else hostname;
    return .{
        .id = id,
        .name = name,
        .machine = machine,
        .hostname = hostname,
        .os = ts.str(v, "os") orelse "",
        .client_version = ts.str(v, "clientVersion") orelse "",
        .addresses = try ts.strings(a, v, "addresses"),
        .tags = try ts.strings(a, v, "tags"),
        .last_seen = time(v, "lastSeen"),
        .connected = ts.boolean(v, "connectedToControl"),
        .key_expiry_disabled = ts.boolean(v, "keyExpiryDisabled"),
        .expires = time(v, "expires"),
        .authorized = ts.boolean(v, "authorized"),
        .external = ts.boolean(v, "isExternal"),
        .advertised = try ts.strings(a, v, "advertisedRoutes"),
        .enabled = try ts.strings(a, v, "enabledRoutes"),
    };
}

/// Every device, with all fields (routes are not in the default set).
pub fn devices(c: *ts.Client) ![]Device {
    const v = try c.get(try c.tailnetPath("/devices?fields=all", .{}));
    const list = ts.field(v, "devices");
    if (list != .array) return c.ctx.fail(error.Protocol, "Tailscale sent an unexpected device list", .{});
    var out: std.ArrayList(Device) = .empty;
    for (list.array.items) |it| if (try device(c.ctx.arena, it)) |d| try out.append(c.ctx.arena, d);
    std.mem.sort(Device, out.items, {}, struct {
        fn lt(_: void, x: Device, y: Device) bool {
            return std.mem.order(u8, x.name, y.name) == .lt;
        }
    }.lt);
    return out.items;
}

/// One device by ID; null when Tailscale answers 404.
pub fn getDevice(c: *ts.Client, id: []const u8) !?Device {
    const v = c.get(try std.fmt.allocPrint(c.ctx.arena, "/device/{s}?fields=all", .{id})) catch |err| switch (err) {
        error.NotFound => {
            c.ctx.diag = null;
            return null;
        },
        else => return err,
    };
    return (try device(c.ctx.arena, v)) orelse c.ctx.fail(error.Protocol, "Tailscale sent an unexpected device {s}", .{id});
}

pub const Routes = struct { advertised: []const []const u8, enabled: []const []const u8 };

pub fn routes(c: *ts.Client, id: []const u8) !Routes {
    const v = try c.get(try std.fmt.allocPrint(c.ctx.arena, "/device/{s}/routes", .{id}));
    return .{ .advertised = try ts.strings(c.ctx.arena, v, "advertisedRoutes"), .enabled = try ts.strings(c.ctx.arena, v, "enabledRoutes") };
}

/// `POST /device/{id}/name`.
pub fn renameDevice(c: *ts.Client, id: []const u8, name: []const u8) !void {
    _ = try c.send(.POST, try std.fmt.allocPrint(c.ctx.arena, "/device/{s}/name", .{id}), .{ .name = name });
}

/// `DELETE /device/{id}`.
pub fn deleteDevice(c: *ts.Client, id: []const u8) !void {
    _ = try c.json(.DELETE, try std.fmt.allocPrint(c.ctx.arena, "/device/{s}", .{id}), null);
}

/// `POST /device/{id}/routes`: the enabled (approved) list, replaced.
pub fn setRoutes(c: *ts.Client, id: []const u8, list: []const []const u8) !void {
    _ = try c.send(.POST, try std.fmt.allocPrint(c.ctx.arena, "/device/{s}/routes", .{id}), .{ .routes = list });
}

/// Exactly `want`, in any order.
pub fn sameSet(have: []const []const u8, want: []const []const u8) bool {
    if (have.len != want.len) return false;
    for (want) |w| if (!contains(have, w)) return false;
    return true;
}

pub const Match = union(enum) {
    device: Device,
    missing,
    ambiguous: []const Device,
};

/// `word` is a node ID, a MagicDNS name or a machine name (exact, then
/// case-insensitive).
pub fn find(a: Allocator, list: []const Device, word: []const u8) !Match {
    const w = std.mem.trimEnd(u8, word, ".");
    for (list) |d| if (std.mem.eql(u8, d.id, w)) return .{ .device = d };
    for ([_]bool{ false, true }) |loose| {
        var hits: std.ArrayList(Device) = .empty;
        for (list) |d| {
            const same = if (loose)
                std.ascii.eqlIgnoreCase(d.machine, w) or std.ascii.eqlIgnoreCase(d.name, w)
            else
                std.mem.eql(u8, d.machine, w) or std.mem.eql(u8, d.name, w);
            if (same) try hits.append(a, d);
        }
        if (hits.items.len == 1) return .{ .device = hits.items[0] };
        if (hits.items.len > 1) return .{ .ambiguous = hits.items };
    }
    return .missing;
}

/// What makes a device the lab's (SPEC §19 "Ownership"): one of artoo's
/// tags, or a machine name that is a Proxmox VM tagged `artoo`.
pub const Ownership = struct {
    /// Names of the VMs tagged `artoo` (templates excluded).
    artoo_vms: []const []const u8,
    /// The tags artoo's join keys carry.
    tags: []const []const u8,
    /// False when Proxmox could not be read: VM names are unknown.
    vms_known: bool = true,
    /// Names of the artoo VMs tagged `role-router`.
    routers: []const []const u8 = &.{},

    /// Why `d` is a lab device; null when it is not.
    pub fn reason(o: Ownership, d: Device) ?[]const u8 {
        if (d.external) return null;
        for (o.tags) |t| if (d.hasTag(t)) return "tag";
        for (o.artoo_vms) |n| if (std.ascii.eqlIgnoreCase(n, d.machine)) return "vm";
        return null;
    }

    /// True when `d` is the subnet router: tagged `tag:lab-router`, or
    /// named after an artoo VM tagged `role-router`.
    pub fn isRouter(o: Ownership, d: Device) bool {
        if (d.external) return false;
        if (d.hasTag(router_tag)) return true;
        for (o.routers) |n| if (std.ascii.eqlIgnoreCase(n, d.machine)) return true;
        return false;
    }
};

pub const KeyInfo = struct {
    id: []const u8,
    type: []const u8,
    description: []const u8,
    tags: []const []const u8,
    reusable: ?bool,
    ephemeral: ?bool,
    preauthorized: ?bool,
    created: ?i64,
    expires: ?i64,
    invalid: bool,
};

/// Key metadata only: the `key` member (a secret, sent once at creation)
/// is never read from a listing.
pub fn keyInfo(a: Allocator, v: Value) !?KeyInfo {
    const id = ts.str(v, "id") orelse return null;
    const create = ts.field(ts.field(ts.field(v, "capabilities"), "devices"), "create");
    const tags = if (create == .object) try ts.strings(a, create, "tags") else try ts.strings(a, v, "tags");
    return .{
        .id = id,
        .type = ts.str(v, "keyType") orelse "",
        .description = ts.str(v, "description") orelse "",
        .tags = tags,
        .reusable = optBool(create, "reusable"),
        .ephemeral = optBool(create, "ephemeral"),
        .preauthorized = optBool(create, "preauthorized"),
        .created = time(v, "created"),
        .expires = time(v, "expires"),
        .invalid = ts.boolean(v, "invalid"),
    };
}

fn optBool(v: Value, key: []const u8) ?bool {
    const x = ts.field(v, key);
    return if (x == .bool) x.bool else null;
}

pub fn keys(c: *ts.Client) ![]KeyInfo {
    const v = try c.get(try c.tailnetPath("/keys", .{}));
    const list = ts.field(v, "keys");
    if (list != .array) return c.ctx.fail(error.Protocol, "Tailscale sent an unexpected key list", .{});
    var out: std.ArrayList(KeyInfo) = .empty;
    for (list.array.items) |it| if (try keyInfo(c.ctx.arena, it)) |k| try out.append(c.ctx.arena, k);
    return out.items;
}

/// A key's metadata; null when deleted (404) or `invalid`.
pub fn getKey(c: *ts.Client, id: []const u8) !?KeyInfo {
    const v = c.get(try c.tailnetPath("/keys/{s}", .{id})) catch |err| switch (err) {
        error.NotFound => {
            c.ctx.diag = null;
            return null;
        },
        else => return err,
    };
    const k = (try keyInfo(c.ctx.arena, v)) orelse return null;
    return if (k.invalid) null else k;
}

/// A join key just created: its value is held in memory for this
/// invocation, handed to a guest over the agent's stdin, never shown.
pub const NewKey = struct { id: []const u8, key: []const u8, expires: ?i64 = null };

/// Join keys live ten minutes: none outlives a run (SPEC §19).
pub const join_key_seconds = 600;

/// `POST /tailnet/{t}/keys`: a single-use, preauthorized, non-ephemeral
/// auth key with `tags`. `description` must be at most 50 letters,
/// digits, spaces or hyphens (the OpenAPI document's rule).
pub fn createJoinKey(c: *ts.Client, tags: []const []const u8, description: []const u8) !NewKey {
    const v = try c.send(.POST, try c.tailnetPath("/keys", .{}), .{
        .keyType = "auth",
        .description = description,
        .expirySeconds = @as(i64, join_key_seconds),
        .capabilities = .{ .devices = .{ .create = .{
            .reusable = false,
            .ephemeral = false,
            .preauthorized = true,
            .tags = tags,
        } } },
    });
    const id = ts.str(v, "id") orelse "";
    const key = ts.str(v, "key") orelse "";
    if (id.len == 0 or key.len == 0 or !std.mem.startsWith(u8, key, "tskey-auth-"))
        return c.ctx.fail(error.OutcomeUnknown, "Tailscale answered the key creation without a key; check 'artoo ts keys ls' and delete a stray key in the console", .{});
    return .{ .id = id, .key = key, .expires = time(v, "expires") };
}

/// The ledger detail for a join key artoo made, the guest did not use
/// and the delete failed for: its ID and when it expires on its own
/// (the creation response's `expires`, else about ten minutes from now).
pub fn strayKey(ctx: *Context, id: []const u8, expires: ?i64, why: []const u8) ![]const u8 {
    const at = expires orelse ctx.ui.now + join_key_seconds;
    return std.fmt.allocPrint(ctx.arena, "{s} unused but not deleted ({s}); it expires {s}{f} — delete it sooner in the console (Settings → Keys)", .{
        try ui.text.sanitize(ctx.arena, id, .line),
        try ui.text.sanitize(ctx.arena, why, .line),
        if (expires == null) "about " else "",
        ui.values.absolute(at, &ctx.ui.zone),
    });
}

/// `DELETE /tailnet/{t}/keys/{id}`.
pub fn deleteKey(c: *ts.Client, id: []const u8) !void {
    _ = try c.json(.DELETE, try c.tailnetPath("/keys/{s}", .{id}), null);
}

/// A key description the API accepts: letters, digits, spaces, hyphens.
pub fn keyDescription(a: Allocator, words: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (words) |w| {
        if (out.items.len > 0) try out.append(a, ' ');
        for (w) |ch| try out.append(a, if (std.ascii.isAlphanumeric(ch) or ch == '-') ch else '-');
    }
    if (out.items.len > 50) out.items.len = 50;
    return out.items;
}

/// `text` with every occurrence of `secret` replaced: a key never
/// reaches an error message, even when a guest echoes it.
pub fn redact(a: Allocator, text: []const u8, secret: []const u8) ![]const u8 {
    if (secret.len == 0 or std.mem.find(u8, text, secret) == null) return text;
    return std.mem.replaceOwned(u8, a, text, secret, "[auth key]");
}

pub const Split = struct { domain: []const u8, nameservers: []const []const u8 };

pub const Dns = struct {
    nameservers: []const []const u8,
    magic_dns: bool,
    override_local: bool,
    search_paths: []const []const u8,
    split: []const Split,
};

/// `GET dns/configuration`: everything in one read.
pub fn dns(c: *ts.Client) !Dns {
    const a = c.ctx.arena;
    const v = try c.get(try c.tailnetPath("/dns/configuration", .{}));
    var ns: std.ArrayList([]const u8) = .empty;
    const list = ts.field(v, "nameservers");
    if (list == .array) for (list.array.items) |r| if (ts.str(r, "address")) |addr| try ns.append(a, addr);
    const prefs = ts.field(v, "preferences");
    return .{
        .nameservers = ns.items,
        .magic_dns = ts.boolean(prefs, "magicDNS"),
        .override_local = ts.boolean(prefs, "overrideLocalDNS"),
        .search_paths = try ts.strings(a, v, "searchPaths"),
        .split = try splitOf(a, ts.field(v, "splitDNS"), true),
    };
}

/// A split-DNS map (`dns/configuration` lists resolver objects,
/// `dns/split-dns` plain addresses), sorted by domain.
pub fn splitOf(a: Allocator, m: Value, resolver_objects: bool) ![]const Split {
    if (m != .object) return &.{};
    var out: std.ArrayList(Split) = .empty;
    var it = m.object.iterator();
    while (it.next()) |e| {
        var ns: std.ArrayList([]const u8) = .empty;
        if (e.value_ptr.* == .array) for (e.value_ptr.array.items) |r| {
            if (resolver_objects) {
                if (ts.str(r, "address")) |addr| try ns.append(a, addr);
            } else if (r == .string) try ns.append(a, r.string);
        };
        if (ns.items.len == 0) continue;
        try out.append(a, .{ .domain = e.key_ptr.*, .nameservers = ns.items });
    }
    std.mem.sort(Split, out.items, {}, struct {
        fn lt(_: void, x: Split, y: Split) bool {
            return std.mem.order(u8, x.domain, y.domain) == .lt;
        }
    }.lt);
    return out.items;
}

/// `GET dns/split-dns`.
pub fn splitDns(c: *ts.Client) ![]const Split {
    return splitOf(c.ctx.arena, try c.get(try c.tailnetPath("/dns/split-dns", .{})), false);
}

/// `PATCH dns/split-dns` with one domain (the others untouched).
pub fn patchSplit(c: *ts.Client, domain: []const u8, nameservers: []const []const u8) !void {
    var out: std.Io.Writer.Allocating = .init(c.ctx.arena);
    const w = &out.writer;
    w.writeByte('{') catch return error.OutOfMemory;
    std.json.Stringify.value(domain, .{}, w) catch return error.OutOfMemory;
    w.writeByte(':') catch return error.OutOfMemory;
    std.json.Stringify.value(nameservers, .{}, w) catch return error.OutOfMemory;
    w.writeByte('}') catch return error.OutOfMemory;
    _ = try c.json(.PATCH, try c.tailnetPath("/dns/split-dns", .{}), out.written());
}

pub const Policy = struct {
    text: []const u8,
    /// As received (quoted), for `If-Match`.
    etag: ?[]const u8,
};

/// The policy as stored: HuJSON, or JSON with `as_json`.
pub fn policy(c: *ts.Client, as_json: bool) !Policy {
    const r = try c.raw(.GET, try c.tailnetPath("/acl", .{}), null, .{ .accept = if (as_json) "application/json" else "application/hujson" });
    return .{ .text = r.body, .etag = r.etag };
}

/// HuJSON (JSON with `//` and `/* */` comments and trailing commas) as
/// standard JSON: comments become spaces, trailing commas go. Strings are
/// kept byte for byte. An unterminated string or comment is an error.
pub fn hujsonToJson(a: std.mem.Allocator, text: []const u8) ![]u8 {
    // Pass 1: comments → spaces (newlines kept).
    const s = try a.dupe(u8, text);
    var i: usize = 0;
    while (i < s.len) {
        switch (s[i]) {
            '"' => i = try skipString(s, i),
            '/' => {
                if (i + 1 >= s.len) return error.InvalidHuJson;
                if (s[i + 1] == '/') {
                    while (i < s.len and s[i] != '\n') : (i += 1) s[i] = ' ';
                } else if (s[i + 1] == '*') {
                    const end = std.mem.find(u8, s[i + 2 ..], "*/") orelse return error.InvalidHuJson;
                    const stop = i + 2 + end + 2;
                    while (i < stop) : (i += 1) {
                        if (s[i] != '\n') s[i] = ' ';
                    }
                } else return error.InvalidHuJson;
            },
            else => i += 1,
        }
    }
    // Pass 2: drop a comma whose next significant byte closes the value.
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(a, s.len);
    i = 0;
    while (i < s.len) {
        switch (s[i]) {
            '"' => {
                const end = try skipString(s, i);
                try out.appendSlice(a, s[i..end]);
                i = end;
            },
            ',' => {
                var j = i + 1;
                while (j < s.len and std.ascii.isWhitespace(s[j])) j += 1;
                if (j < s.len and (s[j] == '}' or s[j] == ']')) {
                    out.appendAssumeCapacity(' ');
                } else out.appendAssumeCapacity(',');
                i += 1;
            },
            else => {
                out.appendAssumeCapacity(s[i]);
                i += 1;
            },
        }
    }
    return out.items;
}

/// The index just past the string starting at `s[start] == '"'`.
fn skipString(s: []const u8, start: usize) !usize {
    var i = start + 1;
    while (i < s.len) : (i += 1) switch (s[i]) {
        '\\' => i += 1,
        '"' => return i + 1,
        '\n' => return error.InvalidHuJson,
        else => {},
    };
    return error.InvalidHuJson;
}

/// The first object key anywhere in `v` that is not plain ASCII, or null.
/// Tailscale folds policy keys like Go's JSON decoder, Unicode folds
/// included (`ſ`, U+017F, matches `s`), so a key artoo cannot compare
/// byte-wise is refused rather than guessed (SPEC §19).
pub fn nonAsciiKey(v: Value) ?[]const u8 {
    switch (v) {
        .object => |o| {
            var it = o.iterator();
            while (it.next()) |e| {
                for (e.key_ptr.*) |ch| if (ch >= 0x80 or ch < 0x20) return e.key_ptr.*;
                if (nonAsciiKey(e.value_ptr.*)) |k| return k;
            }
        },
        .array => |arr| for (arr.items) |x| if (nonAsciiKey(x)) |k| return k,
        else => {},
    }
    return null;
}

/// The `nodeAttrs` entries that grant Funnel (an `attr` naming `funnel`):
/// artoo never applies a policy that opens the lab to the internet
/// (SPEC §9.6, §19). Keys match ASCII-case-insensitively at every level,
/// as Tailscale reads them; every matching key is inspected.
pub fn funnelAttrs(a: std.mem.Allocator, policy_json: Value) ![]const []const u8 {
    var hits: std.ArrayList([]const u8) = .empty;
    if (policy_json != .object) return hits.items;
    var top = policy_json.object.iterator();
    while (top.next()) |te| {
        if (!std.ascii.eqlIgnoreCase(te.key_ptr.*, "nodeAttrs")) continue;
        const attrs = te.value_ptr.*;
        if (attrs != .array) continue;
        for (attrs.array.items) |item| {
            if (item != .object) continue;
            var fields = item.object.iterator();
            while (fields.next()) |fe| {
                if (!std.ascii.eqlIgnoreCase(fe.key_ptr.*, "attr")) continue;
                const list = fe.value_ptr.*;
                const words: []const Value = switch (list) {
                    .array => |arr| arr.items,
                    .string => &.{list},
                    else => &.{},
                };
                for (words) |w| if (w == .string and std.ascii.findIgnoreCase(w.string, "funnel") != null) try hits.append(a, w.string);
            }
        }
    }
    return hits.items;
}

/// Two policies say the same: equal text (outer whitespace aside), or
/// equal JSON once comments and trailing commas are gone.
pub fn samePolicy(a: std.mem.Allocator, x: []const u8, y: []const u8) !bool {
    if (std.mem.eql(u8, std.mem.trim(u8, x, " \t\r\n"), std.mem.trim(u8, y, " \t\r\n"))) return true;
    const jx = hujsonToJson(a, x) catch return false;
    const jy = hujsonToJson(a, y) catch return false;
    const vx = std.json.parseFromSliceLeaky(Value, a, jx, .{}) catch return false;
    const vy = std.json.parseFromSliceLeaky(Value, a, jy, .{}) catch return false;
    const sx = try std.json.Stringify.valueAlloc(a, vx, .{});
    const sy = try std.json.Stringify.valueAlloc(a, vy, .{});
    return std.mem.eql(u8, sx, sy);
}

pub fn setPolicy(c: *ts.Client, text: []const u8, etag: []const u8) !void {
    _ = try c.raw(.POST, try c.tailnetPath("/acl", .{}), text, .{ .accept = "application/hujson", .content_type = "application/hujson", .if_match = etag });
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "device: fields, machine name, never-seen zero time; ownership" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try std.json.parseFromSliceLeaky(Value, a,
        \\{"id":"1","nodeId":"nAbC","name":"naboo.example.ts.net","hostname":"naboo","os":"linux","addresses":["100.64.0.5"],"tags":[],"lastSeen":"0001-01-01T00:00:00Z","expires":"2027-01-01T00:00:00Z","advertisedRoutes":["192.168.1.0/24"]}
    , .{});
    const d = (try device(a, v)).?;
    try testing.expectEqualStrings("nAbC", d.id);
    try testing.expectEqualStrings("naboo", d.machine);
    try testing.expect(d.last_seen == null and d.expires != null);
    const own: Ownership = .{ .artoo_vms = &.{"naboo"}, .tags = &.{router_tag} };
    try testing.expectEqualStrings("vm", own.reason(d).?);
    const other: Ownership = .{ .artoo_vms = &.{"hoth"}, .tags = &.{router_tag} };
    try testing.expect(other.reason(d) == null);
    switch (try find(a, &.{d}, "NABOO")) {
        .device => |x| try testing.expectEqualStrings("nAbC", x.id),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(try find(a, &.{d}, "hoth") == .missing);
}

test "keyInfo: metadata only; a key value is never read" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try std.json.parseFromSliceLeaky(Value, a,
        \\{"id":"k1","key":"tskey-auth-SECRET","keyType":"auth","description":"artoo router dagobah","capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true,"tags":["tag:lab-router"]}}},"created":"2026-11-15T10:00:00Z","expires":"2026-11-15T10:10:00Z"}
    , .{});
    const k = (try keyInfo(a, v)).?;
    const text = try std.json.Stringify.valueAlloc(a, k, .{});
    try testing.expect(std.mem.find(u8, text, "SECRET") == null);
    try testing.expectEqualStrings("tag:lab-router", k.tags[0]);
    try testing.expectEqual(@as(?bool, true), k.preauthorized);
}

test "hujsonToJson: comments and trailing commas go, strings stay; funnel attributes are found" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text =
        \\// lab policy
        \\{
        \\  "grants": [{"src": ["autogroup:member"], "dst": ["tag:lab-guest"], "ip": ["443"],},], /* web */
        \\  "note": "a // not a comment, /* nor this */",
        \\  "nodeAttrs": [{"target": ["tag:lab-guest"], "attr": ["funnel"]}],
        \\}
    ;
    const json = try hujsonToJson(a, text);
    const v = try std.json.parseFromSliceLeaky(Value, a, json, .{});
    try testing.expectEqualStrings("a // not a comment, /* nor this */", ts.str(v, "note").?);
    try testing.expectEqual(@as(usize, 1), (try funnelAttrs(a, v)).len);
    const quiet = try std.json.parseFromSliceLeaky(Value, a, "{\"nodeAttrs\":[{\"target\":[\"*\"],\"attr\":[\"mullvad\"]}]}", .{});
    try testing.expectEqual(@as(usize, 0), (try funnelAttrs(a, quiet)).len);
    // Keys fold as Tailscale reads them.
    for ([_][]const u8{
        "{\"NodeAttrs\":[{\"target\":[\"*\"],\"Attr\":[\"funnel\"]}]}",
        "{\"nodeattrs\":[{\"target\":[\"*\"],\"ATTR\":\"Funnel\"}]}",
        "{\"nodeAttrs\":[{\"attr\":[\"mullvad\"],\"aTtr\":[\"funnel\"]}]}",
    }) |src| {
        const fv = try std.json.parseFromSliceLeaky(Value, a, src, .{});
        try testing.expectEqual(@as(usize, 1), (try funnelAttrs(a, fv)).len);
    }
    // `nodeAttr\u017Fs`-style keys cannot be compared byte-wise: refused.
    const folded = try std.json.parseFromSliceLeaky(Value, a, "{\"grants\":[],\"nodeAttr\u{17F}\":[{\"attr\":[\"funnel\"]}]}", .{});
    try testing.expect(nonAsciiKey(folded) != null);
    const escaped = try std.json.parseFromSliceLeaky(Value, a, "{\"x\":[{\"\\u212Aey\":1}]}", .{});
    try testing.expect(nonAsciiKey(escaped) != null);
    try testing.expect(nonAsciiKey(quiet) == null);
    try testing.expectError(error.InvalidHuJson, hujsonToJson(a, "{\"a\": \"open"));
    try testing.expectError(error.InvalidHuJson, hujsonToJson(a, "{} /* open"));
    try testing.expect(try samePolicy(a, "{\"a\": 1, // x\n}", "{\"a\":1}"));
    try testing.expect(!try samePolicy(a, "{\"a\": 1}", "{\"a\": 2}"));
}
