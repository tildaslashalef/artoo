//! Tailnet resources (SPEC §19, §17.4): devices and their routes, auth
//! key metadata, DNS, the policy — typed views of the API's JSON, and the
//! ownership rule that decides which devices artoo may change. Resource
//! functions never print.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const ts = @import("client.zig");
const parseTime = @import("../unifi/view.zig").parseTime;

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

    /// Why `d` is a lab device; null when it is not.
    pub fn reason(o: Ownership, d: Device) ?[]const u8 {
        if (d.external) return null;
        for (o.tags) |t| if (d.hasTag(t)) return "tag";
        for (o.artoo_vms) |n| if (std.ascii.eqlIgnoreCase(n, d.machine)) return "vm";
        return null;
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
