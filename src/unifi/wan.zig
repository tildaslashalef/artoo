//! WAN health and outages (SPEC §10.4, §17.1). The Integration API knows a
//! WAN only by ID and name; its state comes from undocumented sources the
//! same API key opens, all read-only:
//!
//! - classic `stat/health` (the `wan`/`wan2` subsystems: ISP, next hop,
//!   monitors) and `stat/device` (the gateway: `wanN` port objects,
//!   `ethernet_overrides` = which port carries which WAN, per-WAN status,
//!   uptime and downtime figures);
//! - v2 `wan/load-balancing/status` (name ↔ network group, active/backup);
//! - v2 `system-log/all` (events), a `POST` search that changes nothing
//!   and is never retried.
//!
//! A WAN is matched across sources by its name (Integration API ↔ load
//! balancing) and then by network group (`WAN`, `WAN2`, …). Nothing here
//! depends on a WAN's name beyond that run-time match.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const unifi = @import("client.zig");
const catalog = @import("catalog.zig");
const view = @import("view.zig");

// ---------------------------------------------------------------- model

pub const Role = enum { active, backup, unassigned };

pub const Status = enum {
    online,
    offline,
    /// No gateway port carries this WAN (UI: Port "Unassigned").
    no_port,
    unknown,

    pub fn word(s: Status) []const u8 {
        return switch (s) {
            .no_port => "no port",
            else => @tagName(s),
        };
    }
};

pub const Monitor = struct {
    target: []const u8,
    type: []const u8,
    /// Alerting monitors only (`good`, …).
    health: ?[]const u8 = null,
    /// Fraction 0..1.
    availability: ?f64 = null,
    latency_ms: ?f64 = null,

    /// A monitor is failing when it reports a health other than `good`,
    /// or no availability at all.
    pub fn failing(m: Monitor) bool {
        if (m.health) |h| if (!std.ascii.eqlIgnoreCase(h, "good")) return true;
        if (m.availability) |a| return a <= 0;
        return false;
    }
};

pub const Port = struct {
    index: ?i64 = null,
    ifname: ?[]const u8 = null,
    media: ?[]const u8 = null,
    up: ?bool = null,
    speed_mbps: ?i64 = null,
    full_duplex: ?bool = null,
    rx_errors: ?i64 = null,
    tx_errors: ?i64 = null,
    rx_dropped: ?i64 = null,
    tx_dropped: ?i64 = null,
};

pub const Isp = struct {
    name: ?[]const u8 = null,
    organization: ?[]const u8 = null,
    asn: ?i64 = null,
};

pub const NextHop = struct {
    address: []const u8,
    /// Seen in the port's neighbour table within `reachable_within` s.
    reachable: ?bool = null,
    /// `lastReachable` of its neighbour entry, seconds ago.
    last_reachable_seconds: ?i64 = null,
};

/// The gateway reports a neighbour's `lastReachable` in seconds; a next
/// hop seen within this window counts as reachable now.
pub const reachable_within = 60;

pub const Wan = struct {
    id: []const u8,
    name: []const u8,
    /// Network group: `WAN`, `WAN2`, …; null when no source tied it.
    group: ?[]const u8 = null,
    role: ?Role = null,
    status: Status = .unknown,
    address: ?[]const u8 = null,
    /// Inside 100.64.0.0/10: the ISP's carrier-grade NAT.
    shared_address: bool = false,
    netmask: ?[]const u8 = null,
    next_hop: ?NextHop = null,
    isp: ?Isp = null,
    /// null when unknown; for `no_port` always null.
    port: ?Port = null,
    /// Fraction 0..1 over the gateway's `time_period`.
    availability: ?f64 = null,
    latency_ms: ?f64 = null,
    /// The gateway's `time_period` for availability and monitors, as sent.
    time_period: ?i64 = null,
    monitors: []const Monitor = &.{},
    /// `last_downtime_stats`, seconds.
    last_downtime_seconds: ?i64 = null,
};

/// A source that did not answer.
pub const Problem = struct {
    source: []const u8,
    message: []const u8,
    /// 404 or an unexpected shape: not on this firmware.
    firmware: bool,
};

pub const Raw = struct {
    /// Integration API items (`{id, name}`).
    wans: []const Value,
    health: ?[]const Value = null,
    devices: ?[]const Value = null,
    load: ?Value = null,
};

// ---------------------------------------------------------------- reading

pub const health_path = "stat/health";
pub const device_path = "stat/device";
pub const load_path = "wan/load-balancing/status";
pub const syslog_path = "system-log/all";

/// The Integration API's WANs, then each state source; a source that
/// fails is recorded in `problems` and left null.
pub fn read(c: *unifi.Client, problems: *std.ArrayList(Problem), want: struct { health: bool = true }) !Raw {
    const wans = (try unifi.list(c, comptime catalog.find("wans").?, .{ .all = true })).items;
    var r: Raw = .{ .wans = wans };
    r.load = try attempt(c, problems, "load-balancing", loadStatus(c));
    r.devices = try attempt(c, problems, "device", deviceList(c));
    if (want.health) r.health = try attempt(c, problems, "health", c.classic(.GET, health_path, null));
    return r;
}

/// The load-balancing status, refused unless it has `wan_interfaces[]`.
fn loadStatus(c: *unifi.Client) !Value {
    const v = try c.v2(.GET, load_path, null);
    const arr = view.lookup(v, "wan_interfaces");
    if (arr == null or arr.? != .array) return c.ctx.fail(error.Protocol, "unexpected load-balancing status", .{});
    return v;
}

/// The device list, refused unless it has the gateway (a device with `wan1`).
fn deviceList(c: *unifi.Client) ![]Value {
    const ds = try c.classic(.GET, device_path, null);
    if (gatewayDevice(ds) == null) return c.ctx.fail(error.Protocol, "no gateway in stat/device", .{});
    return ds;
}

/// Unwrap a source; failures (except OOM and cancellation) become a
/// problem and null.
pub fn attempt(c: *unifi.Client, problems: *std.ArrayList(Problem), source: []const u8, result: anytype) !?@typeInfo(@TypeOf(result)).error_union.payload {
    return result catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            const firmware = err == error.NotFound or err == error.Protocol;
            const msg = if (firmware) "not available on this firmware" else c.ctx.diag orelse @errorName(err);
            c.ctx.diag = null;
            try problems.append(c.ctx.arena, .{ .source = source, .message = msg, .firmware = firmware });
            return null;
        },
    };
}

/// True when every state source failed (nothing beyond names to show).
pub fn nothingAnswered(r: Raw) bool {
    return r.health == null and r.devices == null and r.load == null;
}

// ---------------------------------------------------------------- building

/// `WAN` → 1, `WAN2` → 2, else null.
pub fn groupIndex(group: []const u8) ?u32 {
    if (std.mem.eql(u8, group, "WAN")) return 1;
    const rest = std.mem.cutPrefix(u8, group, "WAN") orelse return null;
    return std.fmt.parseInt(u32, rest, 10) catch null;
}

/// The gateway's object: the device that has a `wan1`.
pub fn gatewayDevice(devices: []const Value) ?Value {
    for (devices) |d| {
        if (d == .object and d.object.get("wan1") != null) return d;
    }
    return null;
}

/// The `stat/health` subsystem of a group: `wan` for WAN, `wan2` for WAN2.
fn healthSubsystem(arena: Allocator, health: []const Value, idx: u32) !?Value {
    const want = if (idx == 1) "wan" else try std.fmt.allocPrint(arena, "wan{d}", .{idx});
    for (health) |s| {
        if (std.mem.eql(u8, view.string(s, "subsystem") orelse "", want)) return s;
    }
    return null;
}

pub fn build(arena: Allocator, r: Raw) ![]Wan {
    const gw = if (r.devices) |ds| gatewayDevice(ds) else null;
    const lb: []const Value = if (r.load) |l| blk: {
        const arr = view.lookup(l, "wan_interfaces") orelse break :blk &.{};
        break :blk if (arr == .array) arr.array.items else &.{};
    } else &.{};
    var out: std.ArrayList(Wan) = .empty;
    for (r.wans) |item| {
        var w: Wan = .{
            .id = view.string(item, "id") orelse "",
            .name = view.string(item, "name") orelse "",
        };
        for (lb) |e| {
            if (!std.mem.eql(u8, view.string(e, "name") orelse "", w.name)) continue;
            w.group = view.string(e, "wan_networkgroup");
            const state = view.string(e, "state") orelse "";
            if (std.ascii.eqlIgnoreCase(state, "ACTIVE")) w.role = .active;
            if (std.ascii.eqlIgnoreCase(state, "BACKUP")) w.role = .backup;
            break;
        }
        if (w.group) |g| if (groupIndex(g)) |idx| {
            try fill(arena, &w, g, idx, gw, if (r.health) |h| try healthSubsystem(arena, h, idx) else null);
        };
        try out.append(arena, w);
    }
    return out.items;
}

fn fill(arena: Allocator, w: *Wan, group: []const u8, idx: u32, gw: ?Value, hs: ?Value) !void {
    const key = try std.fmt.allocPrint(arena, "wan{d}", .{idx});
    const port_obj: ?Value = if (gw) |d| blk: {
        const p = d.object.get(key) orelse break :blk null;
        break :blk if (p == .object) p else null;
    } else null;

    // Port assignment: the gateway's `ethernet_overrides` names the
    // interface carrying each group; a group missing there has no port.
    var assigned: ?bool = null;
    var ifname: ?[]const u8 = null;
    if (gw) |d| if (d.object.get("ethernet_overrides")) |ov| if (ov == .array) {
        assigned = false;
        for (ov.array.items) |o| {
            if (std.mem.eql(u8, view.string(o, "networkgroup") orelse "", group)) {
                assigned = true;
                ifname = view.string(o, "ifname");
                break;
            }
        }
    };
    if (assigned == false) {
        w.role = .unassigned;
        w.status = .no_port;
        return;
    }
    if (ifname == null) if (port_obj) |p| {
        ifname = view.string(p, "ifname");
    };
    if (gw) |d| w.port = portOf(d, port_obj, ifname);

    // Address and next hop.
    const lwi = if (gw) |d| view.lookup(d, try std.fmt.allocPrint(arena, "last_wan_interfaces.{s}", .{group})) else null;
    w.address = (if (port_obj) |p| view.string(p, "ip") else null) orelse
        (if (lwi) |x| view.string(x, "ip") else null) orelse
        (if (hs) |s| view.string(s, "wan_ip") else null);
    if (w.address) |a| w.shared_address = sharedAddress(a);
    w.netmask = (if (port_obj) |p| view.string(p, "netmask") else null) orelse (if (hs) |s| view.string(s, "netmask") else null);
    if (hs) |s| {
        if (view.lookup(s, "gateways")) |g| if (g == .array and g.array.items.len > 0 and g.array.items[0] == .string) {
            w.next_hop = nextHop(g.array.items[0].string, port_obj);
        };
        w.isp = .{
            .name = view.string(s, "isp_name"),
            .organization = view.string(s, "isp_organization"),
            .asn = int(s, "asn"),
        };
    }

    // Uptime statistics: the gateway's per group, else the health subsystem's.
    const us_path = try std.fmt.allocPrint(arena, "uptime_stats.{s}", .{group});
    const us = (if (gw) |d| view.lookup(d, us_path) else null) orelse (if (hs) |s| view.lookup(s, us_path) else null);
    if (us) |u| if (u == .object) {
        w.availability = if (num(u, "availability")) |x| x / 100 else null;
        w.latency_ms = num(u, "latency_average");
        w.time_period = int(u, "time_period");
        w.monitors = try monitors(arena, u);
    };
    if (gw) |d| w.last_downtime_seconds = int(d, try std.fmt.allocPrint(arena, "last_downtime_stats.{s}", .{group}));

    // Status: the gateway's per-WAN word, then the link, then health.
    const lws = if (gw) |d| view.string(d, try std.fmt.allocPrint(arena, "last_wan_status.{s}", .{group})) else null;
    w.status = if (lws) |s| statusWord(s) else .unknown;
    if (w.status == .unknown) if (w.port) |p| if (p.up == false) {
        w.status = .offline;
    };
    if (w.status == .unknown) if (lwi) |x| if (view.lookup(x, "alive")) |al| if (al == .bool) {
        w.status = if (al.bool) .online else .offline;
    };
    if (w.status == .unknown) if (hs) |s| {
        const st = view.string(s, "status") orelse "";
        if (std.mem.eql(u8, st, "ok")) w.status = .online;
        if (std.mem.eql(u8, st, "error")) w.status = .offline;
    };
}

fn statusWord(s: []const u8) Status {
    if (std.ascii.eqlIgnoreCase(s, "online")) return .online;
    if (std.ascii.eqlIgnoreCase(s, "offline") or std.ascii.eqlIgnoreCase(s, "down")) return .offline;
    return .unknown;
}

fn portOf(gw: Value, port_obj: ?Value, ifname: ?[]const u8) ?Port {
    // The `wanN` object when it is that interface (it has the counters),
    // else the port table's entry.
    const src: Value = blk: {
        if (port_obj) |p| {
            const pn = view.string(p, "ifname");
            if (ifname == null or pn == null or std.mem.eql(u8, pn.?, ifname.?)) break :blk p;
        }
        const name = ifname orelse return null;
        const pt = gw.object.get("port_table") orelse return null;
        if (pt != .array) return null;
        for (pt.array.items) |e| {
            if (std.mem.eql(u8, view.string(e, "ifname") orelse "", name)) break :blk e;
        }
        return .{ .ifname = name };
    };
    var p: Port = .{
        .index = int(src, "port_idx"),
        .ifname = view.string(src, "ifname") orelse ifname,
        .media = view.string(src, "media"),
        .up = boolean(src, "up"),
        .speed_mbps = int(src, "speed"),
        .full_duplex = boolean(src, "full_duplex"),
        .rx_errors = int(src, "rx_errors"),
        .tx_errors = int(src, "tx_errors"),
        .rx_dropped = int(src, "rx_dropped"),
        .tx_dropped = int(src, "tx_dropped"),
    };
    // The port table has the index when the `wanN` object does not.
    if (p.index == null) if (gw.object.get("port_table")) |pt| if (pt == .array) for (pt.array.items) |e| {
        if (std.mem.eql(u8, view.string(e, "ifname") orelse "", p.ifname orelse break)) {
            p.index = int(e, "port_idx");
            break;
        }
    };
    return p;
}

fn nextHop(addr: []const u8, port_obj: ?Value) NextHop {
    var h: NextHop = .{ .address = addr };
    const p = port_obj orelse return h;
    const mt = p.object.get("mac_table") orelse return h;
    if (mt != .array) return h;
    h.reachable = false;
    for (mt.array.items) |e| {
        if (!std.mem.eql(u8, view.string(e, "ip") orelse "", addr)) continue;
        h.last_reachable_seconds = int(e, "lastReachable");
        h.reachable = if (h.last_reachable_seconds) |s| s <= reachable_within else false;
        break;
    }
    return h;
}

fn monitors(arena: Allocator, u: Value) ![]const Monitor {
    var out: std.ArrayList(Monitor) = .empty;
    if (u != .object) return out.items;
    // Alerting monitors carry `health`; the others only figures.
    for ([_][]const u8{ "alerting_monitors", "monitors" }) |key| {
        const arr = u.object.get(key) orelse continue;
        if (arr != .array) continue;
        for (arr.array.items) |m| {
            try out.append(arena, .{
                .target = view.string(m, "target") orelse "",
                .type = view.string(m, "type") orelse "",
                .health = view.string(m, "health"),
                .availability = if (num(m, "availability")) |x| x / 100 else null,
                .latency_ms = num(m, "latency_average"),
            });
        }
    }
    return out.items;
}

/// Inside 100.64.0.0/10 (RFC 6598, carrier-grade NAT).
pub fn sharedAddress(addr: []const u8) bool {
    var it = std.mem.splitScalar(u8, addr, '.');
    const a = std.fmt.parseInt(u8, it.next() orelse return false, 10) catch return false;
    const b = std.fmt.parseInt(u8, it.next() orelse return false, 10) catch return false;
    return a == 100 and b >= 64 and b <= 127;
}

pub fn num(v: Value, path: []const u8) ?f64 {
    const x = view.lookup(v, path) orelse return null;
    return switch (x) {
        .integer => |n| @floatFromInt(n),
        .float => |f| f,
        .number_string, .string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

pub fn int(v: Value, path: []const u8) ?i64 {
    const x = view.lookup(v, path) orelse return null;
    return switch (x) {
        .integer => |n| n,
        .float => |f| if (std.math.isFinite(f) and @abs(f) < 1e15) @intFromFloat(f) else null,
        .number_string, .string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn boolean(v: Value, path: []const u8) ?bool {
    const x = view.lookup(v, path) orelse return null;
    return if (x == .bool) x.bool else null;
}

/// The WAN named (exact, then case-insensitive) or with this ID.
pub fn find(wans: []const Wan, word: []const u8) ?*const Wan {
    for (wans) |*w| if (std.mem.eql(u8, w.id, word) or std.mem.eql(u8, w.name, word)) return w;
    for (wans) |*w| if (std.ascii.eqlIgnoreCase(w.name, word)) return w;
    return null;
}

// ---------------------------------------------------------------- events

pub const Kind = enum {
    failed,
    restored,
    /// A short disconnection reported once it is over (with `DURATION`).
    temporary,
    /// Packet loss or high latency: lead-up evidence.
    degraded,
    link_down,
    link_up,
    /// Known or not, shown as it is.
    other,
};

pub const Event = struct {
    id: []const u8,
    /// Epoch milliseconds.
    timestamp: i64,
    event: []const u8,
    kind: Kind,
    severity: ?[]const u8 = null,
    /// Network group from `WAN_NAME`/`WAN_ID` (`WAN`, `WAN2`).
    group: ?[]const u8 = null,
    /// Title and message with their `{PLACEHOLDERS}` filled in.
    title: []const u8,
    message: []const u8,
    /// `DURATION` of a restore, seconds.
    duration_seconds: ?i64 = null,
};

pub fn classify(event: []const u8) Kind {
    if (std.mem.eql(u8, event, "NETWORK_WAN_FAILED")) return .failed;
    if (std.mem.eql(u8, event, "NETWORK_WAN_RESTORED")) return .restored;
    if (std.mem.eql(u8, event, "NETWORK_WAN_FAILED_TEMPORARY")) return .temporary;
    if (std.mem.find(u8, event, "PACKET_LOSS") != null or std.mem.find(u8, event, "LATENCY") != null) return .degraded;
    if (std.mem.find(u8, event, "LINK") != null) {
        if (std.mem.find(u8, event, "DOWN") != null) return .link_down;
        if (std.mem.find(u8, event, "UP") != null) return .link_up;
    }
    return .other;
}

/// `{NAME}` → `parameters.NAME.name` (else `.id`); unknown placeholders stay.
pub fn fillIn(arena: Allocator, raw: []const u8, params: ?Value) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '{') if (std.mem.findScalarPos(u8, raw, i, '}')) |end| {
            const key = raw[i + 1 .. end];
            const p = if (params) |ps| (if (ps == .object) ps.object.get(key) else null) else null;
            if (p) |v| if (view.string(v, "name") orelse view.string(v, "id")) |s| {
                try out.appendSlice(arena, s);
                i = end + 1;
                continue;
            };
        };
        try out.append(arena, raw[i]);
        i += 1;
    }
    return out.items;
}

pub fn parseEvent(arena: Allocator, v: Value) !?Event {
    const ts = int(v, "timestamp") orelse return null;
    const name = view.string(v, "event") orelse return null;
    const params = view.lookup(v, "parameters");
    const group = if (params) |p| view.string(p, "WAN_NAME.id") orelse view.string(p, "WAN_ID.id") else null;
    var e: Event = .{
        .id = view.string(v, "id") orelse "",
        .timestamp = ts,
        .event = name,
        .kind = classify(name),
        .severity = view.string(v, "severity"),
        .group = group,
        .title = try fillIn(arena, view.string(v, "title_raw") orelse name, params),
        .message = try fillIn(arena, view.string(v, "message_raw") orelse "", params),
    };
    if (params) |p| e.duration_seconds = int(p, "DURATION.id");
    return e;
}

pub const Since = enum {
    @"24h",
    @"7d",
    @"30d",

    pub fn seconds(s: Since) i64 {
        return switch (s) {
            .@"24h" => 86400,
            .@"7d" => 7 * 86400,
            .@"30d" => 30 * 86400,
        };
    }
};

pub const page_size = 100;
/// A bound on paging (100 pages of 100 events).
pub const max_pages = 100;

/// Every `INTERNET_AND_WAN` event in [from, to] (epoch ms), all pages,
/// oldest first, duplicates (by ID) dropped. Each page is one `POST`
/// that changes nothing; never retried.
pub fn events(c: *unifi.Client, from_ms: i64, to_ms: i64) ![]Event {
    const arena = c.ctx.arena;
    var out: std.ArrayList(Event) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var page: u32 = 0;
    while (page < max_pages) : (page += 1) {
        const body = try std.json.Stringify.valueAlloc(arena, .{
            .timestampFrom = from_ms,
            .timestampTo = to_ms,
            .pageSize = page_size,
            .pageNumber = page,
            .categories = .{"INTERNET_AND_WAN"},
        }, .{});
        const v = try c.v2(.POST, syslog_path, body);
        const data = view.lookup(v, "data");
        if (v != .object or (data != null and data.? != .array)) return c.ctx.fail(error.Protocol, "UniFi sent an unexpected system-log page", .{});
        const items = if (data) |d| d.array.items else &.{};
        for (items) |item| {
            const e = try parseEvent(arena, item) orelse continue;
            if (e.id.len > 0) {
                const gop = try seen.getOrPut(arena, e.id);
                if (gop.found_existing) continue;
            }
            try out.append(arena, e);
        }
        const pages = int(v, "total_page_count") orelse 1;
        if (items.len == 0 or page + 1 >= pages) break;
    }
    std.mem.sort(Event, out.items, {}, struct {
        fn lt(_: void, a: Event, b: Event) bool {
            return a.timestamp < b.timestamp;
        }
    }.lt);
    return out.items;
}

// ---------------------------------------------------------------- outages

pub const Cause = enum {
    link,
    isp_access,
    isp_network,
    dns,
    unknown,

    pub fn text(c: Cause) []const u8 {
        return switch (c) {
            .link => "link: cable, modem or ONT",
            .isp_access => "ISP access: modem or the ISP's first hop",
            .isp_network => "ISP network beyond the first hop",
            .dns => "DNS: resolvers unreachable, ICMP answers",
            .unknown => "unknown",
        };
    }
};

pub const Outage = struct {
    group: []const u8,
    /// The WAN's name, filled in by the caller.
    wan: ?[]const u8 = null,
    /// Epoch ms; derived from the restore's `DURATION` when the failure
    /// lies before the window.
    start: i64,
    /// null while ongoing.
    end: ?i64 = null,
    ongoing: bool = false,
    duration_seconds: ?i64 = null,
    /// Packet loss, latency and link events in the 10 minutes before.
    lead_up: []const Event = &.{},
    /// Link events during the outage.
    during: []const Event = &.{},
    cause: Cause = .unknown,
    degraded_before: bool = false,
    /// From a `NETWORK_WAN_FAILED_TEMPORARY` event: reported after the
    /// fact, with its length.
    temporary: bool = false,
};

pub const lead_up_ms = 10 * 60 * 1000;

pub const Folded = struct {
    outages: []Outage,
    /// Events that are neither an outage's edge nor its lead-up, as sent.
    others: []const Event,
};

/// Fold events (oldest first) into outages: a failure opens one, the next
/// restore of that group closes it.
pub fn fold(arena: Allocator, evs: []const Event) !Folded {
    var outages: std.ArrayList(Outage) = .empty;
    var others: std.ArrayList(Event) = .empty;
    var used = try arena.alloc(bool, evs.len);
    @memset(used, false);
    for (evs, 0..) |e, i| {
        const g = e.group orelse continue;
        switch (e.kind) {
            .failed => {
                if (openFor(outages.items, g) != null) continue; // a repeat while down
                used[i] = true;
                try outages.append(arena, .{ .group = g, .start = e.timestamp, .ongoing = true, .lead_up = try leadUp(arena, evs, used, i, e.timestamp, g) });
            },
            .temporary => {
                // Reported after the fact: down for DURATION, already back.
                const d = e.duration_seconds orelse continue;
                if (openFor(outages.items, g) != null) continue;
                used[i] = true;
                const start = e.timestamp - d * 1000;
                try outages.append(arena, .{ .group = g, .start = start, .end = e.timestamp, .duration_seconds = d, .temporary = true, .lead_up = try leadUp(arena, evs, used, i, start, g) });
            },
            .restored => {
                used[i] = true;
                if (openFor(outages.items, g)) |o| {
                    o.end = e.timestamp;
                    o.ongoing = false;
                    o.duration_seconds = e.duration_seconds orelse @divTrunc(e.timestamp - o.start, 1000);
                } else if (e.duration_seconds) |d| {
                    // Failed before the window: the restore says how long.
                    try outages.append(arena, .{ .group = g, .start = e.timestamp - d * 1000, .end = e.timestamp, .duration_seconds = d });
                } else used[i] = false;
            },
            .link_down, .link_up => if (openFor(outages.items, g)) |o| {
                used[i] = true;
                const d = try arena.alloc(Event, o.during.len + 1);
                @memcpy(d[0..o.during.len], o.during);
                d[o.during.len] = e;
                o.during = d;
            },
            else => {},
        }
    }
    for (evs, used) |e, u| if (!u) try others.append(arena, e);
    for (outages.items) |*o| {
        for (o.lead_up) |e| if (e.kind == .degraded) {
            o.degraded_before = true;
        };
        for (o.during) |e| if (e.kind == .link_down) {
            o.cause = .link;
        };
    }
    return .{ .outages = outages.items, .others = others.items };
}

/// Degradation and link events of group `g` in the 10 minutes before
/// `start`, among the events before index `i`; marks them used.
fn leadUp(arena: Allocator, evs: []const Event, used: []bool, i: usize, start: i64, g: []const u8) ![]const Event {
    var lead: std.ArrayList(Event) = .empty;
    var j = i;
    while (j > 0) {
        j -= 1;
        const p = evs[j];
        if (p.timestamp > start) continue;
        if (start - p.timestamp > lead_up_ms) break;
        if (used[j] or !sameGroup(p, g)) continue;
        if (p.kind == .degraded or p.kind == .link_down or p.kind == .link_up) {
            used[j] = true;
            try lead.insert(arena, 0, p);
        }
    }
    return lead.items;
}

fn sameGroup(e: Event, g: []const u8) bool {
    return std.mem.eql(u8, e.group orelse return false, g);
}

fn openFor(outages: []Outage, g: []const u8) ?*Outage {
    var i = outages.len;
    while (i > 0) {
        i -= 1;
        if (outages[i].ongoing and std.mem.eql(u8, outages[i].group, g)) return &outages[i];
    }
    return null;
}

/// The cause of an ongoing outage from the WAN's state now (SPEC §10.4).
/// A past outage keeps what its events showed (link, else unknown): no
/// next-hop or monitor state was recorded for it.
pub fn judgeOngoing(o: *Outage, w: ?*const Wan) void {
    if (!o.ongoing or o.cause == .link) return;
    const x = w orelse return;
    if (x.port) |p| if (p.up == false) {
        o.cause = .link;
        return;
    };
    const link_up = if (x.port) |p| p.up == true else false;
    if (!link_up) return;
    if (x.next_hop) |h| if (h.reachable == false) {
        o.cause = .isp_access;
        return;
    };
    if (x.monitors.len == 0) return;
    var failing: usize = 0;
    var failing_dns: usize = 0;
    var icmp_ok = false;
    for (x.monitors) |m| {
        if (m.failing()) {
            failing += 1;
            if (std.ascii.eqlIgnoreCase(m.type, "dns")) failing_dns += 1;
        } else if (std.ascii.eqlIgnoreCase(m.type, "icmp")) icmp_ok = true;
    }
    if (failing == x.monitors.len) {
        o.cause = .isp_network;
    } else if (failing > 0 and failing == failing_dns and icmp_ok) {
        o.cause = .dns;
    }
}

pub const Summary = struct {
    group: []const u8,
    wan: ?[]const u8 = null,
    outages: usize,
    downtime_seconds: i64,
    longest_seconds: i64,
    /// Fraction 0..1 of the window.
    availability: f64,
};

/// Per group, over [from_ms, now_ms]: count, total and longest downtime
/// (clipped to the window), availability.
pub fn summarize(arena: Allocator, outages: []const Outage, groups: []const []const u8, from_ms: i64, now_ms: i64) ![]Summary {
    const out = try arena.alloc(Summary, groups.len);
    const window: f64 = @floatFromInt(@max(now_ms - from_ms, 1));
    for (groups, out) |g, *s| {
        s.* = .{ .group = g, .outages = 0, .downtime_seconds = 0, .longest_seconds = 0, .availability = 1 };
        var down_ms: i64 = 0;
        for (outages) |o| {
            if (!std.mem.eql(u8, o.group, g)) continue;
            s.outages += 1;
            const end = o.end orelse now_ms;
            const len_ms = if (o.duration_seconds) |d| d * 1000 else end - o.start;
            const start = end - len_ms;
            const clipped = @max(0, @min(end, now_ms) - @max(start, from_ms));
            down_ms += clipped;
            s.longest_seconds = @max(s.longest_seconds, @divTrunc(len_ms, 1000));
        }
        s.downtime_seconds = @divTrunc(down_ms, 1000);
        s.availability = @max(0, 1 - @as(f64, @floatFromInt(down_ms)) / window);
    }
    return out;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "sharedAddress: 100.64.0.0/10 only" {
    try testing.expect(sharedAddress("100.64.10.5"));
    try testing.expect(sharedAddress("100.127.255.254"));
    try testing.expect(!sharedAddress("100.128.0.1"));
    try testing.expect(!sharedAddress("100.63.0.1"));
    try testing.expect(!sharedAddress("192.168.1.1"));
    try testing.expect(!sharedAddress("nope"));
}

test "groupIndex" {
    try testing.expectEqual(@as(?u32, 1), groupIndex("WAN"));
    try testing.expectEqual(@as(?u32, 2), groupIndex("WAN2"));
    try testing.expectEqual(@as(?u32, null), groupIndex("LAN"));
}

test "fillIn: placeholders from parameters, unknown ones kept" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const p = try std.json.parseFromSliceLeaky(Value, a.allocator(), "{\"WAN_ID\":{\"id\":\"WAN\",\"name\":\"WAN1\"},\"PORT\":{\"id\":\"5\"}}", .{});
    try testing.expectEqualStrings("WAN1 on port 5 {NOPE} {", try fillIn(a.allocator(), "{WAN_ID} on port {PORT} {NOPE} {", p));
}

test "classify" {
    try testing.expectEqual(Kind.failed, classify("NETWORK_WAN_FAILED"));
    try testing.expectEqual(Kind.restored, classify("NETWORK_WAN_RESTORED"));
    try testing.expectEqual(Kind.other, classify("NETWORK_WAN_FAILED_MULTIPLE_TIMES"));
    try testing.expectEqual(Kind.temporary, classify("NETWORK_WAN_FAILED_TEMPORARY"));
    try testing.expectEqual(Kind.degraded, classify("ISP_PACKET_LOSS"));
    try testing.expectEqual(Kind.degraded, classify("ISP_HIGH_LATENCY"));
    try testing.expectEqual(Kind.link_down, classify("WAN_LINK_DOWN"));
}

fn ev(ts: i64, kind: Kind, group: []const u8, dur: ?i64) Event {
    return .{ .id = "", .timestamp = ts, .event = @tagName(kind), .kind = kind, .group = group, .title = @tagName(kind), .message = "", .duration_seconds = dur };
}

test "fold: closed, back to back, ongoing, lead-up, before the window, unknown events" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const m = 60_000;
    const evs = [_]Event{
        ev(0, .restored, "WAN", 120), // failed before the window
        ev(10 * m, .degraded, "WAN", null),
        ev(15 * m, .failed, "WAN", null),
        ev(16 * m, .failed, "WAN", null), // repeat while down
        ev(17 * m, .restored, "WAN", 150),
        ev(18 * m, .other, "WAN", null),
        ev(19 * m, .failed, "WAN", null), // back to back
        ev(19 * m + 500, .link_down, "WAN", null),
        ev(20 * m, .restored, "WAN", null),
        ev(25 * m, .degraded, "WAN", null),
        ev(26 * m, .temporary, "WAN", 30),
        ev(30 * m, .failed, "WAN2", null),
    };
    const f = try fold(a.allocator(), &evs);
    try testing.expectEqual(@as(usize, 5), f.outages.len);
    try testing.expect(f.outages[3].temporary);
    try testing.expectEqual(@as(i64, 26 * m - 30_000), f.outages[3].start);
    try testing.expect(f.outages[3].degraded_before);
    try testing.expectEqual(@as(i64, -120_000), f.outages[0].start);
    try testing.expectEqual(@as(?i64, 150), f.outages[1].duration_seconds);
    try testing.expect(f.outages[1].degraded_before);
    try testing.expectEqual(@as(usize, 1), f.outages[1].lead_up.len);
    try testing.expectEqual(Cause.link, f.outages[2].cause);
    try testing.expectEqual(@as(?i64, 60), f.outages[2].duration_seconds);
    try testing.expect(f.outages[4].ongoing);
    try testing.expectEqualStrings("WAN2", f.outages[4].group);
    // The repeat failure and the unknown event are kept as they are.
    try testing.expectEqual(@as(usize, 2), f.others.len);

    const s = try summarize(a.allocator(), f.outages, &.{ "WAN", "WAN2" }, 0, 60 * m);
    try testing.expectEqual(@as(usize, 4), s[0].outages);
    // 0 of the first (before the window, clipped) + 150 + 60 + 30.
    try testing.expectEqual(@as(i64, 240), s[0].downtime_seconds);
    try testing.expectEqual(@as(i64, 150), s[0].longest_seconds);
    try testing.expectEqual(@as(i64, 30 * 60), s[1].downtime_seconds);
    try testing.expectApproxEqAbs(@as(f64, 0.5), s[1].availability, 1e-9);
}

test "judgeOngoing: every cause row" {
    const up: Port = .{ .up = true };
    const icmp_ok: Monitor = .{ .target = "a", .type = "icmp", .health = "good", .availability = 1 };
    const icmp_bad: Monitor = .{ .target = "a", .type = "icmp", .health = "bad", .availability = 0 };
    const dns_bad: Monitor = .{ .target = "b", .type = "dns", .health = "bad", .availability = 0 };
    const Case = struct { w: Wan, cause: Cause };
    const cases = [_]Case{
        .{ .w = .{ .id = "", .name = "", .port = .{ .up = false } }, .cause = .link },
        .{ .w = .{ .id = "", .name = "", .port = up, .next_hop = .{ .address = "100.64.0.1", .reachable = false } }, .cause = .isp_access },
        .{ .w = .{ .id = "", .name = "", .port = up, .next_hop = .{ .address = "100.64.0.1", .reachable = true }, .monitors = &.{ icmp_bad, dns_bad } }, .cause = .isp_network },
        .{ .w = .{ .id = "", .name = "", .port = up, .monitors = &.{ icmp_ok, dns_bad } }, .cause = .dns },
        .{ .w = .{ .id = "", .name = "", .port = up, .monitors = &.{icmp_ok} }, .cause = .unknown },
        .{ .w = .{ .id = "", .name = "" }, .cause = .unknown },
    };
    for (cases) |cs| {
        var o: Outage = .{ .group = "WAN", .start = 0, .ongoing = true };
        judgeOngoing(&o, &cs.w);
        try testing.expectEqual(cs.cause, o.cause);
    }
    // A past outage is never blamed on the first hop.
    var past: Outage = .{ .group = "WAN", .start = 0, .end = 1 };
    judgeOngoing(&past, &cases[1].w);
    try testing.expectEqual(Cause.unknown, past.cause);
}

test "build: unexpected shapes are skipped, never trusted" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const devs = try std.json.parseFromSliceLeaky(Value, ar,
        \\[{"name":"gw","wan1":{"up":true,"mac_table":5},"ethernet_overrides":[5,"x"],"uptime_stats":{"WAN":5},"port_table":7,"last_wan_interfaces":3}]
    , .{});
    const health = try std.json.parseFromSliceLeaky(Value, ar,
        \\[{"subsystem":"wan","gateways":[5],"uptime_stats":{"WAN":[1]}},7]
    , .{});
    const wans = try std.json.parseFromSliceLeaky(Value, ar, "[{\"id\":\"w1\",\"name\":\"Main\"},3]", .{});
    const load = try std.json.parseFromSliceLeaky(Value, ar, "{\"wan_interfaces\":[{\"name\":\"Main\",\"state\":\"ACTIVE\",\"wan_networkgroup\":\"WAN\"},4]}", .{});
    const ws = try build(ar, .{ .wans = wans.array.items, .devices = devs.array.items, .health = health.array.items, .load = load });
    try testing.expectEqual(@as(usize, 2), ws.len);
    try testing.expectEqual(@as(usize, 0), ws[0].monitors.len);
}

test "build: matched by name and group; port assignment; shared mark" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const p = struct {
        fn j(arena: Allocator, s: []const u8) !Value {
            return std.json.parseFromSliceLeaky(Value, arena, s, .{});
        }
    }.j;
    const wans = try p(ar, fixture_wans);
    const devs = try p(ar, fixture_device);
    const health = try p(ar, fixture_health);
    const load = try p(ar, fixture_load);
    const ws = try build(ar, .{ .wans = view.lookup(wans, "data").?.array.items, .devices = view.lookup(devs, "data").?.array.items, .health = view.lookup(health, "data").?.array.items, .load = load });
    try testing.expectEqual(@as(usize, 2), ws.len);
    const w1 = ws[0];
    try testing.expectEqualStrings("WAN", w1.group.?);
    try testing.expectEqual(Role.active, w1.role.?);
    try testing.expectEqual(Status.online, w1.status);
    try testing.expectEqualStrings("100.64.10.5", w1.address.?);
    try testing.expect(w1.shared_address);
    try testing.expectEqual(@as(?i64, 5), w1.port.?.index);
    try testing.expectEqual(@as(?i64, 1000), w1.port.?.speed_mbps);
    try testing.expect(w1.next_hop.?.reachable.?);
    try testing.expectEqualStrings("Example ISP", w1.isp.?.name.?);
    try testing.expectApproxEqAbs(@as(f64, 0.998), w1.availability.?, 1e-9);
    try testing.expectEqual(@as(usize, 3), w1.monitors.len);
    try testing.expectEqual(@as(?i64, 95), w1.last_downtime_seconds);
    const w2 = ws[1];
    try testing.expectEqualStrings("WAN2", w2.group.?);
    try testing.expectEqual(Role.unassigned, w2.role.?);
    try testing.expectEqual(Status.no_port, w2.status);
    try testing.expect(w2.port == null);
    try testing.expect(find(ws, "fiber-backup") == &ws[1]);
    try testing.expect(find(ws, "a1b2c3d4-0000-4000-8000-000000000001") == &ws[0]);
}

// Generic fixtures shaped like the verified documents (SPEC §17.1).
pub const fixture_wans =
    \\{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[{"id":"a1b2c3d4-0000-4000-8000-000000000001","name":"Fiber-Main"},{"id":"a1b2c3d4-0000-4000-8000-000000000002","name":"Fiber-Backup"}]}
;
pub const fixture_load =
    \\{"wan_interfaces":[{"name":"Fiber-Backup","state":"BACKUP","wan_networkgroup":"WAN2"},{"name":"Fiber-Main","state":"ACTIVE","wan_networkgroup":"WAN"}]}
;
pub const fixture_health =
    \\{"meta":{"rc":"ok"},"data":[{"subsystem":"wlan","status":"ok"},
    \\{"subsystem":"wan","status":"ok","wan_ip":"100.64.10.5","gateways":["100.64.0.1"],"netmask":"255.255.224.0","isp_name":"Example ISP","isp_organization":"Example Networks","asn":64500,"gw_name":"gw",
    \\"uptime_stats":{"WAN":{"availability":99.8,"latency_average":4,"time_period":150,"uptime":68,
    \\"alerting_monitors":[{"availability":100.0,"health":"good","id":"eth4-0","latency_average":4,"target":"monitor.example.com","type":"icmp"},{"availability":100.0,"health":"good","id":"eth4-1","latency_average":8,"target":"192.0.2.53","type":"dns"}],
    \\"monitors":[{"availability":99.5,"id":"eth4-3","latency_average":3,"target":"example.com","type":"icmp"}]}}},
    \\{"subsystem":"www","status":"ok","latency":5,"uptime":3600,"drops":1}]}
;
pub const fixture_device =
    \\{"meta":{"rc":"ok"},"data":[{"name":"ap","type":"uap"},{"name":"gw","type":"udm",
    \\"ethernet_overrides":[{"ifname":"eth4","networkgroup":"WAN"},{"ifname":"eth0","networkgroup":"LAN"}],
    \\"wan1":{"up":true,"ip":"100.64.10.5","netmask":"255.255.224.0","speed":1000,"full_duplex":true,"media":"2.5GE","port_idx":5,"ifname":"eth4","rx_errors":0,"tx_errors":0,"rx_dropped":2,"tx_dropped":0,"mac_table":[{"ip":"100.64.0.1","mac":"02:00:00:00:00:01","lastReachable":5}]},
    \\"wan2":null,
    \\"last_wan_status":{"WAN":"online"},"last_wan_interfaces":{"WAN":{"ip":"100.64.10.5","alive":true}},"last_downtime_stats":{"WAN":95},
    \\"port_table":[{"port_idx":1,"ifname":"eth0","media":"GE","up":true,"speed":1000,"full_duplex":true},{"port_idx":5,"ifname":"eth4","media":"2.5GE","up":true,"speed":1000,"full_duplex":true}]}]}
;
