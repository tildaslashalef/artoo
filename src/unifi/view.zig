//! Rendering UniFi JSON for humans: redaction, dotted lookups, table cells
//! from catalog columns, and a generic detail view for `show`.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const catalog = @import("catalog.zig");
const ui = @import("../ui.zig");

pub const redacted = "<redacted>";

/// Keys whose values are secrets (Wi-Fi passphrases, RADIUS shared
/// secrets, VPN keys). Matched case-insensitively as substrings.
const secret_markers = [_][]const u8{ "passphrase", "password", "secret", "psk", "privatekey", "presharedkey" };

pub fn isSecretKey(key: []const u8) bool {
    for (secret_markers) |m| {
        if (std.ascii.findIgnoreCase(key, m) != null) return true;
    }
    return false;
}

/// Replace every secret-bearing value in place, recursively. Runs before
/// anything is rendered, JSON included (SPEC: no raw secret output mode).
pub fn redact(v: *Value) void {
    switch (v.*) {
        .object => |*o| {
            var it = o.iterator();
            while (it.next()) |e| {
                if (isSecretKey(e.key_ptr.*) and e.value_ptr.* != .null) {
                    e.value_ptr.* = .{ .string = redacted };
                } else redact(e.value_ptr);
            }
        },
        .array => |*a| for (a.items) |*x| redact(x),
        else => {},
    }
}

/// `a.b.c`; `x|y` tries alternatives in order.
pub fn lookup(v: Value, path: []const u8) ?Value {
    var alts = std.mem.splitScalar(u8, path, '|');
    while (alts.next()) |alt| {
        if (lookupOne(v, alt)) |found| {
            if (found != .null) return found;
        }
    }
    return null;
}

fn lookupOne(v: Value, path: []const u8) ?Value {
    var cur = v;
    var parts = std.mem.splitScalar(u8, path, '.');
    while (parts.next()) |p| {
        if (cur != .object) return null;
        cur = cur.object.get(p) orelse return null;
    }
    return cur;
}

pub fn string(v: Value, path: []const u8) ?[]const u8 {
    const x = lookup(v, path) orelse return null;
    return if (x == .string) x.string else null;
}

/// Scalars as text; null for objects/arrays.
pub fn scalar(arena: Allocator, v: Value) Allocator.Error!?[]const u8 {
    return switch (v) {
        .null => "--",
        .bool => |b| if (b) "yes" else "no",
        .integer => |n| try std.fmt.allocPrint(arena, "{d}", .{n}),
        .float => |f| try std.fmt.allocPrint(arena, "{d}", .{f}),
        .number_string, .string => |s| try ui.text.sanitize(arena, s, .line),
        else => null,
    };
}

/// `2026-09-13T14:42:08Z` (optional fraction) → epoch seconds.
pub fn parseTime(s: []const u8) ?i64 {
    if (s.len < 20 or s[4] != '-' or s[7] != '-' or s[10] != 'T' or s[13] != ':' or s[16] != ':') return null;
    if (s[s.len - 1] != 'Z') return null;
    const n = struct {
        fn f(x: []const u8) ?i64 {
            return std.fmt.parseInt(i64, x, 10) catch null;
        }
    }.f;
    const y = n(s[0..4]) orelse return null;
    const mo = n(s[5..7]) orelse return null;
    const d = n(s[8..10]) orelse return null;
    const h = n(s[11..13]) orelse return null;
    const mi = n(s[14..16]) orelse return null;
    const se = n(s[17..19]) orelse return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31) return null;
    // Days from civil (Howard Hinnant).
    const yy = if (mo <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mp = @mod(mo + 9, 12);
    const doy = @divFloor(153 * mp + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400 + h * 3600 + mi * 60 + se;
}

pub fn stateCell(arena: Allocator, u: *const ui.Ui, s: []const u8) Allocator.Error!ui.table.Cell {
    const lower = try std.ascii.allocLowerString(arena, s);
    const status: ui.style.Status = if (std.mem.eql(u8, s, "ONLINE") or std.mem.eql(u8, s, "UP"))
        .running
    else if (std.mem.eql(u8, s, "OFFLINE") or std.mem.eql(u8, s, "DOWN"))
        .stopped
    else
        .warning;
    const role: ui.style.Role = switch (status) {
        .running => .ok,
        .stopped => .fail,
        else => .warn,
    };
    return .{ .text = try std.fmt.allocPrint(arena, "{s} {s}", .{ status.glyph(u.glyphs), lower }), .role = role };
}

pub fn cell(arena: Allocator, u: *const ui.Ui, item: Value, col: catalog.Column) Allocator.Error!ui.table.Cell {
    const v = lookup(item, col.path) orelse return .{ .text = "--" };
    switch (col.fmt) {
        .text => return .{ .text = (try scalar(arena, v)) orelse "…", .role = if (col.id) .text else .text },
        .bool => return switch (v) {
            .bool => |b| .{ .text = if (b) "yes" else "no", .role = if (b) .text else .muted },
            else => .{ .text = (try scalar(arena, v)) orelse "…" },
        },
        .state => return if (v == .string) stateCell(arena, u, v.string) else .{ .text = "--" },
        .time => {
            const t = if (v == .string) parseTime(v.string) else null;
            if (t == null) return .{ .text = (try scalar(arena, v)) orelse "--" };
            return .{ .text = try ui.values.alloc(arena, ui.values.relative(u.now, t)) };
        },
        .list => {
            if (v != .array) return .{ .text = (try scalar(arena, v)) orelse "…" };
            var out: std.ArrayList(u8) = .empty;
            for (v.array.items, 0..) |x, i| {
                if (i > 0) try out.appendSlice(arena, ", ");
                try out.appendSlice(arena, (try scalar(arena, x)) orelse "…");
            }
            return .{ .text = out.items };
        },
        .count => return .{ .text = if (v == .array) try std.fmt.allocPrint(arena, "{d}", .{v.array.items.len}) else "--" },
    }
}

pub fn columnsFor(arena: Allocator, cols: []const catalog.Column) Allocator.Error![]const ui.table.Column {
    const out = try arena.alloc(ui.table.Column, cols.len);
    for (cols, out) |c, *o| o.* = .{
        .title = c.title,
        .alignment = if (c.right) .right else .left,
        .drop = c.drop,
        .truncate = !c.id,
    };
    return out;
}

pub fn rows(arena: Allocator, u: *const ui.Ui, items: []const Value, cols: []const catalog.Column) Allocator.Error![]const []const ui.table.Cell {
    const out = try arena.alloc([]const ui.table.Cell, items.len);
    for (items, out) |item, *row| {
        const cells = try arena.alloc(ui.table.Cell, cols.len);
        for (cols, cells) |c, *x| x.* = try cell(arena, u, item, c);
        row.* = cells;
    }
    return out;
}

/// Generic `show`: top-level scalars as one aligned block, then each
/// nested object as a titled block (flattened to dotted keys) and each
/// array of objects as a titled table.
pub fn detail(w: *Io.Writer, arena: Allocator, u: *const ui.Ui, title: []const u8, v: Value) !void {
    if (v != .object) {
        try w.print("{s}\n", .{(try scalar(arena, v)) orelse "--"});
        return;
    }
    var general: std.ArrayList(ui.blocks.Field) = .empty;
    var it = v.object.iterator();
    while (it.next()) |e| {
        const val = e.value_ptr.*;
        if (val == .object or (val == .array and hasObjects(val))) continue;
        try general.append(arena, try field(arena, u, e.key_ptr.*, val));
    }
    try ui.blocks.detail(w, u, &.{.{ .title = title, .fields = general.items }});

    it = v.object.iterator();
    while (it.next()) |e| {
        const val = e.value_ptr.*;
        if (val == .object) {
            var fields: std.ArrayList(ui.blocks.Field) = .empty;
            try flatten(arena, u, &fields, "", val);
            try w.writeByte('\n');
            if (fields.items.len == 0) {
                try ui.blocks.detail(w, u, &.{.{ .title = e.key_ptr.*, .fields = &.{.{ .key = "(empty)", .value = "" }} }});
            } else {
                try ui.blocks.detail(w, u, &.{.{ .title = e.key_ptr.*, .fields = fields.items }});
            }
        } else if (val == .array and hasObjects(val)) {
            try w.print("\n{s}{s}{s}\n", .{ u.palette.on(.title), e.key_ptr.*, u.palette.off(.title) });
            try objectTable(w, arena, u, val.array.items, 2);
        }
    }
}

fn hasObjects(v: Value) bool {
    for (v.array.items) |x| {
        if (x == .object) return true;
    }
    return false;
}

fn field(arena: Allocator, u: *const ui.Ui, key: []const u8, v: Value) !ui.blocks.Field {
    if (v == .string) if (parseTime(v.string)) |t| {
        return .{ .key = key, .value = try std.fmt.allocPrint(arena, "{f} ({f})", .{ ui.values.absolute(t, &u.zone), ui.values.relative(u.now, t) }) };
    };
    if (v == .array) {
        var out: std.ArrayList(u8) = .empty;
        for (v.array.items, 0..) |x, i| {
            if (i > 0) try out.appendSlice(arena, ", ");
            try out.appendSlice(arena, (try scalar(arena, x)) orelse "…");
        }
        return .{ .key = key, .value = if (v.array.items.len == 0) "(none)" else out.items, .role = if (v.array.items.len == 0) .muted else .text };
    }
    const text = (try scalar(arena, v)) orelse "…";
    return .{ .key = key, .value = text, .role = if (std.mem.eql(u8, text, redacted)) .muted else .text };
}

fn flatten(arena: Allocator, u: *const ui.Ui, out: *std.ArrayList(ui.blocks.Field), prefix: []const u8, v: Value) !void {
    var it = v.object.iterator();
    while (it.next()) |e| {
        const key = if (prefix.len == 0) e.key_ptr.* else try std.fmt.allocPrint(arena, "{s}.{s}", .{ prefix, e.key_ptr.* });
        const val = e.value_ptr.*;
        if (val == .object) {
            if (val.object.count() == 0) {
                try out.append(arena, .{ .key = key, .value = "(empty)", .role = .muted });
            } else try flatten(arena, u, out, key, val);
        } else if (val == .array and hasObjects(val)) {
            try out.append(arena, .{ .key = key, .value = try std.fmt.allocPrint(arena, "{d} item(s); see -o json", .{val.array.items.len}), .role = .muted });
        } else {
            try out.append(arena, try field(arena, u, key, val));
        }
    }
}

/// Table of objects: columns = scalar keys in first-seen order.
pub fn objectTable(w: *Io.Writer, arena: Allocator, u: *const ui.Ui, items: []const Value, indent: usize) !void {
    var keys: std.ArrayList([]const u8) = .empty;
    for (items) |x| {
        if (x != .object) continue;
        var it = x.object.iterator();
        while (it.next()) |e| {
            const val = e.value_ptr.*;
            if (val == .object or (val == .array and hasObjects(val))) continue;
            for (keys.items) |k| {
                if (std.mem.eql(u8, k, e.key_ptr.*)) break;
            } else try keys.append(arena, e.key_ptr.*);
        }
    }
    const cols = try arena.alloc(ui.table.Column, keys.items.len);
    for (keys.items, cols) |k, *c| c.* = .{ .title = try std.ascii.allocUpperString(arena, k), .truncate = false };
    const out_rows = try arena.alloc([]const ui.table.Cell, items.len);
    for (items, out_rows) |x, *row| {
        const cells = try arena.alloc(ui.table.Cell, keys.items.len);
        for (keys.items, cells) |k, *cl| {
            const val = if (x == .object) x.object.get(k) else null;
            cl.* = if (val) |vv| blk: {
                if (std.mem.eql(u8, k, "state") and vv == .string) break :blk try stateCell(arena, u, vv.string);
                break :blk (try field(arena, u, k, vv)).toCell();
            } else .{ .text = "--" };
        }
        row.* = cells;
    }
    var buf: Io.Writer.Allocating = .init(arena);
    var narrowed = u.*;
    if (narrowed.width) |wd| narrowed.width = if (wd > indent) wd - indent else wd;
    try ui.table.render(&buf.writer, &narrowed, arena, cols, out_rows);
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, buf.written(), "\n"), '\n');
    while (lines.next()) |line| {
        try w.splatByteAll(' ', indent);
        try w.print("{s}\n", .{line});
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn parse(arena: Allocator, s: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, arena, s, .{});
}

test "redact: nested secrets, JSON-wide" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    var v = try parse(a.allocator(), "{\"name\":\"LabNet\",\"securityConfiguration\":{\"type\":\"WPA2\",\"passphrase\":\"hunter2\"},\"radius\":[{\"sharedSecret\":\"s\",\"port\":1812}],\"x\":null}");
    redact(&v);
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try std.json.Stringify.value(v, .{}, &out.writer);
    try testing.expect(std.mem.find(u8, out.written(), "hunter2") == null);
    try testing.expectEqualStrings("{\"name\":\"LabNet\",\"securityConfiguration\":{\"type\":\"WPA2\",\"passphrase\":\"<redacted>\"},\"radius\":[{\"sharedSecret\":\"<redacted>\",\"port\":1812}],\"x\":null}", out.written());
}

test "lookup and alternatives" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const v = try parse(a.allocator(), "{\"type\":\"CNAME\",\"targetDomain\":\"x.home.arpa\",\"access\":{\"type\":\"DEFAULT\"},\"ipv4Address\":null}");
    try testing.expectEqualStrings("DEFAULT", string(v, "access.type").?);
    try testing.expectEqualStrings("x.home.arpa", string(v, "ipv4Address|targetDomain").?);
    try testing.expect(lookup(v, "nope.deeper") == null);
}

test "parseTime" {
    try testing.expectEqual(@as(?i64, 1757774528), parseTime("2025-09-13T14:42:08Z"));
    try testing.expectEqual(@as(?i64, 0), parseTime("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(?i64, 1791635525), parseTime("2026-10-10T12:32:05.123Z"));
    try testing.expect(parseTime("2026-10-10 12:32:05") == null);
}

test "rows from catalog columns" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const u: ui.Ui = .{ .now = 1791635525 };
    const items = (try parse(ar,
        \\[{"name":"Beacon","model":"U6+","state":"ONLINE","ipAddress":"192.168.1.20","firmwareVersion":"6.7.54","firmwareUpdatable":false,"features":["accessPoint"],"id":"c0de"},
        \\ {"name":"Old","model":"U6+","state":"OFFLINE","id":"x"}]
    )).array.items;
    const r = catalog.find("devices").?;
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try ui.table.render(&out.writer, &u, ar, try columnsFor(ar, r.columns), try rows(ar, &u, items, r.columns));
    try testing.expectEqualStrings(
        \\NAME    MODEL  STATE      IP            FIRMWARE  UPDATE  FEATURES     ID
        \\Beacon  U6+    ● online   192.168.1.20  6.7.54    no      accessPoint  c0de
        \\Old     U6+    ○ offline  --            --        --      --           x
        \\
    , out.written());
}

test "detail: general block, flattened objects, object arrays as tables" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const u: ui.Ui = .{ .now = 1791635525 };
    const v = try parse(ar,
        \\{"name":"Default","vlanId":1,"enabled":true,"metadata":{"origin":"SYSTEM_DEFINED"},
        \\ "ipv4Configuration":{"hostIpAddress":"192.168.1.1","dhcpConfiguration":{"mode":"SERVER","ipAddressRange":{"start":"192.168.1.6","stop":"192.168.1.254"},"dnsServerIpAddressesOverride":["1.1.1.1","1.0.0.1"]}},
        \\ "ports":[{"idx":1,"state":"UP","speedMbps":1000},{"idx":2,"state":"DOWN","speedMbps":10}]}
    );
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try detail(&out.writer, ar, &u, "Network", v);
    try testing.expectEqualStrings(
        \\Network
        \\  name     Default
        \\  vlanId   1
        \\  enabled  yes
        \\
        \\metadata
        \\  origin  SYSTEM_DEFINED
        \\
        \\ipv4Configuration
        \\  hostIpAddress                                   192.168.1.1
        \\  dhcpConfiguration.mode                          SERVER
        \\  dhcpConfiguration.ipAddressRange.start          192.168.1.6
        \\  dhcpConfiguration.ipAddressRange.stop           192.168.1.254
        \\  dhcpConfiguration.dnsServerIpAddressesOverride  1.1.1.1, 1.0.0.1
        \\
        \\ports
        \\  IDX  STATE   SPEEDMBPS
        \\  1    ● up    1000
        \\  2    ○ down  10
        \\
    , out.written());
}
