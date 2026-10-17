//! Request bodies for catalog writes (SPEC §10.2): load a `--from FILE`
//! document, check it against the operation's allowed/required fields,
//! and the pure helpers plans and verification need — flattening for
//! display (secrets hidden), diffs, and the "fresh read contains what we
//! sent" check. Deeper schema validation is left to the server.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const catalog = @import("catalog.zig");
const view = @import("view.zig");
const ui = @import("../ui.zig");

pub const hidden = "(hidden)";

pub const Problem = union(enum) {
    not_json,
    not_object,
    unknown_field: []const u8,
    missing_field: []const u8,
    /// A `<redacted>` placeholder copied from artoo output, at this path.
    redacted: []const u8,
    /// `action` is fixed by the verb.
    action_field,
};

pub const Prepared = struct {
    body: Value,
    /// Read-only fields that were removed (named in the plan).
    dropped: []const []const u8,
};

/// Parse `bytes`, unwrap an artoo `-o json` envelope (`data`), drop the
/// resource's read-only fields and validate the rest. On failure returns
/// `error.Invalid` with `problem` set.
pub fn prepare(arena: Allocator, bytes: []const u8, w: catalog.Write, read_only: []const []const u8, problem: *Problem) (Allocator.Error || error{Invalid})!Prepared {
    var v = std.json.parseFromSliceLeaky(Value, arena, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(problem, .not_json),
    };
    if (v == .object and v.object.get("schema_version") != null) {
        if (v.object.get("data")) |d| v = d;
    }
    if (v != .object) return fail(problem, .not_object);
    var obj = v.object;
    var dropped: std.ArrayList([]const u8) = .empty;
    for (read_only) |k| {
        if (obj.orderedRemove(k)) try dropped.append(arena, k);
    }
    var it = obj.iterator();
    while (it.next()) |e| {
        const k = e.key_ptr.*;
        if (w.action != null and std.mem.eql(u8, k, "action")) return fail(problem, .action_field);
        for (w.fields) |f| {
            if (std.mem.eql(u8, f, k)) break;
        } else return fail(problem, .{ .unknown_field = k });
    }
    if (w.kind != .patch) {
        for (w.required) |r| {
            if (obj.get(r) == null) return fail(problem, .{ .missing_field = r });
        }
    }
    if (try findRedacted(arena, .{ .object = obj }, "")) |path| return fail(problem, .{ .redacted = path });
    return .{ .body = .{ .object = obj }, .dropped = dropped.items };
}

fn fail(problem: *Problem, p: Problem) error{Invalid} {
    problem.* = p;
    return error.Invalid;
}

fn findRedacted(arena: Allocator, v: Value, prefix: []const u8) Allocator.Error!?[]const u8 {
    switch (v) {
        .string => |s| return if (std.mem.eql(u8, s, view.redacted)) (if (prefix.len > 0) prefix else "(body)") else null,
        .object => |o| {
            var it = o.iterator();
            while (it.next()) |e| {
                const key = if (prefix.len == 0) e.key_ptr.* else try std.fmt.allocPrint(arena, "{s}.{s}", .{ prefix, e.key_ptr.* });
                if (try findRedacted(arena, e.value_ptr.*, key)) |p| return p;
            }
        },
        .array => |a| for (a.items, 0..) |x, i| {
            if (try findRedacted(arena, x, try std.fmt.allocPrint(arena, "{s}[{d}]", .{ prefix, i }))) |p| return p;
        },
        else => {},
    }
    return null;
}

pub const Pair = struct {
    key: []const u8,
    /// Display text (sanitized; secrets replaced by `(hidden)`).
    text: []const u8,
    /// Canonical JSON of the raw value, for comparison only (never shown).
    raw: []const u8,
};

/// Leaves as dotted keys (`a.b`, `list[0].x`); arrays of scalars stay one
/// leaf. Secret-bearing keys show `(hidden)`.
pub fn flatten(arena: Allocator, v: Value) Allocator.Error![]const Pair {
    var out: std.ArrayList(Pair) = .empty;
    try walk(arena, &out, v, "", false);
    return out.items;
}

fn walk(arena: Allocator, out: *std.ArrayList(Pair), v: Value, prefix: []const u8, secret: bool) Allocator.Error!void {
    switch (v) {
        .object => |o| {
            if (o.count() == 0 and prefix.len > 0) return out.append(arena, try leaf(arena, prefix, v, secret));
            var it = o.iterator();
            while (it.next()) |e| {
                const key = if (prefix.len == 0) e.key_ptr.* else try std.fmt.allocPrint(arena, "{s}.{s}", .{ prefix, e.key_ptr.* });
                try walk(arena, out, e.value_ptr.*, key, secret or view.isSecretKey(e.key_ptr.*));
            }
        },
        .array => |a| {
            var objects = false;
            for (a.items) |x| objects = objects or x == .object or x == .array;
            if (!objects) return out.append(arena, try leaf(arena, prefix, v, secret));
            for (a.items, 0..) |x, i| try walk(arena, out, x, try std.fmt.allocPrint(arena, "{s}[{d}]", .{ prefix, i }), secret);
        },
        else => try out.append(arena, try leaf(arena, prefix, v, secret)),
    }
}

fn leaf(arena: Allocator, key: []const u8, v: Value, secret: bool) Allocator.Error!Pair {
    const raw = try std.json.Stringify.valueAlloc(arena, v, .{});
    const text: []const u8 = if (secret and v != .null)
        hidden
    else switch (v) {
        .string => |s| try ui.text.sanitize(arena, s, .line),
        else => try ui.text.sanitize(arena, raw, .line),
    };
    return .{ .key = key, .text = text, .raw = raw };
}

pub const Change = struct {
    key: []const u8,
    from: ?[]const u8,
    to: ?[]const u8,
};

/// Field-level changes from `current` to `next`. Keys under `ignore`
/// (top-level read-only fields) are skipped. A changed secret shows
/// `(hidden)` on both sides but is still reported.
pub fn diff(arena: Allocator, current: Value, next: Value, ignore: []const []const u8) Allocator.Error![]const Change {
    const a = try flatten(arena, current);
    const b = try flatten(arena, next);
    var out: std.ArrayList(Change) = .empty;
    for (b) |nb| {
        if (ignored(nb.key, ignore)) continue;
        const old = find(a, nb.key);
        if (old) |o| {
            if (!std.mem.eql(u8, o.raw, nb.raw)) try out.append(arena, .{ .key = nb.key, .from = o.text, .to = if (std.mem.eql(u8, nb.text, hidden)) "(hidden, changed)" else nb.text });
        } else try out.append(arena, .{ .key = nb.key, .from = null, .to = nb.text });
    }
    for (a) |oa| {
        if (ignored(oa.key, ignore)) continue;
        if (find(b, oa.key) == null) try out.append(arena, .{ .key = oa.key, .from = oa.text, .to = null });
    }
    return out.items;
}

fn find(pairs: []const Pair, key: []const u8) ?Pair {
    for (pairs) |p| {
        if (std.mem.eql(u8, p.key, key)) return p;
    }
    return null;
}

fn ignored(key: []const u8, ignore: []const []const u8) bool {
    for (ignore) |i| {
        if (std.mem.eql(u8, key, i)) return true;
        if (key.len > i.len and std.mem.startsWith(u8, key, i) and (key[i.len] == '.' or key[i.len] == '[')) return true;
    }
    return false;
}

/// Every value in `want` is present and equal in `have` (objects
/// recursively; arrays element-wise; numbers by value).
pub fn contains(want: Value, have: Value) bool {
    switch (want) {
        .object => |w| {
            if (have != .object) return false;
            var it = w.iterator();
            while (it.next()) |e| {
                const h = have.object.get(e.key_ptr.*) orelse return e.value_ptr.* == .null;
                if (!contains(e.value_ptr.*, h)) return false;
            }
            return true;
        },
        .array => |w| {
            if (have != .array or have.array.items.len != w.items.len) return false;
            for (w.items, have.array.items) |x, y| {
                if (!contains(x, y)) return false;
            }
            return true;
        },
        .integer, .float, .number_string => return number(want) != null and number(have) != null and number(want).? == number(have).?,
        .string => |s| return have == .string and std.mem.eql(u8, s, have.string),
        .bool => |b| return have == .bool and have.bool == b,
        .null => return have == .null,
    }
}

fn number(v: Value) ?f64 {
    return switch (v) {
        .integer => |n| @floatFromInt(n),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

/// Human text for a problem.
pub fn describe(arena: Allocator, p: Problem, w: catalog.Write) Allocator.Error![]const u8 {
    return switch (p) {
        .not_json => "the file is not valid JSON",
        .not_object => "the body must be a JSON object",
        .unknown_field => |f| std.fmt.allocPrint(arena, "field '{s}' is not accepted by {s} (allowed: {s})", .{ f, w.op.id, try std.mem.join(arena, ", ", w.fields) }),
        .missing_field => |f| std.fmt.allocPrint(arena, "required field '{s}' is missing ({s} needs: {s})", .{ f, w.op.id, try std.mem.join(arena, ", ", w.required) }),
        .redacted => |path| std.fmt.allocPrint(arena, "{s} holds '{s}' copied from artoo output; put the real value in the file", .{ path, view.redacted }),
        .action_field => "do not set 'action'; the verb fixes it",
    };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const net_set = catalog.find("networks").?.writes[1];

test "prepare: envelope unwrapped, read-only dropped, fields checked" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var p: Problem = .not_json;
    const ro = catalog.find("networks").?.read_only;
    const ok = try prepare(ar,
        \\{"schema_version":1,"target":"unifi","data":{"id":"N1","metadata":{"origin":"SYSTEM_DEFINED"},"default":true,
        \\ "name":"Default","enabled":true,"management":"GATEWAY","vlanId":1},"meta":{}}
    , net_set, ro, &p);
    try testing.expectEqual(@as(usize, 3), ok.dropped.len);
    try testing.expect(ok.body.object.get("id") == null);
    try testing.expectError(error.Invalid, prepare(ar, "{\"name\":\"x\",\"enabled\":true,\"management\":\"GATEWAY\",\"vlanId\":1,\"bogus\":1}", net_set, ro, &p));
    try testing.expectEqualStrings("bogus", p.unknown_field);
    try testing.expectError(error.Invalid, prepare(ar, "{\"name\":\"x\",\"enabled\":true}", net_set, ro, &p));
    try testing.expectEqualStrings("management", p.missing_field);
    try testing.expectError(error.Invalid, prepare(ar, "[1]", net_set, ro, &p));
    try testing.expect(p == .not_object);
}

test "prepare: redacted placeholders and fixed actions are refused" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var p: Problem = .not_json;
    const wifi_set = catalog.find("wifi").?.writes[1];
    const body =
        \\{"name":"LabNet","enabled":true,"type":"STANDARD","hideName":false,"clientIsolationEnabled":false,
        \\ "multicastToUnicastConversionEnabled":false,"uapsdEnabled":false,"channel2gLockedTo6":false,"dtimPeriod2gLockedTo3":false,
        \\ "securityConfiguration":{"type":"WPA2_WPA3_PERSONAL","passphrase":"<redacted>"}}
    ;
    try testing.expectError(error.Invalid, prepare(ar, body, wifi_set, &.{}, &p));
    try testing.expectEqualStrings("securityConfiguration.passphrase", p.redacted);
    const authorize = catalog.find("clients").?.writes[0];
    try testing.expectError(error.Invalid, prepare(ar, "{\"action\":\"X\"}", authorize, &.{}, &p));
    try testing.expect(p == .action_field);
}

test "diff: changes, additions, removals; secrets hidden but detected" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const cur = try std.json.parseFromSliceLeaky(Value, ar,
        \\{"id":"W1","name":"LabNet","enabled":true,"securityConfiguration":{"passphrase":"old","type":"WPA2"},"bands":[2.4,5],"extra":1}
    , .{});
    const next = try std.json.parseFromSliceLeaky(Value, ar,
        \\{"name":"LabNet","enabled":false,"securityConfiguration":{"passphrase":"new","type":"WPA2"},"bands":[5]}
    , .{});
    const ch = try diff(ar, cur, next, &.{"id"});
    try testing.expectEqual(@as(usize, 4), ch.len);
    try testing.expectEqualStrings("enabled", ch[0].key);
    try testing.expectEqualStrings("false", ch[0].to.?);
    try testing.expectEqualStrings("securityConfiguration.passphrase", ch[1].key);
    try testing.expectEqualStrings(hidden, ch[1].from.?);
    try testing.expectEqualStrings("(hidden, changed)", ch[1].to.?);
    try testing.expectEqualStrings("[5]", ch[2].to.?);
    try testing.expectEqualStrings("extra", ch[3].key);
    try testing.expect(ch[3].to == null);
    try testing.expectEqual(@as(usize, 0), (try diff(ar, cur, cur, &.{})).len);
}

test "contains: subset semantics for verification" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const have = try std.json.parseFromSliceLeaky(Value, ar,
        \\{"id":"X","name":"lab","vlanId":20,"ipv4Configuration":{"hostIpAddress":"10.0.20.1","prefixLength":24},"tags":["a","b"]}
    , .{});
    try testing.expect(contains(try std.json.parseFromSliceLeaky(Value, ar, "{\"name\":\"lab\",\"vlanId\":20.0,\"ipv4Configuration\":{\"prefixLength\":24}}", .{}), have));
    try testing.expect(!contains(try std.json.parseFromSliceLeaky(Value, ar, "{\"vlanId\":21}", .{}), have));
    try testing.expect(!contains(try std.json.parseFromSliceLeaky(Value, ar, "{\"tags\":[\"a\"]}", .{}), have));
    try testing.expect(contains(try std.json.parseFromSliceLeaky(Value, ar, "{\"absent\":null}", .{}), have));
}
