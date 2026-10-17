//! Drift between the built-in catalog and an OpenAPI document — the
//! gateway's live one or a local export (`artoo gw spec`, SPEC §10.2).
//! Compares every operation (method + path + operationId), each write's
//! request-body fields (allowed and required, top level, union over
//! discriminator variants), and for every list the catalog generates the
//! "Filterable properties" table that drives `--filter` help.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const catalog = @import("catalog.zig");

pub const OpRef = struct {
    method: []const u8,
    path: []const u8,
    operation_id: []const u8,
};

pub const Renamed = struct {
    method: []const u8,
    path: []const u8,
    catalog: []const u8,
    document: []const u8,
};

pub const Change = enum {
    /// In the document only.
    added,
    /// In the catalog only.
    removed,
    /// Type or functions differ.
    changed,
};

pub const PropDrift = struct {
    /// CLI command, e.g. `devices ls`.
    list: []const u8,
    property: []const u8,
    change: Change,
    /// `TYPE fn fn …`, null when absent on that side.
    catalog: ?[]const u8,
    document: ?[]const u8,
};

pub const BodyDrift = struct {
    operation_id: []const u8,
    field: []const u8,
    /// `added`: the document has it, the catalog not; `removed`: reverse.
    change: Change,
    /// About the required list rather than the allowed fields.
    required: bool,
};

pub const Methods = struct {
    get: usize = 0,
    post: usize = 0,
    put: usize = 0,
    patch: usize = 0,
    delete: usize = 0,

    pub fn total(m: Methods) usize {
        return m.get + m.post + m.put + m.patch + m.delete;
    }
};

pub const Report = struct {
    /// `info.version` (the Network application version).
    version: ?[]const u8,
    paths: usize,
    operations: Methods,
    schemas: usize,
    /// Catalog operations (reads + writes) and how many match.
    catalog_ops: usize,
    ops_matched: usize,
    /// Operations in the document the catalog lacks.
    missing: []const OpRef,
    /// Catalog operations the document no longer has.
    stale: []const OpRef,
    renamed: []const Renamed,
    bodies_matched: usize,
    bodies: []const BodyDrift,
    lists_matched: usize,
    filterable: []const PropDrift,

    pub fn driftCount(r: Report) usize {
        return r.missing.len + r.stale.len + r.renamed.len + r.bodies.len + r.filterable.len;
    }
};

pub const Error = error{InvalidDocument} || Allocator.Error;

pub fn parse(arena: Allocator, bytes: []const u8) Error!Value {
    return std.json.parseFromSliceLeaky(Value, arena, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.InvalidDocument,
    };
}

/// One catalog operation, any method (lowercase, as in OpenAPI).
const CatOp = struct {
    method: []const u8,
    path: []const u8,
    id: []const u8,
    write: ?*const catalog.Write = null,
};

const catalog_ops: []const CatOp = blk: {
    @setEvalBranchQuota(20_000);
    var ops: []const CatOp = &.{};
    for (catalog.all_ops) |op| ops = ops ++ .{CatOp{ .method = "get", .path = op.path, .id = op.id }};
    for (&catalog.resources) |*r| {
        for (r.writes) |*w| {
            const m = switch (w.method) {
                .POST => "post",
                .PUT => "put",
                .PATCH => "patch",
                .DELETE => "delete",
            };
            // Several verbs can share one operation (authorize/unauthorize).
            const dup = for (ops) |o| {
                if (std.mem.eql(u8, o.method, m) and std.mem.eql(u8, o.path, w.op.path)) break true;
            } else false;
            if (!dup) ops = ops ++ .{CatOp{ .method = m, .path = w.op.path, .id = w.op.id, .write = w }};
        }
    }
    break :blk ops;
};

fn findCatOp(method: []const u8, path: []const u8) ?CatOp {
    for (catalog_ops) |op| {
        if (std.mem.eql(u8, op.method, method) and std.mem.eql(u8, op.path, path)) return op;
    }
    return null;
}

const method_names = @typeInfo(Methods).@"struct".field_names;

pub fn compare(arena: Allocator, doc: Value) Error!Report {
    if (doc != .object) return error.InvalidDocument;
    const paths_v = doc.object.get("paths") orelse return error.InvalidDocument;
    if (paths_v != .object) return error.InvalidDocument;
    const paths = paths_v.object;
    const comps = doc.object.get("components");
    const schemas_v = if (comps != null and comps.? == .object) comps.?.object.get("schemas") else null;
    const schemas: ?std.json.ObjectMap = if (schemas_v != null and schemas_v.? == .object) schemas_v.?.object else null;

    var methods: Methods = .{};
    var missing: std.ArrayList(OpRef) = .empty;
    var renamed: std.ArrayList(Renamed) = .empty;
    var bodies: std.ArrayList(BodyDrift) = .empty;
    var matched: usize = 0;
    var bodies_matched: usize = 0;
    var it = paths.iterator();
    while (it.next()) |e| {
        if (e.value_ptr.* != .object) return error.InvalidDocument;
        const ops = e.value_ptr.object;
        inline for (method_names) |m| {
            if (ops.get(m)) |op_v| {
                @field(methods, m) += 1;
                const id = operationId(op_v);
                const upper = comptime upperName(m);
                if (findCatOp(m, e.key_ptr.*)) |cat| {
                    if (std.mem.eql(u8, cat.id, id)) {
                        matched += 1;
                    } else try renamed.append(arena, .{ .method = upper, .path = e.key_ptr.*, .catalog = cat.id, .document = id });
                    if (cat.write) |w| {
                        if (try compareBody(arena, &bodies, schemas, op_v, w)) bodies_matched += 1;
                    }
                } else try missing.append(arena, .{ .method = upper, .path = e.key_ptr.*, .operation_id = id });
            }
        }
    }

    var stale: std.ArrayList(OpRef) = .empty;
    for (catalog_ops) |op| {
        const p = paths.get(op.path);
        if (p == null or p.? != .object or p.?.object.get(op.method) == null) {
            try stale.append(arena, .{ .method = try std.ascii.allocUpperString(arena, op.method), .path = op.path, .operation_id = op.id });
        }
    }

    var drift: std.ArrayList(PropDrift) = .empty;
    var lists_matched: usize = 0;
    for (catalog.resources) |r| {
        const label = try std.fmt.allocPrint(arena, "{s} ls", .{r.name});
        if (try compareList(arena, &drift, paths, label, r.list.path, if (r.filter) r.filterable else &.{})) lists_matched += 1;
        for (r.extras) |x| {
            if (x.shape != .page) continue;
            const xl = try std.fmt.allocPrint(arena, "{s} {s}", .{ r.name, x.verb });
            if (try compareList(arena, &drift, paths, xl, x.op.path, x.filterable)) lists_matched += 1;
        }
    }

    const info = doc.object.get("info");
    const version = if (info != null and info.? == .object) info.?.object.get("version") else null;
    return .{
        .version = if (version != null and version.? == .string) version.?.string else null,
        .paths = paths.count(),
        .operations = methods,
        .schemas = if (schemas) |s| s.count() else 0,
        .catalog_ops = catalog_ops.len,
        .ops_matched = matched,
        .missing = missing.items,
        .stale = stale.items,
        .renamed = renamed.items,
        .bodies_matched = bodies_matched,
        .bodies = bodies.items,
        .lists_matched = lists_matched,
        .filterable = drift.items,
    };
}

fn upperName(comptime m: []const u8) []const u8 {
    comptime {
        var out: [m.len]u8 = undefined;
        for (m, 0..) |ch, i| out[i] = std.ascii.toUpper(ch);
        const final = out;
        return &final;
    }
}

// ---------------------------------------------------------------- request bodies

const Fields = struct {
    allowed: std.StringArrayHashMapUnmanaged(void) = .empty,
    required: std.StringArrayHashMapUnmanaged(void) = .empty,
};

fn resolveRef(schemas: ?std.json.ObjectMap, v: Value) ?Value {
    var cur = v;
    var hops: usize = 0;
    while (cur == .object) : (hops += 1) {
        if (hops > 32) return null;
        const ref = cur.object.get("$ref") orelse return cur;
        if (ref != .string) return null;
        const name = ref.string[(std.mem.findScalarLast(u8, ref.string, '/') orelse return null) + 1 ..];
        cur = (schemas orelse return null).get(name) orelse return null;
    }
    return null;
}

/// Top-level properties of `schema`: own, `allOf` (incl. required),
/// `oneOf`/`anyOf` and discriminator variants (properties only). Each
/// schema is visited once, so variant → base cycles terminate.
fn collect(arena: Allocator, schemas: ?std.json.ObjectMap, schema: Value, out: *Fields, seen: *std.AutoHashMapUnmanaged(usize, void), with_required: bool) Allocator.Error!void {
    const s = resolveRef(schemas, schema) orelse return;
    if (s != .object) return;
    const key = @intFromPtr(s.object.keys().ptr);
    if ((try seen.getOrPut(arena, key)).found_existing) return;
    if (s.object.get("properties")) |p| if (p == .object) {
        for (p.object.keys()) |k| try out.allowed.put(arena, k, {});
    };
    if (with_required) if (s.object.get("required")) |r| if (r == .array) {
        for (r.array.items) |x| if (x == .string) try out.required.put(arena, x.string, {});
    };
    if (s.object.get("allOf")) |all| if (all == .array) {
        for (all.array.items) |part| try collect(arena, schemas, part, out, seen, with_required);
    };
    inline for (.{ "oneOf", "anyOf" }) |k| {
        if (s.object.get(k)) |any| if (any == .array) {
            for (any.array.items) |part| try collect(arena, schemas, part, out, seen, false);
        };
    }
    if (s.object.get("discriminator")) |d| if (d == .object) if (d.object.get("mapping")) |m| if (m == .object) {
        for (m.object.values()) |ref| try collect(arena, schemas, .{ .object = refObject(arena, ref) catch return }, out, seen, false);
    };
}

fn refObject(arena: Allocator, ref: Value) Allocator.Error!std.json.ObjectMap {
    var o: std.json.ObjectMap = .empty;
    try o.put(arena, "$ref", ref);
    return o;
}

fn requestSchema(op: Value) ?Value {
    if (op != .object) return null;
    const rb = op.object.get("requestBody") orelse return null;
    if (rb != .object) return null;
    const content = rb.object.get("content") orelse return null;
    if (content != .object) return null;
    const json = content.object.get("application/json") orelse return null;
    if (json != .object) return null;
    return json.object.get("schema");
}

/// True when the write's catalog fields equal the document's.
fn compareBody(arena: Allocator, out: *std.ArrayList(BodyDrift), schemas: ?std.json.ObjectMap, op: Value, w: *const catalog.Write) Allocator.Error!bool {
    var doc: Fields = .{};
    if (requestSchema(op)) |schema| {
        var seen: std.AutoHashMapUnmanaged(usize, void) = .empty;
        try collect(arena, schemas, schema, &doc, &seen, true);
    }
    if (w.action != null) {
        _ = doc.allowed.orderedRemove("action");
        _ = doc.required.orderedRemove("action");
    }
    const before = out.items.len;
    try diffNames(arena, out, w.op.id, doc.allowed.keys(), w.fields, false);
    try diffNames(arena, out, w.op.id, doc.required.keys(), w.required, true);
    return out.items.len == before;
}

fn diffNames(arena: Allocator, out: *std.ArrayList(BodyDrift), id: []const u8, doc: []const []const u8, cat: []const []const u8, required: bool) Allocator.Error!void {
    for (doc) |d| {
        if (!contains(cat, d)) try out.append(arena, .{ .operation_id = id, .field = d, .change = .added, .required = required });
    }
    for (cat) |c| {
        if (!contains(doc, c)) try out.append(arena, .{ .operation_id = id, .field = c, .change = .removed, .required = required });
    }
}

fn contains(list: []const []const u8, s: []const u8) bool {
    for (list) |x| {
        if (std.mem.eql(u8, x, s)) return true;
    }
    return false;
}

fn operationId(op: Value) []const u8 {
    if (op != .object) return "";
    const id = op.object.get("operationId") orelse return "";
    return if (id == .string) id.string else "";
}

const Prop = struct { name: []const u8, type: []const u8, functions: []const u8 };

/// Rows of the markdown table `|`name`|`TYPE`|`fn` `fn`|` in a list
/// operation's description; functions normalized to `fn fn`.
pub fn documentProps(arena: Allocator, op: Value) Allocator.Error![]const Prop {
    if (op != .object) return &.{};
    const d = op.object.get("description") orelse return &.{};
    if (d != .string) return &.{};
    var out: std.ArrayList(Prop) = .empty;
    var lines = std.mem.splitScalar(u8, d.string, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r");
        if (!std.mem.startsWith(u8, line, "|`")) continue;
        var cells = std.mem.splitScalar(u8, line[1..], '|');
        const name = std.mem.trim(u8, cells.next() orelse continue, "` ");
        const typ = std.mem.trim(u8, cells.next() orelse continue, "` ");
        const fns_raw = cells.next() orelse continue;
        var fns: std.ArrayList(u8) = .empty;
        var words = std.mem.tokenizeAny(u8, fns_raw, "` ");
        while (words.next()) |w| {
            if (fns.items.len > 0) try fns.append(arena, ' ');
            try fns.appendSlice(arena, w);
        }
        try out.append(arena, .{ .name = name, .type = typ, .functions = fns.items });
    }
    return out.items;
}

/// Same functions, any order.
fn sameFunctions(a: []const u8, b: []const u8) bool {
    var na: usize = 0;
    var it = std.mem.tokenizeScalar(u8, a, ' ');
    while (it.next()) |w| {
        na += 1;
        var found = false;
        var jt = std.mem.tokenizeScalar(u8, b, ' ');
        while (jt.next()) |x| found = found or std.mem.eql(u8, w, x);
        if (!found) return false;
    }
    var nb: usize = 0;
    var kt = std.mem.tokenizeScalar(u8, b, ' ');
    while (kt.next()) |_| nb += 1;
    return na == nb;
}

/// True when the list's filterable table matches (or the path is absent:
/// that is reported as a stale operation instead).
fn compareList(arena: Allocator, out: *std.ArrayList(PropDrift), paths: std.json.ObjectMap, label: []const u8, path: []const u8, cat: []const catalog.Filterable) Allocator.Error!bool {
    const p = paths.get(path) orelse return false;
    if (p != .object) return false;
    const get = p.object.get("get") orelse return false;
    const doc = try documentProps(arena, get);
    const before = out.items.len;
    for (doc) |d| {
        const c = for (cat) |c| {
            if (std.mem.eql(u8, c.name, d.name)) break c;
        } else null;
        const dtext = try std.fmt.allocPrint(arena, "{s} {s}", .{ d.type, d.functions });
        if (c) |cv| {
            if (!std.mem.eql(u8, cv.type, d.type) or !sameFunctions(cv.functions, d.functions)) {
                try out.append(arena, .{ .list = label, .property = d.name, .change = .changed, .catalog = try std.fmt.allocPrint(arena, "{s} {s}", .{ cv.type, cv.functions }), .document = dtext });
            }
        } else try out.append(arena, .{ .list = label, .property = d.name, .change = .added, .catalog = null, .document = dtext });
    }
    for (cat) |c| {
        for (doc) |d| {
            if (std.mem.eql(u8, c.name, d.name)) break;
        } else try out.append(arena, .{ .list = label, .property = c.name, .change = .removed, .catalog = try std.fmt.allocPrint(arena, "{s} {s}", .{ c.type, c.functions }), .document = null });
    }
    return out.items.len == before;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

/// A document equal to the catalog: every GET with its operationId and
/// filterable table, plus one write operation.
fn catalogDocument(arena: Allocator) !Value {
    var paths: std.json.ObjectMap = .empty;
    for (catalog.all_ops) |op| {
        var get: std.json.ObjectMap = .empty;
        try get.put(arena, "operationId", .{ .string = op.id });
        try get.put(arena, "description", .{ .string = try table(arena, propsFor(op.path)) });
        var item: std.json.ObjectMap = .empty;
        try item.put(arena, "get", .{ .object = get });
        try paths.put(arena, op.path, .{ .object = item });
    }
    // Writes: one schema per operation, named by its operationId.
    var schemas: std.json.ObjectMap = .empty;
    for (catalog_ops) |op| {
        const w = op.write orelse continue;
        const item = try paths.getOrPut(arena, op.path);
        if (!item.found_existing) item.value_ptr.* = .{ .object = .empty };
        var o: std.json.ObjectMap = .empty;
        try o.put(arena, "operationId", .{ .string = op.id });
        if (w.fields.len > 0 or w.action != null) {
            var props: std.json.ObjectMap = .empty;
            for (w.fields) |f| try props.put(arena, f, .{ .object = .empty });
            var req: std.json.Array = .init(arena);
            for (w.required) |f| try req.append(.{ .string = f });
            if (w.action != null) {
                try props.put(arena, "action", .{ .object = .empty });
                try req.append(.{ .string = "action" });
            }
            var schema: std.json.ObjectMap = .empty;
            try schema.put(arena, "properties", .{ .object = props });
            try schema.put(arena, "required", .{ .array = req });
            try schemas.put(arena, op.id, .{ .object = schema });
            const ref = try std.fmt.allocPrint(arena, "#/components/schemas/{s}", .{op.id});
            const body = try std.json.parseFromSliceLeaky(Value, arena, try std.fmt.allocPrint(arena, "{{\"content\":{{\"application/json\":{{\"schema\":{{\"$ref\":\"{s}\"}}}}}}}}", .{ref}), .{});
            try o.put(arena, "requestBody", body);
        }
        try item.value_ptr.object.put(arena, op.method, .{ .object = o });
    }
    var comps: std.json.ObjectMap = .empty;
    try comps.put(arena, "schemas", .{ .object = schemas });
    var info: std.json.ObjectMap = .empty;
    try info.put(arena, "version", .{ .string = "10.6.106" });
    var doc: std.json.ObjectMap = .empty;
    try doc.put(arena, "info", .{ .object = info });
    try doc.put(arena, "paths", .{ .object = paths });
    try doc.put(arena, "components", .{ .object = comps });
    return .{ .object = doc };
}

fn propsFor(path: []const u8) []const catalog.Filterable {
    for (catalog.resources) |r| {
        if (std.mem.eql(u8, r.list.path, path)) return if (r.filter) r.filterable else &.{};
        for (r.extras) |x| {
            if (x.shape == .page and std.mem.eql(u8, x.op.path, path)) return x.filterable;
        }
    }
    return &.{};
}

fn table(arena: Allocator, props: []const catalog.Filterable) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    try s.appendSlice(arena, "List.\n\n|Name|Type|Allowed functions|\n|-|-|-|\n");
    for (props) |p| {
        try s.print(arena, "|`{s}`|`{s}`|", .{ p.name, p.type });
        var it = std.mem.tokenizeScalar(u8, p.functions, ' ');
        var first = true;
        while (it.next()) |f| : (first = false) try s.print(arena, "{s}`{s}`", .{ if (first) "" else " ", f });
        try s.appendSlice(arena, "|\n");
    }
    return s.items;
}

test "compare: a document equal to the catalog has no drift" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const r = try compare(ar, try catalogDocument(ar));
    try testing.expectEqual(@as(usize, 0), r.driftCount());
    try testing.expectEqual(catalog_ops.len, r.ops_matched);
    try testing.expectEqual(@as(usize, 32), r.bodies_matched);
    try testing.expectEqual(@as(usize, 12), r.operations.post);
    try testing.expectEqual(@as(usize, 73), r.operations.total());
    try testing.expectEqualStrings("10.6.106", r.version.?);
}

test "compare: missing, stale, renamed operations and filterable drift" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var doc = try catalogDocument(ar);
    const paths = &doc.object.getPtr("paths").?.object;
    // Stale: gone from the document.
    _ = paths.orderedRemove("/v1/countries");
    // Missing: new in the document.
    var get: std.json.ObjectMap = .empty;
    try get.put(ar, "operationId", .{ .string = "getNewThings" });
    var item: std.json.ObjectMap = .empty;
    try item.put(ar, "get", .{ .object = get });
    try paths.put(ar, "/v1/sites/{siteId}/new-things", .{ .object = item });
    // Renamed operationId.
    try paths.getPtr("/v1/info").?.object.getPtr("get").?.object.put(ar, "operationId", .{ .string = "getApplicationInfo" });
    // Filterable: drop `id`, change `state`, add `uplink` on the device list.
    const dev = paths.getPtr("/v1/sites/{siteId}/devices").?.object.getPtr("get").?;
    const props = catalog.find("devices").?.filterable;
    var changed: std.ArrayList(catalog.Filterable) = .empty;
    for (props[1..]) |p| try changed.append(ar, if (std.mem.eql(u8, p.name, "state")) .{ .name = "state", .type = "STRING", .functions = "eq ne" } else p);
    try changed.append(ar, .{ .name = "uplink", .type = "UUID", .functions = "eq" });
    try dev.object.put(ar, "description", .{ .string = try table(ar, changed.items) });

    // Body: the zone schema gains `color` and stops requiring `networkIds`.
    const zone = &doc.object.getPtr("components").?.object.getPtr("schemas").?.object.getPtr("createFirewallZone").?.object;
    try zone.getPtr("properties").?.object.put(ar, "color", .{ .object = .empty });
    try zone.put(ar, "required", try std.json.parseFromSliceLeaky(Value, ar, "[\"name\"]", .{}));

    const r = try compare(ar, doc);
    try testing.expectEqual(@as(usize, 2), r.bodies.len);
    try testing.expectEqualStrings("color", r.bodies[0].field);
    try testing.expectEqual(Change.added, r.bodies[0].change);
    try testing.expectEqualStrings("networkIds", r.bodies[1].field);
    try testing.expect(r.bodies[1].required and r.bodies[1].change == .removed);
    try testing.expectEqual(@as(usize, 1), r.missing.len);
    try testing.expectEqualStrings("getNewThings", r.missing[0].operation_id);
    try testing.expectEqualStrings("GET", r.missing[0].method);
    try testing.expectEqual(@as(usize, 1), r.stale.len);
    try testing.expectEqualStrings("/v1/countries", r.stale[0].path);
    try testing.expectEqual(@as(usize, 1), r.renamed.len);
    try testing.expectEqualStrings("getApplicationInfo", r.renamed[0].document);
    try testing.expectEqual(@as(usize, 3), r.filterable.len);
    try testing.expectEqual(Change.changed, r.filterable[0].change);
    try testing.expectEqualStrings("state", r.filterable[0].property);
    try testing.expectEqualStrings("STRING eq ne", r.filterable[0].document.?);
    try testing.expectEqual(Change.added, r.filterable[1].change);
    try testing.expectEqual(Change.removed, r.filterable[2].change);
    try testing.expectEqualStrings("devices ls", r.filterable[2].list);
}

test "documentProps and sameFunctions" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const op = try parse(ar,
        \\{"description":"x\n|Name|Type|Allowed functions|\n|-|-|-|\n|`macAddress`|`STRING`|`eq` `ne` `in` `notIn`|\n"}
    );
    const props = try documentProps(ar, op);
    try testing.expectEqual(@as(usize, 1), props.len);
    try testing.expectEqualStrings("eq ne in notIn", props[0].functions);
    try testing.expect(sameFunctions("eq ne in", "in eq ne"));
    try testing.expect(!sameFunctions("eq ne", "eq ne in"));
}

// The operator's v10.6.106 export must match the catalog exactly
// (the private homelab checkout; clones without it skip this test).
test "compare: the v10.6.106 export has no drift" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const bytes = std.Io.Dir.cwd().readFileAlloc(testing.io, "../homelab/api/unifi/network_v10.6.106_openapi.json", ar, .limited(64 << 20)) catch
        return error.SkipZigTest;
    const r = try compare(ar, try parse(ar, bytes));
    for (r.filterable) |d| std.debug.print("drift {s} {s} {t}\n", .{ d.list, d.property, d.change });
    try testing.expectEqual(@as(usize, 0), r.driftCount());
    try testing.expectEqual(@as(usize, 73), r.operations.total());
}

test "collect: discriminator variants that point back at their base terminate" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const doc = try parse(ar,
        \\{"Base":{"discriminator":{"propertyName":"type","mapping":{"A":"#/components/schemas/A"}},"properties":{"type":{},"enabled":{}},"required":["type","enabled"]},
        \\ "A":{"allOf":[{"$ref":"#/components/schemas/Base"},{"properties":{"domain":{}}}],"required":["domain"]}}
    );
    var f: Fields = .{};
    var seen: std.AutoHashMapUnmanaged(usize, void) = .empty;
    try collect(ar, doc.object, try parse(ar, "{\"$ref\":\"#/components/schemas/Base\"}"), &f, &seen, true);
    try testing.expectEqual(@as(usize, 3), f.allowed.count());
    try testing.expectEqual(@as(usize, 2), f.required.count());
}
