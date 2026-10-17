//! `artoo gw …` (SPEC §10.2): UniFi's read surface. Every resource
//! group (`gw <resource> ls|show|<extra>`) is generated at compile time from
//! `unifi/catalog.zig`, so commands, flags, help and columns cannot drift
//! from the catalog. `gw info` is the one-screen gateway summary.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const catalog = @import("../unifi/catalog.zig");
const unifi = @import("../unifi/client.zig");
const view = @import("../unifi/view.zig");
const spec = @import("../unifi/spec.zig");
const writes = @import("gw_write.zig");

const Context = app.Context;
const Value = std.json.Value;

// ---------------------------------------------------------------- flags

const page_flags = [_]cli.Flag{
    .{ .long = "limit", .short = 'l', .kind = .int, .metavar = "N", .default = "200", .help = "Items per request (1-200)" },
    .{ .long = "offset", .kind = .int, .metavar = "N", .default = "0", .help = "Skip the first N items" },
    .{ .long = "all", .help = "Fetch every page (pages of 200; not a snapshot)" },
};

const filter_flags = [_]cli.Flag{
    .{ .long = "filter", .kind = .string, .metavar = "EXPR", .help = "Server-side filter (grammar above)" },
} ++ page_flags;

const filter_grammar =
    \\Filter grammar (server-side): PROPERTY.FUNCTION(ARGS), e.g. name.eq('x').
    \\Strings take single quotes, booleans are bare (enabled.eq(true)), like
    \\uses * wildcards (name.like('web*')), in takes a list (name.in('a','b')).
    \\Combine with and(A, B), or(A, B), not(A). Quote EXPR for the shell.
;

/// Help details for a filterable list: grammar plus an aligned property
/// table generated from the catalog.
fn filterHelp(comptime props: []const catalog.Filterable) []const u8 {
    comptime {
        @setEvalBranchQuota(20_000);
        var nw: usize = 0;
        var tw: usize = 0;
        for (props) |p| {
            nw = @max(nw, p.name.len);
            tw = @max(tw, p.type.len);
        }
        var s: []const u8 = filter_grammar ++ "\n\nFilterable properties:\n";
        for (props) |p| s = s ++ "  " ++ pad(p.name, nw) ++ "  " ++ pad(p.type, tw) ++ "  " ++ p.functions ++ "\n";
        return s;
    }
}

fn pad(comptime s: []const u8, comptime n: usize) []const u8 {
    const spaces: [n - s.len]u8 = @splat(' ');
    return s ++ &spaces;
}

/// An example filter for the first string property (prefers `name`).
fn exampleFilter(comptime props: []const catalog.Filterable) ?[]const u8 {
    comptime {
        var pick: ?catalog.Filterable = null;
        for (props) |p| {
            if (!std.mem.eql(u8, p.type, "STRING")) continue;
            if (pick == null or std.mem.eql(u8, p.name, "name")) pick = p;
        }
        const p = pick orelse return null;
        const like = std.mem.find(u8, p.functions, "like") != null;
        return if (like) p.name ++ ".like('a*')" else p.name ++ ".eq('x')";
    }
}

fn listOptions(ctx: *Context, comptime D: type, args: cli.Args(D)) !unifi.ListOptions {
    const filter: ?[]const u8 = if (comptime hasFlag(D, "filter")) args.string("filter") else null;
    const limit = args.int("limit");
    const offset = args.int("offset") orelse 0;
    const all = args.has("all");
    if (limit != null and all) return ctx.fail(error.Usage, "--limit and --all are mutually exclusive", .{});
    if (limit) |n| if (n < 1 or n > unifi.max_page) return ctx.fail(error.Usage, "--limit must be 1-{d}, got {d}", .{ unifi.max_page, n });
    if (offset < 0 or offset > std.math.maxInt(u32)) return ctx.fail(error.Usage, "--offset must be 0 or more, got {d}", .{offset});
    if (filter) |f| if (std.mem.trim(u8, f, " ").len == 0) return ctx.fail(error.Usage, "--filter is empty", .{});
    return .{
        .filter = filter,
        .limit = if (limit) |n| @intCast(n) else unifi.max_page,
        .offset = @intCast(offset),
        .all = all,
    };
}

fn hasFlag(comptime D: type, comptime long: []const u8) bool {
    for (D.flags) |f| {
        if (std.mem.eql(u8, f.long, long)) return true;
    }
    return false;
}

// ---------------------------------------------------------------- generated commands

fn Ls(comptime r: *const catalog.Resource) type {
    if (!r.paginated) @compileError(r.name ++ ": unpaginated lists are not supported");
    return struct {
        pub const name = "ls";
        pub const summary = "List " ++ lowerFirst(r.summary);
        pub const details = if (r.filter) filterHelp(r.filterable) else "";
        pub const flags = if (r.filter) filter_flags else page_flags;
        pub const examples = [_][]const u8{"artoo gw " ++ r.name ++ " ls"} ++
            (if (r.filter) if (exampleFilter(r.filterable)) |f| [_][]const u8{"artoo gw " ++ r.name ++ " ls --filter \"" ++ f ++ "\""} else [_][]const u8{} else [_][]const u8{}) ++
            [_][]const u8{"artoo gw " ++ r.name ++ " ls --all -o json"};

        pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
            const opts = try listOptions(ctx, @This(), args);
            var c = try unifi.Client.open(ctx);
            defer c.deinit();
            const page = try unifi.list(&c, r, opts);
            try renderPage(ctx, &c, r.columns, page);
        }
    };
}

/// "Adopted UniFi devices" → "adopted UniFi devices"; acronyms and
/// hyphenated words ("WAN", "Wi-Fi") stay as they are.
fn lowerFirst(comptime s: []const u8) []const u8 {
    comptime {
        const end = std.mem.findScalar(u8, s, ' ') orelse s.len;
        if (end < 2) return s;
        for (s[1..end]) |ch| if (!std.ascii.isLower(ch)) return s;
        return .{std.ascii.toLower(s[0])} ++ s[1..];
    }
}

pub fn targetHelp(comptime r: *const catalog.Resource) []const u8 {
    comptime {
        var s: []const u8 = "ID";
        for (r.match) |m| s = s ++ ", or exact " ++ m;
        return s;
    }
}

fn Show(comptime r: *const catalog.Resource) type {
    return struct {
        pub const name = "show";
        pub const summary = "Show one " ++ r.label ++ " in detail";
        pub const details = "Names match exactly first, then case-insensitively; an ambiguous name\nlists the matching IDs.";
        pub const positionals = [_]cli.Positional{.{ .name = "ID|NAME", .help = targetHelp(r) }};
        pub const examples = [_][]const u8{"artoo gw " ++ r.name ++ " show ID"};

        pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
            var c = try unifi.Client.open(ctx);
            defer c.deinit();
            const found = try unifi.resolve(&c, r, args.pos("ID|NAME"));
            const item = if (r.show) |op|
                try unifi.getJson(&c, try unifi.expandPath(&c, op.path, found.id))
            else
                found.item orelse return ctx.fail(error.NotFound, "no {s} '{s}' on UniFi", .{ r.label, found.id });
            const title = try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ try capitalized(ctx, r.label), try display(ctx, r, item, found.id) });
            try renderObject(ctx, &c, title, item);
        }
    };
}

fn Extra(comptime r: *const catalog.Resource, comptime e: catalog.Extra) type {
    return struct {
        pub const name = e.verb;
        pub const summary = e.summary;
        pub const details = switch (e.shape) {
            .page => filterHelp(e.filterable),
            .zone_pair => "Zones by ID or exact name (see 'artoo gw fw-zones ls').",
            .object => "",
        };
        pub const flags = switch (e.shape) {
            .page => filter_flags,
            .zone_pair, .object => [_]cli.Flag{},
        };
        pub const positionals = if (e.shape == .zone_pair)
            zone_positionals
        else if (e.targeted) [_]cli.Positional{.{ .name = "ID|NAME", .help = targetHelp(r) }} else [_]cli.Positional{};
        pub const examples = [_][]const u8{"artoo gw " ++ r.name ++ " " ++ e.verb ++ switch (e.shape) {
            .zone_pair => " Internal External",
            else => if (e.targeted) " ID" else "",
        }};

        pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
            const opts: unifi.ListOptions = if (comptime e.shape == .page) try listOptions(ctx, @This(), args) else .{};
            var c = try unifi.Client.open(ctx);
            defer c.deinit();
            switch (comptime e.shape) {
                .page => {
                    const page = try unifi.listPath(&c, try unifi.expandPath(&c, e.op.path, null), opts);
                    return renderPage(ctx, &c, e.columns, page);
                },
                .zone_pair => {
                    const from = args.pos("SRC_ZONE");
                    const to = args.pos("DST_ZONE");
                    const path = try zonePairPath(&c, e.op.path, from, to);
                    const title = try std.fmt.allocPrint(ctx.arena, "Policy order {s} {s} {s}", .{ try sanitized(ctx, from), ctx.ui.glyphs.arrow, try sanitized(ctx, to) });
                    return renderObject(ctx, &c, title, try unifi.getJson(&c, path));
                },
                .object => {
                    if (comptime e.targeted) {
                        const found = try unifi.resolve(&c, r, args.pos("ID|NAME"));
                        const v = try unifi.getJson(&c, try unifi.expandPath(&c, e.op.path, found.id));
                        const who = if (found.item) |it| try display(ctx, r, it, found.id) else try sanitized(ctx, found.id);
                        return renderObject(ctx, &c, try std.fmt.allocPrint(ctx.arena, "{s} {s} {s}", .{ who, ctx.ui.glyphs.dot, e.verb }), v);
                    }
                    const v = try unifi.getJson(&c, try unifi.expandPath(&c, e.op.path, null));
                    return renderObject(ctx, &c, try capitalized(ctx, e.summary), v);
                },
            }
        }
    };
}

pub const zone_positionals = [_]cli.Positional{
    .{ .name = "SRC_ZONE", .help = "Source firewall zone (ID or name)" },
    .{ .name = "DST_ZONE", .help = "Destination firewall zone (ID or name)" },
};

/// `template` + `?sourceFirewallZoneId=…&destinationFirewallZoneId=…`,
/// zones resolved by ID or name.
pub fn zonePairPath(c: *unifi.Client, template: []const u8, from: []const u8, to: []const u8) ![]const u8 {
    const arena = c.ctx.arena;
    const zones = catalog.find("fw-zones").?;
    const src = try unifi.resolve(c, zones, from);
    const dst = try unifi.resolve(c, zones, to);
    var p: std.ArrayList(u8) = .empty;
    try p.appendSlice(arena, try unifi.expandPath(c, template, null));
    try p.appendSlice(arena, "?sourceFirewallZoneId=");
    try catalog.appendEscaped(arena, &p, src.id);
    try p.appendSlice(arena, "&destinationFirewallZoneId=");
    try catalog.appendEscaped(arena, &p, dst.id);
    return p.items;
}

fn resourceGroup(comptime r: *const catalog.Resource) cli.Command {
    comptime {
        var children: []const cli.Command = &.{ cli.leaf(Ls(r)), cli.leaf(Show(r)) };
        for (r.extras) |e| children = children ++ .{cli.leaf(Extra(r, e))};
        for (r.writes) |w| children = children ++ .{cli.leaf(writes.Verb(r, w))};
        const final = children[0..children.len].*;
        return cli.group(r.name, r.summary, &final);
    }
}

const resource_groups = blk: {
    @setEvalBranchQuota(200_000);
    var out: [catalog.resources.len]cli.Command = undefined;
    for (&catalog.resources, 0..) |*r, i| out[i] = resourceGroup(r);
    break :blk out;
};

// ---------------------------------------------------------------- gw info

const Named = struct {
    count: usize,
    names: []const []const u8,
};

const SectionError = struct {
    section: []const u8,
    message: []const u8,
};

const InfoData = struct {
    application_version: []const u8,
    site: struct { id: []const u8, name: ?[]const u8 },
    devices: ?struct { online: usize, total: usize } = null,
    clients: ?struct { total: usize, wired: usize, wireless: usize, other: usize } = null,
    networks: ?Named = null,
    wifi: ?Named = null,
    wans: ?Named = null,
    dns_policies: ?usize = null,
};

pub const info = struct {
    pub const name = "info";
    pub const summary = "Gateway summary: version, site, devices, clients, networks, Wi-Fi, WANs, DNS";
    pub const details =
        \\Read-only. Each section is fetched separately; a section that fails is
        \\shown as unavailable and the command exits 8.
    ;
    pub const examples = [_][]const u8{ "artoo gw info", "artoo gw info -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try unifi.Client.open(ctx);
        defer c.deinit();
        const i = try unifi.info(&c);
        const site_id = try unifi.siteId(&c);
        var d: InfoData = .{
            .application_version = try sanitized(ctx, i.applicationVersion),
            .site = .{ .id = site_id, .name = if (c.site_name) |n| try sanitized(ctx, n) else null },
        };
        var errors: std.ArrayList(SectionError) = .empty;

        if (section(ctx, &errors, "devices", allItems(&c, "devices"))) |items| {
            var online: usize = 0;
            for (items) |it| {
                if (std.mem.eql(u8, view.string(it, "state") orelse "", "ONLINE")) online += 1;
            }
            d.devices = .{ .online = online, .total = items.len };
        }
        if (section(ctx, &errors, "clients", allItems(&c, "clients"))) |items| {
            d.clients = .{ .total = items.len, .wired = 0, .wireless = 0, .other = 0 };
            for (items) |it| {
                const t = view.string(it, "type") orelse "";
                if (std.mem.eql(u8, t, "WIRED")) {
                    d.clients.?.wired += 1;
                } else if (std.mem.eql(u8, t, "WIRELESS")) {
                    d.clients.?.wireless += 1;
                } else d.clients.?.other += 1;
            }
        }
        if (section(ctx, &errors, "networks", allItems(&c, "networks"))) |items| d.networks = try named(ctx, items);
        if (section(ctx, &errors, "wifi", allItems(&c, "wifi"))) |items| d.wifi = try named(ctx, items);
        if (section(ctx, &errors, "wans", allItems(&c, "wans"))) |items| d.wans = try named(ctx, items);
        if (section(ctx, &errors, "dns_policies", count(&c, "dns-policies"))) |n| d.dns_policies = n;

        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .unifi, d, .{ .collected_at = ctx.ui.now, .errors = errors.items });
        } else {
            try header(ctx, &c);
            try renderInfo(ctx, d, errors.items);
        }
        if (errors.items.len > 0) return ctx.fail(error.Partial, "{d} section{s} unavailable", .{ errors.items.len, if (errors.items.len == 1) "" else "s" });
    }
};

/// Unwrap a section result; record failures (except OOM/cancel, which
/// still abort) and clear the diagnostic so the next section starts clean.
fn section(ctx: *Context, errors: *std.ArrayList(SectionError), label: []const u8, result: anytype) ?@typeInfo(@TypeOf(result)).error_union.payload {
    return result catch |err| {
        const msg = ctx.diag orelse @errorName(err);
        ctx.diag = null;
        errors.append(ctx.arena, .{ .section = label, .message = msg }) catch {};
        return null;
    };
}

fn allItems(c: *unifi.Client, comptime resource: []const u8) ![]Value {
    const page = try unifi.list(c, comptime catalog.find(resource).?, .{ .all = true });
    return page.items;
}

/// Total via `totalCount` of a one-item page; falls back to counting.
fn count(c: *unifi.Client, comptime resource: []const u8) !usize {
    const r = comptime catalog.find(resource).?;
    const page = try unifi.list(c, r, .{ .limit = 1 });
    if (page.total) |t| return @intCast(@max(t, 0));
    return (try unifi.list(c, r, .{ .all = true })).items.len;
}

fn named(ctx: *Context, items: []const Value) !Named {
    const names = try ctx.arena.alloc([]const u8, items.len);
    for (items, names) |it, *n| n.* = try sanitized(ctx, view.string(it, "name") orelse "--");
    return .{ .count = items.len, .names = names };
}

fn renderInfo(ctx: *Context, d: InfoData, errors: []const SectionError) !void {
    const a = ctx.arena;
    var fields: std.ArrayList(ui.blocks.Field) = .empty;
    try fields.append(a, .{ .key = "Version", .value = try std.fmt.allocPrint(a, "Network {s}", .{d.application_version}) });
    try fields.append(a, .{ .key = "Site", .value = d.site.name orelse d.site.id });
    try fields.append(a, if (d.devices) |dv| .{
        .key = "Devices",
        .value = try std.fmt.allocPrint(a, "{d} online / {d}", .{ dv.online, dv.total }),
        .role = if (dv.online == dv.total) .ok else .warn,
    } else unavailable("Devices", errors, "devices"));
    try fields.append(a, if (d.clients) |cl| .{
        .key = "Clients",
        .value = if (cl.other > 0)
            try std.fmt.allocPrint(a, "{d} ({d} wired, {d} wireless, {d} other)", .{ cl.total, cl.wired, cl.wireless, cl.other })
        else
            try std.fmt.allocPrint(a, "{d} ({d} wired, {d} wireless)", .{ cl.total, cl.wired, cl.wireless }),
    } else unavailable("Clients", errors, "clients"));
    try fields.append(a, try namedField(a, "Networks", d.networks, errors, "networks"));
    try fields.append(a, try namedField(a, "Wi-Fi", d.wifi, errors, "wifi"));
    try fields.append(a, try namedField(a, "WANs", d.wans, errors, "wans"));
    try fields.append(a, if (d.dns_policies) |n| .{
        .key = "DNS policies",
        .value = try std.fmt.allocPrint(a, "{d}", .{n}),
    } else unavailable("DNS policies", errors, "dns_policies"));
    try ui.blocks.detail(ctx.out, &ctx.ui, &.{.{ .title = "UniFi", .fields = fields.items }});
}

fn namedField(a: std.mem.Allocator, key: []const u8, n: ?Named, errors: []const SectionError, label: []const u8) !ui.blocks.Field {
    const v = n orelse return unavailable(key, errors, label);
    if (v.count == 0) return .{ .key = key, .value = "0", .role = .muted };
    return .{ .key = key, .value = try std.fmt.allocPrint(a, "{d}: {s}", .{ v.count, try std.mem.join(a, ", ", v.names) }) };
}

fn unavailable(key: []const u8, errors: []const SectionError, label: []const u8) ui.blocks.Field {
    for (errors) |e| {
        if (std.mem.eql(u8, e.section, label)) return .{ .key = key, .value = e.message, .role = .fail };
    }
    return .{ .key = key, .value = "--" };
}

// ---------------------------------------------------------------- gw spec

pub const spec_cmd = struct {
    pub const name = "spec";
    pub const summary = "Compare the gateway's OpenAPI document with the built-in catalog";
    pub const details =
        \\Read-only. Fetches the live document (GET /proxy/network/api-docs/
        \\integration.json, API key) or reads --file, then reports operations the
        \\catalog lacks, no longer finds or names differently, drift in each
        \\write's request-body fields and in each list's filterable properties.
        \\Any drift exits 8. --save keeps the fetched document (never
        \\overwrites) for diffing after a firmware update.
    ;
    pub const flags = [_]cli.Flag{
        .{ .long = "file", .short = 'f', .kind = .string, .metavar = "PATH", .help = "Compare a local OpenAPI export instead" },
        .{ .long = "save", .kind = .string, .metavar = "PATH", .help = "Also write the fetched document to PATH (new file)" },
    };
    pub const examples = [_][]const u8{
        "artoo gw spec",
        "artoo gw spec --save live_openapi.json",
        "artoo gw spec --file ../homelab/api/unifi/network_v10.6.106_openapi.json",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const file = args.string("file");
        const save = args.string("save");
        if (file != null and save != null) return ctx.fail(error.Usage, "--save applies to the fetched document; drop --file", .{});
        if (save) |path| {
            if (try @import("../files.zig").exists(ctx.io, path)) return ctx.fail(error.Usage, "{s} exists; --save never overwrites", .{path});
        }

        var client: ?unifi.Client = null;
        defer if (client) |*c| c.deinit();
        var source: []const u8 = undefined;
        const bytes = if (file) |path| blk: {
            source = try sanitized(ctx, path);
            break :blk std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(64 << 20)) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => return ctx.fail(error.Usage, "cannot read {s}: {t}", .{ source, err }),
            };
        } else blk: {
            client = try unifi.Client.open(ctx);
            source = "live";
            break :blk try client.?.getSpec();
        };
        const doc = spec.parse(ctx.arena, bytes) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidDocument => return ctx.fail(if (file != null) error.Usage else error.Protocol, "{s} is not JSON", .{source}),
        };
        const report = spec.compare(ctx.arena, doc) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidDocument => return ctx.fail(if (file != null) error.Usage else error.Protocol, "{s} is not an OpenAPI document (no paths)", .{source}),
        };
        if (save) |path| {
            const f = std.Io.Dir.cwd().createFile(ctx.io, path, .{ .exclusive = true, .permissions = .fromMode(0o600) }) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return ctx.fail(error.Usage, "cannot create {s}: {t}", .{ path, err }),
            };
            defer f.close(ctx.io);
            f.writeStreamingAll(ctx.io, bytes) catch |err| return ctx.fail(error.Usage, "cannot write {s}: {t}", .{ path, err });
        }

        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .unifi, report, .{ .collected_at = ctx.ui.now, .source = source, .catalog_gets = catalog.all_ops.len, .drift = report.driftCount() });
        } else {
            const right = if (client) |*c|
                try headerRight(ctx, c)
            else
                try std.fmt.allocPrint(ctx.arena, "file {s} {s}", .{ ctx.ui.glyphs.dot, source });
            try ui.blocks.header(ctx.out, &ctx.ui, ctx.path, right);
            try renderSpec(ctx, report, source, save);
        }
        const n = report.driftCount();
        if (n > 0) return ctx.fail(error.Partial, "catalog drift: {d} difference{s}; update unifi/catalog.zig from the official export", .{ n, if (n == 1) "" else "s" });
    }
};

fn renderSpec(ctx: *Context, r: spec.Report, source: []const u8, saved: ?[]const u8) !void {
    const a = ctx.arena;
    const u = &ctx.ui;
    const m = r.operations;
    var fields: std.ArrayList(ui.blocks.Field) = .empty;
    try fields.append(a, .{ .key = "Source", .value = source });
    if (saved) |p| try fields.append(a, .{ .key = "Saved", .value = try sanitized(ctx, p) });
    try fields.append(a, .{ .key = "Version", .value = if (r.version) |v| try sanitized(ctx, v) else "--" });
    try fields.append(a, .{ .key = "Operations", .value = try std.fmt.allocPrint(a, "{d} in {d} paths ({d} GET, {d} POST, {d} PUT, {d} PATCH, {d} DELETE)", .{ m.total(), r.paths, m.get, m.post, m.put, m.patch, m.delete }) });
    try fields.append(a, .{ .key = "Schemas", .value = try std.fmt.allocPrint(a, "{d}", .{r.schemas}) });
    const ops_drift = r.missing.len + r.stale.len + r.renamed.len;
    try fields.append(a, .{
        .key = "Catalog",
        .value = try std.fmt.allocPrint(a, "{d} of {d} operations match{s}", .{ r.ops_matched, r.catalog_ops, if (ops_drift > 0) try std.fmt.allocPrint(a, "; {d} differ", .{ops_drift}) else "" }),
        .role = if (ops_drift == 0) .ok else .warn,
    });
    try fields.append(a, .{
        .key = "Request bodies",
        .value = try std.fmt.allocPrint(a, "{d} writes match{s}", .{ r.bodies_matched, if (r.bodies.len > 0) try std.fmt.allocPrint(a, "; {d} field difference(s)", .{r.bodies.len}) else "" }),
        .role = if (r.bodies.len == 0) .ok else .warn,
    });
    try fields.append(a, .{
        .key = "Filterable",
        .value = try std.fmt.allocPrint(a, "{d} lists match{s}", .{ r.lists_matched, if (r.filterable.len > 0) try std.fmt.allocPrint(a, "; {d} property difference(s)", .{r.filterable.len}) else "" }),
        .role = if (r.filterable.len == 0) .ok else .warn,
    });
    try ui.blocks.detail(ctx.out, u, &.{.{ .title = "OpenAPI document", .fields = fields.items }});

    if (ops_drift > 0) {
        var rows: std.ArrayList([]const ui.table.Cell) = .empty;
        for (r.missing) |o| try rows.append(a, try opRow(ctx, "not in catalog", .warn, o.method, o.path, o.operation_id));
        for (r.stale) |o| try rows.append(a, try opRow(ctx, "gone from document", .fail, o.method, o.path, o.operation_id));
        for (r.renamed) |o| try rows.append(a, try opRow(ctx, "renamed", .warn, o.method, o.path, try std.fmt.allocPrint(a, "{s} {s} {s}", .{ o.catalog, u.glyphs.arrow, try sanitized(ctx, o.document) })));
        try ctx.out.print("\n{s}Operation drift{s}\n", .{ u.palette.on(.title), u.palette.off(.title) });
        try ui.table.render(ctx.out, u, a, &.{
            .{ .title = "CHANGE", .truncate = false },
            .{ .title = "PATH", .truncate = false },
            .{ .title = "OPERATION" },
        }, rows.items);
    }
    if (r.bodies.len > 0) {
        var rows: std.ArrayList([]const ui.table.Cell) = .empty;
        for (r.bodies) |d| {
            const cells = try a.alloc(ui.table.Cell, 4);
            cells[0] = .{ .text = try sanitized(ctx, d.operation_id) };
            cells[1] = .{ .text = try sanitized(ctx, d.field) };
            cells[2] = .{ .text = if (d.required) "required" else "allowed" };
            cells[3] = .{ .text = if (d.change == .added) "only in document" else "only in catalog", .role = if (d.change == .removed) .fail else .warn };
            try rows.append(a, cells);
        }
        try ctx.out.print("\n{s}Request body drift{s}\n", .{ u.palette.on(.title), u.palette.off(.title) });
        try ui.table.render(ctx.out, u, a, &.{
            .{ .title = "OPERATION", .truncate = false },
            .{ .title = "FIELD", .truncate = false },
            .{ .title = "LIST", .truncate = false },
            .{ .title = "WHERE" },
        }, rows.items);
    }
    if (r.filterable.len > 0) {
        var rows: std.ArrayList([]const ui.table.Cell) = .empty;
        for (r.filterable) |d| {
            const cells = try a.alloc(ui.table.Cell, 5);
            cells[0] = .{ .text = d.list };
            cells[1] = .{ .text = try sanitized(ctx, d.property) };
            cells[2] = .{ .text = @tagName(d.change), .role = if (d.change == .removed) .fail else .warn };
            cells[3] = .{ .text = d.catalog orelse "--" };
            cells[4] = .{ .text = if (d.document) |x| try sanitized(ctx, x) else "--" };
            try rows.append(a, cells);
        }
        try ctx.out.print("\n{s}Filterable property drift{s}\n", .{ u.palette.on(.title), u.palette.off(.title) });
        try ui.table.render(ctx.out, u, a, &.{
            .{ .title = "LIST", .truncate = false },
            .{ .title = "PROPERTY", .truncate = false },
            .{ .title = "CHANGE", .truncate = false },
            .{ .title = "CATALOG" },
            .{ .title = "DOCUMENT" },
        }, rows.items);
    }
}

fn opRow(ctx: *Context, change: []const u8, role: ui.style.Role, method: []const u8, path: []const u8, op: []const u8) ![]const ui.table.Cell {
    const cells = try ctx.arena.alloc(ui.table.Cell, 3);
    cells[0] = .{ .text = change, .role = role };
    cells[1] = .{ .text = try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ method, try sanitized(ctx, path) }) };
    cells[2] = .{ .text = try sanitized(ctx, op) };
    return cells;
}

// ---------------------------------------------------------------- rendering

/// `ARTOO · gw <path>` left, `unifi · <site> · <clock>` right.
pub fn header(ctx: *Context, c: *const unifi.Client) !void {
    try ui.blocks.header(ctx.out, &ctx.ui, ctx.path, try headerRight(ctx, c));
}

fn headerRight(ctx: *Context, c: *const unifi.Client) ![]const u8 {
    const site = try sanitized(ctx, c.site_name orelse c.site);
    return std.fmt.allocPrint(ctx.arena, "unifi {s} {s} {s} {f}", .{
        ctx.ui.glyphs.dot, site, ctx.ui.glyphs.dot, ui.values.clock(ctx.ui.now, &ctx.ui.zone),
    });
}

fn renderPage(ctx: *Context, c: *const unifi.Client, cols: []const catalog.Column, page: unifi.Page) !void {
    if (ctx.json()) {
        return ui.json.envelope(ctx.out, .unifi, page.items, .{
            .collected_at = ctx.ui.now,
            .site = c.site_name orelse c.site,
            .offset = page.offset,
            .count = page.items.len,
            .total = page.total,
        });
    }
    try header(ctx, c);
    if (page.items.len == 0) {
        try ctx.out.print("{s}No results.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
    } else {
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, try view.columnsFor(ctx.arena, cols), try view.rows(ctx.arena, &ctx.ui, page.items, cols));
    }
    const total = page.total orelse return;
    const end = page.offset + @as(i64, @intCast(page.items.len));
    if (total <= page.items.len) return;
    const p = ctx.ui.palette;
    try ctx.out.print("\n{s}", .{p.on(.muted)});
    if (page.items.len > 0) {
        try ctx.out.print("Showing {d}-{d} of {d}", .{ page.offset + 1, end, total });
    } else try ctx.out.print("Offset {d} is past the end ({d} total)", .{ page.offset, total });
    if (end < total) try ctx.out.print("; next: --offset {d}, or --all", .{end});
    try ctx.out.print("{s}\n", .{p.off(.muted)});
}

pub fn renderObject(ctx: *Context, c: *const unifi.Client, title: []const u8, v: Value) !void {
    if (ctx.json()) {
        return ui.json.envelope(ctx.out, .unifi, v, .{ .collected_at = ctx.ui.now, .site = c.site_name orelse c.site });
    }
    try header(ctx, c);
    try view.detail(ctx.out, ctx.arena, &ctx.ui, title, v);
}

pub fn sanitized(ctx: *Context, s: []const u8) ![]const u8 {
    return ui.text.sanitize(ctx.arena, s, .line);
}

/// The object's first non-empty match field (its name), else the ID.
fn display(ctx: *Context, comptime r: *const catalog.Resource, item: Value, id: []const u8) ![]const u8 {
    for (r.match) |m| {
        if (view.string(item, m)) |s| if (s.len > 0) return sanitized(ctx, s);
    }
    return sanitized(ctx, id);
}

pub fn capitalized(ctx: *Context, s: []const u8) ![]const u8 {
    const out = try ctx.arena.dupe(u8, s);
    if (out.len > 0) out[0] = std.ascii.toUpper(out[0]);
    return out;
}

pub const group = cli.group("gw", "The UniFi gateway through the Integration API", &([_]cli.Command{ cli.leaf(info), cli.leaf(spec_cmd), cli.leaf(writes.api) } ++ resource_groups));

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Harness = @import("../testkit.zig").Harness;
const Exit = @import("../testkit.zig").Exit;
const root = cli.group("artoo", "test", &.{group});

const sites_body =
    \\{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"51e00001-0000-4000-8000-00000000000d","internalReference":"default","name":"Default"}]}
;
const devices_body =
    \\{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
    \\{"id":"c0de0001-0000-4000-8000-00000000000c","name":"Beacon","model":"U6+","state":"ONLINE","ipAddress":"192.168.1.20","firmwareVersion":"6.7.54","firmwareUpdatable":false,"features":["accessPoint"]},
    \\{"id":"9a7c0b00-0000-4000-8000-00000000000b","name":"UniFi","model":"UCG Ultra","state":"ONLINE","ipAddress":"192.168.1.1","firmwareVersion":"5.1.33","firmwareUpdatable":false,"features":["gateway","switching"]}]}
;

const Fixture = @import("../testkit.zig").Gateway;
const FakeServer = @import("../http.zig").FakeServer;

test "gw: help is generated from the catalog" {
    var h = try Harness.init();
    defer h.deinit();
    try testing.expectEqual(Exit.ok, h.run(&root, "gw devices ls -h"));
    const out = h.stdout();
    try testing.expect(std.mem.find(u8, out, "List adopted UniFi devices") != null);
    try testing.expect(std.mem.find(u8, out, "--filter EXPR") != null);
    try testing.expect(std.mem.find(u8, out, "firmwareVersion    STRING       isNull isNotNull") != null);
    try testing.expect(std.mem.find(u8, out, "artoo gw devices ls --filter \"name.like('a*')\"") != null);
    // WANs have no filter: the flag does not exist.
    try testing.expectEqual(Exit.usage, h.run(&root, "gw wans ls --filter x"));
    try testing.expectEqual(Exit.ok, h.run(&root, "gw devices -h"));
    for ([_][]const u8{ "ls", "show", "stats", "pending" }) |verb| {
        try testing.expect(std.mem.find(u8, h.stdout(), verb) != null);
    }
}

test "gw sites ls: table, pagination footer, request shape" {
    var f: Fixture = undefined;
    try f.init(&.{.{ .respond = .{ .body =
        \\{"offset":0,"limit":1,"count":1,"totalCount":3,"data":[{"id":"51e00001-0000-4000-8000-00000000000d","internalReference":"default","name":"Default"}]}
    } }});
    defer f.deinit();
    try testing.expectEqual(Exit.ok, f.h.run(&root, "gw sites ls -l 1"));
    try testing.expectEqualStrings("GET /v1/sites?offset=0&limit=1 HTTP/1.1", f.request(0));
    try testing.expect(std.ascii.findIgnoreCase(f.srv.received[0].?, "x-api-key: test-key\r\n") != null);
    const out = f.h.stdout();
    try testing.expect(std.mem.startsWith(u8, out, "ARTOO · gw sites ls  unifi · default · "));
    try testing.expect(std.mem.find(u8, out,
        \\NAME     REFERENCE  ID
        \\Default  default    51e00001-0000-4000-8000-00000000000d
        \\
        \\Showing 1-1 of 3; next: --offset 1, or --all
        \\
    ) != null);
}

test "gw devices show NAME: site, list, then detail by ID" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = devices_body } },
        .{ .respond = .{ .body =
        \\{"id":"c0de0001-0000-4000-8000-00000000000c","name":"Beacon","model":"U6+","state":"ONLINE"}
        } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.ok, f.h.run(&root, "gw devices show beacon"));
    try testing.expectEqualStrings("GET /v1/sites?offset=0&limit=200 HTTP/1.1", f.request(0));
    try testing.expectEqualStrings("GET /v1/sites/51e00001-0000-4000-8000-00000000000d/devices?offset=0&limit=200 HTTP/1.1", f.request(1));
    try testing.expectEqualStrings("GET /v1/sites/51e00001-0000-4000-8000-00000000000d/devices/c0de0001-0000-4000-8000-00000000000c HTTP/1.1", f.request(2));
    const out = f.h.stdout();
    try testing.expect(std.mem.startsWith(u8, out, "ARTOO · gw devices show  unifi · Default · "));
    try testing.expect(std.mem.find(u8, out, "Device Beacon\n  id     c0de0001") != null);
}

test "gw devices show: a missing device is a usage error (exit 2)" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = devices_body } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.usage, f.h.run(&root, "gw devices show nope"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "no device 'nope' on UniFi") != null);
}

test "gw devices ls: invalid filter is a usage error (exit 2)" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .status = 400, .body =
        \\{"statusCode":400,"statusName":"BAD_REQUEST","code":"api.request.invalid-filter","message":"Unknown property 'nope'"}
        } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.usage, f.h.run(&root, "gw devices ls --filter nope.eq('x')"));
    try testing.expectEqualStrings("GET /v1/sites/51e00001-0000-4000-8000-00000000000d/devices?offset=0&limit=200&filter=nope.eq%28%27x%27%29 HTTP/1.1", f.request(1));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "invalid --filter: Unknown property 'nope'") != null);
}

test "gw: local flag validation sends nothing" {
    var f: Fixture = undefined;
    try f.init(&.{});
    defer f.deinit();
    try testing.expectEqual(Exit.usage, f.h.run(&root, "gw clients ls -l 0"));
    try testing.expectEqual(Exit.usage, f.h.run(&root, "gw clients ls -l 5 --all"));
    try testing.expectEqual(Exit.usage, f.h.run(&root, "gw fw-policies order a"));
    try testing.expectEqual(@as(usize, 0), f.srv.accepted.load(.acquire));
}

test "gw wifi show -o json: passphrase redacted" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body =
        \\{"id":"5e1f0a00-0000-4000-8000-00000000000a","name":"LabNet","securityConfiguration":{"type":"WPA2_WPA3_PERSONAL","passphrase":"hunter2-secret"}}
        } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.ok, f.h.run(&root, "-o json gw wifi show 5e1f0a00-0000-4000-8000-00000000000a"));
    const out = f.h.stdout();
    try testing.expect(std.mem.find(u8, out, "hunter2") == null);
    const parsed = try std.json.parseFromSlice(Value, testing.allocator, out, .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("unifi", parsed.value.object.get("target").?.string);
    const sec = parsed.value.object.get("data").?.object.get("securityConfiguration").?;
    try testing.expectEqualStrings(view.redacted, sec.object.get("passphrase").?.string);
}

test "gw info: summary, and a failed section is partial (exit 8)" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = "{\"applicationVersion\":\"10.6.106\"}" } },
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = devices_body } },
        .{ .respond = .{ .body =
        \\{"offset":0,"limit":200,"count":3,"totalCount":3,"data":[{"type":"WIRED","name":"Proxmox"},{"type":"WIRELESS","name":"a"},{"type":"WIRELESS","name":"b"}]}
        } },
        .{ .respond = .{ .body =
        \\{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"name":"Default"}]}
        } },
        .{ .respond = .{ .status = 500, .body = "{\"message\":\"boom\"}" } },
        .{ .respond = .{ .body =
        \\{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[{"name":"WAN 1"},{"name":"Internet 2"}]}
        } },
        .{ .respond = .{ .body =
        \\{"offset":0,"limit":1,"count":1,"totalCount":4,"data":[{"domain":"pve.home.arpa"}]}
        } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.partial, f.h.run(&root, "gw info"));
    const out = f.h.stdout();
    const body = out[std.mem.find(u8, out, "\n\n").? + 2 ..];
    try testing.expectEqualStrings(
        \\UniFi
        \\  Version       Network 10.6.106
        \\  Site          Default
        \\  Devices       2 online / 2
        \\  Clients       3 (1 wired, 2 wireless)
        \\  Networks      1: Default
        \\  Wi-Fi         UniFi answered 500 for GET /v1/sites/51e00001-0000-4000-8000-00000000000d/wifi/broadcasts?offset=0&limit=200: boom
        \\  WANs          2: WAN 1, Internet 2
        \\  DNS policies  4
        \\
    , body);
    try testing.expect(std.mem.find(u8, f.h.stderr(), "1 section unavailable") != null);
}

const tiny_spec =
    \\{"openapi":"3.1.0","info":{"version":"10.7.1"},"paths":{"/v1/info":{"get":{"operationId":"getInfo"}},"/v1/sites/{siteId}/new":{"get":{"operationId":"getNew"},"post":{}}},"components":{"schemas":{"A":{}}}}
;

test "gw spec: live document fetched from the gateway origin; drift exits 8" {
    var f: Fixture = undefined;
    try f.init(&.{.{ .respond = .{ .body = tiny_spec } }});
    defer f.deinit();
    try testing.expectEqual(Exit.partial, f.h.run(&root, "gw spec"));
    try testing.expectEqualStrings("GET /proxy/network/api-docs/integration.json HTTP/1.1", f.request(0));
    try testing.expect(std.ascii.findIgnoreCase(f.srv.received[0].?, "x-api-key: test-key\r\n") != null);
    const out = f.h.stdout();
    try testing.expect(std.mem.find(u8, out, "  Version         10.7.1\n") != null);
    try testing.expect(std.mem.find(u8, out, "  Operations      3 in 2 paths (2 GET, 1 POST, 0 PUT, 0 PATCH, 0 DELETE)\n") != null);
    try testing.expect(std.mem.find(u8, out, "not in catalog      GET /v1/sites/{siteId}/new") != null);
    try testing.expect(std.mem.find(u8, out, "gone from document  GET /v1/sites") != null);
    try testing.expect(std.mem.find(u8, f.h.stderr(), "catalog drift: 74 differences") != null);
}

test "gw spec --file: offline; --save refuses to overwrite; bad files are usage errors" {
    var f: Fixture = undefined;
    try f.init(&.{});
    defer f.deinit();
    const ar = f.h.arena.allocator();
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = "doc.json", .data = tiny_spec });
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = "junk.json", .data = "nope" });
    const dir = try f.tmp.dir.realPathFileAlloc(testing.io, ".", ar);
    const doc = try std.fmt.allocPrint(ar, "{s}/doc.json", .{dir});

    try testing.expectEqual(Exit.partial, f.h.run(&root, try std.fmt.allocPrint(ar, "-o json gw spec --file {s}", .{doc})));
    const parsed = try std.json.parseFromSlice(Value, testing.allocator, f.h.stdout(), .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("10.7.1", parsed.value.object.get("data").?.object.get("version").?.string);
    try testing.expectEqual(@as(i64, 74), parsed.value.object.get("meta").?.object.get("drift").?.integer);

    try testing.expectEqual(Exit.usage, f.h.run(&root, try std.fmt.allocPrint(ar, "gw spec --file {s}/junk.json", .{dir})));
    try testing.expectEqual(Exit.usage, f.h.run(&root, try std.fmt.allocPrint(ar, "gw spec --file {s}/absent.json", .{dir})));
    try testing.expectEqual(Exit.usage, f.h.run(&root, try std.fmt.allocPrint(ar, "gw spec --save {s}", .{doc})));
    try testing.expectEqual(Exit.usage, f.h.run(&root, try std.fmt.allocPrint(ar, "gw spec --file {s} --save {s}/new.json", .{ doc, dir })));
    try testing.expectEqual(@as(usize, 0), f.srv.accepted.load(.acquire));
}
