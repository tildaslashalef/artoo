//! `artoo cf dns ls|add|rm` (SPEC §15): records of the Cloudflare zone,
//! written through the one mutation pipeline. artoo changes only records
//! it marked; the §9.6 hard rule and the no-LAN-addresses rule are checked
//! before anything is planned.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const exposure = @import("../exposure.zig");
const ui = @import("../ui.zig");
const cf = @import("../cloudflare/client.zig");
const records = @import("../cloudflare/dns.zig");
const unifi_dns = @import("../unifi/dns.zig");

const Context = app.Context;

const no_lock = "Cloudflare has no record locking; concurrent edits cannot be detected.";

/// `www` → `www.<zone>`; a name ending in the zone is taken as given.
pub fn recordName(ctx: *Context, word: []const u8) ![]const u8 {
    const zone = (try ctx.config()).cloudflare.zone;
    const n = std.mem.trimEnd(u8, word, ".");
    const full = if (std.ascii.eqlIgnoreCase(n, zone) or std.ascii.endsWithIgnoreCase(n, zone) and n.len > zone.len and n[n.len - zone.len - 1] == '.')
        try ctx.arena.dupe(u8, n)
    else if (std.mem.findScalar(u8, n, '.') == null or std.mem.startsWith(u8, n, "_"))
        try std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ n, zone })
    else
        return ctx.fail(error.Usage, "'{s}' is not in the zone {s} (cloudflare.zone)", .{ word, zone });
    for (full) |*ch| ch.* = std.ascii.toLower(ch.*);
    // `_` leads service labels (TXT); the rest are host labels.
    const check = if (std.mem.startsWith(u8, full, "_")) full[1..] else full;
    if (!unifi_dns.validName(check)) return ctx.fail(error.Usage, "invalid DNS name '{s}'", .{word});
    return full;
}

/// True for `domain` and names under it.
pub fn under(name: []const u8, domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, domain)) return true;
    return name.len > domain.len and name[name.len - domain.len - 1] == '.' and std.ascii.endsWithIgnoreCase(name, domain);
}

pub fn zoneLabel(ctx: *Context, c: *const cf.Client) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "Cloudflare (zone {s})", .{c.zone_name});
}

fn recordText(ctx: *Context, r: anytype) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "{s} {s} {s} {s}{s}", .{
        try ui.text.sanitize(ctx.arena, r.name, .line),
        if (@TypeOf(r.type) == records.Type) @tagName(r.type) else r.type,
        ctx.ui.glyphs.arrow,
        try ui.text.sanitize(ctx.arena, r.content, .line),
        if (r.proxied) " (proxied)" else "",
    });
}

fn ttlText(ctx: *Context, ttl: ?i64) ![]const u8 {
    const t = ttl orelse return "--";
    return if (t == records.ttl_auto) "auto" else std.fmt.allocPrint(ctx.arena, "{d}", .{t});
}

fn header(ctx: *Context, c: *const cf.Client) !void {
    try ui.blocks.header(ctx.out, &ctx.ui, ctx.path, try std.fmt.allocPrint(ctx.arena, "cloudflare {s} {s} {s} {f}", .{
        ctx.ui.glyphs.dot, c.zone_name, ctx.ui.glyphs.dot, ui.values.clock(ctx.ui.now, &ctx.ui.zone),
    }));
}

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "List the zone's DNS records";
    pub const details = "Every record; ARTOO marks the ones artoo created and may change.";
    pub const flags = [_]cli.Flag{
        .{ .long = "type", .kind = .string, .metavar = "T", .help = "Only this type (A, CNAME, …)" },
        .{ .long = "name", .kind = .string, .metavar = "NAME", .help = "Only this name (short names get the zone)" },
    };
    pub const examples = [_][]const u8{ "artoo cf dns ls", "artoo cf dns ls --type CNAME", "artoo cf dns ls -o json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const name_filter = if (args.string("name")) |n| try recordName(ctx, n) else null;
        const type_filter = if (args.string("type")) |t| blk: {
            for (t) |ch| if (!std.ascii.isAlphanumeric(ch)) return ctx.fail(error.Usage, "invalid --type '{s}'", .{t});
            break :blk try std.ascii.allocUpperString(ctx.arena, t);
        } else null;
        var c = try cf.Client.open(ctx);
        defer c.deinit();
        const rs = try records.list(&c, name_filter, type_filter);
        if (ctx.json()) {
            return ui.json.envelope(ctx.out, .cloudflare, rs, .{ .collected_at = ctx.ui.now, .zone = c.zone_name });
        }
        try header(ctx, &c);
        if (rs.len == 0) {
            try ctx.out.print("{s}No records.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
            return;
        }
        const rows = try ctx.arena.alloc([]const ui.table.Cell, rs.len);
        for (rs, rows) |r, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 7);
            cells[0] = .{ .text = try ui.text.sanitize(ctx.arena, r.name, .line) };
            cells[1] = .{ .text = try ui.text.sanitize(ctx.arena, r.type, .line) };
            cells[2] = .{ .text = try ui.text.sanitize(ctx.arena, r.content, .line) };
            cells[3] = .{ .text = if (r.proxied) "yes" else "no", .role = if (r.proxied) .text else .muted };
            cells[4] = .{ .text = try ttlText(ctx, r.ttl) };
            cells[5] = .{ .text = if (r.owned()) "yes" else "--", .role = if (r.owned()) .text else .muted };
            cells[6] = .{ .text = r.id, .role = .id };
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "NAME", .truncate = false },
            .{ .title = "TYPE" },
            .{ .title = "CONTENT" },
            .{ .title = "PROXIED", .drop = 2 },
            .{ .title = "TTL", .alignment = .right, .drop = 1 },
            .{ .title = "ARTOO" },
            .{ .title = "ID", .truncate = false, .drop = 3 },
        }, rows);
    }
};

const AddOp = struct {
    c: *cf.Client,
    rec: records.New,
    target: []const u8,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .cloudflare,
    same_name: []const records.Record = &.{},
    created: ?[]const u8 = null,
    state: []const u8 = "",

    pub fn read(op: *AddOp, ctx: *Context) !void {
        op.same_name = try records.list(op.c, op.rec.name, null);
        var ids: std.ArrayList(u8) = .empty;
        for (op.same_name) |r| try ids.print(ctx.arena, "{s}:{s};", .{ r.id, r.content });
        op.state = ids.items;
    }

    pub fn plan(op: *AddOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        for (op.same_name) |r| {
            const same_type = std.mem.eql(u8, r.type, @tagName(op.rec.type));
            // CNAME excludes every other record at that name, and vice versa.
            if (same_type or op.rec.type == .CNAME or std.mem.eql(u8, r.type, "CNAME")) {
                if (same_type and std.mem.eql(u8, r.content, op.rec.content) and r.proxied == op.rec.proxied) return null;
                return ctx.fail(error.Refused, "{s} already exists{s}; remove it first", .{
                    try recordText(ctx, r), if (r.owned()) "" else " (not created by artoo)",
                });
            }
        }
        const changes = try a.dupe(ui.blocks.Change, &.{
            .{ .field = "record", .from = null, .to = try recordText(ctx, op.rec) },
            .{ .field = "TTL", .from = null, .to = if (op.rec.ttl == records.ttl_auto) "auto" else try std.fmt.allocPrint(a, "{d} s", .{op.rec.ttl}) },
            .{ .field = "comment", .from = null, .to = try ui.text.sanitize(a, op.rec.comment, .line) },
        });
        const impact = try a.dupe([]const u8, &.{
            try std.fmt.allocPrint(a, "Public DNS answers {s} for {s}", .{ @tagName(op.rec.type), op.rec.name }),
        });
        return .{
            .action = try std.fmt.allocPrint(a, "Add Cloudflare record {s} {s}", .{ op.rec.name, @tagName(op.rec.type) }),
            .target = try zoneLabel(ctx, op.c),
            .changes = changes,
            .impact = impact,
            .recovery = try std.fmt.allocPrint(a, "artoo cf dns rm {s} --type {s}", .{ op.rec.name, @tagName(op.rec.type) }),
            .notes = try a.dupe([]const u8, &.{no_lock}),
        };
    }

    pub fn fingerprint(op: *AddOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *AddOp, _: *Context) !void {
        op.created = try records.create(op.c, op.rec);
    }

    pub fn verify(op: *AddOp, _: *Context) !bool {
        const r = (try records.get(op.c, op.created.?)) orelse return false;
        return std.ascii.eqlIgnoreCase(r.name, op.rec.name) and std.mem.eql(u8, r.type, @tagName(op.rec.type)) and
            std.mem.eql(u8, r.content, op.rec.content) and r.owned();
    }

    pub fn done(_: *AddOp) []const u8 {
        return "record added and verified";
    }
};

pub const add = struct {
    pub const name = "add";
    pub const summary = "Add a record to the Cloudflare zone";
    pub const details =
        \\Types A, AAAA, CNAME and TXT; a short NAME gets cloudflare.zone. The
        \\record is marked with the comment 'artoo: NOTE' so artoo may remove it
        \\later. Refused before planning (SPEC §9.6, §15): Proxmox or UniFi by
        \\name or address, LAN/loopback/link-local/Tailscale addresses, and names
        \\under guests.domain (private guest names never go public).
    ;
    pub const positionals = [_]cli.Positional{
        .{ .name = "NAME", .help = "Host name or FQDN in the zone" },
        .{ .name = "TYPE", .help = "A, AAAA, CNAME or TXT" },
        .{ .name = "CONTENT", .help = "Address, target host name or text" },
    };
    pub const flags = [_]cli.Flag{
        .{ .long = "proxied", .help = "Through Cloudflare's proxy (A, AAAA, CNAME)" },
        .{ .long = "ttl", .kind = .int, .metavar = "SECONDS", .default = "1", .help = "1 (auto) or 60-86400" },
        .{ .long = "note", .kind = .string, .metavar = "TEXT", .help = "Purpose, kept in the record's comment" },
    };
    pub const examples = [_][]const u8{
        "artoo cf dns add _artoo-test TXT hello -n",
        "artoo cf dns add www CNAME example.pages.dev --proxied --note 'blog'",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const cfg = try ctx.config();
        const fqdn = try recordName(ctx, args.pos("NAME"));
        const rtype = std.meta.stringToEnum(records.Type, try std.ascii.allocUpperString(ctx.arena, args.pos("TYPE"))) orelse
            return ctx.fail(error.Usage, "TYPE must be A, AAAA, CNAME or TXT, got '{s}'", .{args.pos("TYPE")});
        const content = args.pos("CONTENT");
        if (content.len == 0 or content.len > 2048) return ctx.fail(error.Usage, "CONTENT must be 1-2048 characters", .{});
        switch (rtype) {
            .A => if (!unifi_dns.validIpv4(content)) return ctx.fail(error.Usage, "invalid IPv4 address '{s}'", .{content}),
            .AAAA => if (!records.validIpv6(content)) return ctx.fail(error.Usage, "invalid IPv6 address '{s}'", .{content}),
            .CNAME => if (!unifi_dns.validName(std.mem.trimEnd(u8, content, ".")) or std.ascii.eqlIgnoreCase(std.mem.trimEnd(u8, content, "."), fqdn))
                return ctx.fail(error.Usage, "CNAME target must be another host name, got '{s}'", .{content}),
            .TXT => for (content) |ch| if (ch < 0x20 or ch == 0x7f) return ctx.fail(error.Usage, "TXT content must be printable", .{}),
        }
        const proxied = args.has("proxied");
        if (proxied and rtype == .TXT) return ctx.fail(error.Usage, "--proxied applies to A, AAAA and CNAME only", .{});
        const ttl = args.int("ttl") orelse records.ttl_auto;
        if (ttl != records.ttl_auto and (ttl < records.ttl_min or ttl > records.ttl_max))
            return ctx.fail(error.Usage, "--ttl must be 1 (auto) or {d}-{d}, got {d}", .{ records.ttl_min, records.ttl_max, ttl });
        const note = args.string("note") orelse "";
        if (note.len > 80) return ctx.fail(error.Usage, "--note must be at most 80 characters", .{});
        for (note) |ch| if (ch < 0x20 or ch == 0x7f) return ctx.fail(error.Usage, "--note must be printable", .{});

        // SPEC §9.6 / §15: refused before anything is planned, no override.
        const target_name: ?[]const u8 = if (rtype == .CNAME) content else null;
        if (exposure.protected(try ctx.config(), fqdn, if (rtype == .A or rtype == .AAAA) content else null) orelse
            (if (target_name) |t| exposure.protected(try ctx.config(), t, null) else null)) |why|
            return ctx.fail(error.Refused, "refused: {s}; Proxmox and UniFi are never public (SPEC §9.6)", .{why});
        if ((rtype == .A or rtype == .AAAA) and records.nonPublic(content))
            return ctx.fail(error.Refused, "refused: {s} is not a public address; LAN addresses stay out of public DNS (SPEC §15)", .{content});
        if (target_name) |t| if (exposure.isPrivate(t) or under(std.mem.trimEnd(u8, t, "."), cfg.guests.domain))
            return ctx.fail(error.Refused, "refused: {s} is a private name (SPEC §9.6)", .{t});
        if (under(fqdn, cfg.guests.domain))
            return ctx.fail(error.Refused, "refused: {s} is under {s}; private guest names never go public (public names: 'artoo cf tunnel route add HOST SERVICE')", .{ fqdn, cfg.guests.domain });

        var c = try cf.Client.open(ctx);
        defer c.deinit();
        var op: AddOp = .{
            .c = &c,
            .target = fqdn,
            .rec = .{
                .name = fqdn,
                .type = rtype,
                .content = std.mem.trimEnd(u8, content, if (rtype == .CNAME) "." else ""),
                .proxied = proxied,
                .ttl = @intCast(ttl),
                .comment = if (note.len > 0) try std.fmt.allocPrint(ctx.arena, "{s}: {s}", .{ records.marker, note }) else records.marker,
            },
        };
        try exec.run(ctx, &op, .{});
    }
};

const RmOp = struct {
    c: *cf.Client,
    target: []const u8,
    rtype: ?[]const u8,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .cloudflare,
    found: ?records.Record = null,
    state: []const u8 = "",

    pub fn read(op: *RmOp, ctx: *Context) !void {
        const rs = try records.list(op.c, op.target, op.rtype);
        if (rs.len > 1) {
            var types: std.ArrayList(u8) = .empty;
            for (rs, 0..) |r, i| try types.print(ctx.arena, "{s}{s}", .{ if (i > 0) ", " else "", r.type });
            return ctx.fail(error.Usage, "{s} has {d} records ({s}); choose one with --type", .{ op.target, rs.len, types.items });
        }
        op.found = if (rs.len == 1) rs[0] else null;
        op.state = if (op.found) |r| try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ r.id, r.content }) else "absent";
    }

    pub fn plan(op: *RmOp, ctx: *Context) !?exec.Plan {
        const r = op.found orelse return null;
        if (!r.owned()) return ctx.fail(error.Refused, "{s} was not created by artoo (no 'artoo' comment); artoo leaves it alone (SPEC §15)", .{try recordText(ctx, r)});
        const a = ctx.arena;
        const changes = try a.dupe(ui.blocks.Change, &.{
            .{ .field = "record", .from = try recordText(ctx, r), .to = null },
        });
        const impact = try a.dupe([]const u8, &.{
            try std.fmt.allocPrint(a, "{s} stops resolving publicly (caches may hold it up to its TTL)", .{op.target}),
        });
        const proxied: []const u8 = if (r.proxied) " --proxied" else "";
        return .{
            .action = try std.fmt.allocPrint(a, "Delete Cloudflare record {s} {s}", .{ op.target, r.type }),
            .risk = .destructive,
            .target = try zoneLabel(ctx, op.c),
            .changes = changes,
            .impact = impact,
            .recovery = try std.fmt.allocPrint(a, "artoo cf dns add {s} {s} '{s}'{s}", .{ op.target, r.type, try ui.text.sanitize(a, r.content, .line), proxied }),
            .notes = try a.dupe([]const u8, &.{no_lock}),
        };
    }

    pub fn fingerprint(op: *RmOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *RmOp, _: *Context) !void {
        try records.delete(op.c, op.found.?.id);
    }

    pub fn verify(op: *RmOp, _: *Context) !bool {
        return (try records.get(op.c, op.found.?.id)) == null;
    }

    pub fn done(_: *RmOp) []const u8 {
        return "record removed and verified";
    }
};

pub const rm = struct {
    pub const name = "rm";
    pub const summary = "Delete a record artoo created (destructive)";
    pub const details =
        \\Only records marked with an 'artoo' comment. Interactive: type the
        \\record's full name to confirm. Non-interactive: --yes --confirm FQDN.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "NAME", .help = "Host name or FQDN in the zone" }};
    pub const flags = [_]cli.Flag{
        .{ .long = "type", .kind = .string, .metavar = "T", .help = "Record type, when NAME has several" },
        .{ .long = "confirm", .kind = .string, .metavar = "FQDN", .help = "Non-interactive confirmation (with --yes)" },
    };
    pub const examples = [_][]const u8{
        "artoo cf dns rm _artoo-test",
        "artoo cf dns rm _artoo-test --yes --confirm _artoo-test.example.com",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const fqdn = try recordName(ctx, args.pos("NAME"));
        const rtype = if (args.string("type")) |t| try std.ascii.allocUpperString(ctx.arena, t) else null;
        var c = try cf.Client.open(ctx);
        defer c.deinit();
        var op: RmOp = .{ .c = &c, .target = fqdn, .rtype = rtype };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const group = cli.group("cf", "Cloudflare: public DNS of the zone and the lab's tunnel (SPEC §15)", &.{
    cli.group("dns", "Records of cloudflare.zone", &.{
        cli.leaf(ls),
        cli.leaf(add),
        cli.leaf(rm),
    }),
    @import("cf_tunnel.zig").group,
});

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Exit = @import("../testkit.zig").Exit;
const Fixture = @import("../testkit.zig").Gateway;
const root = cli.group("artoo", "test", &.{group});

const zones_body =
    \\{"success":true,"errors":[],"messages":[],"result":[{"id":"Z1","name":"example.com","account":{"id":"A1"}}],"result_info":{"page":1,"per_page":100,"count":1,"total_count":1}}
;
const two_records =
    \\{"success":true,"errors":[],"messages":[],"result":[
    \\{"id":"D1","name":"example.com","type":"MX","content":"mx.example.net","proxied":false,"ttl":1,"comment":null},
    \\{"id":"D2","name":"_artoo-test.example.com","type":"TXT","content":"hello","proxied":false,"ttl":1,"comment":"artoo: live test"}],
    \\"result_info":{"page":1,"per_page":100,"count":2,"total_count":2}}
;
const none =
    \\{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":100,"count":0,"total_count":0}}
;
const test_txt =
    \\{"success":true,"errors":[],"messages":[],"result":[
    \\{"id":"D2","name":"_artoo-test.example.com","type":"TXT","content":"hello","proxied":false,"ttl":1,"comment":"artoo: live test"}],
    \\"result_info":{"page":1,"per_page":100,"count":1,"total_count":1}}
;
const foreign_www =
    \\{"success":true,"errors":[],"messages":[],"result":[
    \\{"id":"D3","name":"www.example.com","type":"CNAME","content":"example.pages.dev","proxied":true,"ttl":1,"comment":""}],
    \\"result_info":{"page":1,"per_page":100,"count":1,"total_count":1}}
;

fn ok(body: []const u8) Fixture.FakeServer.Behavior {
    return .{ .respond = .{ .body = body } };
}

test "cf dns ls: every record, artoo-owned marked; zone resolved by name" {
    var f: Fixture = undefined;
    try f.init(&.{ ok(zones_body), ok(two_records) });
    defer f.deinit();
    try testing.expectEqual(Exit.ok, f.h.run(&root, "cf dns ls"));
    try testing.expectEqualStrings("GET /zones?name=example.com&page=1&per_page=100 HTTP/1.1", f.request(0));
    try testing.expectEqualStrings("GET /zones/Z1/dns_records?page=1&per_page=100 HTTP/1.1", f.request(1));
    const out = f.h.stdout();
    for ([_][]const u8{
        "NAME                     TYPE  CONTENT         PROXIED   TTL  ARTOO  ID\n",
        "example.com              MX    mx.example.net  no       auto  --     D1\n",
        "_artoo-test.example.com  TXT   hello           no       auto  yes    D2\n",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
    // The token travels only as a header.
    for (f.srv.received) |req| if (req) |q| try testing.expect(std.mem.find(u8, q, "Bearer test-token") != null);
}

test "cf dns add: dry run, then one POST with the marked body and a verifying read" {
    var f: Fixture = undefined;
    try f.init(&.{
        ok(zones_body),                                                                    ok(none),
        ok(zones_body),                                                                    ok(none),
        ok("{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"D9\"}}"), ok("{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"D9\",\"name\":\"_artoo-test.example.com\",\"type\":\"TXT\",\"content\":\"hello\",\"proxied\":false,\"ttl\":1,\"comment\":\"artoo: live test\"}}"),
    });
    defer f.deinit();
    try testing.expectEqual(Exit.ok, f.h.run(&root, "cf dns add _artoo-test TXT hello --note live-test -n"));
    try testing.expectEqualStrings(
        \\Plan · Add Cloudflare record _artoo-test.example.com TXT
        \\  Target    Cloudflare (zone example.com)
        \\  Change    record   (none) → _artoo-test.example.com TXT → hello
        \\            TTL      (none) → auto
        \\            comment  (none) → artoo: live-test
        \\  Impact    Public DNS answers TXT for _artoo-test.example.com
        \\  Recovery  artoo cf dns rm _artoo-test.example.com --type TXT
        \\  Note      Cloudflare has no record locking; concurrent edits cannot be detected.
        \\
        \\Dry run: nothing was sent.
        \\
    , f.h.stdout());
    try testing.expectEqualStrings("GET /zones/Z1/dns_records?name.exact=_artoo-test.example.com&page=1&per_page=100 HTTP/1.1", f.request(1));
    try testing.expectEqual(Exit.ok, f.h.run(&root, "cf dns add _artoo-test TXT hello --note live-test -y"));
    try testing.expectEqualStrings("POST /zones/Z1/dns_records HTTP/1.1", f.request(4));
    try testing.expectEqualStrings(
        \\{"name":"_artoo-test.example.com","type":"TXT","content":"hello","proxied":false,"ttl":1,"comment":"artoo: live-test"}
    , f.body(4));
    try testing.expectEqualStrings("GET /zones/Z1/dns_records/D9 HTTP/1.1", f.request(5));
    try testing.expect(std.mem.endsWith(u8, f.h.stdout(), "✓ record added and verified\n"));
}

test "cf dns add: hard rule, LAN addresses, private names and conflicts are refused" {
    var f: Fixture = undefined;
    try f.init(&.{ ok(zones_body), ok(foreign_www) });
    defer f.deinit();
    // Refused before any request (exit 5).
    for ([_][]const u8{
        "cf dns add pve A 1.2.3.4 -y",
        "cf dns add www CNAME unifi.home.arpa -y",
        "cf dns add www A 192.168.1.210 -y",
        "cf dns add www A 100.101.102.103 -y",
        "cf dns add www AAAA fd7a:115c:a1e0::1 -y",
        "cf dns add web-01.lab.example.com A 1.2.3.4 -y",
        "cf dns add www CNAME web-01.lab.example.com -y",
    }) |cmd| {
        if (f.h.run(&root, cmd) != Exit.refused) {
            std.debug.print("not refused: {s}\n{s}\n", .{ cmd, f.h.stderr() });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(@as(usize, 0), f.sent());
    // Local validation (exit 2).
    try testing.expectEqual(Exit.usage, f.h.run(&root, "cf dns add www MX mail.example.net"));
    try testing.expectEqual(Exit.usage, f.h.run(&root, "cf dns add www A 1.2.3"));
    try testing.expectEqual(Exit.usage, f.h.run(&root, "cf dns add www A 1.2.3.4 --ttl 30"));
    try testing.expectEqual(Exit.usage, f.h.run(&root, "cf dns add www.example.org A 1.2.3.4"));
    try testing.expectEqual(Exit.usage, f.h.run(&root, "cf dns add www TXT hi --proxied"));
    try testing.expectEqual(@as(usize, 0), f.sent());
    // An existing record at that name (not artoo's): refused after the read.
    try testing.expectEqual(Exit.refused, f.h.run(&root, "cf dns add www A 1.2.3.4 -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "not created by artoo") != null);
    try testing.expectEqual(@as(usize, 2), f.sent());
}

test "cf dns rm: only artoo's records, typed confirmation, DELETE verified by 404" {
    var f: Fixture = undefined;
    try f.init(&.{
        ok(zones_body),                                                                    ok(foreign_www),
        ok(zones_body),                                                                    ok(test_txt),
        ok(zones_body),                                                                    ok(test_txt),
        ok("{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"D2\"}}"), .{ .respond = .{ .status = 404, .body = "{\"success\":false,\"errors\":[{\"code\":81044,\"message\":\"Record does not exist.\"}],\"messages\":[],\"result\":null}" } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.refused, f.h.run(&root, "cf dns rm www -y --confirm www.example.com"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "was not created by artoo") != null);
    try testing.expectEqual(Exit.refused, f.h.run(&root, "cf dns rm _artoo-test -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "--confirm _artoo-test.example.com") != null);
    try testing.expectEqual(Exit.ok, f.h.run(&root, "cf dns rm _artoo-test -y --confirm _artoo-test.example.com"));
    try testing.expectEqualStrings("DELETE /zones/Z1/dns_records/D2 HTTP/1.1", f.request(6));
    try testing.expect(std.mem.endsWith(u8, f.h.stdout(), "✓ record removed and verified\n"));
}

test "cf: Cloudflare's error messages reach the user; 403 names the permission" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .status = 403, .body = "{\"success\":false,\"errors\":[{\"code\":10000,\"message\":\"Authentication error\"}],\"messages\":[],\"result\":null}" } },
        ok("{\"success\":true,\"errors\":[],\"messages\":[],\"result\":[],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":0,\"total_count\":0}}"),
    });
    defer f.deinit();
    try testing.expectEqual(Exit.auth, f.h.run(&root, "cf dns ls"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "Authentication error") != null);
    try testing.expect(std.mem.find(u8, f.h.stderr(), "SPEC §15") != null);
    try testing.expectEqual(Exit.usage, f.h.run(&root, "cf dns ls"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "Zone → Zone → Read") != null);
}
