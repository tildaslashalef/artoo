//! `artoo dns ls|add|rm` (SPEC §10.3): A records on UniFi, written
//! through the one mutation pipeline (`exec.zig`). Short names get
//! `guests.domain`; dotted names are taken as given.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const exposure = @import("../exposure.zig");
const ui = @import("../ui.zig");
const unifi = @import("../unifi/client.zig");
const dns = @import("../unifi/dns.zig");
const gw = @import("gw.zig");

const Context = app.Context;

const no_etags = "The UniFi API has no ETags; concurrent edits cannot be detected.";

fn recordName(ctx: *Context, word: []const u8) ![]const u8 {
    const cfg = try ctx.config();
    return dns.fqdn(ctx.arena, word, cfg.guests.domain) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.InvalidName => ctx.fail(error.Usage, "invalid DNS name '{s}': labels of letters, digits and '-', at most {d} characters", .{ word, dns.max_domain }),
    };
}

fn siteLabel(ctx: *Context, c: *const unifi.Client) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "UniFi (site {s})", .{try ui.text.sanitize(ctx.arena, c.site_name orelse c.site, .line)});
}

fn recordText(ctx: *Context, domain: []const u8, ipv4: []const u8) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "{s} {s} {s}", .{
        try ui.text.sanitize(ctx.arena, domain, .line), ctx.ui.glyphs.arrow, try ui.text.sanitize(ctx.arena, ipv4, .line),
    });
}

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "List A records on UniFi";
    pub const details = "Other DNS policy types are listed by 'artoo gw dns-policies ls'.";
    pub const examples = [_][]const u8{ "artoo dns ls", "artoo dns ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try unifi.Client.open(ctx);
        defer c.deinit();
        const records = try dns.list(&c);
        if (ctx.json()) {
            return ui.json.envelope(ctx.out, .unifi, records, .{ .collected_at = ctx.ui.now, .site = c.site_name orelse c.site });
        }
        try gw.header(ctx, &c);
        if (records.len == 0) {
            try ctx.out.print("{s}No A records.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
            return;
        }
        const rows = try ctx.arena.alloc([]const ui.table.Cell, records.len);
        for (records, rows) |r, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 5);
            cells[0] = .{ .text = try ui.text.sanitize(ctx.arena, r.domain, .line) };
            cells[1] = .{ .text = try ui.text.sanitize(ctx.arena, r.ipv4, .line) };
            cells[2] = .{ .text = if (r.ttl) |t| try std.fmt.allocPrint(ctx.arena, "{d}", .{t}) else "--" };
            cells[3] = .{ .text = if (r.enabled) "yes" else "no", .role = if (r.enabled) .text else .muted };
            cells[4] = .{ .text = r.id };
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "NAME", .truncate = false },
            .{ .title = "ADDRESS", .truncate = false },
            .{ .title = "TTL", .alignment = .right, .drop = 1 },
            .{ .title = "ENABLED" },
            .{ .title = "ID", .truncate = false, .drop = 2 },
        }, rows);
    }
};

const AddOp = struct {
    c: *unifi.Client,
    target: []const u8,
    ipv4: []const u8,
    ttl: u32,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .unifi,
    existing: ?dns.ARecord = null,
    /// Other names already pointing at the address.
    same_address: []const []const u8 = &.{},
    state: []const u8 = "",

    pub fn read(op: *AddOp, ctx: *Context) !void {
        const records = try dns.list(op.c);
        op.existing = dns.find(records, op.target);
        var others: std.ArrayList([]const u8) = .empty;
        for (records) |r| {
            if (std.mem.eql(u8, r.ipv4, op.ipv4) and !std.ascii.eqlIgnoreCase(r.domain, op.target)) {
                try others.append(ctx.arena, try ui.text.sanitize(ctx.arena, r.domain, .line));
            }
        }
        op.same_address = others.items;
        op.state = if (op.existing) |e| try std.fmt.allocPrint(ctx.arena, "{s} {s} {}", .{ e.id, e.ipv4, e.enabled }) else "absent";
    }

    pub fn plan(op: *AddOp, ctx: *Context) !?exec.Plan {
        if (op.existing) |e| {
            if (std.mem.eql(u8, e.ipv4, op.ipv4) and e.enabled) return null;
            return ctx.fail(error.Refused, "{s} already exists ({s}{s}); remove it first with 'artoo dns rm {s}'", .{
                try recordText(ctx, e.domain, e.ipv4), if (e.enabled) "enabled" else "disabled", "", op.target,
            });
        }
        var notes: std.ArrayList([]const u8) = .empty;
        if (op.same_address.len > 0) {
            try notes.append(ctx.arena, try std.fmt.allocPrint(ctx.arena, "Also pointing at {s}: {s}", .{ op.ipv4, try std.mem.join(ctx.arena, ", ", op.same_address) }));
        }
        try notes.append(ctx.arena, no_etags);
        const changes = try ctx.arena.dupe(ui.blocks.Change, &.{
            .{ .field = "A record", .from = null, .to = try recordText(ctx, op.target, op.ipv4) },
            .{ .field = "TTL", .from = null, .to = try std.fmt.allocPrint(ctx.arena, "{d} s", .{op.ttl}) },
        });
        const impact = try ctx.arena.dupe([]const u8, &.{
            try std.fmt.allocPrint(ctx.arena, "Clients that use UniFi for DNS resolve {s} to {s}", .{ op.target, op.ipv4 }),
        });
        return .{
            .action = try std.fmt.allocPrint(ctx.arena, "Add DNS record {s}", .{op.target}),
            .target = try siteLabel(ctx, op.c),
            .changes = changes,
            .impact = impact,
            .recovery = try std.fmt.allocPrint(ctx.arena, "artoo dns rm {s}", .{op.target}),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *AddOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *AddOp, _: *Context) !void {
        try dns.create(op.c, op.target, op.ipv4, op.ttl);
    }

    pub fn verify(op: *AddOp, _: *Context) !bool {
        const r = dns.find(try dns.list(op.c), op.target) orelse return false;
        return std.mem.eql(u8, r.ipv4, op.ipv4) and r.enabled;
    }

    pub fn done(_: *AddOp) []const u8 {
        return "record added and verified";
    }
};

pub const add = struct {
    pub const name = "add";
    pub const summary = "Add an A record on UniFi";
    pub const details =
        \\NAME without a dot gets guests.domain (lab.example.com by default).
        \\Names or addresses of Proxmox and UniFi are refused outside
        \\home.arpa (SPEC §9.6). An existing record with another address is
        \\refused; remove it first.
    ;
    pub const positionals = [_]cli.Positional{
        .{ .name = "NAME", .help = "Host name or FQDN" },
        .{ .name = "IP", .help = "IPv4 address" },
    };
    pub const flags = [_]cli.Flag{
        .{ .long = "ttl", .kind = .int, .metavar = "SECONDS", .default = "300", .help = "Record TTL (0-86400)" },
    };
    pub const examples = [_][]const u8{
        "artoo dns add web-01 192.168.1.201 --dry-run",
        "artoo dns add nas.home.arpa 192.168.1.90 --ttl 3600",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const fqdn = try recordName(ctx, args.pos("NAME"));
        const ip = args.pos("IP");
        if (!dns.validIpv4(ip)) return ctx.fail(error.Usage, "invalid IPv4 address '{s}'", .{ip});
        const ttl = args.int("ttl") orelse dns.default_ttl;
        if (ttl < 0 or ttl > dns.max_ttl) return ctx.fail(error.Usage, "--ttl must be 0-{d}, got {d}", .{ dns.max_ttl, ttl });
        if (!exposure.isPrivate(fqdn)) {
            if (exposure.protected(try ctx.config(), fqdn, ip)) |why| return ctx.fail(error.Refused, "refused: {s}; Proxmox and UniFi keep home.arpa names only (SPEC §9.6)", .{why});
        }
        var c = try unifi.Client.open(ctx);
        defer c.deinit();
        var op: AddOp = .{ .c = &c, .target = fqdn, .ipv4 = ip, .ttl = @intCast(ttl) };
        try exec.run(ctx, &op, .{});
    }
};

const RmOp = struct {
    c: *unifi.Client,
    target: []const u8,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .unifi,
    existing: ?dns.ARecord = null,
    state: []const u8 = "",

    pub fn read(op: *RmOp, ctx: *Context) !void {
        op.existing = dns.find(try dns.list(op.c), op.target);
        op.state = if (op.existing) |e| try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ e.id, e.ipv4 }) else "absent";
    }

    pub fn plan(op: *RmOp, ctx: *Context) !?exec.Plan {
        const e = op.existing orelse return null;
        const ttl = e.ttl orelse 0;
        const changes = try ctx.arena.dupe(ui.blocks.Change, &.{
            .{ .field = "A record", .from = try recordText(ctx, e.domain, e.ipv4), .to = null },
        });
        const impact = try ctx.arena.dupe([]const u8, &.{
            try std.fmt.allocPrint(ctx.arena, "{s} stops resolving through UniFi", .{op.target}),
            try std.fmt.allocPrint(ctx.arena, "Clients may keep a cached answer for up to {d} s", .{ttl}),
        });
        const notes = try ctx.arena.dupe([]const u8, &.{no_etags});
        return .{
            .action = try std.fmt.allocPrint(ctx.arena, "Delete DNS record {s}", .{op.target}),
            .risk = .destructive,
            .target = try siteLabel(ctx, op.c),
            .changes = changes,
            .impact = impact,
            .recovery = try std.fmt.allocPrint(ctx.arena, "artoo dns add {s} {s} --ttl {d}", .{ op.target, try ui.text.sanitize(ctx.arena, e.ipv4, .line), ttl }),
            .notes = notes,
        };
    }

    pub fn fingerprint(op: *RmOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *RmOp, _: *Context) !void {
        try dns.delete(op.c, op.existing.?.id);
    }

    pub fn verify(op: *RmOp, _: *Context) !bool {
        return dns.find(try dns.list(op.c), op.target) == null;
    }

    pub fn done(_: *RmOp) []const u8 {
        return "record removed and verified";
    }
};

pub const rm = struct {
    pub const name = "rm";
    pub const summary = "Delete an A record on UniFi (destructive)";
    pub const details =
        \\Interactive: type the record's full name to confirm. Non-interactive:
        \\--yes --confirm FQDN. A missing record changes nothing (exit 5).
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "NAME", .help = "Host name or FQDN" }};
    pub const flags = [_]cli.Flag{
        .{ .long = "confirm", .kind = .string, .metavar = "FQDN", .help = "Non-interactive confirmation (with --yes)" },
    };
    pub const examples = [_][]const u8{
        "artoo dns rm web-01",
        "artoo dns rm web-01 --yes --confirm web-01.lab.example.com",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const fqdn = try recordName(ctx, args.pos("NAME"));
        var c = try unifi.Client.open(ctx);
        defer c.deinit();
        var op: RmOp = .{ .c = &c, .target = fqdn };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const group = cli.group("dns", "A records on UniFi (shortcut for gw dns-policies)", &.{
    cli.leaf(ls),
    cli.leaf(add),
    cli.leaf(rm),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Harness = @import("../testkit.zig").Harness;
const Exit = @import("../testkit.zig").Exit;
const root = cli.group("artoo", "test", &.{group});

const sites_body =
    \\{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"S1","internalReference":"default","name":"Default"}]}
;
const one_record =
    \\{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
    \\{"type":"A_RECORD","id":"R1","enabled":true,"domain":"pve.home.arpa","ipv4Address":"192.168.1.10","ttlSeconds":0},
    \\{"type":"CNAME_RECORD","id":"R9","enabled":true,"domain":"alias.home.arpa","targetDomain":"pve.home.arpa"}]}
;
const with_web =
    \\{"offset":0,"limit":200,"count":2,"totalCount":2,"data":[
    \\{"type":"A_RECORD","id":"R1","enabled":true,"domain":"pve.home.arpa","ipv4Address":"192.168.1.10","ttlSeconds":0},
    \\{"type":"A_RECORD","id":"R2","enabled":true,"domain":"web-01.lab.example.com","ipv4Address":"192.168.1.201","ttlSeconds":300}]}
;

const Fixture = @import("../testkit.zig").Gateway;

test "dns ls: A records only" {
    var f: Fixture = undefined;
    try f.init(&.{ .{ .respond = .{ .body = sites_body } }, .{ .respond = .{ .body = one_record } } });
    defer f.deinit();
    try testing.expectEqual(Exit.ok, f.h.run(&root, "dns ls"));
    const out = f.h.stdout();
    try testing.expect(std.mem.find(u8, out,
        \\NAME           ADDRESS       TTL  ENABLED  ID
        \\pve.home.arpa  192.168.1.10    0  yes      R1
        \\
    ) != null);
    try testing.expect(std.mem.find(u8, out, "alias") == null);
}

test "dns add: dry run plans and sends no write" {
    var f: Fixture = undefined;
    try f.init(&.{ .{ .respond = .{ .body = sites_body } }, .{ .respond = .{ .body = one_record } } });
    defer f.deinit();
    try testing.expectEqual(Exit.ok, f.h.run(&root, "dns add web-01 192.168.1.201 -n"));
    try testing.expectEqual(@as(usize, 2), f.sent());
    try testing.expectEqualStrings(
        \\Plan · Add DNS record web-01.lab.example.com
        \\  Target    UniFi (site Default)
        \\  Change    A record  (none) → web-01.lab.example.com → 192.168.1.201
        \\            TTL       (none) → 300 s
        \\  Impact    Clients that use UniFi for DNS resolve web-01.lab.example.com to 192.168.1.201
        \\  Recovery  artoo dns rm web-01.lab.example.com
        \\  Note      The UniFi API has no ETags; concurrent edits cannot be detected.
        \\
        \\Dry run: nothing was sent.
        \\
    , f.h.stdout());
}

test "dns add --yes: one POST with the typed body, then a verifying read" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = one_record } },
        .{ .respond = .{ .status = 201, .body = "{}" } },
        .{ .respond = .{ .body = with_web } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.ok, f.h.run(&root, "dns add web-01 192.168.1.201 -y"));
    try testing.expectEqualStrings("POST /v1/sites/S1/dns/policies HTTP/1.1", f.request(2));
    try testing.expectEqualStrings(
        \\{"type":"A_RECORD","enabled":true,"domain":"web-01.lab.example.com","ipv4Address":"192.168.1.201","ttlSeconds":300}
    , f.body(2));
    try testing.expect(std.mem.endsWith(u8, f.h.stdout(), "✓ record added and verified\n"));
}

test "dns add: no-op, conflicts and protected targets are refused" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = with_web } },
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = with_web } },
    });
    defer f.deinit();
    // Identical record: nothing to change.
    try testing.expectEqual(Exit.refused, f.h.run(&root, "dns add web-01 192.168.1.201 -y"));
    // Same name, other address.
    try testing.expectEqual(Exit.refused, f.h.run(&root, "dns add web-01 192.168.1.202 -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "already exists") != null);
    try testing.expectEqual(@as(usize, 4), f.sent());
    // Protected names/addresses outside home.arpa: refused before any request.
    try testing.expectEqual(Exit.refused, f.h.run(&root, "dns add pve 192.168.1.50 -y"));
    try testing.expectEqual(Exit.refused, f.h.run(&root, "dns add web-02 192.168.1.1 -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "SPEC §9.6") != null);
    // Local validation.
    try testing.expectEqual(Exit.usage, f.h.run(&root, "dns add web_02 192.168.1.50"));
    try testing.expectEqual(Exit.usage, f.h.run(&root, "dns add web-02 192.168.1.500"));
    try testing.expectEqual(Exit.usage, f.h.run(&root, "dns add web-02 192.168.1.50 --ttl 90000"));
    try testing.expectEqual(@as(usize, 4), f.sent());
}

test "dns add: write outcomes — lost response and 5xx are unknown (exit 7), never retried" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = one_record } },
        .drop_after_request,
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = one_record } },
        .{ .respond = .{ .status = 502, .body = "{\"message\":\"bad gateway\"}" } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.unknown, f.h.run(&root, "dns add web-01 192.168.1.201 -y"));
    try testing.expectEqual(Exit.unknown, f.h.run(&root, "dns add web-01 192.168.1.201 -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "may or may not have applied") != null);
    try testing.expectEqual(@as(usize, 6), f.sent());
}

test "dns rm: destructive confirmation, then one DELETE and a verifying read" {
    var f: Fixture = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = with_web } },
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = with_web } },
        .{ .respond = .{ .body = "" } },
        .{ .respond = .{ .body = one_record } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.refused, f.h.run(&root, "dns rm web-01 -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "--confirm web-01.lab.example.com") != null);
    try testing.expectEqual(Exit.ok, f.h.run(&root, "dns rm web-01 -y --confirm web-01.lab.example.com"));
    try testing.expectEqualStrings("DELETE /v1/sites/S1/dns/policies/R2 HTTP/1.1", f.request(4));
    try testing.expect(std.mem.find(u8, f.h.stdout(), "Recovery  artoo dns add web-01.lab.example.com 192.168.1.201 --ttl 300") != null);
    try testing.expectEqual(@as(usize, 6), f.sent());
}

test "dns rm: a missing record changes nothing" {
    var f: Fixture = undefined;
    try f.init(&.{ .{ .respond = .{ .body = sites_body } }, .{ .respond = .{ .body = one_record } } });
    defer f.deinit();
    try testing.expectEqual(Exit.refused, f.h.run(&root, "dns rm web-01 -y --confirm web-01.lab.example.com"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "nothing to change") != null);
}
