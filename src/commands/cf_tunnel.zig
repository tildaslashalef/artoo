//! `artoo cf tunnel ls | route add | route rm` (SPEC §15): public names
//! through the lab's Cloudflare Tunnel. A public host always reaches an
//! existing service (§9.6): Cloudflare → cloudflared on the edge VM →
//! Caddy on localhost → the service's route → guest. Each route is an
//! ingress rule plus a marked, proxied CNAME to the tunnel.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const exposure = @import("../exposure.zig");
const ui = @import("../ui.zig");
const cf = @import("../cloudflare/client.zig");
const records = @import("../cloudflare/dns.zig");
const tunnels = @import("../cloudflare/tunnel.zig");
const pve = @import("../pve/client.zig");
const cf_cmd = @import("cf.zig");
const svc = @import("svc.zig");
const watch = @import("watch.zig");
const vm_cmd = @import("vm.zig");
const vms = @import("../pve/vm.zig");

/// The search gateway's role (SPEC §9.9): unauthenticated search and
/// fetch, so never public.
pub const search_role = "search";

const Context = app.Context;

fn labTunnel(ctx: *Context, c: *cf.Client) !tunnels.Tunnel {
    const name = (try ctx.config()).cloudflare.tunnel;
    return (try tunnels.find(c, name)) orelse
        ctx.fail(error.NotFound, "no Cloudflare Tunnel '{s}' (cloudflare.tunnel); create it with 'artoo edge tunnel'", .{name});
}

fn cnameTarget(a: std.mem.Allocator, t: tunnels.Tunnel) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}.cfargotunnel.com", .{t.id});
}

/// The service a rule points at (`grafana` for `grafana.apps.<domain>`).
fn serviceOf(r: tunnels.Route, d: svc.Domains) ?[]const u8 {
    const h = r.serviceHost() orelse return null;
    if (h.len <= d.apps.len + 1 or !std.ascii.endsWithIgnoreCase(h, d.apps) or h[h.len - d.apps.len - 1] != '.') return null;
    return h[0 .. h.len - d.apps.len - 1];
}

/// Public hosts whose route reaches service `name` (for `svc rm`); `note`
/// is set when Cloudflare could not be read.
pub fn routesTo(ctx: *Context, name: []const u8) !svc.Usage {
    const p = try publicRoutes(ctx);
    return .{ .names = try p.hostsFor(ctx.arena, name), .note = p.note };
}

/// The lab tunnel's routes; `note` is set when Cloudflare could not be
/// read. No tunnel means no routes.
pub const Public = struct {
    routes: []const tunnels.Route = &.{},
    d: svc.Domains = .{ .apps = "", .guests = "" },
    note: ?[]const u8 = null,

    /// Public hosts that reach service `name`.
    pub fn hostsFor(p: Public, a: std.mem.Allocator, name: []const u8) ![]const []const u8 {
        var hosts: std.ArrayList([]const u8) = .empty;
        for (p.routes) |r| {
            if (serviceOf(r, p.d)) |s| if (std.mem.eql(u8, s, name)) try hosts.append(a, r.hostname);
        }
        return hosts.items;
    }
};

pub fn publicRoutes(ctx: *Context) !Public {
    const d = try svc.domains(ctx);
    var c = cf.Client.open(ctx) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return soft(ctx, err),
    };
    defer c.deinit();
    const t = (tunnels.find(&c, (try ctx.config()).cloudflare.tunnel) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return soft(ctx, err),
    }) orelse return .{ .d = d };
    const conf = tunnels.getConfig(&c, t.id) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return soft(ctx, err),
    };
    return .{ .routes = try tunnels.routes(ctx.arena, conf.config), .d = d };
}

fn soft(ctx: *Context, err: anyerror) !Public {
    const note = try std.fmt.allocPrint(ctx.arena, "Public routes not checked: {s}", .{ctx.diag orelse @errorName(err)});
    ctx.diag = null;
    return .{ .note = note };
}

// ---------------------------------------------------------------- ls

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "The account's tunnels and the lab tunnel's public routes";
    pub const examples = [_][]const u8{ "artoo cf tunnel ls", "artoo cf tunnel ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        const a = ctx.arena;
        const cfg = try ctx.config();
        const d = try svc.domains(ctx);
        var c = try cf.Client.open(ctx);
        defer c.deinit();
        const all = try tunnels.list(&c);
        var lab: ?tunnels.Tunnel = null;
        for (all) |t| if (std.mem.eql(u8, t.name, cfg.cloudflare.tunnel)) {
            lab = t;
        };
        const RouteRow = struct { host: []const u8, service: []const u8, record: bool };
        var rows: std.ArrayList(RouteRow) = .empty;
        if (lab) |t| {
            const conf = try tunnels.getConfig(&c, t.id);
            const target = try cnameTarget(a, t);
            for (try tunnels.routes(a, conf.config)) |r| {
                var record = false;
                for (try records.list(&c, r.hostname, "CNAME")) |rec| {
                    if (std.ascii.eqlIgnoreCase(rec.content, target)) record = true;
                }
                try rows.append(a, .{
                    .host = try ui.text.sanitize(a, r.hostname, .line),
                    .service = if (serviceOf(r, d)) |s| try std.fmt.allocPrint(a, "svc {s}", .{s}) else try ui.text.sanitize(a, r.service, .line),
                    .record = record,
                });
            }
        }
        if (ctx.json()) return ui.json.envelope(ctx.out, .cloudflare, .{ .tunnels = all, .routes = rows.items }, .{ .collected_at = ctx.ui.now, .tunnel = cfg.cloudflare.tunnel });
        try ui.blocks.header(ctx.out, &ctx.ui, ctx.path, try cf_cmd.zoneLabel(ctx, &c));
        if (all.len == 0) {
            try ctx.out.print("{s}No tunnels. Create the lab's with 'artoo edge tunnel'.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
            return;
        }
        const trows = try a.alloc([]const ui.table.Cell, all.len);
        for (all, trows) |t, *row| {
            const cs = try a.alloc(ui.table.Cell, 4);
            cs[0] = .{ .text = try ui.text.sanitize(a, t.name, .line) };
            cs[1] = .{ .text = try ui.text.sanitize(a, t.status, .line), .role = if (std.mem.eql(u8, t.status, "healthy")) .ok else .warn };
            cs[2] = .{ .text = try std.fmt.allocPrint(a, "{d}", .{t.connections}) };
            cs[3] = .{ .text = t.id };
            row.* = cs;
        }
        try ui.table.render(ctx.out, &ctx.ui, a, &.{
            .{ .title = "TUNNEL", .truncate = false },
            .{ .title = "STATUS" },
            .{ .title = "CONNECTIONS", .alignment = .right },
            .{ .title = "ID", .truncate = false, .drop = 1 },
        }, trows);
        if (lab == null) {
            try ctx.out.print("\n{s}No tunnel '{s}' (cloudflare.tunnel); create it with 'artoo edge tunnel'.{s}\n", .{ ctx.ui.palette.on(.muted), cfg.cloudflare.tunnel, ctx.ui.palette.off(.muted) });
            return;
        }
        try ctx.out.writeAll("\n");
        if (rows.items.len == 0) {
            try ctx.out.print("{s}No public routes. Add one with 'artoo cf tunnel route add HOST SERVICE'.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
            return;
        }
        const rrows = try a.alloc([]const ui.table.Cell, rows.items.len);
        for (rows.items, rrows) |r, *row| {
            const cs = try a.alloc(ui.table.Cell, 3);
            cs[0] = .{ .text = r.host };
            cs[1] = .{ .text = r.service };
            cs[2] = .{ .text = if (r.record) "yes" else "missing", .role = if (r.record) .text else .warn };
            row.* = cs;
        }
        try ui.table.render(ctx.out, &ctx.ui, a, &.{
            .{ .title = "PUBLIC HOST", .truncate = false },
            .{ .title = "ROUTE", .truncate = false },
            .{ .title = "RECORD" },
        }, rrows);
    }
};

// ---------------------------------------------------------------- route add / rm

const AddOp = struct {
    c: *cf.Client,
    pc: *pve.Client,
    host: []const u8,
    service: []const u8,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .cloudflare,
    target: []const u8 = "",
    service_host: []const u8 = "",
    tunnel: tunnels.Tunnel = undefined,
    conf: tunnels.Config = undefined,
    cname: []const u8 = "",
    put_route: bool = false,
    add_record: bool = false,
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *AddOp, ctx: *Context) !void {
        const a = ctx.arena;
        op.target = op.host;
        const d = try svc.domains(ctx);
        op.service_host = try svc.fqdn(ctx, d, op.service);
        const view = try svc.read(ctx, op.pc);
        const route = view.find(op.service) orelse
            return ctx.fail(error.NotFound, "no service {s}; add it first with 'artoo svc add {s} VM:PORT'", .{ op.service, op.service });
        if (!route.managed()) return ctx.fail(error.Refused, "service {s} was not written by artoo or was edited by hand; fix it first", .{op.service});
        try refuseNeverPublic(ctx, op.pc, op.service, route.vm);
        op.tunnel = try labTunnel(ctx, op.c);
        op.cname = try cnameTarget(a, op.tunnel);
        op.conf = try tunnels.getConfig(op.c, op.tunnel.id);
        const existing = tunnels.findRoute(try tunnels.routes(a, op.conf.config), op.host);
        if (existing) |r| {
            const to = r.serviceHost() orelse "";
            if (!std.ascii.eqlIgnoreCase(to, op.service_host))
                return ctx.fail(error.Refused, "{s} already routes to {s}; remove it first with 'artoo cf tunnel route rm {s}'", .{ op.host, try ui.text.sanitize(a, if (to.len > 0) to else r.service, .line), op.host });
        }
        op.put_route = existing == null;
        const recs = try records.list(op.c, op.host, null);
        op.add_record = recs.len == 0;
        for (recs) |r| {
            if (!(std.mem.eql(u8, r.type, "CNAME") and std.ascii.eqlIgnoreCase(r.content, op.cname) and r.owned()))
                return ctx.fail(error.Refused, "{s} already has a {s} record ({s}); artoo leaves it alone", .{ op.host, r.type, try ui.text.sanitize(a, r.content, .line) });
        }
        op.fp = try std.fmt.allocPrint(a, "{d}|{d}", .{ op.conf.version, recs.len });
    }

    pub fn plan(op: *AddOp, ctx: *Context) !?exec.Plan {
        if (!op.put_route and !op.add_record) return null;
        const a = ctx.arena;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (op.put_route) try changes.append(a, .{ .field = "tunnel route", .from = null, .to = try std.fmt.allocPrint(a, "{s} {s} service {s} (Caddy on the edge, TLS verified as {s})", .{ op.host, ctx.ui.glyphs.arrow, op.service, op.service_host }) });
        if (op.add_record) try changes.append(a, .{ .field = "public record", .from = null, .to = try std.fmt.allocPrint(a, "{s} CNAME {s} {s} (proxied)", .{ op.host, ctx.ui.glyphs.arrow, op.cname }) });
        return .{
            .action = try std.fmt.allocPrint(a, "Publish {s} {s} service {s}", .{ op.host, ctx.ui.glyphs.arrow, op.service }),
            .target = try std.fmt.allocPrint(a, "Cloudflare tunnel {s} + zone {s}", .{ op.tunnel.name, op.c.zone_name }),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{
                try std.fmt.allocPrint(a, "https://{s}/ is reachable from the internet and serves service {s}", .{ op.host, op.service }),
                "The app sees the service name as Host; set its public URL in the app if it builds absolute links",
            }),
            .recovery = try std.fmt.allocPrint(a, "artoo cf tunnel route rm {s}", .{op.host}),
            .notes = try a.dupe([]const u8, &.{"The route list is re-read before it is replaced; a changed version aborts."}),
        };
    }

    pub fn fingerprint(op: *AddOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *AddOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const s_route = if (op.put_route) try l.add(a, "add tunnel route") else null;
        const s_rec = if (op.add_record) try l.add(a, "add public record") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (s_route) |i| {
            const now = try tunnels.getConfig(op.c, op.tunnel.id);
            if (now.version != op.conf.version) {
                l.set(i, .not_run, "");
                return ctx.fail(error.Changed, "tunnel {s}'s routes changed (version {d} → {d}); nothing was sent — run again", .{ op.tunnel.name, op.conf.version, now.version });
            }
            l.set(i, .unknown, "");
            try tunnels.putConfig(op.c, op.tunnel.id, try tunnels.withRoute(a, now.config, op.host, op.service_host));
            l.set(i, .done, op.host);
        }
        if (s_rec) |i| {
            l.set(i, .unknown, "");
            _ = try records.create(op.c, .{
                .name = op.host,
                .type = .CNAME,
                .content = op.cname,
                .proxied = true,
                .ttl = records.ttl_auto,
                .comment = try std.fmt.allocPrint(a, "{s}: tunnel {s}", .{ records.marker, op.service }),
            });
            l.set(i, .done, op.cname);
        }
    }

    pub fn verify(op: *AddOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const conf = try tunnels.getConfig(op.c, op.tunnel.id);
        const r = tunnels.findRoute(try tunnels.routes(ctx.arena, conf.config), op.host) orelse return false;
        if (!std.ascii.eqlIgnoreCase(r.serviceHost() orelse "", op.service_host)) return false;
        for (try records.list(op.c, op.host, "CNAME")) |rec| {
            if (std.ascii.eqlIgnoreCase(rec.content, op.cname) and rec.proxied) return true;
        }
        return false;
    }

    pub fn done(op: *AddOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "https://{s}/ {s} service {s} — public DNS may take a minute", .{ op.host, op.c.ctx.ui.glyphs.arrow, op.service }) catch "done";
    }
};

/// Refused before planning: protected names, private names, the zone apex.
fn publicHost(ctx: *Context, word: []const u8) ![]const u8 {
    const cfg = try ctx.config();
    const host = try cf_cmd.recordName(ctx, word);
    if (exposure.protected(try ctx.config(), host, null)) |why| return ctx.fail(error.Refused, "refused: {s}; Proxmox and UniFi are never public (SPEC §9.6)", .{why});
    if (exposure.isPrivate(host) or cf_cmd.under(host, cfg.guests.domain))
        return ctx.fail(error.Refused, "refused: {s} is a private name (SPEC §9.6)", .{host});
    if (std.ascii.eqlIgnoreCase(host, cfg.cloudflare.zone)) return ctx.fail(error.Refused, "refused: the zone apex {s} is not a tunnel route", .{host});
    if (std.mem.startsWith(u8, host, "_")) return ctx.fail(error.Usage, "'{s}' is not a host name", .{host});
    return host;
}

pub const route_add = struct {
    pub const name = "add";
    pub const summary = "Publish HOST through the tunnel to an existing service";
    pub const details =
        \\HOST is a name in cloudflare.zone (a short name gets it appended);
        \\SERVICE an existing 'artoo svc' service. Adds an ingress rule (Caddy on
        \\the edge VM, TLS verified as SERVICE.apps.<guests.domain>) and a marked,
        \\proxied CNAME to the tunnel. Refused: Proxmox or UniFi names, private
        \\names, the zone apex, a host that already has a record or another route.
    ;
    pub const positionals = [_]cli.Positional{
        .{ .name = "HOST", .help = "Public host name in the zone" },
        .{ .name = "SERVICE", .help = "Service name (see 'artoo svc ls')" },
    };
    pub const examples = [_][]const u8{ "artoo cf tunnel route add blog grafana -n", "artoo cf tunnel route add blog.example.com grafana -y" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const host = try publicHost(ctx, args.pos("HOST"));
        const service = args.pos("SERVICE");
        if (!svc.validName(service)) return ctx.fail(error.Usage, "invalid service name '{s}'", .{service});
        var pc = try pve.Client.open(ctx);
        defer pc.deinit();
        var c = try cf.Client.open(ctx);
        defer c.deinit();
        var op: AddOp = .{ .c = &c, .pc = &pc, .host = host, .service = service };
        try exec.run(ctx, &op, .{});
    }
};

const RmOp = struct {
    c: *cf.Client,
    host: []const u8,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .cloudflare,
    target: []const u8 = "",
    tunnel: tunnels.Tunnel = undefined,
    conf: tunnels.Config = undefined,
    route: ?tunnels.Route = null,
    record: ?records.Record = null,
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *RmOp, ctx: *Context) !void {
        const a = ctx.arena;
        op.target = op.host;
        op.tunnel = try labTunnel(ctx, op.c);
        op.conf = try tunnels.getConfig(op.c, op.tunnel.id);
        op.route = tunnels.findRoute(try tunnels.routes(a, op.conf.config), op.host);
        const cname = try cnameTarget(a, op.tunnel);
        op.record = null;
        for (try records.list(op.c, op.host, "CNAME")) |r| {
            if (std.ascii.eqlIgnoreCase(r.content, cname) and r.owned()) op.record = r;
        }
        op.fp = try std.fmt.allocPrint(a, "{d}|{s}", .{ op.conf.version, if (op.record) |r| r.id else "-" });
    }

    pub fn plan(op: *RmOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        if (op.route) |r| if (r.serviceHost() == null)
            return ctx.fail(error.Refused, "the route for {s} ({s}) was not written by artoo; change it in the dashboard", .{ op.host, try ui.text.sanitize(a, r.service, .line) });
        if (op.route == null and op.record == null) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (op.record) |r| try changes.append(a, .{ .field = "public record", .from = try std.fmt.allocPrint(a, "{s} CNAME {s} {s}", .{ op.host, ctx.ui.glyphs.arrow, r.content }), .to = null });
        if (op.route) |r| try changes.append(a, .{ .field = "tunnel route", .from = try std.fmt.allocPrint(a, "{s} {s} {s}", .{ op.host, ctx.ui.glyphs.arrow, r.serviceHost().? }), .to = null });
        return .{
            .action = try std.fmt.allocPrint(a, "Unpublish {s}", .{op.host}),
            .risk = .destructive,
            .target = try std.fmt.allocPrint(a, "Cloudflare tunnel {s} + zone {s}", .{ op.tunnel.name, op.c.zone_name }),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{try std.fmt.allocPrint(a, "https://{s}/ stops answering from the internet; the service stays on the LAN", .{op.host})}),
            .notes = try a.dupe([]const u8, &.{"The record goes first, then the route; the route list is re-read before it is replaced."}),
        };
    }

    pub fn fingerprint(op: *RmOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *RmOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const s_rec = if (op.record != null) try l.add(a, "remove public record") else null;
        const s_route = if (op.route != null) try l.add(a, "remove tunnel route") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (s_rec) |i| {
            l.set(i, .unknown, "");
            try records.delete(op.c, op.record.?.id);
            l.set(i, .done, op.host);
        }
        if (s_route) |i| {
            const now = try tunnels.getConfig(op.c, op.tunnel.id);
            if (now.version != op.conf.version) {
                l.set(i, .not_run, "");
                return ctx.fail(error.Changed, "tunnel {s}'s routes changed (version {d} → {d}); the route was not removed — run again", .{ op.tunnel.name, op.conf.version, now.version });
            }
            l.set(i, .unknown, "");
            try tunnels.putConfig(op.c, op.tunnel.id, try tunnels.withoutRoute(a, now.config, op.host));
            l.set(i, .done, "");
        }
    }

    pub fn verify(op: *RmOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const conf = try tunnels.getConfig(op.c, op.tunnel.id);
        if (tunnels.findRoute(try tunnels.routes(ctx.arena, conf.config), op.host) != null) return false;
        if (op.record) |r| if ((try records.get(op.c, r.id)) != null) return false;
        return true;
    }

    pub fn done(op: *RmOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} unpublished", .{op.host}) catch "done";
    }
};

pub const route_rm = struct {
    pub const name = "rm";
    pub const summary = "Unpublish HOST: record, then route (destructive)";
    pub const details =
        \\Removes the marked CNAME and the tunnel's ingress rule for HOST; the
        \\service itself stays on the LAN. Type the full host name to confirm, or
        \\--yes --confirm HOST.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "HOST", .help = "Public host name in the zone" }};
    pub const flags = [_]cli.Flag{.{ .long = "confirm", .kind = .string, .metavar = "HOST", .help = "Non-interactive confirmation (with --yes)" }};
    pub const examples = [_][]const u8{ "artoo cf tunnel route rm blog", "artoo cf tunnel route rm blog --yes --confirm blog.example.com" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const host = try cf_cmd.recordName(ctx, args.pos("HOST"));
        var c = try cf.Client.open(ctx);
        defer c.deinit();
        var op: RmOp = .{ .c = &c, .host = host };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const group = cli.group("tunnel", "The lab's Cloudflare Tunnel and its public routes", &.{
    cli.leaf(ls),
    cli.group("route", "Public hosts → services", &.{
        cli.leaf(route_add),
        cli.leaf(route_rm),
    }),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "serviceOf: only artoo's rules under the apps domain" {
    const d: svc.Domains = .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" };
    try testing.expectEqualStrings("grafana", serviceOf(.{ .hostname = "blog.example.com", .service = tunnels.origin, .server_name = "grafana.apps.lab.example.com" }, d).?);
    try testing.expect(serviceOf(.{ .hostname = "x", .service = "http://naboo:80", .server_name = null }, d) == null);
    try testing.expect(serviceOf(.{ .hostname = "x", .service = tunnels.origin, .server_name = "evilapps.lab.example.com" }, d) == null);
}

const testkit = @import("../testkit.zig");
const root = cli.group("artoo", "t", &.{@import("cf.zig").group});

fn agentBody(a: std.mem.Allocator, out: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
}

pub const zones_body = "{\"success\":true,\"errors\":[],\"result\":[{\"id\":\"Z1\",\"name\":\"example.com\",\"account\":{\"id\":\"A1\"}}],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":1,\"total_count\":1}}";
pub const tunnels_body = "{\"success\":true,\"errors\":[],\"result\":[{\"id\":\"T1\",\"name\":\"lab\",\"status\":\"healthy\",\"connections\":[{},{}]}],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":1,\"total_count\":1}}";
const no_records = "{\"success\":true,\"errors\":[],\"result\":[],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":0,\"total_count\":0}}";
const vms_body = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"}]}";

test "cf tunnel route add -n: service checked, version read, rule + CNAME planned, nothing sent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const route = try svc.render(a, .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" }, "grafana", "naboo", 3000);
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{route})) } },
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = zones_body } },
        .{ .respond = .{ .body = tunnels_body } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":{\"tunnel_id\":\"T1\",\"version\":3,\"config\":{\"ingress\":[{\"service\":\"http_status:404\"}]}}}" } },
        .{ .respond = .{ .body = no_records } },
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "cf tunnel route add blog grafana -n"));
    try testing.expectEqual(@as(usize, 9), g.sent());
    try testing.expectEqualStrings("GET /accounts/A1/cfd_tunnel/T1/configurations HTTP/1.1", g.request(7));
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Publish blog.example.com → service grafana",
        "tunnel route   (none) → blog.example.com → service grafana (Caddy on the edge, TLS verified as grafana.apps.lab.example.com)",
        "public record  (none) → blog.example.com CNAME → T1.cfargotunnel.com (proxied)",
        "artoo cf tunnel route rm blog.example.com",
        "Dry run: nothing was sent.",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "cf tunnel route add: a missing service is a usage error (exit 2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const route = try svc.render(a, .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" }, "grafana", "naboo", 3000);
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{route})) } },
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "cf tunnel route add blog ghost -n"));
    try testing.expectEqual(@as(usize, 4), g.sent());
    try testing.expect(std.mem.find(u8, g.h.stderr(), "no service ghost") != null);
}

/// SPEC §9.9: services on the watchdog (`role-watch`) and the search
/// gateway (`role-search`) are never public, with no override.
fn refuseNeverPublic(ctx: *Context, c: *pve.Client, service: []const u8, vm: []const u8) !void {
    for (try vms.list(c)) |v| {
        if (v.template or !std.ascii.eqlIgnoreCase(vm, v.name)) continue;
        const r = vm_cmd.roleOf(v.tags) orelse continue;
        if (std.mem.eql(u8, r, watch.role))
            return ctx.fail(error.Refused, "refused: service {s} runs on the watchdog {s}; Grafana and ntfy are never public (SPEC §9.9)", .{ service, v.name });
        if (std.mem.eql(u8, r, search_role))
            return ctx.fail(error.Refused, "refused: service {s} runs on the search gateway {s}; an unauthenticated search and fetch proxy is never public (SPEC §9.9)", .{ service, v.name });
    }
}

test "cf tunnel route add: a service on the search gateway is never public" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const route = try svc.render(a, .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" }, "search", "hoth", 8080);
    const with_search = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"},{\"vmid\":203,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo;role-search\"}]}";
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = with_search } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/search.caddy\n{s}\n==caddy== active\n", .{route})) } },
        .{ .respond = .{ .body = with_search } },
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "cf tunnel route add find search -n"));
    try testing.expectEqual(@as(usize, 5), g.sent());
    try testing.expect(std.mem.find(u8, g.h.stderr(), "runs on the search gateway hoth") != null);
}

test "cf tunnel route add: a service on the watchdog is never public" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const route = try svc.render(a, .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" }, "grafana", "scarif", 3000);
    const with_watch = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"},{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"}]}";
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = with_watch } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{route})) } },
        .{ .respond = .{ .body = with_watch } },
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "cf tunnel route add blog grafana -n"));
    try testing.expectEqual(@as(usize, 5), g.sent());
    try testing.expect(std.mem.find(u8, g.h.stderr(), "runs on the watchdog scarif") != null);
}

test "cf tunnel route add: protected, private and apex hosts refused before any request" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{});
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "cf tunnel route add pve grafana -n"));
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "cf tunnel route add naboo.lab.example.com grafana -n"));
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "cf tunnel route add example.com grafana -n"));
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "cf tunnel route add blog Grafana -n"));
    try testing.expectEqual(@as(usize, 0), g.sent());
}

test "svc rm refuses while a public host reaches the service" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const route = try svc.render(a, .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" }, "grafana", "naboo", 3000);
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\"}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{route})) } },
        .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"S1\",\"internalReference\":\"default\",\"name\":\"Default\"}]}" } },
        .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}" } },
        .{ .respond = .{ .body = zones_body } },
        .{ .respond = .{ .body = tunnels_body } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":{\"version\":4,\"config\":{\"ingress\":[{\"hostname\":\"blog.example.com\",\"service\":\"https://localhost:443\",\"originRequest\":{\"originServerName\":\"grafana.apps.lab.example.com\"}},{\"service\":\"http_status:404\"}]}}}" } },
    });
    defer g.deinit();
    const svc_root = cli.group("artoo", "t", &.{svc.group});
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&svc_root, "svc rm grafana -n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "public host(s) blog.example.com reach service grafana") != null);
}
