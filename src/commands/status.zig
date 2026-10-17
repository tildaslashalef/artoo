//! `artoo status` (SPEC §11): one screen over the lab — Proxmox (host,
//! guests, storage, tasks), UniFi (gateway, guest DNS records), the
//! edge, the router, the tunnel and service drift. Each system is read by
//! its own concurrent task with its own `Context` copy
//! (the arena is thread-safe; `diag` is per task); sections are sampled,
//! not atomic, and independent: a failing section is shown as unavailable
//! and the command exits 8.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const unifi = @import("../unifi/client.zig");
const catalog = @import("../unifi/catalog.zig");
const view = @import("../unifi/view.zig");
const dns = @import("../unifi/dns.zig");
const host = @import("host.zig");
const storage = @import("storage.zig");
const task = @import("task.zig");
const k = @import("node.zig");
const edge = @import("edge.zig");
const router = @import("router.zig");
const svc = @import("svc.zig");
const vm_new = @import("vm_new.zig");
const cf = @import("../cloudflare/client.zig");
const tunnels = @import("../cloudflare/tunnel.zig");

const Context = app.Context;

const SectionError = struct { section: []const u8, message: []const u8 };

const Guest = struct {
    vmid: u32,
    name: []const u8,
    status: []const u8,
    vcpus: ?f64,
    cpu: ?f64,
    mem: ?u64,
    maxmem: ?u64,
    uptime: ?u64,
    /// Guest-agent IPv4 (running VMs with the agent), else null.
    address: ?[]const u8,
    /// `/run/reboot-required` (running VMs with the agent), else null.
    reboot_pending: ?bool = null,
    /// The packages that want it (`/run/reboot-required.pkgs`).
    reboot_packages: []const []const u8 = &.{},
};

const Gateway = struct {
    version: []const u8,
    devices_online: usize,
    devices_total: usize,
    clients: usize,
    wans: []const []const u8,
};

const DnsCheck = struct {
    domain: []const u8,
    /// Guests with a record under the guest domain.
    matched: usize,
    /// Guests (not templates) without one.
    missing: []const []const u8,
    /// Records under the guest domain without a guest.
    orphans: []const []const u8,
};

/// A role VM's checks; `vm` null when no VM carries the role.
const Checks = struct {
    vm: ?[]const u8 = null,
    checks: []const vm_new.Check = &.{},
};

const PublicRoute = struct { host: []const u8, service: ?[]const u8, missing: bool = false };

/// The lab tunnel; `found` false when it does not exist.
const Tunnel = struct {
    name: []const u8,
    found: bool = false,
    status: []const u8 = "",
    connections: usize = 0,
    routes: []PublicRoute = &.{},
};

const Report = struct {
    host: ?host.Host = null,
    guests: ?[]const Guest = null,
    templates: usize = 0,
    storage: ?[]const storage.Storage = null,
    running_tasks: ?usize = null,
    failed_tasks: ?[]const task.Task = null,
    gateway: ?Gateway = null,
    dns: ?DnsCheck = null,
    edge: ?Checks = null,
    router: ?Checks = null,
    tunnel: ?Tunnel = null,
    services: ?[]const svc.Row = null,
};

/// Run `f`, recording a failure (message from ctx.diag) instead of
/// propagating it; OOM and cancellation still abort.
fn attempt(ctx: *Context, errors: *std.ArrayList(SectionError), section: []const u8, result: anytype) ?@typeInfo(@TypeOf(result)).error_union.payload {
    return result catch |err| {
        errors.append(ctx.arena, .{ .section = section, .message = ctx.diag orelse @errorName(err) }) catch {};
        ctx.diag = null;
        return null;
    };
}

fn guests(c: *pve.Client, templates: *usize) ![]const Guest {
    const ctx = c.ctx;
    var out: std.ArrayList(Guest) = .empty;
    for (try vms.list(c)) |v| {
        if (v.template) {
            templates.* += 1;
            continue;
        }
        var addr: ?[]const u8 = null;
        var reboot: ?bool = null;
        var pkgs: std.ArrayList([]const u8) = .empty;
        if (v.running()) {
            const cfg = vms.config(c, v.vmid) catch null;
            if (cfg != null and vms.agentEnabled(cfg.?)) {
                if (vms.agentAddresses(c, v.vmid)) |list| {
                    for (list) |a| if (!a.ipv6) {
                        addr = a.address;
                        break;
                    };
                } else |err| switch (err) {
                    error.OutOfMemory, error.Canceled => |e| return e,
                    else => ctx.diag = null,
                }
                // SPEC §9.1: the operator reboots; status shows who waits.
                if (agent.sh(c, v.vmid, reboot_script, 30_000)) |r| {
                    var lines = std.mem.tokenizeAny(u8, r.out, "\r\n");
                    if (lines.next()) |first| reboot = std.mem.eql(u8, first, "yes");
                    while (lines.next()) |p| {
                        for (pkgs.items) |q| {
                            if (std.mem.eql(u8, p, q)) break;
                        } else try pkgs.append(ctx.arena, p);
                    }
                } else |err| switch (err) {
                    error.OutOfMemory, error.Canceled => |e| return e,
                    else => ctx.diag = null,
                }
            }
        }
        try out.append(ctx.arena, .{ .vmid = v.vmid, .name = v.name, .status = v.status, .vcpus = v.cpus, .cpu = v.cpu, .mem = v.mem, .maxmem = v.maxmem, .uptime = v.uptime, .address = addr, .reboot_pending = reboot, .reboot_packages = pkgs.items });
    }
    return out.items;
}

const reboot_script = "if [ -f /run/reboot-required ]; then echo yes; cat /run/reboot-required.pkgs 2>/dev/null; else echo no; fi";

fn gateway(c: *unifi.Client) !Gateway {
    const i = try unifi.info(c);
    const devs = (try unifi.list(c, catalog.find("devices").?, .{ .all = true })).items;
    var online: usize = 0;
    for (devs) |d| {
        if (std.mem.eql(u8, view.string(d, "state") orelse "", "ONLINE")) online += 1;
    }
    const clients = (try unifi.list(c, catalog.find("clients").?, .{ .limit = 1 })).total;
    const wans = (try unifi.list(c, catalog.find("wans").?, .{ .all = true })).items;
    const names = try c.ctx.arena.alloc([]const u8, wans.len);
    for (wans, names) |w, *n| n.* = view.string(w, "name") orelse "--";
    return .{
        .version = i.applicationVersion,
        .devices_online = online,
        .devices_total = devs.len,
        .clients = if (clients) |t| @intCast(@max(t, 0)) else 0,
        .wans = names,
    };
}

fn dnsCheck(arena: std.mem.Allocator, domain: []const u8, d: svc.Domains, records: []const dns.ARecord, gs: []const Guest) !DnsCheck {
    var missing: std.ArrayList([]const u8) = .empty;
    var orphans: std.ArrayList([]const u8) = .empty;
    var matched: usize = 0;
    for (gs) |g| {
        if (g.name.len == 0) continue;
        const fqdn = try std.fmt.allocPrint(arena, "{s}.{s}", .{ g.name, domain });
        if (dns.find(records, fqdn) != null) matched += 1 else try missing.append(arena, g.name);
    }
    for (records) |r| {
        if (svc.isServiceDomain(r.domain, d)) continue;
        const label = std.mem.cutSuffix(u8, r.domain, domain) orelse continue;
        if (label.len < 2 or label[label.len - 1] != '.') continue;
        const name = label[0 .. label.len - 1];
        for (gs) |g| {
            if (std.ascii.eqlIgnoreCase(g.name, name)) break;
        } else try orphans.append(arena, r.domain);
    }
    return .{ .domain = domain, .matched = matched, .missing = missing.items, .orphans = orphans.items };
}

pub const status = struct {
    pub const name = "status";
    pub const summary = "One-screen overview of the lab";
    pub const details =
        \\Read-only. Proxmox, UniFi, the edge, the router and the tunnel are
        \\read concurrently; sections are sampled, not atomic. A section that
        \\fails is shown as unavailable, and a failed edge or router check is
        \\listed; either exits 8. A role VM or tunnel that does not exist shows
        \\as "none". Service drift is shown but does not change the exit code.
        \\Guest CPU is % of the guest's vCPUs; host CPU is % of host threads.
    ;
    pub const examples = [_][]const u8{ "artoo status", "artoo status -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var r: Report = .{};
        const cfg = try ctx.config();

        const d = try svc.domains(ctx);

        var parts: [5]Part = @splat(.{ .ctx = ctx.* });
        var records: ?[]const dns.ARecord = null;
        var edge_view: EdgeRead = .{};
        var group: std.Io.Group = .init;
        spawn(ctx.io, &group, readPve, .{ &parts[0], &r });
        spawn(ctx.io, &group, readUnifi, .{ &parts[1], &r, &records });
        spawn(ctx.io, &group, readEdge, .{ &parts[2], &r, d, &edge_view });
        spawn(ctx.io, &group, readRouter, .{ &parts[3], &r });
        spawn(ctx.io, &group, readTunnel, .{ &parts[4], &r, d });
        try group.await(ctx.io);

        var errors: std.ArrayList(SectionError) = .empty;
        for (&parts) |*p| try errors.appendSlice(ctx.arena, p.errors.items);
        if (r.guests) |gs| if (records) |rs| {
            r.dns = attempt(ctx, &errors, "dns", dnsCheck(ctx.arena, cfg.guests.domain, d, rs, gs));
        };
        // Service drift from what the tasks read: no extra requests.
        if (edge_view.view) |ev| if (records) |rs| if (r.guests) |gs| {
            var names: std.ArrayList([]const u8) = .empty;
            for (gs) |g| try names.append(ctx.arena, g.name);
            r.services = attempt(ctx, &errors, "services", svc.drift(ctx, d, ev, rs, names.items, edge_view.addr));
        };
        if (r.tunnel) |t| if (edge_view.view) |ev| {
            for (t.routes) |*pr| {
                const n = pr.service orelse continue;
                pr.missing = ev.find(n) == null;
            }
        };
        var failed: usize = 0;
        for ([_]?Checks{ r.edge, r.router }) |ch| if (ch) |x| {
            failed += vm_new.failures(x.checks);
        };

        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .local, r, .{ .collected_at = ctx.ui.now, .errors = errors.items, .guest_cpu_unit = "fraction of the guest's vCPUs", .host_cpu_unit = "fraction of host threads" });
        } else try render(ctx, r, errors.items);
        if (errors.items.len > 0) return ctx.fail(error.Partial, "{d} section{s} unavailable", .{ errors.items.len, if (errors.items.len == 1) "" else "s" });
        if (failed > 0) return ctx.fail(error.Partial, "{d} check{s} failed", .{ failed, if (failed == 1) "" else "s" });
    }
};

/// One concurrent reader: its own `Context` copy (shared thread-safe
/// arena, own `diag`) and the sections that failed.
const Part = struct {
    ctx: Context,
    errors: std.ArrayList(SectionError) = .empty,
};

/// Run `f` concurrently in `group`, or inline when the Io has no
/// concurrency to spare.
fn spawn(io: std.Io, group: *std.Io.Group, comptime f: anytype, args: std.meta.ArgsTuple(@TypeOf(f))) void {
    group.concurrent(io, f, args) catch @call(.auto, f, args);
}

fn readPve(p: *Part, r: *Report) void {
    const ctx = &p.ctx;
    var c = attempt(ctx, &p.errors, "pve", pve.Client.open(ctx)) orelse return;
    defer c.deinit();
    r.host = attempt(ctx, &p.errors, "host", host.read(&c));
    r.guests = attempt(ctx, &p.errors, "guests", guests(&c, &r.templates));
    r.storage = attempt(ctx, &p.errors, "storage", storage.list(&c));
    if (attempt(ctx, &p.errors, "tasks", task.list(&c, 100, .running))) |running| r.running_tasks = running.len;
    if (attempt(ctx, &p.errors, "tasks", task.list(&c, 20, .failed))) |failed| r.failed_tasks = failed;
}

fn readUnifi(p: *Part, r: *Report, records: *?[]const dns.ARecord) void {
    const ctx = &p.ctx;
    var c = attempt(ctx, &p.errors, "unifi", unifi.Client.open(ctx)) orelse return;
    defer c.deinit();
    r.gateway = attempt(ctx, &p.errors, "gateway", gateway(&c));
    records.* = attempt(ctx, &p.errors, "dns", dns.list(&c));
}

/// What the edge task read for service drift.
const EdgeRead = struct { view: ?svc.EdgeView = null, addr: []const u8 = "" };

/// Record a failed section unless the role VM simply does not exist.
fn roleVm(ctx: *Context, errors: *std.ArrayList(SectionError), section: []const u8, result: anytype) ?(@typeInfo(@TypeOf(result)).error_union.payload) {
    return result catch |err| {
        if (err != error.NotFound) errors.append(ctx.arena, .{ .section = section, .message = ctx.diag orelse @errorName(err) }) catch {};
        ctx.diag = null;
        return null;
    };
}

fn readEdge(p: *Part, r: *Report, d: svc.Domains, out: *EdgeRead) void {
    const ctx = &p.ctx;
    var c = attempt(ctx, &p.errors, "edge", pve.Client.open(ctx)) orelse return;
    defer c.deinit();
    const before = p.errors.items.len;
    const v = roleVm(ctx, &p.errors, "edge", edge.edgeVm(ctx, &c)) orelse {
        if (p.errors.items.len == before) r.edge = .{};
        return;
    };
    if (attempt(ctx, &p.errors, "edge", edge.healthOf(ctx, &c, v))) |h| r.edge = .{ .vm = h.vm, .checks = h.checks };
    const addr = attempt(ctx, &p.errors, "services", svc.edgeAddress(&c, v)) orelse return;
    out.view = attempt(ctx, &p.errors, "services", svc.readEdge(&c, v.vmid, d));
    out.addr = addr;
}

fn readRouter(p: *Part, r: *Report) void {
    const ctx = &p.ctx;
    var c = attempt(ctx, &p.errors, "router", pve.Client.open(ctx)) orelse return;
    defer c.deinit();
    const before = p.errors.items.len;
    const h = roleVm(ctx, &p.errors, "router", router.health(ctx, &c)) orelse {
        if (p.errors.items.len == before) r.router = .{};
        return;
    };
    r.router = .{ .vm = h.vm, .checks = h.checks };
}

fn readTunnel(p: *Part, r: *Report, d: svc.Domains) void {
    const ctx = &p.ctx;
    const name = (ctx.config() catch return).cloudflare.tunnel;
    var c = attempt(ctx, &p.errors, "tunnel", cf.Client.open(ctx)) orelse return;
    defer c.deinit();
    const found = attempt(ctx, &p.errors, "tunnel", tunnels.find(&c, name)) orelse return;
    const t = found orelse {
        r.tunnel = .{ .name = name };
        return;
    };
    const conf = attempt(ctx, &p.errors, "tunnel", tunnels.getConfig(&c, t.id)) orelse return;
    const rs = attempt(ctx, &p.errors, "tunnel", tunnels.routes(ctx.arena, conf.config)) orelse return;
    const routes = ctx.arena.alloc(PublicRoute, rs.len) catch return;
    for (rs, routes) |rt, *o| {
        const sh = rt.serviceHost();
        o.* = .{ .host = rt.hostname, .service = if (sh != null and svc.isServiceDomain(sh.?, d)) sh.?[0 .. sh.?.len - d.apps.len - 1] else null };
    }
    r.tunnel = .{ .name = name, .found = true, .status = t.status, .connections = t.connections, .routes = routes };
}

fn unavailable(errors: []const SectionError, section: []const u8) ?[]const u8 {
    for (errors) |e| {
        if (std.mem.eql(u8, e.section, section)) return e.message;
    }
    return null;
}

fn sectionTitle(ctx: *Context, title: []const u8) !void {
    try ctx.out.print("\n{s}{s}{s}\n", .{ ctx.ui.palette.on(.title), title, ctx.ui.palette.off(.title) });
}

fn failLine(ctx: *Context, msg: []const u8) !void {
    try ctx.out.print("  {s}{s} unavailable: {s}{s}\n", .{ ctx.ui.palette.on(.fail), ctx.ui.glyphs.fail, try k.clean(ctx, msg), ctx.ui.palette.off(.fail) });
}

fn render(ctx: *Context, r: Report, errors: []const SectionError) !void {
    const a = ctx.arena;
    const u = &ctx.ui;
    const right = try std.fmt.allocPrint(a, "lab {s} {f}", .{ u.glyphs.dot, ui.values.clock(u.now, &u.zone) });
    try ui.blocks.header(ctx.out, u, "status", right);

    // Proxmox host.
    try ctx.out.print("{s}Proxmox{s}\n", .{ u.palette.on(.title), u.palette.off(.title) });
    if (r.host) |h| {
        const load = if (h.load[0]) |l| try std.fmt.allocPrint(a, "{d:.2} {d:.2} {d:.2}", .{ l, h.load[1] orelse 0, h.load[2] orelse 0 }) else "--";
        try ui.blocks.detail(ctx.out, u, &.{.{ .fields = &.{
            .{ .key = "  Proxmox VE", .value = if (h.version) |v| try k.clean(ctx, v) else "--" },
            .{ .key = "  CPU", .value = try std.fmt.allocPrint(a, "{f} of {d} threads, load {s}", .{ ui.values.percent(h.cpu), h.threads orelse 0, load }) },
            .{ .key = "  RAM", .value = try k.usage(ctx, h.mem_used, h.mem_total) },
            .{ .key = "  Root FS", .value = try k.usage(ctx, h.rootfs_used, h.rootfs_total) },
            .{ .key = "  Uptime", .value = try k.fmt(ctx, ui.values.duration(h.uptime)) },
        } }});
    } else try failLine(ctx, unavailable(errors, "host") orelse unavailable(errors, "pve") orelse "--");

    // Guests.
    try sectionTitle(ctx, "Guests");
    if (r.guests) |gs| {
        var running: usize = 0;
        for (gs) |g| running += @intFromBool(std.mem.eql(u8, g.status, "running"));
        try ctx.out.print("  {d} running, {d} stopped, {d} template(s)\n", .{ running, gs.len - running, r.templates });
        if (gs.len > 0) {
            const rows = try a.alloc([]const ui.table.Cell, gs.len);
            for (gs, rows) |g, *row| {
                const run = std.mem.eql(u8, g.status, "running");
                const cells = try a.alloc(ui.table.Cell, 7);
                cells[0] = .{ .text = try std.fmt.allocPrint(a, "  {d}", .{g.vmid}) };
                cells[1] = .{ .text = try k.clean(ctx, g.name) };
                cells[2] = try k.vmStatus(ctx, g.status, false);
                cells[3] = .{ .text = if (run and g.cpu != null) try std.fmt.allocPrint(a, "{f} of {d}", .{ ui.values.percent(g.cpu), @as(u64, @intFromFloat(g.vcpus orelse 0)) }) else "--" };
                cells[4] = .{ .text = if (run) try k.fmt(ctx, ui.values.usedTotal(g.mem, g.maxmem)) else "--" };
                cells[5] = .{ .text = if (run) try k.fmt(ctx, ui.values.duration(g.uptime)) else "--" };
                cells[6] = .{ .text = if (g.address) |ad| try k.clean(ctx, ad) else "--" };
                row.* = cells;
            }
            try ui.table.render(ctx.out, u, a, &.{
                .{ .title = "  VMID", .alignment = .right, .truncate = false },
                .{ .title = "NAME", .truncate = false },
                .{ .title = "STATUS" },
                .{ .title = "CPU", .alignment = .right, .drop = 2 },
                .{ .title = "MEMORY", .drop = 1 },
                .{ .title = "UPTIME", .alignment = .right, .drop = 3 },
                .{ .title = "ADDRESS", .truncate = false },
            }, rows);
            var waiting: std.ArrayList([]const u8) = .empty;
            for (gs) |g| if (g.reboot_pending orelse false) {
                const shown = g.reboot_packages[0..@min(g.reboot_packages.len, 2)];
                try waiting.append(a, if (shown.len == 0) try k.clean(ctx, g.name) else try std.fmt.allocPrint(a, "{s} ({s}{s})", .{ try k.clean(ctx, g.name), try k.clean(ctx, try std.mem.join(a, ", ", shown)), if (g.reboot_packages.len > 2) ", …" else "" }));
            };
            if (waiting.items.len > 0) try ctx.out.print("  {s}{s} reboot pending: {s} — 'artoo vm reboot VM'{s}\n", .{ u.palette.on(.warn), u.glyphs.warn, try std.mem.join(a, ", ", waiting.items), u.palette.off(.warn) });
        }
    } else try failLine(ctx, unavailable(errors, "guests") orelse unavailable(errors, "pve") orelse "--");

    // Storage.
    try sectionTitle(ctx, "Storage");
    if (r.storage) |ss| {
        var fields: std.ArrayList(ui.blocks.Field) = .empty;
        for (ss) |s| try fields.append(a, .{ .key = try std.fmt.allocPrint(a, "  {s}", .{try k.clean(ctx, s.name)}), .value = try k.usage(ctx, s.used, s.total) });
        try ui.blocks.detail(ctx.out, u, &.{.{ .fields = fields.items }});
    } else try failLine(ctx, unavailable(errors, "storage") orelse unavailable(errors, "pve") orelse "--");

    // Tasks.
    try sectionTitle(ctx, "Tasks");
    if (r.running_tasks != null and r.failed_tasks != null) {
        // PVE's errors=1 filter also returns tasks that ended with warnings.
        const recent = r.failed_tasks.?;
        var failed: usize = 0;
        var warned: usize = 0;
        for (recent) |t| switch (t.state()) {
            .failed => failed += 1,
            .warning => warned += 1,
            else => {},
        };
        try ctx.out.print("  {d} running, {d} recent failure(s), {d} with warnings\n", .{ r.running_tasks.?, failed, warned });
        var shown: usize = 0;
        for (recent) |t| {
            if (shown == 3) break;
            const st = t.state();
            if (st != .failed and st != .warning) continue;
            shown += 1;
            try ctx.out.print("  {s}{s} {s}  {s}{s}\n", .{ u.palette.on(st.role()), st.glyph(u.glyphs), try k.clean(ctx, t.handle), try k.clean(ctx, t.exitstatus orelse ""), u.palette.off(st.role()) });
        }
    } else try failLine(ctx, unavailable(errors, "tasks") orelse unavailable(errors, "pve") orelse "--");

    // UniFi.
    try sectionTitle(ctx, "UniFi");
    if (r.gateway) |g| {
        try ui.blocks.detail(ctx.out, u, &.{.{ .fields = &.{
            .{ .key = "  Network", .value = try k.clean(ctx, g.version) },
            .{ .key = "  Devices", .value = try std.fmt.allocPrint(a, "{d} online / {d}", .{ g.devices_online, g.devices_total }), .role = if (g.devices_online == g.devices_total) .ok else .warn },
            .{ .key = "  Clients", .value = try std.fmt.allocPrint(a, "{d}", .{g.clients}) },
            .{ .key = "  WANs", .value = try k.clean(ctx, try std.mem.join(a, ", ", g.wans)) },
        } }});
    } else try failLine(ctx, unavailable(errors, "gateway") orelse unavailable(errors, "unifi") orelse "--");
    if (r.dns) |d| {
        const ok = d.missing.len == 0 and d.orphans.len == 0;
        try ctx.out.print("  {s}Guest DNS ({s}): {d} matched", .{ u.palette.on(if (ok) .text else .warn), try k.clean(ctx, d.domain), d.matched });
        if (d.missing.len > 0) try ctx.out.print(", no record: {s}", .{try k.clean(ctx, try std.mem.join(a, ", ", d.missing))});
        if (d.orphans.len > 0) try ctx.out.print(", no guest: {s}", .{try k.clean(ctx, try std.mem.join(a, ", ", d.orphans))});
        try ctx.out.print("{s}\n", .{u.palette.off(if (ok) .text else .warn)});
    } else if (unavailable(errors, "dns")) |m| try failLine(ctx, m);

    try roleSection(ctx, "Edge", r.edge, unavailable(errors, "edge"), "no VM tagged role-edge");
    try roleSection(ctx, "Router", r.router, unavailable(errors, "router"), "no VM tagged role-router");

    // Tunnel.
    try sectionTitle(ctx, "Tunnel");
    if (r.tunnel) |t| {
        if (!t.found) {
            try muted(ctx, try std.fmt.allocPrint(a, "none (no tunnel '{s}')", .{try k.clean(ctx, t.name)}));
        } else {
            const healthy = std.mem.eql(u8, t.status, "healthy");
            try ctx.out.print("  {s}{s}: {s}, {d} connection(s), {d} public route(s){s}\n", .{ u.palette.on(if (healthy) .text else .warn), try k.clean(ctx, t.name), try k.clean(ctx, t.status), t.connections, t.routes.len, u.palette.off(if (healthy) .text else .warn) });
            for (t.routes) |pr| {
                const target = if (pr.service) |s| try std.fmt.allocPrint(a, "service {s}", .{try k.clean(ctx, s)}) else "not an artoo service";
                if (pr.missing) {
                    try ctx.out.print("  {s}{s} {s} {s} {s}: the service does not exist{s}\n", .{ u.palette.on(.warn), u.glyphs.warn, try k.clean(ctx, pr.host), u.glyphs.arrow, target, u.palette.off(.warn) });
                } else try ctx.out.print("  {s} {s} {s}\n", .{ try k.clean(ctx, pr.host), u.glyphs.arrow, target });
            }
        }
    } else try failLine(ctx, unavailable(errors, "tunnel") orelse "--");

    // Services.
    try sectionTitle(ctx, "Services");
    if (r.services) |rows| {
        var ok: std.ArrayList([]const u8) = .empty;
        for (rows) |row| if (row.problems.len == 0) try ok.append(a, row.name);
        if (rows.len == 0) try muted(ctx, "none");
        if (ok.items.len > 0) try ctx.out.print("  {d} ok: {s}\n", .{ ok.items.len, try std.mem.join(a, ", ", ok.items) });
        for (rows) |row| if (row.problems.len > 0) {
            try ctx.out.print("  {s}{s} {s}: {s}{s}\n", .{ u.palette.on(.warn), u.glyphs.warn, row.name, try std.mem.join(a, "; ", row.problems), u.palette.off(.warn) });
        };
    } else if (r.edge != null and r.edge.?.vm == null) {
        try muted(ctx, "none (no edge VM)");
    } else try failLine(ctx, unavailable(errors, "services") orelse unavailable(errors, "edge") orelse unavailable(errors, "dns") orelse unavailable(errors, "guests") orelse "--");
}

fn muted(ctx: *Context, text: []const u8) !void {
    try ctx.out.print("  {s}{s}{s}\n", .{ ctx.ui.palette.on(.muted), text, ctx.ui.palette.off(.muted) });
}

/// A role VM's checks: one line when all pass, else each one that does not.
fn roleSection(ctx: *Context, title: []const u8, ch: ?Checks, err: ?[]const u8, none: []const u8) !void {
    const a = ctx.arena;
    const u = &ctx.ui;
    const x = ch orelse {
        try sectionTitle(ctx, title);
        return failLine(ctx, err orelse "--");
    };
    const vm = x.vm orelse {
        try sectionTitle(ctx, title);
        return muted(ctx, try std.fmt.allocPrint(a, "none ({s})", .{none}));
    };
    try sectionTitle(ctx, try std.fmt.allocPrint(a, "{s} ({s})", .{ title, try k.clean(ctx, vm) }));
    var bad: usize = 0;
    for (x.checks) |c| bad += @intFromBool(c.status != .ok);
    if (bad == 0) {
        try ctx.out.print("  {s}{s} all {d} checks ok{s}\n", .{ u.palette.on(.ok), u.glyphs.ok, x.checks.len, u.palette.off(.ok) });
    } else for (x.checks) |c| if (c.status != .ok) {
        const role: ui.style.Role = if (c.status == .failed) .fail else .warn;
        try ctx.out.print("  {s}{s} {s}  {s}{s}\n", .{ u.palette.on(role), if (c.status == .failed) u.glyphs.fail else u.glyphs.warn, c.name, try k.clean(ctx, c.detail), u.palette.off(role) });
    };
    if (err) |m| try failLine(ctx, m);
}

pub const command = cli.leaf(status);

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");

/// The same VM list answers every reader (Proxmox, edge, router): which
/// task asks first is not fixed.
const qemu_plain = "{\"data\":[{\"vmid\":100,\"name\":\"web-01\",\"status\":\"stopped\",\"maxmem\":1073741824},{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"status\":\"stopped\",\"template\":1}]}";

test "status: Proxmox and UniFi sections; a failed section exits 8" {
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        .{ .match = "/nodes/pve/status ", .behavior = .{ .respond = .{ .body = host.status_body } } },
        .{ .match = "/api2/json/version ", .behavior = .{ .respond = .{ .body = host.version_body } } },
        .{ .match = "/nodes/pve/qemu ", .behavior = .{ .respond = .{ .body = qemu_plain } } },
        .{ .match = "/nodes/pve/storage ", .behavior = .{ .respond = .{ .body = storage.storage_body } } },
        .{ .match = "/tasks?limit=100", .behavior = .{ .respond = .{ .body = "{\"data\":[]}" } } },
        .{ .match = "errors=1", .behavior = .{ .respond = .{ .status = 500, .body = "{\"data\":null}", .reason = "boom" } } },
        .{ .match = "/v1/info ", .behavior = .{ .respond = .{ .body = "{\"applicationVersion\":\"10.6.106\"}" } } },
        .{ .match = "/v1/sites?", .behavior = .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"S1\",\"internalReference\":\"default\",\"name\":\"Default\"}]}" } } },
        .{ .match = "/devices?", .behavior = .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"name\":\"Beacon\",\"state\":\"ONLINE\"}]}" } } },
        .{ .match = "/clients?", .behavior = .{ .respond = .{ .body = "{\"offset\":0,\"limit\":1,\"count\":1,\"totalCount\":7,\"data\":[{}]}" } } },
        .{ .match = "/wans?", .behavior = .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"name\":\"WAN 1\"}]}" } } },
        .{ .match = "/dns/policies?", .behavior = .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R1\",\"enabled\":true,\"domain\":\"old-01.lab.example.com\",\"ipv4Address\":\"192.168.1.201\"}]}" } } },
        // No edge or router VM, no tunnel.
        .{ .match = "/nodes/pve/qemu ", .behavior = .{ .respond = .{ .body = qemu_plain } } },
        .{ .match = "/nodes/pve/qemu ", .behavior = .{ .respond = .{ .body = qemu_plain } } },
        .{ .match = "/zones?", .behavior = .{ .respond = .{ .body = @import("cf_tunnel.zig").zones_body } } },
        .{ .match = "/cfd_tunnel?", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":[],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":0,\"total_count\":0}}" } } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{command});
    try testing.expectEqual(testkit.Exit.partial, g.h.run(&root, "status"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    for ([_][]const u8{
        "  0 running, 1 stopped, 1 template(s)\n",
        "  local-zfs  ",
        "✗ unavailable: Proxmox refused GET /nodes/pve/tasks?limit=20&source=all&errors=1 (500): boom",
        "  Devices  1 online / 1\n",
        "  Clients  7\n",
        "Guest DNS (lab.example.com): 0 matched, no record: web-01, no guest: old-01.lab.example.com",
        "Edge\n  none (no VM tagged role-edge)\n",
        "Router\n  none (no VM tagged role-router)\n",
        "Tunnel\n  none (no tunnel 'lab')\n",
        "Services\n  none (no edge VM)\n",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

fn agentOut(a: std.mem.Allocator, out: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
}

const json_list = "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}";

test "status: the whole lab — edge drops first, no router, tunnel and service drift" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d: svc.Domains = .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" };
    const qemu = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"},{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"}]}";
    const cfg200 = "{\"data\":{\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0\",\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\"}}";
    const counters = "{\"nftables\":[{\"counter\":{\"name\":\"to_pve\",\"packets\":3}},{\"counter\":{\"name\":\"to_gateway\",\"packets\":0}},{\"counter\":{\"name\":\"to_lan\",\"packets\":0}}]}";
    const dump = try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{try svc.render(a, d, "grafana", "scarif", 3000)});
    const pid = "{\"data\":{\"pid\":42}}";
    const no_data = "{\"data\":[]}";
    const R = testkit.Gateway.FakeServer.Route;
    const ok = struct {
        fn r(match: []const u8, body: []const u8) R {
            return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
        }
    }.r;
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&[_]R{
        // Proxmox
        ok("/nodes/pve/status ", host.status_body),
        ok("/api2/json/version ", host.version_body),
        ok("/nodes/pve/qemu ", qemu),
        ok("/qemu/200/config ", cfg200),
        ok("/qemu/202/config ", "{\"data\":{\"agent\":\"1\"}}"),
        ok("/qemu/202/agent/network-get-interfaces ", "{\"data\":{\"result\":[]}}"),
        ok("/qemu/202/agent/exec ", pid),
        ok("/qemu/202/agent/exec-status", try agentOut(a, "yes\nlinux-image-7.0.0-39-generic\nlinux-base\nlinux-image-7.0.0-39-generic\n")),
        ok("/nodes/pve/storage ", storage.storage_body),
        ok("/tasks?limit=100", no_data),
        ok("errors=1", no_data),
        // Edge: VM, agent, probe, status script, host firewall, address, routes
        ok("/nodes/pve/qemu ", qemu),
        ok("/qemu/200/agent/ping ", "{\"data\":{\"result\":{}}}"),
        ok("/qemu/200/agent/exec ", pid),
        ok("/qemu/200/agent/exec-status", try agentOut(a, "caddy -\ncaddymod no\nnft yes\nnftenabled yes\ncaddyactive no\nreboot no\n")),
        ok("/qemu/200/agent/exec ", pid),
        ok("/qemu/200/agent/exec-status", try agentOut(a, try std.fmt.allocPrint(a, "{s}\n---\nnocert\n---\ninactive\n---\n0\n", .{counters}))),
        ok("/qemu/200/config ", cfg200),
        ok("/qemu/200/firewall/options ", "{\"data\":{}}"),
        ok("/qemu/200/firewall/rules ", no_data),
        ok("/qemu/200/firewall/ipset ", no_data),
        ok("/qemu/200/config ", cfg200),
        ok("/qemu/200/agent/exec ", pid),
        ok("/qemu/200/agent/exec-status", try agentOut(a, dump)),
        // Router: no role-router VM
        ok("/nodes/pve/qemu ", qemu),
        // Tunnel
        ok("/zones?", @import("cf_tunnel.zig").zones_body),
        ok("/cfd_tunnel?", @import("cf_tunnel.zig").tunnels_body),
        ok("/cfd_tunnel/T1/configurations ", "{\"success\":true,\"errors\":[],\"result\":{\"config\":{\"ingress\":[{\"hostname\":\"blog.example.com\",\"service\":\"https://localhost:443\",\"originRequest\":{\"originServerName\":\"blog.apps.lab.example.com\"}},{\"service\":\"http_status:404\"}]}}}"),
        // UniFi
        ok("/v1/info ", "{\"applicationVersion\":\"10.6.106\"}"),
        ok("/v1/sites?", "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"S1\",\"internalReference\":\"default\",\"name\":\"Default\"}]}"),
        ok("/devices?", json_list),
        ok("/clients?", "{\"offset\":0,\"limit\":1,\"count\":0,\"totalCount\":0,\"data\":[]}"),
        ok("/wans?", json_list),
        ok("/dns/policies?", "{\"offset\":0,\"limit\":200,\"count\":4,\"totalCount\":4,\"data\":[" ++
            "{\"type\":\"A_RECORD\",\"id\":\"R1\",\"enabled\":true,\"domain\":\"bespin.lab.example.com\",\"ipv4Address\":\"192.168.1.200\"}," ++
            "{\"type\":\"A_RECORD\",\"id\":\"R2\",\"enabled\":true,\"domain\":\"scarif.lab.example.com\",\"ipv4Address\":\"192.168.1.202\"}," ++
            "{\"type\":\"A_RECORD\",\"id\":\"R3\",\"enabled\":true,\"domain\":\"ntfy.apps.lab.example.com\",\"ipv4Address\":\"192.168.1.200\"}," ++
            "{\"type\":\"A_RECORD\",\"id\":\"R4\",\"enabled\":true,\"domain\":\"grafana.apps.lab.example.com\",\"ipv4Address\":\"192.168.1.200\"}]}"),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{command});
    try testing.expectEqual(testkit.Exit.partial, g.h.run(&root, "status"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    for ([_][]const u8{
        "Guest DNS (lab.example.com): 2 matched\n",
        "  ▲ reboot pending: scarif (linux-image-7.0.0-39-generic, linux-base) — 'artoo vm reboot VM'\n",
        "Edge (bespin)\n  ✗ drops to Proxmox  3 packet(s) blocked — investigate\n",
        "Router\n  none (no VM tagged role-router)\n",
        "Tunnel\n  lab: healthy, 2 connection(s), 1 public route(s)\n  ▲ blog.example.com → service blog: the service does not exist\n",
        "Services\n  1 ok: grafana\n  ▲ ntfy: no route on the edge\n",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n--- stderr:\n{s}\n", .{ line, out, g.h.stderr() });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expect(std.mem.find(u8, g.h.stderr(), "check") != null);
}
