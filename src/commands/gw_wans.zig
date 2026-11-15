//! `artoo gw wans ls|show|log` (SPEC §10.4): WAN health and outages from
//! the gateway's own WAN data (`unifi/wan.zig`). All read-only; the
//! system-log search is a `POST` that changes nothing, sent once.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const unifi = @import("../unifi/client.zig");
const wan = @import("../unifi/wan.zig");
const gw = @import("gw.zig");

const Context = app.Context;
const Cell = ui.table.Cell;

const units = .{ .availability = "fraction", .latency = "ms", .times = "ms since the epoch", .durations = "seconds" };

// ---------------------------------------------------------------- shared

pub const Loaded = struct {
    wans: []wan.Wan,
    problems: std.ArrayList(wan.Problem) = .empty,
    raw: wan.Raw,

    /// Exit 8: nothing beyond names answered, or a source failed for a
    /// reason other than the firmware (SPEC §10.4).
    pub fn partial(l: Loaded) bool {
        if (wan.nothingAnswered(l.raw)) return true;
        for (l.problems.items) |p| if (!p.firmware) return true;
        return false;
    }
};

pub fn load(c: *unifi.Client) !Loaded {
    var l: Loaded = .{ .wans = &.{}, .raw = undefined };
    l.raw = try wan.read(c, &l.problems, .{});
    l.wans = try wan.build(c.ctx.arena, l.raw);
    return l;
}

pub const Outages = struct {
    from_ms: i64,
    to_ms: i64,
    outages: []wan.Outage,
    others: []const wan.Event,
    summary: []wan.Summary,
};

/// The system log over [now - since, now], folded, WANs without a port
/// left out, ongoing outages judged from the WANs' state now. `only`
/// limits it to one network group.
pub fn outages(c: *unifi.Client, wans: []const wan.Wan, since_s: i64, only: ?[]const u8) !Outages {
    const a = c.ctx.arena;
    const now_ms = c.ctx.ui.now * 1000;
    const from_ms = now_ms - since_s * 1000;
    const all = try wan.events(c, from_ms, now_ms);
    var kept: std.ArrayList(wan.Event) = .empty;
    for (all) |e| {
        if (e.group) |g| {
            if (only) |o| if (!std.mem.eql(u8, g, o)) continue;
            if (byGroup(wans, g)) |w| if (w.status == .no_port) continue;
        } else if (only != null) continue;
        try kept.append(a, e);
    }
    const f = try wan.fold(a, kept.items);
    for (f.outages) |*o| {
        const w = byGroup(wans, o.group);
        o.wan = if (w) |x| x.name else null;
        wan.judgeOngoing(o, w);
    }
    // One summary per WAN with a port (or the one asked for).
    var groups: std.ArrayList([]const u8) = .empty;
    if (only) |o| {
        try groups.append(a, o);
    } else for (wans) |w| {
        const g = w.group orelse continue;
        if (w.status != .no_port) try groups.append(a, g);
    }
    for (f.outages) |o| {
        for (groups.items) |g| {
            if (std.mem.eql(u8, g, o.group)) break;
        } else try groups.append(a, o.group);
    }
    const sum = try wan.summarize(a, f.outages, groups.items, from_ms, now_ms);
    for (sum) |*s| s.wan = if (byGroup(wans, s.group)) |x| x.name else null;
    return .{ .from_ms = from_ms, .to_ms = now_ms, .outages = f.outages, .others = f.others, .summary = sum };
}

fn byGroup(wans: []const wan.Wan, g: []const u8) ?*const wan.Wan {
    for (wans) |*w| if (std.mem.eql(u8, w.group orelse continue, g)) return w;
    return null;
}

fn resolve(ctx: *Context, wans: []const wan.Wan, word: []const u8) !*const wan.Wan {
    return wan.find(wans, word) orelse ctx.fail(error.NotFound, "no WAN '{s}' on UniFi (see 'artoo gw wans ls')", .{try gw.sanitized(ctx, word)});
}

fn clean(ctx: *Context, s: []const u8) ![]const u8 {
    return gw.sanitized(ctx, s);
}

pub fn statusCell(ctx: *Context, s: wan.Status) Cell {
    const g = ctx.ui.glyphs;
    return switch (s) {
        .online => .{ .text = std.fmt.allocPrint(ctx.arena, "{s} online", .{g.running}) catch "online", .role = .ok },
        .offline => .{ .text = std.fmt.allocPrint(ctx.arena, "{s} offline", .{g.fail}) catch "offline", .role = .fail },
        .no_port => .{ .text = std.fmt.allocPrint(ctx.arena, "{s} no port", .{g.not_checked}) catch "no port", .role = .muted },
        .unknown => .{ .text = std.fmt.allocPrint(ctx.arena, "{s} unknown", .{g.unknown}) catch "unknown", .role = .muted },
    };
}

fn roleText(r: ?wan.Role) []const u8 {
    return if (r) |x| @tagName(x) else "--";
}

/// 1000 → `1 Gbps`, 2500 → `2.5 Gbps`, 100 → `100 Mbps`.
pub fn speed(a: std.mem.Allocator, mbps: ?i64) ![]const u8 {
    const m = mbps orelse return "--";
    if (m >= 1000) {
        if (@mod(m, 1000) == 0) return std.fmt.allocPrint(a, "{d} Gbps", .{@divTrunc(m, 1000)});
        return std.fmt.allocPrint(a, "{d}.{d} Gbps", .{ @divTrunc(m, 1000), @divTrunc(@mod(m, 1000), 100) });
    }
    return std.fmt.allocPrint(a, "{d} Mbps", .{m});
}

/// `port 5, 1 Gbps full`, `port 5, down`, `--`.
fn linkText(ctx: *Context, w: wan.Wan) ![]const u8 {
    const a = ctx.arena;
    if (w.status == .no_port) return "no port";
    const p = w.port orelse return "--";
    const idx = if (p.index) |i| try std.fmt.allocPrint(a, "port {d}", .{i}) else if (p.ifname) |n| try clean(ctx, n) else "port ?";
    if (p.up == false) return std.fmt.allocPrint(a, "{s}, down", .{idx});
    if (p.speed_mbps == null) return idx;
    const duplex: []const u8 = if (p.full_duplex) |f| (if (f) " full" else " half") else "";
    return std.fmt.allocPrint(a, "{s}, {s}{s}", .{ idx, try speed(a, p.speed_mbps), duplex });
}

fn addressText(ctx: *Context, w: wan.Wan) ![]const u8 {
    const addr = w.address orelse return "--";
    if (w.shared_address) return std.fmt.allocPrint(ctx.arena, "{s} shared", .{try clean(ctx, addr)});
    return clean(ctx, addr);
}

fn latencyText(a: std.mem.Allocator, ms: ?f64) ![]const u8 {
    const v = ms orelse return "--";
    return std.fmt.allocPrint(a, "{d:.0} ms", .{v});
}

fn problemLines(ctx: *Context, problems: []const wan.Problem) !void {
    const p = ctx.ui.palette;
    for (problems) |pr| {
        const role: ui.style.Role = if (pr.firmware) .muted else .fail;
        try ctx.out.print("{s}{s} {s}: {s}{s}\n", .{ p.on(role), if (pr.firmware) ctx.ui.glyphs.not_checked else ctx.ui.glyphs.fail, pr.source, try clean(ctx, pr.message), p.off(role) });
    }
}

fn finish(ctx: *Context, l: Loaded) !void {
    if (l.partial()) return ctx.fail(error.Partial, "WAN state incomplete: {d} source{s} did not answer", .{ l.problems.items.len, if (l.problems.items.len == 1) "" else "s" });
}

// ---------------------------------------------------------------- ls

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "List WAN interfaces: role, status, address, ISP, link, availability";
    pub const details =
        \\Read-only. Names and IDs from the Integration API; state from the
        \\gateway's classic stat/health and stat/device documents and the v2
        \\load-balancing status (SPEC §10.4). "shared" marks an address in
        \\100.64.0.0/10 (the ISP's carrier-grade NAT). A WAN no gateway port
        \\carries shows as "no port" (role unassigned). A source this firmware
        \\lacks is named; the command exits 8 when none answers.
    ;
    pub const examples = [_][]const u8{ "artoo gw wans ls", "artoo gw wans ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try unifi.Client.open(ctx);
        defer c.deinit();
        const l = try load(&c);
        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .unifi, l.wans, .{ .collected_at = ctx.ui.now, .site = c.site_name orelse c.site, .units = units, .errors = l.problems.items });
        } else {
            try gw.header(ctx, &c);
            try renderList(ctx, l.wans);
            if (l.problems.items.len > 0) {
                try ctx.out.writeByte('\n');
                try problemLines(ctx, l.problems.items);
            }
        }
        try finish(ctx, l);
    }
};

fn renderList(ctx: *Context, wans: []const wan.Wan) !void {
    const a = ctx.arena;
    if (wans.len == 0) return ctx.out.print("{s}No WANs.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
    const rows = try a.alloc([]const Cell, wans.len);
    for (wans, rows) |w, *row| {
        const cells = try a.alloc(Cell, 9);
        const assigned = w.status != .no_port;
        cells[0] = .{ .text = try clean(ctx, w.name) };
        cells[1] = .{ .text = roleText(w.role), .role = if (w.role == .unassigned) .muted else .text };
        cells[2] = statusCell(ctx, w.status);
        cells[3] = .{ .text = try addressText(ctx, w) };
        cells[4] = .{ .text = if (w.isp) |i| if (i.name) |n| try clean(ctx, n) else "--" else "--" };
        cells[5] = .{ .text = try linkText(ctx, w), .role = if (assigned) .text else .muted };
        cells[6] = .{ .text = if (assigned) try ui.values.alloc(a, ui.values.percent(w.availability)) else "--" };
        cells[7] = .{ .text = if (assigned) try latencyText(a, w.latency_ms) else "--" };
        cells[8] = .{ .text = try clean(ctx, w.id) };
        row.* = cells;
    }
    try ui.table.render(ctx.out, &ctx.ui, a, &.{
        .{ .title = "NAME", .truncate = false },
        .{ .title = "ROLE", .drop = 2 },
        .{ .title = "STATUS" },
        .{ .title = "ADDRESS", .truncate = false },
        .{ .title = "ISP", .drop = 4 },
        .{ .title = "LINK", .drop = 1 },
        .{ .title = "AVAIL", .alignment = .right, .drop = 3 },
        .{ .title = "LATENCY", .alignment = .right, .drop = 3 },
        .{ .title = "ID", .truncate = false, .drop = 5 },
    }, rows);
}

// ---------------------------------------------------------------- show

const ShowData = struct {
    wan: wan.Wan,
    /// The last 24 hours; null when the system log did not answer or the
    /// WAN has no port.
    outages: ?[]const wan.Outage = null,
    events: ?[]const wan.Event = null,
};

pub const show = struct {
    pub const name = "show";
    pub const summary = "Show one WAN in depth: address, next hop, ISP, port, monitors, outages";
    pub const details =
        \\Read-only. WAN by name (exact, then case-insensitive) or ID. The
        \\outages are the last 24 hours of the system log, as 'gw wans log'
        \\shows them. A past outage has no recorded next-hop state, so it is
        \\never blamed on the ISP's first hop.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "WAN", .help = "WAN name or ID" }};
    pub const examples = [_][]const u8{ "artoo gw wans show WAN-NAME", "artoo gw wans show WAN-NAME -o json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try unifi.Client.open(ctx);
        defer c.deinit();
        var l = try load(&c);
        const w = try resolve(ctx, l.wans, args.pos("WAN"));
        var d: ShowData = .{ .wan = w.* };
        var o: ?Outages = null;
        if (w.status != .no_port) if (w.group) |g| {
            o = try wan.attempt(&c, &l.problems, "system-log", outages(&c, l.wans, wan.Since.@"24h".seconds(), g));
        };
        if (o) |x| {
            d.outages = x.outages;
            d.events = x.others;
        }
        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .unifi, d, .{ .collected_at = ctx.ui.now, .site = c.site_name orelse c.site, .units = units, .errors = l.problems.items });
        } else {
            try gw.header(ctx, &c);
            try renderShow(ctx, w.*, o);
            if (l.problems.items.len > 0) {
                try ctx.out.writeByte('\n');
                try problemLines(ctx, l.problems.items);
            }
        }
        try finish(ctx, l);
    }
};

fn renderShow(ctx: *Context, w: wan.Wan, o: ?Outages) !void {
    const a = ctx.arena;
    const u = &ctx.ui;
    var sections: std.ArrayList(ui.blocks.Section) = .empty;

    const st = statusCell(ctx, w.status);
    var head: std.ArrayList(ui.blocks.Field) = .empty;
    try head.append(a, .{ .key = "Status", .value = if (w.role) |r| try std.fmt.allocPrint(a, "{s} ({s})", .{ st.text, @tagName(r) }) else st.text, .role = st.role });
    try head.append(a, .{ .key = "Group", .value = if (w.group) |g| try clean(ctx, g) else "--" });
    try head.append(a, .{ .key = "ID", .value = try clean(ctx, w.id) });
    try sections.append(a, .{ .title = try std.fmt.allocPrint(a, "WAN {s}", .{try clean(ctx, w.name)}), .fields = head.items });

    if (w.status == .no_port) {
        try head.append(a, .{ .key = "Port", .value = "none: no gateway port carries this WAN", .role = .muted });
        sections.items[0].fields = head.items;
        return ui.blocks.detail(ctx.out, u, sections.items);
    }

    var addr: std.ArrayList(ui.blocks.Field) = .empty;
    try addr.append(a, .{ .key = "Address", .value = if (w.address) |x| (if (w.shared_address) try std.fmt.allocPrint(a, "{s} (shared: the ISP's carrier-grade NAT)", .{try clean(ctx, x)}) else try clean(ctx, x)) else "--" });
    try addr.append(a, .{ .key = "Netmask", .value = if (w.netmask) |x| try clean(ctx, x) else "--" });
    if (w.next_hop) |h| {
        const seen = if (h.last_reachable_seconds) |s| try std.fmt.allocPrint(a, " (seen {f})", .{ui.values.relative(0, -s)}) else "";
        const word: []const u8, const role: ui.style.Role = if (h.reachable) |r| (if (r) .{ "reachable now", .ok } else .{ "not reachable now", .fail }) else .{ "reachability unknown", .muted };
        try addr.append(a, .{ .key = "Next hop", .value = try std.fmt.allocPrint(a, "{s}, {s}{s}", .{ try clean(ctx, h.address), word, seen }), .role = role });
    } else try addr.append(a, .{ .key = "Next hop", .value = "--" });
    if (w.isp) |i| {
        var parts: std.ArrayList([]const u8) = .empty;
        if (i.name) |n| try parts.append(a, try clean(ctx, n));
        if (i.organization) |n| try parts.append(a, try clean(ctx, n));
        if (i.asn) |n| try parts.append(a, try std.fmt.allocPrint(a, "AS{d}", .{n}));
        try addr.append(a, .{ .key = "ISP", .value = if (parts.items.len > 0) try std.mem.join(a, ", ", parts.items) else "--" });
    } else try addr.append(a, .{ .key = "ISP", .value = "--" });
    try sections.append(a, .{ .title = "Address", .fields = addr.items });

    if (w.port) |p| {
        var pf: std.ArrayList(ui.blocks.Field) = .empty;
        const idx = if (p.index) |i| try std.fmt.allocPrint(a, "{d}", .{i}) else "--";
        const ifn = if (p.ifname) |n| try std.fmt.allocPrint(a, " ({s})", .{try clean(ctx, n)}) else "";
        const media = if (p.media) |m| try std.fmt.allocPrint(a, ", {s}", .{try clean(ctx, m)}) else "";
        try pf.append(a, .{ .key = "Port", .value = try std.fmt.allocPrint(a, "{s}{s}{s}", .{ idx, ifn, media }) });
        const link: []const u8 = if (p.up) |up| (if (up) "up" else "down") else "--";
        const duplex: []const u8 = if (p.full_duplex) |f| (if (f) ", full duplex" else ", half duplex") else "";
        try pf.append(a, .{
            .key = "Link",
            .value = if (p.up == true) try std.fmt.allocPrint(a, "up, {s}{s}", .{ try speed(a, p.speed_mbps), duplex }) else link,
            .role = if (p.up == false) .fail else .text,
        });
        try pf.append(a, .{ .key = "Errors", .value = try std.fmt.allocPrint(a, "rx {s}, tx {s}", .{ try count(a, p.rx_errors), try count(a, p.tx_errors) }) });
        try pf.append(a, .{ .key = "Drops", .value = try std.fmt.allocPrint(a, "rx {s}, tx {s}", .{ try count(a, p.rx_dropped), try count(a, p.tx_dropped) }) });
        try sections.append(a, .{ .title = "Port", .fields = pf.items });
    }

    var hf: std.ArrayList(ui.blocks.Field) = .empty;
    try hf.append(a, .{ .key = "Availability", .value = try ui.values.alloc(a, ui.values.percent(w.availability)) });
    try hf.append(a, .{ .key = "Latency", .value = try latencyText(a, w.latency_ms) });
    try hf.append(a, .{ .key = "Period", .value = if (w.time_period) |t| try std.fmt.allocPrint(a, "time_period {d} (as the gateway reports it)", .{t}) else "--" });
    try hf.append(a, .{ .key = "Last downtime", .value = if (w.last_downtime_seconds) |s| try ui.values.alloc(a, ui.values.duration(@intCast(@max(s, 0)))) else "--" });
    try sections.append(a, .{ .title = "Health", .fields = hf.items });
    try ui.blocks.detail(ctx.out, u, sections.items);

    if (w.monitors.len > 0) {
        try ctx.out.print("\n{s}Monitors{s}\n", .{ u.palette.on(.title), u.palette.off(.title) });
        const rows = try a.alloc([]const Cell, w.monitors.len);
        for (w.monitors, rows) |m, *row| {
            const cells = try a.alloc(Cell, 5);
            cells[0] = .{ .text = try std.fmt.allocPrint(a, "  {s}", .{try clean(ctx, m.target)}) };
            cells[1] = .{ .text = try clean(ctx, m.type) };
            cells[2] = if (m.failing()) .{ .text = if (m.health) |h| try clean(ctx, h) else "failing", .role = .fail } else .{ .text = if (m.health) |h| try clean(ctx, h) else "--", .role = if (m.health != null) .ok else .muted };
            cells[3] = .{ .text = try ui.values.alloc(a, ui.values.percent(m.availability)) };
            cells[4] = .{ .text = try latencyText(a, m.latency_ms) };
            row.* = cells;
        }
        try ui.table.render(ctx.out, u, a, &.{
            .{ .title = "  TARGET", .truncate = false },
            .{ .title = "TYPE" },
            .{ .title = "HEALTH" },
            .{ .title = "AVAIL", .alignment = .right },
            .{ .title = "LATENCY", .alignment = .right },
        }, rows);
    }

    try ctx.out.print("\n{s}Outages, last 24h{s}\n", .{ u.palette.on(.title), u.palette.off(.title) });
    if (o) |x| {
        try renderOutages(ctx, x, true);
    } else try ctx.out.print("  {s}system log unavailable{s}\n", .{ u.palette.on(.muted), u.palette.off(.muted) });
}

fn count(a: std.mem.Allocator, n: ?i64) ![]const u8 {
    return if (n) |x| std.fmt.allocPrint(a, "{d}", .{x}) else "--";
}

// ---------------------------------------------------------------- log

const LogData = struct {
    since: []const u8,
    from: i64,
    to: i64,
    outages: []const wan.Outage,
    events: []const wan.Event,
    summary: []const wan.Summary,
};

pub const log = struct {
    pub const name = "log";
    pub const summary = "WAN outages from the system log, with lead-up and likely cause";
    pub const details =
        \\Read-only. The system log's INTERNET_AND_WAN events in the window,
        \\every page read (each a POST search that changes nothing, never
        \\retried), folded into outages: a failure opens one, the next restore
        \\of that WAN closes it (its DURATION is the outage's length). Packet
        \\loss, latency and link events in the 10 minutes before a failure are
        \\its lead-up. The likely cause comes from evidence only:
        \\  link-down event during the outage   link: cable, modem or ONT
        \\  link up, next hop unreachable       ISP access (ongoing only)
        \\  link up, every monitor failing      ISP network beyond the first hop
        \\  only the DNS monitors failing       DNS: resolvers unreachable
        \\  nothing to go on                    unknown
        \\Other events are shown as they are. WANs without a port are left out.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "WAN", .help = "WAN name or ID (default: every WAN)", .required = false }};
    pub const flags = [_]cli.Flag{
        .{ .long = "since", .kind = .choice, .choices = &.{ "24h", "7d", "30d" }, .default = "24h", .help = "Window to read" },
    };
    pub const examples = [_][]const u8{ "artoo gw wans log", "artoo gw wans log --since 7d", "artoo gw wans log WAN-NAME --since 30d -o json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const since = args.choice("since", wan.Since) orelse .@"24h";
        var c = try unifi.Client.open(ctx);
        defer c.deinit();
        const l = try load(&c);
        var only: ?[]const u8 = null;
        if (args.optPos("WAN")) |word| {
            const w = try resolve(ctx, l.wans, word);
            if (w.status == .no_port) {
                if (ctx.json()) {
                    try ui.json.envelope(ctx.out, .unifi, LogData{ .since = @tagName(since), .from = (ctx.ui.now - since.seconds()) * 1000, .to = ctx.ui.now * 1000, .outages = &.{}, .events = &.{}, .summary = &.{} }, .{ .collected_at = ctx.ui.now, .site = c.site_name orelse c.site, .units = units, .errors = l.problems.items, .note = "no gateway port carries this WAN" });
                } else {
                    try gw.header(ctx, &c);
                    try ctx.out.print("{s}{s} has no port: no gateway port carries it, nothing to log.{s}\n", .{ ctx.ui.palette.on(.muted), try clean(ctx, w.name), ctx.ui.palette.off(.muted) });
                }
                return;
            }
            only = w.group orelse return ctx.fail(error.Partial, "cannot tie WAN '{s}' to the system log: its network group is unknown (load-balancing status unavailable)", .{try clean(ctx, w.name)});
        }
        const o = outages(&c, l.wans, since.seconds(), only) catch |err| switch (err) {
            error.NotFound, error.Protocol => {
                ctx.diag = null;
                return ctx.fail(error.Partial, "the system log is not available on this firmware", .{});
            },
            else => |e| return e,
        };
        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .unifi, LogData{ .since = @tagName(since), .from = o.from_ms, .to = o.to_ms, .outages = o.outages, .events = o.others, .summary = o.summary }, .{ .collected_at = ctx.ui.now, .site = c.site_name orelse c.site, .units = units, .errors = l.problems.items });
        } else {
            try gw.header(ctx, &c);
            try renderOutages(ctx, o, false);
            try renderSummary(ctx, o, @tagName(since));
            if (l.problems.items.len > 0) {
                try ctx.out.writeByte('\n');
                try problemLines(ctx, l.problems.items);
            }
        }
        // The log answered; the state sources only sharpen ongoing causes,
        // so their absence is named but does not fail the command.
    }
};

const Entry = struct {
    ts: i64,
    outage: ?*const wan.Outage = null,
    event: ?*const wan.Event = null,
};

fn renderOutages(ctx: *Context, o: Outages, indent: bool) !void {
    const a = ctx.arena;
    const u = &ctx.ui;
    var entries: std.ArrayList(Entry) = .empty;
    for (o.outages) |*x| try entries.append(a, .{ .ts = x.start, .outage = x });
    for (o.others) |*e| try entries.append(a, .{ .ts = e.timestamp, .event = e });
    std.mem.sort(Entry, entries.items, {}, struct {
        fn lt(_: void, x: Entry, y: Entry) bool {
            return x.ts < y.ts;
        }
    }.lt);
    const pad: []const u8 = if (indent) "  " else "";
    if (entries.items.len == 0) {
        return ctx.out.print("{s}{s}No outages or WAN events.{s}\n", .{ pad, u.palette.on(.muted), u.palette.off(.muted) });
    }
    var rows: std.ArrayList([]const Cell) = .empty;
    for (entries.items) |en| {
        if (en.outage) |x| {
            const cells = try a.alloc(Cell, 5);
            cells[0] = .{ .text = try std.fmt.allocPrint(a, "{s}{f}", .{ pad, ui.values.absolute(@divFloor(x.start, 1000), &u.zone) }) };
            cells[1] = .{ .text = try clean(ctx, x.wan orelse x.group) };
            if (x.ongoing) {
                cells[2] = .{ .text = try std.fmt.allocPrint(a, "{s} down, ongoing", .{u.glyphs.fail}), .role = .fail };
                cells[3] = .{ .text = try std.fmt.allocPrint(a, "{f}+", .{ui.values.duration(@intCast(@max(@divTrunc(o.to_ms - x.start, 1000), 0)))}), .role = .fail };
            } else {
                cells[2] = .{ .text = try std.fmt.allocPrint(a, "{s} down{s}", .{ u.glyphs.warn, if (x.temporary) ", brief" else "" }), .role = .warn };
                cells[3] = .{ .text = if (x.duration_seconds) |d| try ui.values.alloc(a, ui.values.duration(@intCast(@max(d, 0)))) else "--" };
            }
            cells[4] = .{ .text = if (x.degraded_before) try std.fmt.allocPrint(a, "{s}; degraded before", .{x.cause.text()}) else x.cause.text(), .role = if (x.cause == .unknown) .muted else .text };
            try rows.append(a, cells);
            for (x.lead_up) |e| try rows.append(a, try subRow(ctx, pad, "lead-up", e));
            for (x.during) |e| try rows.append(a, try subRow(ctx, pad, "during", e));
        } else if (en.event) |e| {
            const cells = try a.alloc(Cell, 5);
            cells[0] = .{ .text = try std.fmt.allocPrint(a, "{s}{f}", .{ pad, ui.values.absolute(@divFloor(e.timestamp, 1000), &u.zone) }) };
            cells[1] = .{ .text = if (e.group) |g| try clean(ctx, groupName(o, g)) else "--" };
            cells[2] = .{ .text = try clean(ctx, e.title), .role = .muted };
            cells[3] = .{ .text = "" };
            cells[4] = .{ .text = try clean(ctx, e.message), .role = .muted };
            try rows.append(a, cells);
        }
    }
    try ui.table.render(ctx.out, u, a, &.{
        .{ .title = try std.fmt.allocPrint(a, "{s}TIME", .{pad}), .truncate = false },
        .{ .title = "WAN", .truncate = false },
        .{ .title = "EVENT" },
        .{ .title = "DOWN", .alignment = .right },
        .{ .title = "CAUSE / DETAIL" },
    }, rows.items);
}

fn groupName(o: Outages, g: []const u8) []const u8 {
    for (o.summary) |s| if (std.mem.eql(u8, s.group, g)) return s.wan orelse g;
    for (o.outages) |x| if (std.mem.eql(u8, x.group, g)) return x.wan orelse g;
    return g;
}

fn subRow(ctx: *Context, pad: []const u8, what: []const u8, e: wan.Event) ![]const Cell {
    const a = ctx.arena;
    const cells = try a.alloc(Cell, 5);
    cells[0] = .{ .text = "" };
    cells[1] = .{ .text = "" };
    cells[2] = .{ .text = try std.fmt.allocPrint(a, "{s}{s} {s} {f} {s}", .{ pad, ctx.ui.glyphs.arrow, what, ui.values.clock(@divFloor(e.timestamp, 1000), &ctx.ui.zone), try clean(ctx, e.title) }), .role = .muted };
    cells[3] = .{ .text = "" };
    cells[4] = .{ .text = try clean(ctx, e.message), .role = .muted };
    return cells;
}

fn renderSummary(ctx: *Context, o: Outages, since: []const u8) !void {
    const a = ctx.arena;
    const u = &ctx.ui;
    try ctx.out.print("\n{s}Summary, last {s}{s}\n", .{ u.palette.on(.title), since, u.palette.off(.title) });
    if (o.summary.len == 0) return ctx.out.print("  {s}No WANs with a port.{s}\n", .{ u.palette.on(.muted), u.palette.off(.muted) });
    var fields: std.ArrayList(ui.blocks.Field) = .empty;
    for (o.summary) |s| {
        const value = if (s.outages == 0)
            try std.fmt.allocPrint(a, "no outages, availability {f}", .{ui.values.percent(s.availability)})
        else
            try std.fmt.allocPrint(a, "{d} outage{s}, {f} down (longest {f}), availability {f}", .{
                s.outages,                                                 if (s.outages == 1) "" else "s",
                ui.values.duration(@intCast(@max(s.downtime_seconds, 0))), ui.values.duration(@intCast(@max(s.longest_seconds, 0))),
                ui.values.percent(s.availability),
            });
        try fields.append(a, .{ .key = try std.fmt.allocPrint(a, "  {s}", .{try clean(ctx, s.wan orelse s.group)}), .value = value, .role = if (s.outages == 0) .ok else .warn });
    }
    try ui.blocks.detail(ctx.out, u, &.{.{ .fields = fields.items }});
}

// ---------------------------------------------------------------- group

pub const group = cli.group("wans", "WAN interfaces: health and outages", &.{ cli.leaf(ls), cli.leaf(show), cli.leaf(log) });

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Route = testkit.Gateway.FakeServer.Route;
const root = cli.group("artoo", "test", &.{gw.group});

const sites_body =
    \\{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"51e00001-0000-4000-8000-00000000000d","internalReference":"default","name":"Default"}]}
;

fn ok(match: []const u8, body: []const u8) Route {
    return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
}

fn answer(match: []const u8, code: u16, body: []const u8) Route {
    return .{ .match = match, .behavior = .{ .respond = .{ .status = code, .body = body } } };
}

const state_routes = [_]Route{
    ok("/v1/sites?", sites_body),
    ok("/wans?", wan.fixture_wans),
    ok("GET /proxy/network/v2/api/site/default/wan/load-balancing/status ", wan.fixture_load),
    ok("GET /proxy/network/api/s/default/stat/device ", wan.fixture_device),
    ok("GET /proxy/network/api/s/default/stat/health ", wan.fixture_health),
};

fn nowMs() i64 {
    return @intCast(@divFloor(std.Io.Clock.real.now(testing.io).nanoseconds, std.time.ns_per_ms));
}

/// A system-log page; `events` already JSON.
fn logPage(a: std.mem.Allocator, events: []const u8, page: u32, pages: u32) ![]const u8 {
    return std.fmt.allocPrint(a, "{{\"data\":[{s}],\"page_number\":{d},\"total_element_count\":0,\"total_page_count\":{d}}}", .{ events, page, pages });
}

fn logEvent(a: std.mem.Allocator, id: []const u8, event: []const u8, ts: i64, grp: []const u8, duration: ?i64) ![]const u8 {
    const dur = if (duration) |d| try std.fmt.allocPrint(a, ",\"DURATION\":{{\"id\":\"{d}\",\"name\":\"{d}s\"}}", .{ d, d }) else "";
    return std.fmt.allocPrint(a,
        \\{{"id":"{s}","event":"{s}","severity":"MEDIUM","timestamp":{d},"title_raw":"{{WAN_ID}} {s}","message_raw":"Internet connection {{WAN_ID}} {{ISP_NAME}} on port {{PORT}}.","parameters":{{"WAN_ID":{{"id":"{s}","name":"WAN1"}},"WAN_NAME":{{"id":"{s}","name":"Fiber-Main"}},"ISP_NAME":{{"name":"Example ISP"}},"PORT":{{"id":"5","name":"5"}}{s}}}}}
    , .{ id, event, ts, event, grp, grp, dur });
}

fn expectLines(out: []const u8, lines: []const []const u8) !void {
    for (lines) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "gw wans ls: matched by name and group, shared mark, port, no port" {
    var f: testkit.Gateway = undefined;
    try f.initRoutes(&state_routes);
    defer f.deinit();
    try testing.expectEqual(testkit.Exit.ok, f.h.run(&root, "gw wans ls"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    const out = f.h.stdout();
    const body = out[std.mem.find(u8, out, "\n\n").? + 2 ..];
    try testing.expectEqualStrings(
        \\NAME          ROLE        STATUS     ADDRESS             ISP          LINK                 AVAIL  LATENCY  ID
        \\Fiber-Main    active      ● online   100.64.10.5 shared  Example ISP  port 5, 1 Gbps full  99.8%     4 ms  a1b2c3d4-0000-4000-8000-000000000001
        \\Fiber-Backup  unassigned  – no port  --                  --           no port                 --       --  a1b2c3d4-0000-4000-8000-000000000002
        \\
    , body);
}

test "gw wans ls -o json: id and name kept, state added" {
    var f: testkit.Gateway = undefined;
    try f.initRoutes(&state_routes);
    defer f.deinit();
    try testing.expectEqual(testkit.Exit.ok, f.h.run(&root, "-o json gw wans ls"));
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, f.h.stdout(), .{});
    defer parsed.deinit();
    const d = parsed.value.object.get("data").?.array.items;
    try testing.expectEqualStrings("a1b2c3d4-0000-4000-8000-000000000001", d[0].object.get("id").?.string);
    try testing.expectEqualStrings("Fiber-Main", d[0].object.get("name").?.string);
    try testing.expectEqualStrings("online", d[0].object.get("status").?.string);
    try testing.expect(d[0].object.get("shared_address").?.bool);
    try testing.expectEqualStrings("no_port", d[1].object.get("status").?.string);
    try testing.expectEqualStrings("unassigned", d[1].object.get("role").?.string);
}

test "gw wans ls: a source missing on this firmware is named; none answering exits 8" {
    {
        var f: testkit.Gateway = undefined;
        try f.initRoutes(&.{
            state_routes[0],                                                                            state_routes[1], state_routes[2], state_routes[3],
            answer("/stat/health ", 404, "{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.NotFound\"}}"),
        });
        defer f.deinit();
        try testing.expectEqual(testkit.Exit.ok, f.h.run(&root, "gw wans ls"));
        try expectLines(f.h.stdout(), &.{ "– health: not available on this firmware\n", "Fiber-Main    active      ● online" });
    }
    {
        var f: testkit.Gateway = undefined;
        try f.initRoutes(&.{
            state_routes[0],                                  state_routes[1],
            answer("/wan/load-balancing/status ", 404, "{}"), ok("/stat/device ", "{\"unexpected\":true}"),
            answer("/stat/health ", 404, "{}"),
        });
        defer f.deinit();
        try testing.expectEqual(testkit.Exit.partial, f.h.run(&root, "gw wans ls"));
        try expectLines(f.h.stdout(), &.{"Fiber-Main    --    ? unknown"});
    }
    {
        // Unexpected shapes: a load status without `wan_interfaces`, odd
        // uptime statistics. Named, never a crash.
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const health = try std.mem.replaceOwned(u8, arena.allocator(), wan.fixture_health, "\"uptime_stats\":{\"WAN\":{", "\"uptime_stats\":{\"WAN\":5,\"X\":{");
        var f: testkit.Gateway = undefined;
        try f.initRoutes(&.{
            state_routes[0],                            state_routes[1],
            ok("/wan/load-balancing/status ", "[1,2]"), state_routes[3],
            ok("/stat/health ", health),
        });
        defer f.deinit();
        try testing.expectEqual(testkit.Exit.ok, f.h.run(&root, "gw wans ls"));
        try expectLines(f.h.stdout(), &.{"– load-balancing: not available on this firmware\n"});
    }
}

test "gw wans show: in depth, outages of the last 24 hours, ongoing cause from the state now" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const now = nowMs();
    const events = try std.mem.join(a, ",", &.{
        try logEvent(a, "e3", "NETWORK_WAN_FAILED", now - 90_000, "WAN", null),
        try logEvent(a, "e2", "NETWORK_WAN_RESTORED", now - 3_600_000, "WAN", 95),
        try logEvent(a, "e1", "NETWORK_WAN_FAILED", now - 3_660_000, "WAN", null),
    });
    // Link up, next hop not seen for a while: the ISP's first hop.
    const device = try std.mem.replaceOwned(u8, a, wan.fixture_device, "\"lastReachable\":5", "\"lastReachable\":300");
    var f: testkit.Gateway = undefined;
    try f.initRoutes(&.{
        state_routes[0],             state_routes[1], state_routes[2],
        ok("/stat/device ", device), state_routes[4], ok("POST /proxy/network/v2/api/site/default/system-log/all ", try logPage(a, events, 0, 1)),
    });
    defer f.deinit();
    try testing.expectEqual(testkit.Exit.ok, f.h.run(&root, "gw wans show fiber-main"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    try expectLines(f.h.stdout(), &.{
        "WAN Fiber-Main\n  Status         ● online (active)\n",
        "  Address        100.64.10.5 (shared: the ISP's carrier-grade NAT)\n",
        "  Next hop       100.64.0.1, not reachable now (seen 5m ago)\n",
        "  ISP            Example ISP, Example Networks, AS64500\n",
        "  Port           5 (eth4), 2.5GE\n",
        "  Link           up, 1 Gbps, full duplex\n",
        "  Drops          rx 2, tx 0\n",
        "  Availability   99.8%\n",
        "  Last downtime  1m 35s\n",
        "  monitor.example.com  icmp  good",
        "Outages, last 24h\n",
        "▲ down            1m 35s  unknown\n",
        "✗ down, ongoing  1m ",
        "s+  ISP access: modem or the ISP's first hop\n",
    });
}

test "gw wans show: a WAN without a port; a missing WAN is exit 2" {
    var f: testkit.Gateway = undefined;
    try f.initRoutes(&state_routes);
    defer f.deinit();
    try testing.expectEqual(testkit.Exit.ok, f.h.run(&root, "gw wans show a1b2c3d4-0000-4000-8000-000000000002"));
    try expectLines(f.h.stdout(), &.{ "  Status  – no port (unassigned)\n", "  Port    none: no gateway port carries this WAN\n" });
    try testing.expect(std.mem.find(u8, f.h.stdout(), "Outages") == null);
    f.srv.stop();
    try f.srv.startRoutes(testing.io, &state_routes);
    f.h.hooks.unifi_base = try f.srv.url(f.h.arena.allocator(), "");
    try testing.expectEqual(testkit.Exit.usage, f.h.run(&root, "gw wans show nope"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "no WAN 'nope' on UniFi") != null);
}

test "gw wans log --since 7d: every page, window and category in the search, folded with a summary" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const now = nowMs();
    const page0 = try std.mem.join(a, ",", &.{
        try logEvent(a, "e5", "SOMETHING_NEW", now - 1_000_000, "WAN", null),
        try logEvent(a, "e4", "NETWORK_WAN_RESTORED", now - 2_000_000, "WAN", 150),
        try logEvent(a, "e3", "NETWORK_WAN_FAILED", now - 2_100_000, "WAN", null),
    });
    const page1 = try std.mem.join(a, ",", &.{
        try logEvent(a, "e3", "NETWORK_WAN_FAILED", now - 2_100_000, "WAN", null), // repeated across pages
        try logEvent(a, "e2", "ISP_PACKET_LOSS", now - 2_300_000, "WAN", null),
        try logEvent(a, "e1", "NETWORK_WAN_FAILED", now - 5_000_000, "WAN2", null), // no port: left out
    });
    var f: testkit.Gateway = undefined;
    try f.initRoutes(&(state_routes ++ [_]Route{
        ok("POST /proxy/network/v2/api/site/default/system-log/all ", try logPage(a, page0, 0, 2)),
        ok("POST /proxy/network/v2/api/site/default/system-log/all ", try logPage(a, page1, 1, 2)),
    }));
    defer f.deinit();
    try testing.expectEqual(testkit.Exit.ok, f.h.run(&root, "gw wans log --since 7d"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    var pages: usize = 0;
    for (0..f.sent()) |i| {
        if (std.mem.find(u8, f.request(i), "system-log") == null) continue;
        const b = f.body(i);
        try expectLines(b, &.{ "\"pageSize\":100", "\"categories\":[\"INTERNET_AND_WAN\"]" });
        const from = std.fmt.parseInt(i64, b[std.mem.find(u8, b, "\"timestampFrom\":").? + 16 ..][0..13], 10) catch 0;
        const to = std.fmt.parseInt(i64, b[std.mem.find(u8, b, "\"timestampTo\":").? + 14 ..][0..13], 10) catch 0;
        try testing.expectEqual(@as(i64, 7 * 86400 * 1000), to - from);
        pages += 1;
    }
    try testing.expectEqual(@as(usize, 2), pages);
    const out = f.h.stdout();
    try expectLines(out, &.{
        "Fiber-Main  ▲ down",
        "2m 30s  unknown; degraded before\n",
        "→ lead-up ",
        "WAN1 ISP_PACKET_LOSS",
        "Fiber-Main  WAN1 SOMETHING_NEW",
        "Internet connection WAN1 Example ISP on port 5.",
        "Summary, last 7d\n  Fiber-Main  1 outage, 2m 30s down (longest 2m 30s), availability 100.0%\n",
    });
    try testing.expect(std.mem.find(u8, out, "Fiber-Backup") == null);
}

test "gw wans log: a failed search is never retried and is a read failure (exit 4)" {
    var f: testkit.Gateway = undefined;
    try f.initRoutes(&(state_routes ++ [_]Route{
        answer("POST /proxy/network/v2/api/site/default/system-log/all ", 502, "{}"),
        answer("POST /proxy/network/v2/api/site/default/system-log/all ", 200, "{}"),
    }));
    defer f.deinit();
    try testing.expectEqual(testkit.Exit.network, f.h.run(&root, "gw wans log"));
    try testing.expectEqual(@as(usize, 1), f.srv.unused());
    try expectLines(f.h.stderr(), &.{"UniFi answered 502 for POST /proxy/network/v2/api/site/default/system-log/all"});
    try testing.expect(std.mem.find(u8, f.h.stderr(), "may or may not") == null);
}

test "gw wans log: missing on this firmware exits 8; a WAN without a port has nothing to log" {
    {
        var f: testkit.Gateway = undefined;
        try f.initRoutes(&(state_routes ++ [_]Route{answer("system-log/all ", 404, "{}")}));
        defer f.deinit();
        try testing.expectEqual(testkit.Exit.partial, f.h.run(&root, "gw wans log"));
        try expectLines(f.h.stderr(), &.{"not available on this firmware"});
    }
    {
        var f: testkit.Gateway = undefined;
        try f.initRoutes(&state_routes);
        defer f.deinit();
        try testing.expectEqual(testkit.Exit.ok, f.h.run(&root, "gw wans log Fiber-Backup"));
        try expectLines(f.h.stdout(), &.{"Fiber-Backup has no port"});
        try testing.expectEqual(testkit.Exit.usage, f.h.run(&root, "gw wans log --since 1y"));
    }
}
