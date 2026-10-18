//! `artoo svc ls|add|set|rm` (SPEC §9.6): service names
//! `<name>.apps.<guests.domain>`. A service is two halves and no local
//! state: a Caddy route file on the edge VM (written through the guest
//! agent, the record of the upstream) and a UniFi A record to the edge
//! VM's address. Both are read every time.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const exec = @import("../exec.zig");
const exposure = @import("../exposure.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const unifi = @import("../unifi/client.zig");
const dns = @import("../unifi/dns.zig");
const edge = @import("edge.zig");
const vm_cmd = @import("vm.zig");
const vm_new = @import("vm_new.zig");
const life = @import("vm_life.zig");
const template = @import("template.zig");
const k = @import("node.zig");

const vm_fence = @import("vm_fence.zig");
const Context = app.Context;

pub const dir = "/etc/caddy/services";
const no_etags = "The UniFi API has no ETags; concurrent edits cannot be detected.";

// ---------------------------------------------------------------- route files

/// One file in `dir`.
pub const Route = struct {
    name: []const u8,
    /// Upstream from the artoo header; empty when the file is not artoo's.
    vm: []const u8 = "",
    port: u16 = 0,
    /// The content differs from what artoo renders for the header.
    edited: bool = false,
    health: Health = .{},

    pub fn managed(r: Route) bool {
        return r.vm.len > 0 and !r.edited;
    }
};

pub const Domains = struct {
    /// `apps.lab.example.com`
    apps: []const u8,
    /// `lab.example.com` (machine names)
    guests: []const u8,
};

/// Where a service reports its health (SPEC §9.6): the path probed by
/// the edge and the watchdog, and a text that means "down" in its answer.
pub const Health = struct {
    path: []const u8 = "/",
    down: ?[]const u8 = null,

    pub fn eql(x: Health, y: Health) bool {
        if (!std.mem.eql(u8, x.path, y.path)) return false;
        if (x.down == null or y.down == null) return x.down == null and y.down == null;
        return std.mem.eql(u8, x.down.?, y.down.?);
    }

    /// `/v1/health`, `/v1/health, down "down"`.
    pub fn describe(h: Health, a: std.mem.Allocator) ![]const u8 {
        return if (h.down) |t| std.fmt.allocPrint(a, "{s}, down {s}", .{ h.path, t }) else h.path;
    }
};

const health_line = "# artoo health ";
const down_line = "# artoo health-down ";

/// A health path: `/`, then at most 128 characters of a URL path and
/// query — nothing Caddy, Alloy or a shell would read specially.
pub fn validHealthPath(s: []const u8) bool {
    if (s.len == 0 or s.len > 128 or s[0] != '/') return false;
    for (s) |ch| {
        if (std.ascii.isAlphanumeric(ch)) continue;
        if (std.mem.findScalar(u8, "-._~/%?=&+,;:@!$'()*", ch) == null) return false;
    }
    return true;
}

/// A down text: 1–64 printable ASCII characters, no backtick.
pub fn validDownText(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s) |ch| if (ch < 0x20 or ch > 0x7e or ch == '`') return false;
    return true;
}

/// The route file for `name` → `vm:port`; the upstream is the guest's
/// machine name, resolved by Caddy through UniFi.
pub fn render(a: std.mem.Allocator, d: Domains, name: []const u8, vm: []const u8, port: u16) ![]const u8 {
    return renderRoute(a, d, name, vm, port, .{});
}

/// `render` with the health lines after the header, only when set.
pub fn renderRoute(a: std.mem.Allocator, d: Domains, name: []const u8, vm: []const u8, port: u16, h: Health) ![]const u8 {
    var lines: std.ArrayList(u8) = .empty;
    if (!std.mem.eql(u8, h.path, "/")) try lines.print(a, health_line ++ "{s}\n", .{h.path});
    if (h.down) |t| try lines.print(a, down_line ++ "{s}\n", .{t});
    return std.fmt.allocPrint(a,
        \\# artoo service {[n]s} -> {[vm]s}:{[p]d}
        \\{[h]s}@svc-{[n]s} host {[n]s}.{[apps]s}
        \\handle @svc-{[n]s} {{
        \\    reverse_proxy {[vm]s}.{[guests]s}:{[p]d}
        \\}}
        \\
    , .{ .n = name, .vm = vm, .p = port, .h = lines.items, .apps = d.apps, .guests = d.guests });
}

/// What the edge holds: the route files and whether Caddy runs.
pub const EdgeView = struct {
    routes: []const Route = &.{},
    caddy_active: bool = false,
    raw: []const u8 = "",

    pub fn find(v: EdgeView, name: []const u8) ?Route {
        for (v.routes) |r| if (std.mem.eql(u8, r.name, name)) return r;
        return null;
    }
};

const dump_script =
    \\for f in /etc/caddy/services/*.caddy; do [ -e "$f" ] || continue; printf '==artoo== %s\n' "$f"; cat "$f"; echo; done
    \\systemctl is-active caddy >/dev/null 2>&1 && echo '==caddy== active' || echo '==caddy== inactive'
    \\
;

/// Parse `dump_script`'s output. `edge setup`'s placeholder file is not a
/// service.
pub fn parseDump(a: std.mem.Allocator, d: Domains, out: []const u8) !EdgeView {
    var v: EdgeView = .{ .raw = out };
    var routes: std.ArrayList(Route) = .empty;
    var path: ?[]const u8 = null;
    var body: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, out, '\n');
    while (lines.next()) |line| {
        const file = std.mem.cutPrefix(u8, line, "==artoo== ");
        const caddy = std.mem.cutPrefix(u8, line, "==caddy== ");
        if (file != null or caddy != null) {
            if (path) |p| try addRoute(a, d, &routes, p, body.items);
            path = file;
            body = .empty;
            if (caddy) |s| v.caddy_active = std.mem.eql(u8, s, "active");
            continue;
        }
        if (path != null) {
            try body.appendSlice(a, line);
            try body.append(a, '\n');
        }
    }
    if (path) |p| try addRoute(a, d, &routes, p, body.items);
    v.routes = routes.items;
    return v;
}

fn addRoute(a: std.mem.Allocator, d: Domains, routes: *std.ArrayList(Route), path: []const u8, body: []const u8) !void {
    const base = std.fs.path.basename(path);
    const name = std.mem.cutSuffix(u8, base, ".caddy") orelse return;
    if (std.mem.eql(u8, name, "000-none")) return;
    // `cat; echo` adds one newline after every file.
    const content = if (std.mem.endsWith(u8, body, "\n")) body[0 .. body.len - 1] else body;
    var r: Route = .{ .name = try a.dupe(u8, name), .edited = true };
    var lines = std.mem.splitScalar(u8, content, '\n');
    if (std.mem.cutPrefix(u8, lines.first(), "# artoo service ")) |rest| {
        if (std.mem.cut(u8, rest, " -> ")) |parts| {
            if (std.mem.eql(u8, parts[0], name)) {
                if (parseUpstream(parts[1])) |up| {
                    var h: Health = .{};
                    var line = lines.next() orelse "";
                    if (std.mem.cutPrefix(u8, line, health_line)) |p| {
                        h.path = try a.dupe(u8, p);
                        line = lines.next() orelse "";
                    }
                    if (std.mem.cutPrefix(u8, line, down_line)) |t| h.down = try a.dupe(u8, t);
                    r.vm = try a.dupe(u8, up.vm);
                    r.port = up.port;
                    r.health = h;
                    // Health lines outside the rules count as an edit.
                    r.edited = !validHealthPath(h.path) or (h.down != null and !validDownText(h.down.?)) or
                        !std.mem.eql(u8, content, try renderRoute(a, d, name, up.vm, up.port, h));
                }
            }
        }
    }
    try routes.append(a, r);
}

pub const Upstream = struct { vm: []const u8, port: u16 };

/// `naboo:3000` → VM word and port (1–65535, never 22).
pub fn parseUpstream(s: []const u8) ?Upstream {
    const parts = std.mem.cutLast(u8, s, ":") orelse return null;
    if (parts[0].len == 0) return null;
    const port = std.fmt.parseInt(u16, parts[1], 10) catch return null;
    if (port == 0 or port == 22) return null;
    return .{ .vm = parts[0], .port = port };
}

/// A service name: one DNS label, lowercase, starting with a letter.
pub fn validName(s: []const u8) bool {
    if (s.len == 0 or s.len > 63 or !std.ascii.isLower(s[0]) or s[s.len - 1] == '-') return false;
    for (s) |ch| if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch) and ch != '-') return false;
    return true;
}

/// Writes the route (base64 on stdin) for service `$1`, has Caddy
/// validate the whole configuration with it, then reloads; a rejected or
/// failed reload puts the previous file back.
const apply_script =
    \\set -eu
    \\d=/etc/caddy/services
    \\f="$d/$1.caddy"; t="$d/.$1.artoo-new"; b="$d/.$1.artoo-old"
    \\base64 -d > "$t"
    \\chmod 0644 "$t"
    \\rm -f "$b"
    \\if [ -e "$f" ]; then cp -p "$f" "$b"; fi
    \\mv -f "$t" "$f"
    \\restore() { if [ -e "$b" ]; then mv -f "$b" "$f"; else rm -f "$f"; fi; }
    \\if ! out=$(runuser -u caddy -- env XDG_DATA_HOME=/var/lib/caddy XDG_CONFIG_HOME=/var/lib/caddy sh -c 'set -a; . /etc/caddy/cloudflare.env; set +a; exec /usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile' 2>&1); then
    \\  restore
    \\  printf '%s\n' "$out" | grep -v '^{' | tail -n 1 >&2
    \\  exit 3
    \\fi
    \\if ! systemctl reload caddy; then
    \\  restore
    \\  systemctl reload caddy || true
    \\  echo "caddy reload failed; the previous route is back" >&2
    \\  exit 4
    \\fi
    \\rm -f "$b"
    \\
;

/// Removes service `$1`'s route and reloads; a failed reload keeps it.
const remove_script =
    \\set -eu
    \\f="/etc/caddy/services/$1.caddy"; b="/etc/caddy/services/.$1.artoo-old"
    \\[ -e "$f" ] || exit 0
    \\mv -f "$f" "$b"
    \\if ! systemctl reload caddy; then mv -f "$b" "$f"; echo "caddy reload failed; the route stays" >&2; exit 4; fi
    \\rm -f "$b"
    \\
;

/// Caddy's live configuration names host `$1`, what `https://$1$2` (the
/// health path) answers through Caddy on the edge itself (certificate
/// verified), and whether the answer holds the down text `$3`.
const probe_script =
    \\curl -s --max-time 5 http://localhost:2019/config/ | grep -qF "\"$1\"" && echo "route yes" || echo "route no"
    \\t=$(mktemp)
    \\c=$(curl -s -o "$t" -w '%{http_code}' --max-time 10 --resolve "$1:443:127.0.0.1" "https://$1$2" 2>/dev/null) || true
    \\echo "http ${c:-000}"
    \\if [ -n "${3:-}" ] && grep -qF -- "$3" "$t"; then echo "down yes"; fi
    \\rm -f "$t"
    \\
;

pub const Probe = struct {
    route: bool = false,
    http: []const u8 = "000",
    /// The answer holds the service's down text.
    down: bool = false,

    /// The upstream answered (any status but a proxy error or nothing).
    pub fn answering(p: Probe) bool {
        return !(std.mem.eql(u8, p.http, "000") or std.mem.eql(u8, p.http, "502") or std.mem.eql(u8, p.http, "503") or std.mem.eql(u8, p.http, "504"));
    }

    /// A 2xx answer without the down text: what the watchdog counts as up.
    pub fn healthy(p: Probe) bool {
        return p.http.len == 3 and p.http[0] == '2' and !p.down;
    }
};

pub fn parseProbe(out: []const u8) Probe {
    var p: Probe = .{};
    var lines = std.mem.tokenizeScalar(u8, out, '\n');
    while (lines.next()) |line| {
        if (std.mem.cutPrefix(u8, line, "route ")) |v| p.route = std.mem.eql(u8, v, "yes");
        if (std.mem.cutPrefix(u8, line, "http ")) |v| p.http = v;
        if (std.mem.eql(u8, line, "down yes")) p.down = true;
    }
    return p;
}

// ---------------------------------------------------------------- reads

pub fn domains(ctx: *Context) !Domains {
    return .{ .apps = try edge.appsDomain(ctx), .guests = (try ctx.config()).guests.domain };
}

pub fn fqdn(ctx: *Context, d: Domains, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ name, d.apps });
}

/// The services on the edge VM (the one tagged role-edge, running).
pub fn read(ctx: *Context, c: *pve.Client) !EdgeView {
    const e = try edge.edgeVm(ctx, c);
    return readEdge(c, e.vmid, try domains(ctx));
}

pub fn readEdge(c: *pve.Client, vmid: u32, d: Domains) !EdgeView {
    const ctx = c.ctx;
    const r = try agent.sh(c, vmid, dump_script, 60_000);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading the service routes on the edge VM failed: {s}", .{try k.clean(ctx, std.mem.trim(u8, r.err, " \n"))});
    return parseDump(ctx.arena, d, r.out);
}

/// The edge VM's static address (the target of every service record).
pub fn edgeAddress(c: *pve.Client, v: vms.Vm) ![]const u8 {
    return life.staticAddress(try vms.config(c, v.vmid)) orelse
        c.ctx.fail(error.Refused, "the edge VM {s} has no static address (ipconfig0)", .{v.name});
}

/// Whether `domain` is a service name (`<label>.<apps>`).
pub fn isServiceDomain(domain: []const u8, d: Domains) bool {
    return domain.len > d.apps.len + 1 and std.ascii.endsWithIgnoreCase(domain, d.apps) and domain[domain.len - d.apps.len - 1] == '.';
}

/// Records under the apps domain, by service name.
fn serviceRecords(a: std.mem.Allocator, all: []const dns.ARecord, d: Domains) ![]const dns.ARecord {
    var out: std.ArrayList(dns.ARecord) = .empty;
    for (all) |r| if (isServiceDomain(r.domain, d)) try out.append(a, r);
    return out.items;
}

fn labelOf(domain: []const u8, d: Domains) []const u8 {
    return domain[0 .. domain.len - d.apps.len - 1];
}

/// The guest a service may point at: an artoo guest (not a template, not
/// the edge) with a static address in the guest pool, never Proxmox or
/// UniFi.
fn upstreamVm(ctx: *Context, c: *pve.Client, word: []const u8) !vms.Vm {
    const v = try vms.resolve(c, word);
    if (v.template) return ctx.fail(error.Refused, "{s} is a template", .{v.name});
    if (!template.taggedWith(v.tags, vm_new.tag)) return ctx.fail(error.Refused, "{s} was not created by artoo (no '{s}' tag)", .{ try k.clean(ctx, v.name), vm_new.tag });
    if (vm_cmd.roleOf(v.tags)) |r| if (std.mem.eql(u8, r, edge.role)) return ctx.fail(error.Refused, "{s} is the edge VM itself", .{v.name});
    const addr = life.staticAddress(try vms.config(c, v.vmid)) orelse return ctx.fail(error.Refused, "{s} has no static address (ipconfig0)", .{v.name});
    if (exposure.protected(try ctx.config(), v.name, addr)) |why| return ctx.fail(error.Refused, "refused: {s} (SPEC §9.6)", .{why});
    const cfg = try ctx.config();
    const pool = config.parseRange(cfg.guests.address_pool) orelse return ctx.fail(error.ConfigInvalid, "guests.address_pool is not A-B", .{});
    const ip = vm_new.ip4(addr) orelse return ctx.fail(error.Refused, "{s} has no IPv4 address ({s})", .{ v.name, addr });
    if (ip < pool.first or ip > pool.last) return ctx.fail(error.Refused, "{s} ({s}) is outside the guest pool {s}; the edge reaches only the pool", .{ v.name, addr, cfg.guests.address_pool });
    return v;
}

/// Services whose route points at VM `name` (for `vm rm`); `note` is set
/// when the edge VM could not be read.
pub const Usage = struct { names: []const []const u8 = &.{}, note: ?[]const u8 = null };

pub fn pointingAt(ctx: *Context, c: *pve.Client, name: []const u8) !Usage {
    const at = try routesAt(ctx, c, name);
    var names: std.ArrayList([]const u8) = .empty;
    for (at.routes) |r| try names.append(ctx.arena, r.name);
    return .{ .names = names.items, .note = at.note };
}

/// Routes whose upstream is VM `name`; `note` is set when the edge VM
/// could not be read.
pub const RoutesAt = struct { routes: []const Route = &.{}, note: ?[]const u8 = null };

pub fn routesAt(ctx: *Context, c: *pve.Client, name: []const u8) !RoutesAt {
    var found: ?vms.Vm = null;
    for (try vms.list(c)) |v| {
        const r = vm_cmd.roleOf(v.tags) orelse continue;
        if (std.mem.eql(u8, r, edge.role) and !v.template) found = v;
    }
    const e = found orelse return .{};
    if (std.mem.eql(u8, e.name, name)) return .{};
    if (!e.running()) return .{ .note = try std.fmt.allocPrint(ctx.arena, "Services not checked: the edge VM {s} is {s}", .{ e.name, e.status }) };
    const view = readEdge(c, e.vmid, try domains(ctx)) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |x| return x,
        else => {
            const note = try std.fmt.allocPrint(ctx.arena, "Services not checked: {s}", .{ctx.diag orelse @errorName(err)});
            ctx.diag = null;
            return .{ .note = note };
        },
    };
    var routes: std.ArrayList(Route) = .empty;
    for (view.routes) |r| if (std.ascii.eqlIgnoreCase(r.vm, name)) try routes.append(ctx.arena, r);
    return .{ .routes = routes.items };
}

// ---------------------------------------------------------------- ls

pub const Row = struct {
    name: []const u8,
    url: []const u8,
    upstream: ?[]const u8,
    record: ?[]const u8,
    route: bool,
    /// The path the probes request (SPEC §9.6).
    health: []const u8 = "/",
    health_down: ?[]const u8 = null,
    problems: []const []const u8,
};

/// Every service — a route on the edge, a record under the apps domain, or
/// both — with its drift (`svc ls`, `status`). `vm_names` are the VMs that
/// exist; `edge_addr` is where every record must point.
pub fn drift(ctx: *Context, d: Domains, view: EdgeView, all_records: []const dns.ARecord, vm_names: []const []const u8, edge_addr: []const u8) ![]const Row {
    const a = ctx.arena;
    const records = try serviceRecords(a, all_records, d);
    var names: std.ArrayList([]const u8) = .empty;
    for (view.routes) |r| try names.append(a, r.name);
    for (records) |r| {
        const n = labelOf(r.domain, d);
        if (view.find(n) == null) try names.append(a, n);
    }
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);

    var rows: std.ArrayList(Row) = .empty;
    for (names.items) |n| {
        const route = view.find(n);
        const rec = dns.find(records, try fqdn(ctx, d, n));
        var problems: std.ArrayList([]const u8) = .empty;
        if (route == null) try problems.append(a, "no route on the edge");
        if (rec == null) try problems.append(a, "no DNS record");
        if (rec) |r| {
            if (!std.mem.eql(u8, r.ipv4, edge_addr)) try problems.append(a, try std.fmt.allocPrint(a, "record points at {s}, not the edge ({s})", .{ try k.clean(ctx, r.ipv4), edge_addr }));
            if (!r.enabled) try problems.append(a, "record disabled");
        }
        if (route) |r| {
            if (r.vm.len == 0) {
                try problems.append(a, "route not written by artoo");
            } else {
                if (r.edited) try problems.append(a, "route edited by hand");
                if (!hasName(vm_names, r.vm)) try problems.append(a, try std.fmt.allocPrint(a, "VM {s} does not exist", .{r.vm}));
            }
        }
        try rows.append(a, .{
            .name = try k.clean(ctx, n),
            .url = try std.fmt.allocPrint(a, "https://{s}/", .{try k.clean(ctx, try fqdn(ctx, d, n))}),
            .upstream = if (route != null and route.?.vm.len > 0) try std.fmt.allocPrint(a, "{s}:{d}", .{ route.?.vm, route.?.port }) else null,
            .record = if (rec) |r| try k.clean(ctx, r.ipv4) else null,
            .route = route != null,
            .health = if (route) |r| try k.clean(ctx, r.health.path) else "/",
            .health_down = if (route) |r| if (r.health.down) |t| try k.clean(ctx, t) else null else null,
            .problems = problems.items,
        });
    }
    return rows.items;
}

fn hasName(names: []const []const u8, want: []const u8) bool {
    for (names) |n| if (std.ascii.eqlIgnoreCase(n, want)) return true;
    return false;
}

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "List service names: URL, upstream, record and route";
    pub const details =
        \\Joins the route files on the edge VM with the A records under
        \\apps.<guests.domain> on UniFi and reports drift: a record without
        \\a route, a route without a record, a record pointing elsewhere, a route
        \\edited by hand or to a VM that no longer exists.
    ;
    pub const examples = [_][]const u8{ "artoo svc ls", "artoo svc ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        const a = ctx.arena;
        const d = try domains(ctx);
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const e = try edge.edgeVm(ctx, &c);
        const addr = try edgeAddress(&c, e);
        const view = try readEdge(&c, e.vmid, d);
        const all = try vms.list(&c);
        var u = try unifi.Client.open(ctx);
        defer u.deinit();
        const all_records = try dns.list(&u);

        var vm_names: std.ArrayList([]const u8) = .empty;
        for (all) |v| try vm_names.append(a, v.name);
        const rows = try drift(ctx, d, view, all_records, vm_names.items, addr);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, rows, .{ .collected_at = ctx.ui.now, .edge = e.name });
        try k.header(ctx, &c);
        if (rows.len == 0) {
            try ctx.out.print("{s}No services. Add one with 'artoo svc add NAME VM:PORT'.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
            return;
        }
        const cells = try a.alloc([]const ui.table.Cell, rows.len);
        for (rows, cells) |r, *row| {
            const cs = try a.alloc(ui.table.Cell, 5);
            cs[0] = .{ .text = r.name };
            cs[1] = .{ .text = r.upstream orelse "--", .role = if (r.upstream == null) .muted else .text };
            cs[2] = if (r.problems.len == 0)
                try k.statusCell(ctx, .running, "ok")
            else
                try k.statusCell(ctx, .unknown, try std.mem.join(a, "; ", r.problems));
            const h: Health = .{ .path = r.health, .down = r.health_down };
            cs[3] = if (!r.route) .{ .text = "--", .role = .muted } else .{ .text = try h.describe(a), .role = if (h.eql(.{})) .muted else .text };
            cs[4] = .{ .text = r.url };
            row.* = cs;
        }
        try ui.table.render(ctx.out, &ctx.ui, a, &.{
            .{ .title = "SERVICE", .truncate = false },
            .{ .title = "UPSTREAM", .truncate = false },
            .{ .title = "STATUS" },
            .{ .title = "HEALTH", .drop = 2 },
            .{ .title = "URL", .truncate = false, .drop = 1 },
        }, cells);
    }
};

// ---------------------------------------------------------------- add / set

const Mode = enum { add, set };

const PutOp = struct {
    c: *pve.Client,
    u: *unifi.Client,
    mode: Mode,
    name: []const u8,
    vm_word: []const u8,
    port: u16,
    /// From `--health`/`--health-down`; null keeps what the route says.
    want_health: ?Health = null,
    health: Health = .{},
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    d: Domains = undefined,
    edge_vm: vms.Vm = undefined,
    edge_addr: []const u8 = "",
    vm: vms.Vm = undefined,
    view: EdgeView = .{},
    route: ?Route = null,
    record: ?dns.ARecord = null,
    content: []const u8 = "",
    write_route: bool = false,
    add_record: bool = false,
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},
    probe: Probe = .{},
    /// Fenced guests whose fence the move opens or closes (SPEC §9.11).
    fences: []const vm_fence.Follow = &.{},

    pub fn read(op: *PutOp, ctx: *Context) !void {
        const a = ctx.arena;
        op.d = try domains(ctx);
        op.target = try fqdn(ctx, op.d, op.name);
        const list = try vms.list(op.c);
        op.edge_vm = try edge.edgeVmFrom(ctx, op.c, list);
        op.edge_addr = try edgeAddress(op.c, op.edge_vm);
        op.view = try readEdge(op.c, op.edge_vm.vmid, op.d);
        if (!op.view.caddy_active) return ctx.fail(error.Refused, "Caddy is not running on {s}; see 'artoo edge status'", .{op.edge_vm.name});
        op.vm = try upstreamVm(ctx, op.c, op.vm_word);
        op.route = op.view.find(op.name);
        op.fences = try fencesFor(ctx, op.c, list, op.edge_vm, op.edge_addr, op.view.routes, op.name, op.vm.name, op.port, if (op.route) |r| r.vm else null);
        op.record = dns.find(try dns.list(op.u), op.target);
        op.health = op.want_health orelse if (op.route) |r| r.health else .{};
        op.content = try renderRoute(a, op.d, op.name, op.vm.name, op.port, op.health);
        const rec = if (op.record) |r| try std.fmt.allocPrint(a, "{s} {s} {}", .{ r.id, r.ipv4, r.enabled }) else "absent";
        op.fp = try std.fmt.allocPrint(a, "{s}|{s}", .{ op.view.raw, rec });
    }

    pub fn plan(op: *PutOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const path = try std.fmt.allocPrint(a, "{s}/{s}.caddy", .{ dir, op.name });
        if (op.route) |r| if (!r.managed())
            return ctx.fail(error.Refused, "{s} on {s} was {s}; fix or remove it by hand first", .{ path, op.edge_vm.name, if (r.vm.len == 0) "not written by artoo" else "edited by hand" });
        const same = if (op.route) |r| std.mem.eql(u8, r.vm, op.vm.name) and r.port == op.port else false;
        const old_health: Health = if (op.route) |r| r.health else .{};
        const health_changes = !old_health.eql(op.health);
        switch (op.mode) {
            .add => if (op.route) |r| if (!same)
                return ctx.fail(error.Refused, "service {s} already routes to {s}:{d}; move it with 'artoo svc set {s} {s}:{d}'", .{ op.name, r.vm, r.port, op.name, op.vm.name, op.port }),
            .set => if (op.route == null)
                return ctx.fail(error.NotFound, "no service {s} on {s}; add it with 'artoo svc add {s} {s}:{d}'", .{ op.name, op.edge_vm.name, op.name, op.vm.name, op.port }),
        }
        if (op.record) |r| if (!std.mem.eql(u8, r.ipv4, op.edge_addr) or !r.enabled)
            return ctx.fail(error.Refused, "{s} already points at {s}{s}, not the edge ({s}); remove it with 'artoo dns rm {s}'", .{ op.target, try k.clean(ctx, r.ipv4), if (r.enabled) "" else " (disabled)", op.edge_addr, op.target });
        op.write_route = !same or health_changes;
        op.add_record = op.mode == .add and op.record == null;
        if (!op.write_route and !op.add_record and op.fences.len == 0) return null;

        const up = try std.fmt.allocPrint(a, "{s}:{d}", .{ op.vm.name, op.port });
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (!same) try changes.append(a, .{
            .field = "route",
            .from = if (op.route) |r| try std.fmt.allocPrint(a, "{s}:{d}", .{ r.vm, r.port }) else null,
            .to = try std.fmt.allocPrint(a, "{s}.{s}:{d} ({s} on {s})", .{ op.vm.name, op.d.guests, op.port, path, op.edge_vm.name }),
        });
        if (health_changes) try changes.append(a, .{
            .field = "health",
            .from = if (op.route != null) try old_health.describe(a) else null,
            .to = try std.fmt.allocPrint(a, "{s}{s}", .{ try op.health.describe(a), if (same) try std.fmt.allocPrint(a, " ({s} on {s})", .{ path, op.edge_vm.name }) else "" }),
        });
        if (op.add_record) try changes.append(a, .{ .field = "DNS record", .from = null, .to = try std.fmt.allocPrint(a, "{s} {s} {s} (UniFi)", .{ op.target, ctx.ui.glyphs.arrow, op.edge_addr }) });
        for (op.fences) |f| try vm_fence.followChanges(a, f, &changes);
        var notes: std.ArrayList([]const u8) = .empty;
        if (op.fences.len > 0) try notes.append(a, "A fenced guest's fence opens before the route is written and closes after it is gone (SPEC §9.11).");
        if (op.write_route) try notes.append(a, "Caddy validates the whole configuration first and reloads gracefully; a rejected route is put back.");
        if (op.mode == .set and op.record == null) try notes.append(a, try std.fmt.allocPrint(a, "{s} has no DNS record; 'artoo svc add {s} {s}' adds it.", .{ op.target, op.name, up }));
        if (op.add_record) try notes.append(a, no_etags);
        if (health_changes) try notes.append(a, try std.fmt.allocPrint(a, "Health is not routing: Caddy proxies every path. Run 'artoo watch setup' afterwards so the watchdog probes https://{s}{s}.", .{ op.target, op.health.path }));
        return .{
            .action = if (same)
                try std.fmt.allocPrint(a, "Set the health of service {s} {s} {s}", .{ op.name, ctx.ui.glyphs.arrow, try op.health.describe(a) })
            else
                try std.fmt.allocPrint(a, "{s} service {s} {s} {s}", .{ if (op.mode == .add) "Add" else "Move", op.name, ctx.ui.glyphs.arrow, up }),
            .target = try std.fmt.allocPrint(a, "edge VM {s} ({d}) + UniFi", .{ op.edge_vm.name, op.edge_vm.vmid }),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{try std.fmt.allocPrint(a, "https://{s}/ is proxied by {s} to {s} (LAN clients that use UniFi for DNS)", .{ op.target, op.edge_vm.name, up })}),
            .recovery = if (op.route) |r|
                try std.fmt.allocPrint(a, "artoo svc set {s} {s}:{d}{s}", .{ op.name, r.vm, r.port, if (health_changes) try healthFlags(a, r.health, true) else "" })
            else
                try std.fmt.allocPrint(a, "artoo svc rm {s}", .{op.name}),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *PutOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *PutOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const s_open = try addFenceSteps(a, l, op.fences, true);
        const s_route = if (op.write_route) try l.add(a, "write route, reload Caddy") else null;
        const s_rec = if (op.add_record) try l.add(a, "add DNS record") else null;
        const s_close = try addFenceSteps(a, l, op.fences, false);
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        try runFenceSteps(op.c, l, op.fences, s_open, true);
        if (s_route) |i| {
            l.set(i, .unknown, "");
            const enc = std.base64.standard.Encoder;
            const b64 = try a.alloc(u8, enc.calcSize(op.content.len));
            _ = enc.encode(b64, op.content);
            const r = try agent.exec(op.c, op.edge_vm.vmid, &.{ "sh", "-c", apply_script, "sh", op.name }, b64, 120_000);
            if (!r.ok()) {
                const why = try k.clean(ctx, std.mem.trim(u8, r.err, " \n"));
                if (r.code != null and r.code.? == 3) {
                    l.set(i, .failed, "rejected by caddy validate");
                    return ctx.fail(error.TaskFailed, "Caddy rejected the route; nothing changed: {s}", .{why});
                }
                l.set(i, .failed, "");
                return ctx.fail(error.Partial, "writing the route on {s} failed (exit {?d}): {s}", .{ op.edge_vm.name, r.code, why });
            }
            l.set(i, .done, try std.fmt.allocPrint(a, "{s}/{s}.caddy", .{ dir, op.name }));
        }
        if (s_rec) |i| {
            l.set(i, .unknown, "");
            try dns.create(op.u, op.target, op.edge_addr, dns.default_ttl);
            l.set(i, .done, op.target);
        }
        try runFenceSteps(op.c, l, op.fences, s_close, false);
    }

    pub fn verify(op: *PutOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        if (!try fencesConverged(op.c, op.fences)) return false;
        const view = try readEdge(op.c, op.edge_vm.vmid, op.d);
        const r = view.find(op.name) orelse return false;
        if (!r.managed() or !std.mem.eql(u8, r.vm, op.vm.name) or r.port != op.port or !r.health.eql(op.health)) return false;
        if (op.mode == .add) {
            const rec = dns.find(try dns.list(op.u), op.target) orelse return false;
            if (!std.mem.eql(u8, rec.ipv4, op.edge_addr) or !rec.enabled) return false;
        }
        const p = try agent.exec(op.c, op.edge_vm.vmid, &.{ "sh", "-c", probe_script, "sh", op.target, op.health.path, op.health.down orelse "" }, null, 30_000);
        op.probe = parseProbe(p.out);
        return op.probe.route;
    }

    pub fn done(op: *PutOp) []const u8 {
        const a = op.c.ctx.arena;
        const url = std.fmt.allocPrint(a, "https://{s}{s}", .{ op.target, op.health.path }) catch return "done";
        const arrow = op.c.ctx.ui.glyphs.arrow;
        const custom = !op.health.eql(.{});
        return (if (!op.probe.answering())
            std.fmt.allocPrint(a, "{s} {s} {s}:{d} is routed; the service does not answer yet (HTTP {s})", .{ url, arrow, op.vm.name, op.port, op.probe.http })
        else if (custom and op.probe.down)
            std.fmt.allocPrint(a, "{s} {s} {s}:{d} answers HTTP {s} but reports down (holds {s})", .{ url, arrow, op.vm.name, op.port, op.probe.http, op.health.down.? })
        else if (custom and !op.probe.healthy())
            std.fmt.allocPrint(a, "{s} {s} {s}:{d} answers HTTP {s}, not 2xx: the watchdog's probe will fail", .{ url, arrow, op.vm.name, op.port, op.probe.http })
        else if (custom)
            std.fmt.allocPrint(a, "{s} {s} {s}:{d} — healthy (HTTP {s})", .{ url, arrow, op.vm.name, op.port, op.probe.http })
        else
            std.fmt.allocPrint(a, "{s} {s} {s}:{d} — answers HTTP {s}", .{ url, arrow, op.vm.name, op.port, op.probe.http })) catch "done";
    }
};

/// ` --health PATH --health-down 'TEXT'` for a recovery command; `reset`
/// spells out the default (`--health /`), which no flag would restore.
fn healthFlags(a: std.mem.Allocator, h: Health, reset: bool) ![]const u8 {
    if (h.eql(.{}) and !reset) return "";
    const path = try std.fmt.allocPrint(a, " --health {s}", .{h.path});
    const t = h.down orelse return path;
    const quoted = try std.mem.replaceOwned(u8, a, t, "'", "'\\''");
    return std.fmt.allocPrint(a, "{s} --health-down '{s}'", .{ path, quoted });
}

/// The health flags: none keeps the route's; `--health` replaces both.
fn wantHealth(ctx: *Context, path: ?[]const u8, down: ?[]const u8) !?Health {
    const p = path orelse {
        if (down != null) return ctx.fail(error.Usage, "--health-down needs --health PATH", .{});
        return null;
    };
    if (!validHealthPath(p)) return ctx.fail(error.Usage, "invalid --health '{s}': a path starting with '/', at most 128 characters of letters, digits and -._~/%?=&+,;:@!$'()*", .{try k.clean(ctx, p)});
    if (down) |t| if (!validDownText(t)) return ctx.fail(error.Usage, "invalid --health-down: 1-64 printable ASCII characters, no backtick", .{});
    return .{ .path = p, .down = down };
}

fn put(ctx: *Context, mode: Mode, name_word: []const u8, up_word: []const u8, health: ?[]const u8, health_down: ?[]const u8) !void {
    if (!validName(name_word)) return ctx.fail(error.Usage, "invalid service name '{s}': one DNS label of lowercase letters, digits and '-', starting with a letter", .{name_word});
    if (exposure.protected(try ctx.config(), name_word, null)) |why| return ctx.fail(error.Refused, "refused: {s} (SPEC §9.6)", .{why});
    const up = parseUpstream(up_word) orelse return ctx.fail(error.Usage, "expected VM:PORT (port 1-65535, not 22), got '{s}'", .{up_word});
    const want = try wantHealth(ctx, health, health_down);
    var c = try pve.Client.open(ctx);
    defer c.deinit();
    var u = try unifi.Client.open(ctx);
    defer u.deinit();
    var op: PutOp = .{ .c = &c, .u = &u, .mode = mode, .name = name_word, .vm_word = up.vm, .port = up.port, .want_health = want };
    try exec.run(ctx, &op, .{});
}

const put_positionals = [_]cli.Positional{
    .{ .name = "NAME", .help = "Service name (one DNS label), served as NAME.apps.<guests.domain>" },
    .{ .name = "VM:PORT", .help = "Guest (VMID or name) and the HTTP port its service listens on" },
};

const put_flags = [_]cli.Flag{
    .{ .long = "health", .kind = .string, .metavar = "PATH", .help = "Path the edge probe and the watchdog request (2xx = up); replaces the down text too" },
    .{ .long = "health-down", .kind = .string, .metavar = "TEXT", .help = "Literal text that means down in the health answer (with --health)" },
};

pub const add = struct {
    pub const name = "add";
    pub const summary = "Add a service name: edge route + UniFi record";
    pub const details =
        \\NAME.apps.<guests.domain> gets a route on the edge VM to the guest's
        \\machine name and port (plain HTTP), then an A record on UniFi to
        \\the edge's address. The guest must be an artoo guest in the address
        \\pool. Caddy validates the configuration before it reloads; a probe
        \\from the edge shows whether the service answers (a 502 is a warning:
        \\the service may not run yet). A half that already exists and matches
        \\is kept.
        \\
        \\--health names the path that reports the service's health (default /),
        \\and --health-down a text that means down in its answer; both live in
        \\the route file and are what the edge probe and the watchdog's probe
        \\request ('artoo watch setup' picks up a change). Without --health an
        \\existing route keeps its health; an existing route to the same VM:PORT
        \\with other health is rewritten.
    ;
    pub const positionals = put_positionals;
    pub const flags = put_flags;
    pub const examples = [_][]const u8{
        "artoo svc add grafana naboo:3000 -n",
        "artoo svc add grafana naboo:3000 -y",
        "artoo svc add search holocron:8080 --health /v1/health --health-down '\"down\"'",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        try put(ctx, .add, args.pos("NAME"), args.pos("VM:PORT"), args.string("health"), args.string("health-down"));
    }
};

pub const set = struct {
    pub const name = "set";
    pub const summary = "Move a service to another guest or port (route only)";
    pub const details =
        \\The name and its DNS record stay; only the edge route changes. The
        \\health path and down text stay unless --health replaces them
        \\(--health / alone resets them).
    ;
    pub const positionals = put_positionals;
    pub const flags = put_flags;
    pub const examples = [_][]const u8{ "artoo svc set grafana hoth:3000", "artoo svc set search holocron:8080 --health /" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        try put(ctx, .set, args.pos("NAME"), args.pos("VM:PORT"), args.string("health"), args.string("health-down"));
    }
};

// ---------------------------------------------------------------- rm

const RmOp = struct {
    c: *pve.Client,
    u: *unifi.Client,
    name: []const u8,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    d: Domains = undefined,
    edge_vm: vms.Vm = undefined,
    edge_addr: []const u8 = "",
    route: ?Route = null,
    record: ?dns.ARecord = null,
    record_note: ?[]const u8 = null,
    public_note: ?[]const u8 = null,
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},
    fences: []const vm_fence.Follow = &.{},

    pub fn read(op: *RmOp, ctx: *Context) !void {
        const a = ctx.arena;
        op.target = op.name;
        op.d = try domains(ctx);
        const list = try vms.list(op.c);
        op.edge_vm = try edge.edgeVmFrom(ctx, op.c, list);
        op.edge_addr = try edgeAddress(op.c, op.edge_vm);
        const view = try readEdge(op.c, op.edge_vm.vmid, op.d);
        op.route = view.find(op.name);
        if (op.route) |r| if (r.managed()) {
            op.fences = try fencesFor(ctx, op.c, list, op.edge_vm, op.edge_addr, view.routes, op.name, null, 0, r.vm);
        };
        const domain = try fqdn(ctx, op.d, op.name);
        op.record = null;
        op.record_note = null;
        if (dns.find(try dns.list(op.u), domain)) |r| {
            if (std.mem.eql(u8, r.ipv4, op.edge_addr)) {
                op.record = r;
            } else {
                op.record_note = try std.fmt.allocPrint(a, "{s} {s} {s} kept: it does not point at the edge ({s})", .{ domain, ctx.ui.glyphs.arrow, try k.clean(ctx, r.ipv4), op.edge_addr });
            }
        }
        op.fp = try std.fmt.allocPrint(a, "{s}|{s}", .{ view.raw, if (op.record) |r| r.id else "absent" });
        const public = try @import("cf_tunnel.zig").routesTo(ctx, op.name);
        if (public.names.len > 0) return ctx.fail(error.Refused, "public host(s) {s} reach service {s}; unpublish them first ('artoo cf tunnel route rm HOST')", .{ try std.mem.join(a, ", ", public.names), op.name });
        op.public_note = public.note;
    }

    pub fn plan(op: *RmOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const path = try std.fmt.allocPrint(a, "{s}/{s}.caddy", .{ dir, op.name });
        if (op.route) |r| if (r.vm.len == 0)
            return ctx.fail(error.Refused, "{s} on {s} was not written by artoo; remove it by hand", .{ path, op.edge_vm.name });
        if (op.route == null and op.record == null) {
            if (op.record_note) |n| return ctx.fail(error.Refused, "no service {s} on {s}; {s}", .{ op.name, op.edge_vm.name, n });
            return null;
        }
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (op.record) |r| try changes.append(a, .{ .field = "DNS record", .from = try std.fmt.allocPrint(a, "{s} {s} {s} (UniFi)", .{ try k.clean(ctx, r.domain), ctx.ui.glyphs.arrow, r.ipv4 }), .to = null });
        if (op.route) |r| try changes.append(a, .{ .field = "route", .from = try std.fmt.allocPrint(a, "{s}:{d} ({s} on {s})", .{ r.vm, r.port, path, op.edge_vm.name }), .to = null });
        for (op.fences) |f| try vm_fence.followChanges(a, f, &changes);
        var notes: std.ArrayList([]const u8) = .empty;
        if (op.record_note) |n| try notes.append(a, n);
        if (op.public_note) |n| try notes.append(a, n);
        if (op.route) |r| if (r.edited) try notes.append(a, "The route was edited by hand; the edits are lost.");
        try notes.append(a, "Steps run in order and stop at the first failure.");
        return .{
            .action = try std.fmt.allocPrint(a, "Remove service {s}", .{op.name}),
            .risk = .destructive,
            .target = try std.fmt.allocPrint(a, "edge VM {s} ({d}) + UniFi", .{ op.edge_vm.name, op.edge_vm.vmid }),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{try std.fmt.allocPrint(a, "https://{s}.{s}/ stops resolving and routing; the guest is untouched", .{ op.name, op.d.apps })}),
            .recovery = if (op.route) |r| if (r.vm.len > 0) try std.fmt.allocPrint(a, "artoo svc add {s} {s}:{d}{s}", .{ op.name, r.vm, r.port, try healthFlags(a, r.health, false) }) else null else null,
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *RmOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *RmOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const s_rec = if (op.record != null) try l.add(a, "remove DNS record") else null;
        const s_route = if (op.route != null) try l.add(a, "remove route, reload Caddy") else null;
        const s_close = try addFenceSteps(a, l, op.fences, false);
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (s_rec) |i| {
            l.set(i, .unknown, "");
            try dns.delete(op.u, op.record.?.id);
            l.set(i, .done, try k.clean(ctx, op.record.?.domain));
        }
        if (s_route) |i| {
            l.set(i, .unknown, "");
            const r = try agent.exec(op.c, op.edge_vm.vmid, &.{ "sh", "-c", remove_script, "sh", op.name }, null, 120_000);
            if (!r.ok()) {
                l.set(i, .failed, "");
                return ctx.fail(error.Partial, "removing the route on {s} failed (exit {?d}): {s}", .{ op.edge_vm.name, r.code, try k.clean(ctx, std.mem.trim(u8, r.err, " \n")) });
            }
            l.set(i, .done, "");
        }
        try runFenceSteps(op.c, l, op.fences, s_close, false);
    }

    pub fn verify(op: *RmOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        if (!try fencesConverged(op.c, op.fences)) return false;
        if ((try readEdge(op.c, op.edge_vm.vmid, op.d)).find(op.name) != null) return false;
        if (op.record) |r| if (dns.find(try dns.list(op.u), r.domain) != null) return false;
        return true;
    }

    pub fn done(op: *RmOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "service {s} removed", .{op.name}) catch "done";
    }
};

// ---------------------------------------------------------------- fences

/// The fences a route change moves (SPEC §9.11): the new upstream `to`
/// (null for `rm`) and the old one `from`, when they are fenced guests
/// whose fence differs for the new route set. Reads nothing more unless
/// one of them is fenced.
fn fencesFor(ctx: *Context, c: *pve.Client, list: []const vms.Vm, edge_vm: vms.Vm, edge_addr: []const u8, routes: []const Route, name: []const u8, to: ?[]const u8, port: u16, from: ?[]const u8) ![]const vm_fence.Follow {
    const a = ctx.arena;
    const new_vm = if (to) |n| vm_fence.fencedNamed(list, n) else null;
    const old_vm = if (from) |n| (if (to != null and std.ascii.eqlIgnoreCase(n, to.?)) null else vm_fence.fencedNamed(list, n)) else null;
    if (new_vm == null and old_vm == null) return &.{};
    const after = try vm_fence.routesWith(a, routes, name, to, port);
    const lab = try vm_fence.labFor(ctx, c, list, edge_vm, edge_addr, after);
    var out: std.ArrayList(vm_fence.Follow) = .empty;
    if (new_vm) |v| if (try vm_fence.follow(ctx, c, lab, v, after, true)) |f| try out.append(a, f);
    if (old_vm) |v| if (try vm_fence.follow(ctx, c, lab, v, after, false)) |f| try out.append(a, f);
    return out.items;
}

/// One ledger step per fence that opens (`opens`) or closes; the first
/// index, or null when there is none.
fn addFenceSteps(a: std.mem.Allocator, l: *exec.Ledger, fences: []const vm_fence.Follow, opens: bool) !?usize {
    var first: ?usize = null;
    for (fences) |f| {
        if (f.opens != opens) continue;
        const i = try l.add(a, try std.fmt.allocPrint(a, "{s} fence {s}", .{ if (opens) "open" else "close", f.vm.name }));
        if (first == null) first = i;
    }
    return first;
}

fn runFenceSteps(c: *pve.Client, l: *exec.Ledger, fences: []const vm_fence.Follow, first: ?usize, opens: bool) !void {
    var i = first orelse return;
    for (fences) |f| {
        if (f.opens != opens) continue;
        l.set(i, .unknown, "");
        try vm_fence.apply(c, f.vm, f.want, f.state);
        l.set(i, .done, try std.fmt.allocPrint(c.ctx.arena, "{d} rules on Proxmox", .{f.want.len}));
        i += 1;
    }
}

fn fencesConverged(c: *pve.Client, fences: []const vm_fence.Follow) !bool {
    for (fences) |f| {
        const v = try vms.resolve(c, f.vm.name);
        if (!(try vm_fence.readState(c, v, f.want)).converged()) return false;
    }
    return true;
}

pub const rm = struct {
    pub const name = "rm";
    pub const summary = "Remove a service name: record, then route (destructive)";
    pub const details =
        \\Removes the UniFi record (only when it points at the edge VM), then
        \\the route on the edge, and reloads Caddy. The guest is untouched. Type
        \\the service name to confirm, or --yes --confirm NAME.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "NAME", .help = "Service name" }};
    pub const flags = [_]cli.Flag{.{ .long = "confirm", .kind = .string, .metavar = "NAME", .help = "Non-interactive confirmation (with --yes)" }};
    pub const examples = [_][]const u8{ "artoo svc rm grafana", "artoo svc rm grafana --yes --confirm grafana" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const n = args.pos("NAME");
        if (!validName(n)) return ctx.fail(error.Usage, "invalid service name '{s}'", .{n});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var u = try unifi.Client.open(ctx);
        defer u.deinit();
        var op: RmOp = .{ .c = &c, .u = &u, .name = n };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const group = cli.group("svc", "Service names <name>.apps.<guests.domain> on the edge VM (SPEC §9.6)", &.{
    cli.leaf(ls),
    cli.leaf(add),
    cli.leaf(set),
    cli.leaf(rm),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;
const test_domains: Domains = .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" };

test "render: the SPEC §9.6 route file" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        \\# artoo service grafana -> naboo:3000
        \\@svc-grafana host grafana.apps.lab.example.com
        \\handle @svc-grafana {
        \\    reverse_proxy naboo.lab.example.com:3000
        \\}
        \\
    , try render(arena.allocator(), test_domains, "grafana", "naboo", 3000));
}

test "parseDump: artoo's, edited and foreign routes; placeholder skipped; caddy state" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const good = try render(a, test_domains, "grafana", "naboo", 3000);
    const edited = try std.mem.replaceOwned(u8, a, try render(a, test_domains, "wiki", "hoth", 8080), "8080\n}", "8080\n    encode gzip\n}");
    const out = try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/000-none.caddy\n# placeholder\n\n==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==artoo== /etc/caddy/services/hand.caddy\n@x host hand.apps.lab.example.com\n==artoo== /etc/caddy/services/wiki.caddy\n{s}\n==caddy== active\n", .{ good, edited });
    const v = try parseDump(a, test_domains, out);
    try testing.expect(v.caddy_active);
    try testing.expectEqual(@as(usize, 3), v.routes.len);
    const g = v.find("grafana").?;
    try testing.expect(g.managed());
    try testing.expectEqualStrings("naboo", g.vm);
    try testing.expectEqual(@as(u16, 3000), g.port);
    try testing.expect(!v.find("hand").?.managed());
    try testing.expectEqualStrings("", v.find("hand").?.vm);
    try testing.expect(v.find("wiki").?.edited);
    try testing.expect(v.find("000-none") == null);
    try testing.expect(!(try parseDump(a, test_domains, "==caddy== inactive\n")).caddy_active);
}

test "renderRoute: health lines after the header, only when set" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings(
        \\# artoo service search -> holocron:8080
        \\# artoo health /v1/health
        \\# artoo health-down "down"
        \\@svc-search host search.apps.lab.example.com
        \\handle @svc-search {
        \\    reverse_proxy holocron.lab.example.com:8080
        \\}
        \\
    , try renderRoute(a, test_domains, "search", "holocron", 8080, .{ .path = "/v1/health", .down = "\"down\"" }));
    try testing.expectEqualStrings(try render(a, test_domains, "grafana", "naboo", 3000), try renderRoute(a, test_domains, "grafana", "naboo", 3000, .{}));
    const down_only = try renderRoute(a, test_domains, "x", "naboo", 80, .{ .down = "DOWN" });
    try testing.expect(std.mem.startsWith(u8, down_only, "# artoo service x -> naboo:80\n# artoo health-down DOWN\n@svc-x"));
}

test "parseDump: health lines read back; malformed ones are edits" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const search = try renderRoute(a, test_domains, "search", "holocron", 8080, .{ .path = "/v1/health", .down = "\"down\"" });
    const down_only = try renderRoute(a, test_domains, "plain", "naboo", 80, .{ .down = "DOWN" });
    const bad = try renderRoute(a, test_domains, "bad", "naboo", 80, .{ .path = "/a b" });
    const root_line = try std.mem.replaceOwned(u8, a, try render(a, test_domains, "slash", "naboo", 80), "naboo:80\n", "naboo:80\n# artoo health /\n");
    const out = try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/bad.caddy\n{s}\n==artoo== /etc/caddy/services/plain.caddy\n{s}\n==artoo== /etc/caddy/services/search.caddy\n{s}\n==artoo== /etc/caddy/services/slash.caddy\n{s}\n==caddy== active\n", .{ bad, down_only, search, root_line });
    const v = try parseDump(a, test_domains, out);
    const s = v.find("search").?;
    try testing.expect(s.managed());
    try testing.expectEqualStrings("/v1/health", s.health.path);
    try testing.expectEqualStrings("\"down\"", s.health.down.?);
    const p = v.find("plain").?;
    try testing.expect(p.managed());
    try testing.expectEqualStrings("/", p.health.path);
    try testing.expectEqualStrings("DOWN", p.health.down.?);
    try testing.expect(v.find("bad").?.edited);
    try testing.expect(v.find("slash").?.edited);
}

test "health: paths, down texts, describe, recovery flags" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{ "/", "/v1/health", "/healthz?full=1&x=%20", "/a/b-c_d.e~f" }) |s| try testing.expect(validHealthPath(s));
    for ([_][]const u8{ "", "v1/health", "/a b", "/a\"b", "/a#b", "/a\\b", "/{x}", "/" ++ @as([128]u8, @splat('a')) }) |s| try testing.expect(!validHealthPath(s));
    try testing.expect(validDownText("\"down\"") and validDownText("it's down"));
    for ([_][]const u8{ "", "a`b", "a\nb", &@as([65]u8, @splat('a')) }) |s| try testing.expect(!validDownText(s));
    const h: Health = .{ .path = "/v1/health", .down = "it's \"down\"" };
    try testing.expect(h.eql(.{ .path = "/v1/health", .down = "it's \"down\"" }));
    try testing.expect(!h.eql(.{ .path = "/v1/health" }) and !(Health{}).eql(.{ .down = "x" }));
    try testing.expectEqualStrings("/v1/health, down it's \"down\"", try h.describe(a));
    try testing.expectEqualStrings(" --health /v1/health --health-down 'it'\\''s \"down\"'", try healthFlags(a, h, false));
    try testing.expectEqualStrings("", try healthFlags(a, .{}, false));
    try testing.expectEqualStrings(" --health /", try healthFlags(a, .{}, true));
}

test "parseUpstream, validName, parseProbe" {
    try testing.expectEqual(@as(u16, 3000), parseUpstream("naboo:3000").?.port);
    try testing.expectEqualStrings("201", parseUpstream("201:80").?.vm);
    for ([_][]const u8{ "naboo", "naboo:22", "naboo:0", "naboo:65536", ":80", "naboo:http" }) |s| try testing.expect(parseUpstream(s) == null);
    try testing.expect(validName("grafana") and validName("home-assistant") and validName("s3"));
    for ([_][]const u8{ "", "Grafana", "3d", "a.b", "web-", "-web", "000-none" }) |s| try testing.expect(!validName(s));
    const p = parseProbe("route yes\nhttp 502\n");
    try testing.expect(p.route and !p.answering());
    try testing.expect(parseProbe("route yes\nhttp 302\n").answering());
    try testing.expect(!parseProbe("route no\nhttp 000\n").route);
    try testing.expect(parseProbe("route yes\nhttp 200\n").healthy());
    const down = parseProbe("route yes\nhttp 200\ndown yes\n");
    try testing.expect(down.down and down.answering() and !down.healthy());
    try testing.expect(!parseProbe("route yes\nhttp 404\n").healthy());
}

const testkit = @import("../testkit.zig");
const root = cli.group("artoo", "t", &.{group});

fn agentBody(a: std.mem.Allocator, out: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
}

const vms_body = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;ssh-jump\"},{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":9000,\"name\":\"ubuntu\",\"status\":\"stopped\",\"template\":1,\"tags\":\"artoo\"}]}";
const edge_cfg = "{\"data\":{\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\",\"digest\":\"d1\"}}";
const naboo_cfg = "{\"data\":{\"ipconfig0\":\"ip=192.168.1.201/24,gw=192.168.1.1\",\"digest\":\"d2\"}}";
const sites_body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"S1\",\"internalReference\":\"default\",\"name\":\"Default\"}]}";

test "svc add -n: edge found, guest checked, plans route then record, writes nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = edge_cfg } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, "==artoo== /etc/caddy/services/000-none.caddy\n# x\n\n==caddy== active\n") } },
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = naboo_cfg } },
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}" } },
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "svc add grafana naboo:3000 -n"));
    try testing.expectEqual(@as(usize, 9), g.sent());
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/qemu/201/config HTTP/1.1", g.request(6));
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Add service grafana → naboo:3000",
        "route       (none) → naboo.lab.example.com:3000 (/etc/caddy/services/grafana.caddy on bespin)",
        "DNS record  (none) → grafana.apps.lab.example.com → 192.168.1.200 (UniFi)",
        "artoo svc rm grafana",
        "Dry run: nothing was sent.",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

fn expectLines(out: []const u8, lines: []const []const u8) !void {
    for (lines) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

/// The requests `svc add|set -n` makes, the edge holding `dump`.
fn putReads(a: std.mem.Allocator, dump: []const u8, records: []const u8) ![9]testkit.Gateway.FakeServer.Behavior {
    return .{
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = edge_cfg } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, dump) } },
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = naboo_cfg } },
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = records } },
    };
}

const grafana_record = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R9\",\"enabled\":true,\"domain\":\"search.apps.lab.example.com\",\"ipv4Address\":\"192.168.1.200\",\"ttlSeconds\":300}]}";

test "svc add -n --health: a new service plans its health; the note names watch setup" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.init(&try putReads(a, "==caddy== active\n", "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}"));
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "svc add search naboo:8080 --health /v1/health --health-down \"down\" -n"));
    try expectLines(g.h.stdout(), &.{
        "Plan · Add service search → naboo:8080",
        "route       (none) → naboo.lab.example.com:8080 (/etc/caddy/services/search.caddy on bespin)",
        "health      (none) → /v1/health, down \"down\"",
        "Run 'artoo watch setup' afterwards so the watchdog probes https://search.apps.lab.example.com/v1/health.",
        "artoo svc rm search",
    });
}

test "svc add -n --health: an existing route to the same upstream gets its health repaired" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dump = try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/search.caddy\n{s}\n==caddy== active\n", .{try render(a, test_domains, "search", "naboo", 8080)});
    var g: testkit.Gateway = undefined;
    try g.init(&try putReads(a, dump, grafana_record));
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "svc add search naboo:8080 --health /v1/health -n"));
    const out = g.h.stdout();
    try expectLines(out, &.{
        "Plan · Set the health of service search → /v1/health",
        "health  / → /v1/health (/etc/caddy/services/search.caddy on bespin)",
        "artoo svc set search naboo:8080 --health /",
    });
    try testing.expect(std.mem.find(u8, out, "DNS record") == null);
}

test "svc set -n without --health keeps the route's health" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const route = try renderRoute(a, test_domains, "search", "naboo", 8080, .{ .path = "/v1/health", .down = "\"down\"" });
    const dump = try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/search.caddy\n{s}\n==caddy== active\n", .{route});
    var g: testkit.Gateway = undefined;
    try g.init(&(try putReads(a, dump, grafana_record) ++ try putReads(a, dump, grafana_record)));
    defer g.deinit();
    // Same upstream, health kept: nothing to do.
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "svc set search naboo:8080 -n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "nothing to change") != null);
    // Moved: the route changes, the health stays, so no health line.
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "svc set search naboo:8081 -n"));
    const out = g.h.stdout();
    try expectLines(out, &.{ "Plan · Move service search → naboo:8081", "route  naboo:8080 → naboo.lab.example.com:8081", "artoo svc set search naboo:8080\n" });
    try testing.expect(std.mem.find(u8, out, "/v1/health") == null);
}

test "svc add: health flags are checked before anything is sent" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{});
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "svc add search naboo:8080 --health-down down -n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "--health-down needs --health PATH") != null);
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "svc add search naboo:8080 --health v1/health -n"));
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "svc set search naboo:8080 --health /a\"b -n"));
    try testing.expectEqual(@as(usize, 0), g.sent());
}

test "svc add: refuses bad names, protected names, port 22, the edge itself, templates" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{});
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "svc add Grafana naboo:3000 -n"));
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "svc add pve naboo:3000 -n"));
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "svc add web naboo:22 -n"));
    try testing.expectEqual(@as(usize, 0), g.sent());
}

test "svc add: the edge VM and templates are not upstreams" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dump = try agentBody(a, "==caddy== active\n");
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vms_body } }, .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = edge_cfg } }, .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = dump } },     .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = vms_body } }, .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = edge_cfg } }, .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = dump } },     .{ .respond = .{ .body = vms_body } },
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "svc add web bespin:80 -n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "is the edge VM itself") != null);
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "svc add web ubuntu:80 -n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "is a template") != null);
}

test "svc rm -n: record then route, destructive" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const route = try render(a, test_domains, "grafana", "naboo", 3000);
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vms_body } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = edge_cfg } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{route})) } },
        .{ .respond = .{ .body = sites_body } },
        .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R9\",\"enabled\":true,\"domain\":\"grafana.apps.lab.example.com\",\"ipv4Address\":\"192.168.1.200\",\"ttlSeconds\":300}]}" } },
        .{ .respond = .{ .body = @import("cf_tunnel.zig").zones_body } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":[],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":0,\"total_count\":0}}" } },
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "svc rm grafana -n"));
    try testing.expectEqual(@as(usize, 9), g.sent());
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Remove service grafana",
        "destructive",
        "DNS record  grafana.apps.lab.example.com → 192.168.1.200 (UniFi) → (removed)",
        "route       naboo:3000 (/etc/caddy/services/grafana.caddy on bespin) → (removed)",
        "artoo svc add grafana naboo:3000",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "vm rm refuses while a service points at the VM" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const list = "{\"data\":[{\"vmid\":100,\"name\":\"web-01\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"}]}";
    const route = try render(a, test_domains, "grafana", "web-01", 3000);
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = vm_cmd.config_body } },
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{route})) } },
    });
    defer g.deinit();
    const vm_root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&vm_root, "vm rm web-01 -n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "service(s) grafana point at web-01") != null);
    try testing.expectEqual(@as(usize, 5), g.sent());
}

test "svc add on a fenced guest: the fence opens in the same plan, before the route" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const R = testkit.Gateway.FakeServer.Route;
    const ok = struct {
        fn r(match: []const u8, b: []const u8) R {
            return .{ .match = match, .behavior = .{ .respond = .{ .body = b } } };
        }
    }.r;
    const fenced = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;ssh-jump\"},{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;fenced\"}]}";
    const cfg = "{\"data\":{\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1\",\"ipconfig0\":\"ip=192.168.1.201/24,gw=192.168.1.1\",\"digest\":\"d2\"}}";
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        ok("GET /api2/json/nodes/pve/qemu ", fenced),
        ok("/qemu/200/agent/ping ", "{\"data\":{\"result\":{}}}"),
        ok("/qemu/200/config ", edge_cfg),
        ok("/qemu/200/agent/exec ", "{\"data\":{\"pid\":42}}"),
        ok("/qemu/200/agent/exec-status", try agentBody(a, "==caddy== active\n")),
        ok("GET /api2/json/nodes/pve/qemu ", fenced),
        ok("/qemu/201/config ", naboo_cfg),
        ok("/qemu/201/config ", cfg),
        ok("/qemu/201/firewall/options ", "{\"data\":{\"enable\":1,\"ipfilter\":1,\"macfilter\":1,\"policy_in\":\"DROP\",\"policy_out\":\"DROP\",\"dhcp\":0,\"ndp\":1,\"radv\":0}}"),
        ok("/qemu/201/firewall/rules ", "{\"data\":[]}"),
        ok("/qemu/201/firewall/ipset ", "{\"data\":[]}"),
        ok("/v1/sites?", sites_body),
        ok("/dns/policies?", "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}"),
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "svc add grafana naboo:3000 -n"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try expectLines(g.h.stdout(), &.{
        "fence naboo  (none) → IN ACCEPT tcp 3000 from 192.168.1.200",
        "fence naboo  (none) → OUT DROP\n",
        "fence naboo  drift → IP set, NIC and options as 'vm fence' writes them",
        "A fenced guest's fence opens before the route is written",
    });
}

test "svc rm -y on a fenced guest: record, route, then the fence closes; verified by read-back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const R = testkit.Gateway.FakeServer.Route;
    const ok = struct {
        fn r(match: []const u8, b: []const u8) R {
            return .{ .match = match, .behavior = .{ .respond = .{ .body = b } } };
        }
    }.r;
    const ad = vm_fence.test_ad;
    const before = try vm_fence.rules(a, .{ .ad = ad, .edge = "192.168.1.200", .services = &.{.{ .name = "grafana", .port = 3000 }} });
    const after = try vm_fence.rules(a, .{ .ad = ad, .edge = "192.168.1.200" });
    const fenced = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;ssh-jump\"},{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;fenced\"}]}";
    const cfg = "{\"data\":{\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1\",\"ipconfig0\":\"ip=192.168.1.201/24,gw=192.168.1.1\",\"digest\":\"d2\"}}";
    const opts = "{\"data\":{\"enable\":1,\"ipfilter\":1,\"macfilter\":1,\"policy_in\":\"DROP\",\"policy_out\":\"DROP\",\"dhcp\":0,\"ndp\":1,\"radv\":0}}";
    const ipset = "{\"data\":[{\"name\":\"ipfilter-net0\"}]}";
    const entries = "{\"data\":[{\"cidr\":\"192.168.1.201\"}]}";
    const route = try render(a, test_domains, "grafana", "naboo", 3000);
    const record = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R9\",\"enabled\":true,\"domain\":\"grafana.apps.lab.example.com\",\"ipv4Address\":\"192.168.1.200\",\"ttlSeconds\":300}]}";
    const none = "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}";
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, &.{
        ok("GET /api2/json/nodes/pve/qemu ", fenced),
        ok("/qemu/200/agent/ping ", "{\"data\":{\"result\":{}}}"),
        ok("/qemu/200/config ", edge_cfg),
        ok("/qemu/200/agent/exec ", "{\"data\":{\"pid\":42}}"),
        ok("/qemu/200/agent/exec-status", try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{route}))),
        ok("GET /api2/json/nodes/pve/qemu/201/config ", cfg),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", opts),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/rules ", try vm_fence.rulesBody(a, before)),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset ", ipset),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", entries),
        ok("/v1/sites?", sites_body),
        ok("/dns/policies?", record),
        ok("/zones?", @import("cf_tunnel.zig").zones_body),
        ok("/cfd_tunnel?", "{\"success\":true,\"errors\":[],\"result\":[],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":0,\"total_count\":0}}"),
        // send: record, route, then the fence
        ok("DELETE ", "{}"),
        ok("/qemu/200/agent/exec ", "{\"data\":{\"pid\":43}}"),
        ok("/qemu/200/agent/exec-status", try agentBody(a, "")),
    });
    for (before) |_| try routes.append(a, ok("DELETE /api2/json/nodes/pve/qemu/201/firewall/rules/0 ", "{\"data\":null}"));
    for (after) |_| try routes.append(a, ok("POST /api2/json/nodes/pve/qemu/201/firewall/rules ", "{\"data\":null}"));
    try routes.appendSlice(a, &.{
        // verify: the fence, the route, the record
        ok("GET /api2/json/nodes/pve/qemu ", fenced),
        ok("GET /api2/json/nodes/pve/qemu/201/config ", cfg),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", opts),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/rules ", try vm_fence.rulesBody(a, after)),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset ", ipset),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", entries),
        ok("/qemu/200/agent/exec ", "{\"data\":{\"pid\":44}}"),
        ok("/qemu/200/agent/exec-status", try agentBody(a, "==caddy== active\n")),
        ok("/v1/sites?", sites_body),
        ok("/dns/policies?", none),
    });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "svc rm grafana --yes --confirm grafana"));
    // The record goes first, then the route, then the fence closes.
    var rec_at: ?usize = null;
    var close_at: ?usize = null;
    for (0..g.sent()) |i| {
        const line = g.request(i);
        if (rec_at == null and std.mem.startsWith(u8, line, "DELETE ") and std.mem.find(u8, line, "dns/policies") != null) rec_at = i;
        if (close_at == null and std.mem.find(u8, line, "firewall/rules/0") != null) close_at = i;
    }
    try testing.expect(rec_at.? < close_at.?);
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/200/agent/exec HTTP/1.1", g.request(rec_at.? + 1));
    try expectLines(g.h.stdout(), &.{ "fence naboo  IN ACCEPT tcp 3000 from 192.168.1.200 → (removed)", "close fence naboo", "service grafana removed" });
}

test "svc add -y on a fenced guest: the fence opens before the route is written" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const R = testkit.Gateway.FakeServer.Route;
    const ok = struct {
        fn r(match: []const u8, b: []const u8) R {
            return .{ .match = match, .behavior = .{ .respond = .{ .body = b } } };
        }
    }.r;
    const ad = vm_fence.test_ad;
    const before = try vm_fence.rules(a, .{ .ad = ad, .edge = "192.168.1.200" });
    const after = try vm_fence.rules(a, .{ .ad = ad, .edge = "192.168.1.200", .services = &.{.{ .name = "grafana", .port = 3000 }} });
    const fenced = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;ssh-jump\"},{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;fenced\"}]}";
    const cfg = "{\"data\":{\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1\",\"ipconfig0\":\"ip=192.168.1.201/24,gw=192.168.1.1\",\"digest\":\"d2\"}}";
    const opts = "{\"data\":{\"enable\":1,\"ipfilter\":1,\"macfilter\":1,\"policy_in\":\"DROP\",\"policy_out\":\"DROP\",\"dhcp\":0,\"ndp\":1,\"radv\":0}}";
    const ipset = "{\"data\":[{\"name\":\"ipfilter-net0\"}]}";
    const entries = "{\"data\":[{\"cidr\":\"192.168.1.201\"}]}";
    const route = try render(a, test_domains, "grafana", "naboo", 3000);
    const record = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R9\",\"enabled\":true,\"domain\":\"grafana.apps.lab.example.com\",\"ipv4Address\":\"192.168.1.200\",\"ttlSeconds\":300}]}";
    const none = "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}";
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, &.{
        ok("GET /api2/json/nodes/pve/qemu ", fenced),
        ok("/qemu/200/agent/ping ", "{\"data\":{\"result\":{}}}"),
        ok("/qemu/200/config ", edge_cfg),
        ok("/qemu/200/agent/exec ", "{\"data\":{\"pid\":42}}"),
        ok("/qemu/200/agent/exec-status", try agentBody(a, "==caddy== active\n")),
        ok("GET /api2/json/nodes/pve/qemu ", fenced),
        ok("GET /api2/json/nodes/pve/qemu/201/config ", cfg),
        ok("GET /api2/json/nodes/pve/qemu/201/config ", cfg),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", opts),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/rules ", try vm_fence.rulesBody(a, before)),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset ", ipset),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", entries),
        ok("/v1/sites?", sites_body),
        ok("/dns/policies?", none),
    });
    for (before) |_| try routes.append(a, ok("DELETE /api2/json/nodes/pve/qemu/201/firewall/rules/0 ", "{\"data\":null}"));
    for (after) |_| try routes.append(a, ok("POST /api2/json/nodes/pve/qemu/201/firewall/rules ", "{\"data\":null}"));
    try routes.appendSlice(a, &.{
        ok("/qemu/200/agent/exec ", "{\"data\":{\"pid\":43}}"),
        ok("/qemu/200/agent/exec-status", try agentBody(a, "")),
        ok("POST /v1/sites/S1/dns/policies", "{}"),
        // verify: the fence, the route, the record, the probe
        ok("GET /api2/json/nodes/pve/qemu ", fenced),
        ok("GET /api2/json/nodes/pve/qemu/201/config ", cfg),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", opts),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/rules ", try vm_fence.rulesBody(a, after)),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset ", ipset),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", entries),
        ok("/qemu/200/agent/exec ", "{\"data\":{\"pid\":44}}"),
        ok("/qemu/200/agent/exec-status", try agentBody(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{route}))),
        ok("/v1/sites?", sites_body),
        ok("/dns/policies?", record),
        ok("/qemu/200/agent/exec ", "{\"data\":{\"pid\":45}}"),
        ok("/qemu/200/agent/exec-status", try agentBody(a, "route yes\nhttp 200\n")),
    });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "svc add grafana naboo:3000 -y"));
    // The fence's last POST comes before the route's agent exec.
    var last_rule: usize = 0;
    var route_at: ?usize = null;
    for (0..g.sent()) |i| {
        const line = g.request(i);
        if (std.mem.startsWith(u8, line, "POST /api2/json/nodes/pve/qemu/201/firewall/rules ")) last_rule = i;
        if (route_at == null and last_rule == 0 and i > 13 and std.mem.startsWith(u8, line, "POST /api2/json/nodes/pve/qemu/200/agent/exec ")) route_at = i;
    }
    try testing.expect(route_at == null);
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/200/agent/exec HTTP/1.1", g.request(last_rule + 1));
    try testing.expect(std.mem.find(u8, g.body(last_rule), "dport=3000") != null);
    try expectLines(g.h.stdout(), &.{ "fence naboo  (none) → IN ACCEPT tcp 3000 from 192.168.1.200", "open fence naboo", "answers HTTP 200" });
}
