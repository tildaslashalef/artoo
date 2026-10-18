//! `artoo watch setup|status|enroll|secret` (SPEC §9.9): the watchdog VM
//! (the one tagged `role-watch`) with VictoriaMetrics, Loki, Grafana and
//! ntfy, and Grafana Alloy on the guests. Configured through the guest
//! agent like the edge VM: rendered files, fixed scripts, a step ledger.
//! artoo stays stateless: alert state and history live on the VM.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const exec = @import("../exec.zig");
const prompt = @import("../prompt.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const files = @import("../watch/files.zig");
const grafana = @import("../watch/grafana.zig");
const edge = @import("edge.zig");
const svc = @import("svc.zig");
const template = @import("template.zig");
const vm_cmd = @import("vm.zig");
const vm_new = @import("vm_new.zig");
const life = @import("vm_life.zig");
const k = @import("node.zig");
const guest_names = @import("../guest/names.zig");

const Context = app.Context;
const Value = std.json.Value;
const Check = vm_new.Check;
const Rule = edge.Rule;

pub const role = "watch";
const step_timeout_ms = 10 * 60 * 1000;
/// Metrics or logs older than this mark a guest silent.
const silent_after_s: f64 = 300;

// ---------------------------------------------------------------- the VMs

fn tagged(c: *pve.Client, want: []const u8) !?vms.Vm {
    var found: ?vms.Vm = null;
    for (try vms.list(c)) |v| {
        const r = vm_cmd.roleOf(v.tags) orelse continue;
        if (!std.mem.eql(u8, r, want) or v.template) continue;
        if (found != null) return c.ctx.fail(error.Refused, "several VMs carry role-{s} ({s}, {s}); keep one", .{ want, found.?.name, v.name });
        found = v;
    }
    return found;
}

/// The VM tagged `role-watch`, if any (any state).
pub fn findWatchVm(c: *pve.Client) !?vms.Vm {
    return tagged(c, role);
}

/// The VM tagged `role-watch` (exactly one), running, agent answering.
pub fn watchVm(ctx: *Context, c: *pve.Client) !vms.Vm {
    const v = try findWatchVm(c) orelse return ctx.fail(error.NotFound, "no VM tagged role-watch; create it with 'artoo vm new scarif --role watch --size medium --ssh-jump' (SPEC §9.9)", .{});
    return ready(ctx, c, v);
}

fn ready(ctx: *Context, c: *pve.Client, v: vms.Vm) !vms.Vm {
    if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first", .{ v.name, v.status });
    if (!try agent.ping(c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer", .{v.name});
    return v;
}

/// Where guests push: the watchdog's machine name.
pub fn watchHost(ctx: *Context, v: vms.Vm) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ v.name, (try ctx.config()).guests.domain });
}

pub fn roleOf(tags: []const u8) files.Role {
    const r = vm_cmd.roleOf(tags) orelse return .plain;
    if (std.mem.eql(u8, r, edge.role)) return .edge;
    if (std.mem.eql(u8, r, "router")) return .router;
    if (std.mem.eql(u8, r, "search")) return .search;
    if (std.mem.eql(u8, r, role)) return .watch;
    return .plain;
}

/// The lab as the files need it. `full` adds the edge VM's address and
/// the services to probe (the watchdog itself); guests need neither.
fn lab(ctx: *Context, c: *pve.Client, full: bool) !files.Lab {
    const ad = try edge.addresses(ctx);
    var l: files.Lab = .{ .pve = ad.pve, .gateway = ad.gateway, .lan = ad.lan, .pool = ad.pool, .edge = "", .domain = (try ctx.config()).guests.domain };
    if (!full) return l;
    const e = try tagged(c, edge.role) orelse return ctx.fail(error.Refused, "no VM tagged role-edge: Grafana and ntfy are served through it (SPEC §9.9); set up the edge first", .{});
    l.edge = life.staticAddress(try vms.config(c, e.vmid)) orelse return ctx.fail(error.Refused, "the edge VM {s} has no static address (ipconfig0)", .{e.name});
    if (e.running()) {
        const view = try svc.read(ctx, c);
        var probes: std.ArrayList(files.Service) = .empty;
        for (view.routes) |r| if (r.managed()) try probes.append(ctx.arena, .{ .name = r.name, .path = r.health.path, .down = r.health.down, .vm = r.vm });
        std.mem.sort(files.Service, probes.items, {}, byName);
        l.services = probes.items;
    }
    return l;
}

fn byName(_: void, x: files.Service, y: files.Service) bool {
    return std.mem.order(u8, x.name, y.name) == .lt;
}

/// The watchdog's managed files: its own, then its Alloy files (shared
/// paths once).
fn managedFiles(ctx: *Context, v: vms.Vm, l: files.Lab) ![]const files.File {
    const a = ctx.arena;
    const own = try files.watchFiles(a, l, try grafana.dashboardFiles(a), try grafana.rulesYaml(a));
    const guest = try files.guestFiles(a, .{ .name = v.name, .role = .watch, .watch_host = try watchHost(ctx, v) }, l);
    var out: std.ArrayList(files.File) = .empty;
    try out.appendSlice(a, own);
    outer: for (guest) |g| {
        for (own) |o| if (std.mem.eql(u8, o.path, g.path)) continue :outer;
        try out.append(a, g);
    }
    return out.items;
}

// ---------------------------------------------------------------- host firewall

/// The §9.9 policy as Proxmox VM rules (first match wins): the host-side
/// copy of the watchdog's nftables, which root inside the VM cannot change.
pub fn hostRules(l: files.Lab) [16]Rule {
    return .{
        .{ .type = "in", .action = "ACCEPT", .source = l.pve, .proto = "tcp", .dport = "22", .comment = "artoo: SSH only from Proxmox" },
        .{ .type = "in", .action = "ACCEPT", .source = l.pve, .proto = "tcp", .dport = "8428,3100", .comment = "artoo: Proxmox's metrics" },
        .{ .type = "in", .action = "ACCEPT", .source = l.pool, .proto = "tcp", .dport = "8428,3100", .comment = "artoo: guests push metrics and logs" },
        .{ .type = "in", .action = "ACCEPT", .source = l.edge, .proto = "tcp", .dport = "3000,2586", .comment = "artoo: Grafana and ntfy via the edge" },
        .{ .type = "in", .action = "ACCEPT", .macro = "Ping", .source = l.lan, .comment = "artoo: ping from the LAN" },
        .{ .type = "out", .action = "DROP", .dest = l.pve, .comment = "artoo: never Proxmox" },
        .{ .type = "out", .action = "ACCEPT", .dest = l.gateway, .proto = "udp", .dport = "53", .comment = "artoo: DNS on UniFi" },
        .{ .type = "out", .action = "ACCEPT", .dest = l.gateway, .proto = "tcp", .dport = "53", .comment = "artoo: DNS on UniFi" },
        .{ .type = "out", .action = "DROP", .dest = l.gateway, .comment = "artoo: nothing else on UniFi" },
        .{ .type = "out", .action = "ACCEPT", .dest = l.edge, .proto = "tcp", .dport = "443", .comment = "artoo: HTTPS probes via the edge" },
        .{ .type = "out", .action = "DROP", .dest = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16", .comment = "artoo: no other private IPv4" },
        .{ .type = "out", .action = "DROP", .dest = "fc00::/7,fe80::/10", .comment = "artoo: no private IPv6" },
        .{ .type = "out", .action = "ACCEPT", .proto = "tcp", .dport = "80,443", .comment = "artoo: apt" },
        .{ .type = "out", .action = "ACCEPT", .proto = "udp", .dport = "123", .comment = "artoo: NTP" },
        .{ .type = "out", .action = "ACCEPT", .macro = "Ping", .comment = "artoo: ping out" },
        .{ .type = "out", .action = "DROP", .comment = "artoo: everything else" },
    };
}

// ---------------------------------------------------------------- probe

const services = [_][]const u8{ "victoriametrics", "loki", "grafana-server", "ntfy", "alloy", "artoo-facts.timer" };
const packages = [_][]const u8{ "grafana", "loki", "alloy", "ntfy" };

const State = struct {
    /// path → sha256 hex ("-" when absent).
    hashes: std.StringHashMapUnmanaged([]const u8) = .empty,
    /// package → installed version ("-").
    versions: std.StringHashMapUnmanaged([]const u8) = .empty,
    vm: []const u8 = "-",
    users: bool = false,
    nft_loaded: bool = false,
    nft_enabled: bool = false,
    /// unit → active.
    active: std.StringHashMapUnmanaged(bool) = .empty,
    admin_secret: bool = false,
    token: bool = false,
    auth: bool = false,
    phone: bool = false,
    tailscale: bool = false,
    /// Dashboard files present in /etc/grafana/dashboards.
    dashboards: std.ArrayList([]const u8) = .empty,
    reboot: bool = false,
    raw: []const u8 = "",

    fn version(st: State, p: []const u8) []const u8 {
        return st.versions.get(p) orelse "-";
    }

    fn isActive(st: State, s: []const u8) bool {
        return st.active.get(s) orelse false;
    }
};

fn hashLoop(a: std.mem.Allocator, s: *std.ArrayList(u8), managed: []const files.File) !void {
    try s.appendSlice(a, "for f in");
    for (managed) |f| try s.print(a, " {s}", .{f.path});
    try s.appendSlice(a, "; do h=$(sha256sum \"$f\" 2>/dev/null | cut -d' ' -f1); echo \"file $f ${h:--}\"; done\n");
}

fn probeScript(a: std.mem.Allocator, managed: []const files.File) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    try hashLoop(a, &s, managed);
    try s.appendSlice(a, "for p in");
    for (packages) |p| try s.print(a, " {s}", .{p});
    try s.appendSlice(a, "; do v=$(dpkg-query -W -f='${Version}' \"$p\" 2>/dev/null); echo \"pkg $p ${v:--}\"; done\n");
    try s.appendSlice(a, "for u in grafana loki victoriametrics alloy ntfy; do getent passwd \"$u\" >/dev/null || nouser=1; done; [ -z \"${nouser:-}\" ] && echo 'users yes' || echo 'users no'\n");
    try s.appendSlice(a, "for u in");
    for (services) |u| try s.print(a, " {s}", .{u});
    try s.appendSlice(a,
        \\; do systemctl is-active -q "$u" && echo "active $u yes" || echo "active $u no"; done
        \\v=$(/usr/local/bin/victoria-metrics-prod -version 2>/dev/null | grep -o 'v[0-9]*\.[0-9]*\.[0-9]*' | head -1); echo "vm ${v:--}"
        \\nft list table inet artoo_watch >/dev/null 2>&1 && echo "nft yes" || echo "nft no"
        \\systemctl is-enabled -q nftables 2>/dev/null && echo "nftenabled yes" || echo "nftenabled no"
        \\test -s /etc/grafana/admin_password && echo "admin yes" || echo "admin no"
        \\test -s /etc/grafana/ntfy.env && echo "token yes" || echo "token no"
        \\test -s /etc/ntfy/auth.env && echo "auth yes" || echo "auth no"
        \\grep -q "^NTFY_AUTH_USERS=.*,phone:" /etc/ntfy/auth.env 2>/dev/null && echo "phone yes" || echo "phone no"
        \\test -e /var/run/reboot-required && echo "reboot yes" || echo "reboot no"
        \\for f in /etc/grafana/dashboards/*.json; do [ -e "$f" ] && echo "dash $f"; done
        \\case "$(dpkg-query -W -f='${Status}' tailscale 2>/dev/null)" in *"ok installed") echo "tailscale yes";; *) echo "tailscale no";; esac
        \\
    );
    return s.items;
}

fn parseState(a: std.mem.Allocator, out: []const u8) !State {
    var st: State = .{ .raw = out };
    var lines = std.mem.tokenizeScalar(u8, out, '\n');
    while (lines.next()) |line| {
        var w = std.mem.tokenizeScalar(u8, line, ' ');
        const key = w.next() orelse continue;
        const v1 = w.next() orelse continue;
        const v2 = w.next() orelse "";
        const yes = std.mem.eql(u8, v1, "yes");
        if (std.mem.eql(u8, key, "file")) {
            try st.hashes.put(a, v1, if (v2.len > 0) v2 else "-");
        } else if (std.mem.eql(u8, key, "pkg")) {
            try st.versions.put(a, v1, if (v2.len > 0) v2 else "-");
        } else if (std.mem.eql(u8, key, "active")) {
            try st.active.put(a, v1, std.mem.eql(u8, v2, "yes"));
        } else if (std.mem.eql(u8, key, "vm")) {
            st.vm = v1;
        } else if (std.mem.eql(u8, key, "users")) {
            st.users = yes;
        } else if (std.mem.eql(u8, key, "nft")) {
            st.nft_loaded = yes;
        } else if (std.mem.eql(u8, key, "nftenabled")) {
            st.nft_enabled = yes;
        } else if (std.mem.eql(u8, key, "admin")) {
            st.admin_secret = yes;
        } else if (std.mem.eql(u8, key, "token")) {
            st.token = yes;
        } else if (std.mem.eql(u8, key, "auth")) {
            st.auth = yes;
        } else if (std.mem.eql(u8, key, "phone")) {
            st.phone = yes;
        } else if (std.mem.eql(u8, key, "reboot")) {
            st.reboot = yes;
        } else if (std.mem.eql(u8, key, "tailscale")) {
            st.tailscale = yes;
        } else if (std.mem.eql(u8, key, "dash")) {
            try st.dashboards.append(a, v1);
        }
    }
    return st;
}

fn probe(c: *pve.Client, vmid: u32, managed: []const files.File) !State {
    const ctx = c.ctx;
    const r = try agent.sh(c, vmid, try probeScript(ctx.arena, managed), 60_000);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading the watchdog's state failed: {s}", .{try k.clean(ctx, edge.firstLine(r.err))});
    return parseState(ctx.arena, r.out);
}

// ---------------------------------------------------------------- setup

/// Which service a managed file feeds (restarted when it changes).
fn serviceOf(path: []const u8) ?[]const u8 {
    if (std.mem.endsWith(u8, path, "/victoriametrics.service")) return "victoriametrics";
    if (std.mem.startsWith(u8, path, "/etc/loki/")) return "loki";
    if (std.mem.startsWith(u8, path, "/etc/grafana/") or std.mem.startsWith(u8, path, "/etc/systemd/system/grafana-server")) return "grafana-server";
    if (std.mem.startsWith(u8, path, "/etc/ntfy/") or std.mem.startsWith(u8, path, "/etc/systemd/system/ntfy")) return "ntfy";
    if (std.mem.startsWith(u8, path, "/etc/alloy/") or std.mem.eql(u8, path, "/etc/default/alloy") or std.mem.startsWith(u8, path, "/etc/systemd/system/alloy") or std.mem.find(u8, path, "artoo-facts") != null) return "alloy";
    return null;
}

const Steps = struct {
    accounts: bool = false,
    /// The template's Tailscale probes the gateway (NAT-PMP); the
    /// watchdog needs none (like the edge, SPEC §9.7).
    tailscale: bool = false,
    write: []const files.File = &.{},
    /// Dashboards artoo no longer renders.
    prune: []const []const u8 = &.{},
    firewall: bool = false,
    packages: bool = false,
    vm: bool = false,
    secrets: bool = false,
    auth: bool = false,
    /// Units to (re)start, in order.
    restart: []const []const u8 = &.{},
    alloy: bool = false,

    fn any(s: Steps) bool {
        return s.accounts or s.tailscale or s.write.len > 0 or s.prune.len > 0 or s.firewall or s.packages or s.vm or s.secrets or s.auth or s.restart.len > 0 or s.alloy;
    }
};

fn plannedSteps(a: std.mem.Allocator, managed: []const files.File, st: State) !Steps {
    var write: std.ArrayList(files.File) = .empty;
    var touched: std.StringHashMapUnmanaged(void) = .empty;
    var nft = false;
    var apt = false;
    for (managed) |f| {
        if (std.mem.eql(u8, st.hashes.get(f.path) orelse "-", try files.sha256Hex(a, f.content))) continue;
        try write.append(a, f);
        if (std.mem.eql(u8, f.path, "/etc/nftables.conf")) nft = true;
        if (std.mem.startsWith(u8, f.path, "/etc/apt/") or std.mem.startsWith(u8, f.path, "/usr/share/keyrings/")) apt = true;
        if (serviceOf(f.path)) |u| try touched.put(a, u, {});
    }
    var prune: std.ArrayList([]const u8) = .empty;
    outer: for (st.dashboards.items) |d| {
        for (managed) |f| if (std.mem.eql(u8, f.path, d)) continue :outer;
        try prune.append(a, d);
        try touched.put(a, "grafana-server", {});
    }
    var pkgs = apt;
    for (files.watch_packages) |p| {
        if (!std.mem.eql(u8, st.version(p[0]), p[1])) pkgs = true;
    }
    const vm = !std.mem.eql(u8, st.vm, files.vm_version);
    const secrets = !st.admin_secret or !st.token;
    if (secrets) {
        try touched.put(a, "grafana-server", {});
        try touched.put(a, "ntfy", {});
    }
    if (!st.auth) try touched.put(a, "ntfy", {});
    if (vm) try touched.put(a, "victoriametrics", {});
    if (pkgs) {
        try touched.put(a, "loki", {});
        try touched.put(a, "grafana-server", {});
        try touched.put(a, "ntfy", {});
    }
    var restart: std.ArrayList([]const u8) = .empty;
    for (services[0..4]) |u| {
        if (touched.contains(u) or !st.isActive(u)) try restart.append(a, u);
    }
    return .{
        .accounts = !st.users,
        .tailscale = st.tailscale,
        .write = write.items,
        .prune = prune.items,
        .firewall = nft or !st.nft_loaded or !st.nft_enabled,
        .packages = pkgs,
        .vm = vm,
        .secrets = secrets,
        .auth = !st.auth,
        .restart = restart.items,
        .alloy = touched.contains("alloy") or pkgs or !st.isActive("alloy") or !st.isActive("artoo-facts.timer"),
    };
}

/// A random password's bcrypt hash: the Grafana user's ntfy login, which
/// is never used (Grafana publishes with its token).
fn randomHash(ctx: *Context, buf: []u8) ![]const u8 {
    var raw: [24]u8 = undefined;
    ctx.io.random(&raw);
    var pw: [32]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&pw, &raw);
    return bcryptHash(ctx, &pw, buf);
}

pub const bcrypt_len = std.crypto.pwhash.bcrypt.hash_length;

fn bcryptHash(ctx: *Context, password: []const u8, buf: []u8) ![]const u8 {
    return std.crypto.pwhash.bcrypt.strHash(password, .{
        .params = .{ .rounds_log = 10, .silently_truncate_password = false },
        .encoding = .crypt,
    }, buf, ctx.io);
}

fn writeAuthEnv(c: *pve.Client, vmid: u32, content: []const u8) !void {
    const ctx = c.ctx;
    const enc = std.base64.standard.Encoder;
    const b64 = try ctx.arena.alloc(u8, enc.calcSize(content.len));
    _ = enc.encode(b64, content);
    const r = try agent.exec(c, vmid, &.{ "sh", "-c", files.write_auth_env }, b64, 60_000);
    if (!r.ok()) return ctx.fail(error.Partial, "writing /etc/ntfy/auth.env failed: {s}", .{try k.clean(ctx, edge.firstLine(r.err))});
}

fn restartScript(a: std.mem.Allocator, units: []const []const u8) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    try s.appendSlice(a, "set -e\nsystemctl daemon-reload\n");
    for (units) |u| try s.print(a, "systemctl enable {s} >/dev/null 2>&1\nsystemctl restart {s}\n", .{ u, u });
    return s.items;
}

const SetupOp = struct {
    c: *pve.Client,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: vms.Vm = undefined,
    lab: files.Lab = undefined,
    managed: []const files.File = &.{},
    state: State = .{},
    steps: Steps = .{},
    host: edge.HostState = .{},
    host_rules: []const Rule = &.{},
    host_steps: edge.HostSteps = .{},
    ledger: exec.Ledger = .{},
    fp: []const u8 = "",

    pub fn read(op: *SetupOp, ctx: *Context) !void {
        op.vm = try watchVm(ctx, op.c);
        op.target = op.vm.name;
        op.lab = try lab(ctx, op.c, true);
        op.managed = try managedFiles(ctx, op.vm, op.lab);
        op.state = try probe(op.c, op.vm.vmid, op.managed);
        op.steps = try plannedSteps(ctx.arena, op.managed, op.state);
        op.host_rules = try ctx.arena.dupe(Rule, &hostRules(op.lab));
        op.host = try edge.readHost(op.c, op.vm);
        op.host_steps = edge.hostSteps(op.host_rules, op.host);
        op.fp = try std.fmt.allocPrint(ctx.arena, "{s}|{s}|{}{}{}{}", .{ op.state.raw, op.host.net0, op.host_steps.rules, op.host_steps.ipset, op.host_steps.nic, op.host_steps.options });
    }

    pub fn plan(op: *SetupOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const s = op.steps;
        const h = op.host_steps;
        const st = op.state;
        if (!s.any() and !h.any()) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (s.tailscale) try changes.append(a, .{ .field = "tailscale", .from = "installed", .to = null });
        if (s.accounts) try changes.append(a, .{ .field = "accounts", .from = null, .to = "system users grafana, loki, victoriametrics, alloy, ntfy (before any package)" });
        for (s.prune) |d| try changes.append(a, .{ .field = "dashboard", .from = d, .to = null });
        for (s.write) |f| try changes.append(a, .{ .field = "file", .from = if (std.mem.eql(u8, st.hashes.get(f.path) orelse "-", "-")) null else "differs", .to = f.path });
        if (s.firewall) try changes.append(a, .{ .field = "firewall", .from = if (st.nft_loaded) "loaded" else null, .to = "nftables policy loaded and enabled (service users never reach the internet)" });
        if (s.packages) try changes.append(a, .{
            .field = "packages",
            .from = try std.fmt.allocPrint(a, "grafana {s}, loki {s}, alloy {s}, ntfy {s}", .{ st.version("grafana"), st.version("loki"), st.version("alloy"), st.version("ntfy") }),
            .to = std.fmt.comptimePrint("grafana {s}, loki {s}, alloy {s}, ntfy {s} (held by apt pins)", .{ files.grafana_version, files.loki_version, files.alloy_version, files.ntfy_version }),
        });
        if (s.vm) try changes.append(a, .{ .field = "victoriametrics", .from = if (std.mem.eql(u8, st.vm, "-")) null else st.vm, .to = files.vm_version ++ " from its release tarball, SHA-256 checked" });
        if (s.secrets) try changes.append(a, .{ .field = "secrets", .from = null, .to = "random Grafana admin password and Grafana's ntfy token, made on the VM" });
        if (s.auth) try changes.append(a, .{ .field = "ntfy users", .from = null, .to = "grafana (write-only on '" ++ files.topic ++ "'); the phone follows with 'artoo watch secret phone'" });
        if (s.restart.len > 0) try changes.append(a, .{ .field = "services", .from = null, .to = try std.fmt.allocPrint(a, "{s} (re)started", .{try std.mem.join(a, ", ", s.restart)}) });
        if (s.alloy) try changes.append(a, .{ .field = "alloy", .from = null, .to = try std.fmt.allocPrint(a, "pushes {s}'s metrics and journal, probes {d} service(s)", .{ op.vm.name, op.lab.services.len }) });
        if (h.any()) try changes.append(a, .{
            .field = "host firewall",
            .from = if (op.host.options_ok and op.host.nic_ok) "differs" else null,
            .to = try std.fmt.allocPrint(a, "Proxmox VM firewall: {d} rules, only source {s}, MAC filter, DROP policies, NIC firewall=1", .{ op.host_rules.len, op.host.address }),
        });
        var notes: std.ArrayList([]const u8) = .empty;
        if (op.lab.services.len == 0) try notes.append(a, "No service names to probe yet; add 'artoo svc add grafana " ++ "<vm>:3000' and 'ntfy <vm>:2586', then run setup again.");
        try notes.append(a, "Commands run as root through the guest agent; steps stop at the first failure and re-running continues.");
        return .{
            .action = try std.fmt.allocPrint(a, "Set up watchdog VM {s} ({d})", .{ op.vm.name, op.vm.vmid }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{"The watchdog's firewall, packages and services change, and its own Proxmox firewall rules on Proxmox; other guests and Proxmox's settings are untouched"}),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *SetupOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *SetupOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        const id = op.vm.vmid;
        const s = op.steps;
        const l = &op.ledger;
        const s_ts = if (s.tailscale) try l.add(a, "remove tailscale") else null;
        const s_acct = if (s.accounts) try l.add(a, "accounts") else null;
        const s_write = if (s.write.len > 0) try l.add(a, "write files") else null;
        const s_prune = if (s.prune.len > 0) try l.add(a, "remove old dashboards") else null;
        const s_fw = if (s.firewall) try l.add(a, "load firewall") else null;
        const s_pkg = if (s.packages) try l.add(a, "install packages") else null;
        const s_vm = if (s.vm) try l.add(a, "install victoriametrics") else null;
        const s_sec = if (s.secrets) try l.add(a, "make secrets") else null;
        const s_auth = if (s.auth) try l.add(a, "ntfy users") else null;
        const s_svc = if (s.restart.len > 0) try l.add(a, "start services") else null;
        const s_alloy = if (s.alloy) try l.add(a, "start alloy") else null;
        const s_host = if (op.host_steps.any()) try l.add(a, "host firewall") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (s_ts) |i| {
            try edge.run(c, id, "removing tailscale", "DEBIAN_FRONTEND=noninteractive apt-get purge -y tailscale >/dev/null && rm -f /etc/apt/sources.list.d/tailscale.list /etc/apt/cloud-init.gpg.d/tailscale.gpg", step_timeout_ms);
            l.set(i, .done, "");
        }
        if (s_acct) |i| {
            try edge.run(c, id, "the accounts", files.prepare, step_timeout_ms);
            l.set(i, .done, "");
        }
        if (s_write) |i| {
            l.set(i, .unknown, "");
            for (s.write) |f| try edge.writeFile(c, id, f);
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} file(s)", .{s.write.len}));
        }
        if (s_prune) |i| {
            var script: std.ArrayList(u8) = .empty;
            try script.appendSlice(a, "rm -f --");
            // Paths come from the VM's own listing of /etc/grafana/dashboards;
            // quoted, and only *.json there.
            for (s.prune) |d| {
                if (!std.mem.startsWith(u8, d, "/etc/grafana/dashboards/") or !std.mem.endsWith(u8, d, ".json") or std.mem.findAny(u8, d, "'\n") != null) continue;
                try script.print(a, " '{s}'", .{d});
            }
            try edge.run(c, id, "removing old dashboards", script.items, step_timeout_ms);
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} file(s)", .{s.prune.len}));
        }
        if (s_fw) |i| {
            l.set(i, .unknown, "");
            try edge.run(c, id, "the firewall",
                \\set -e
                \\command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y nftables >/dev/null
                \\nft -c -f /etc/nftables.conf
                \\systemctl enable nftables >/dev/null 2>&1
                \\nft -f /etc/nftables.conf
            , step_timeout_ms);
            l.set(i, .done, "inet artoo_watch");
        }
        if (s_pkg) |i| {
            l.set(i, .unknown, "");
            try edge.run(c, id, "installing packages", files.install_packages, step_timeout_ms);
            l.set(i, .done, "");
        }
        if (s_vm) |i| {
            l.set(i, .unknown, "");
            try edge.run(c, id, "installing VictoriaMetrics", files.install_vm, step_timeout_ms);
            l.set(i, .done, files.vm_version);
        }
        if (s_sec) |i| {
            try edge.run(c, id, "making the secrets", files.make_secrets, step_timeout_ms);
            l.set(i, .done, "on the VM only");
        }
        if (s_auth) |i| {
            var buf: [bcrypt_len]u8 = undefined;
            const hash = try randomHash(ctx, &buf);
            l.set(i, .unknown, "");
            try writeAuthEnv(c, id, try files.ntfyAuthEnv(a, hash, null, files.token_placeholder));
            l.set(i, .done, "grafana");
        }
        if (s_svc) |i| {
            l.set(i, .unknown, "");
            try edge.run(c, id, "starting the services", try restartScript(a, s.restart), step_timeout_ms);
            l.set(i, .done, try std.mem.join(a, ", ", s.restart));
        }
        if (s_alloy) |i| {
            l.set(i, .unknown, "");
            try edge.run(c, id, "starting alloy", files.enroll_script, step_timeout_ms);
            l.set(i, .done, "");
        }
        if (s_host) |i| {
            l.set(i, .unknown, "");
            try edge.applyHost(c, op.vm, op.host_rules, op.host, op.host_steps);
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} rules on Proxmox", .{op.host_rules.len}));
        }
    }

    pub fn verify(op: *SetupOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const after = try probe(op.c, op.vm.vmid, op.managed);
        const left = try plannedSteps(ctx.arena, op.managed, after);
        const host_left = edge.hostSteps(op.host_rules, try edge.readHost(op.c, op.vm));
        return op.ledger.complete() and !left.any() and !host_left.any();
    }

    pub fn done(op: *SetupOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} set up — next: 'artoo watch secret grafana', 'artoo watch secret phone', 'artoo watch enroll --all', then 'artoo watch status'", .{op.vm.name}) catch "done";
    }
};

pub const setup = struct {
    pub const name = "setup";
    pub const summary = "Set up the watchdog VM (idempotent)";
    pub const details =
        \\Brings the VM tagged role-watch to SPEC §9.9: service accounts, the
        \\nftables policy (ingest from the guest pool and Proxmox, Grafana and
        \\ntfy only from the edge, no internet for the service users), Grafana,
        \\Loki, Alloy and ntfy at their pinned versions from their signed
        \\repositories, VictoriaMetrics from its checksummed release, every
        \\telemetry switch off, provisioned data sources, dashboards and alert
        \\rules, and the same policy as the VM's Proxmox firewall on Proxmox.
        \\Only the steps the observed state needs are planned.
    ;
    pub const examples = [_][]const u8{ "artoo watch setup -n", "artoo watch setup -y" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SetupOp = .{ .c = &c };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- enroll

const GuestState = struct {
    hashes: std.StringHashMapUnmanaged([]const u8) = .empty,
    alloy: []const u8 = "-",
    active: bool = false,
    timer: bool = false,
};

fn guestProbeScript(a: std.mem.Allocator, managed: []const files.File) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    try hashLoop(a, &s, managed);
    try s.appendSlice(a,
        \\v=$(dpkg-query -W -f='${Version}' alloy 2>/dev/null); echo "pkg alloy ${v:--}"
        \\systemctl is-active -q alloy && echo "active alloy yes" || echo "active alloy no"
        \\systemctl is-active -q artoo-facts.timer && echo "active timer yes" || echo "active timer no"
        \\
    );
    return s.items;
}

fn parseGuest(a: std.mem.Allocator, out: []const u8) !GuestState {
    const st = try parseState(a, out);
    return .{ .hashes = st.hashes, .alloy = st.version("alloy"), .active = st.isActive("alloy"), .timer = st.isActive("timer") };
}

const Enrollee = struct {
    vm: vms.Vm,
    managed: []const files.File,
    write: []const files.File,
    restart: bool,
    from: []const u8,
};

fn enrollee(ctx: *Context, c: *pve.Client, v: vms.Vm, host: []const u8, l: files.Lab) !Enrollee {
    const a = ctx.arena;
    const managed = try files.guestFiles(a, .{ .name = v.name, .role = roleOf(v.tags), .watch_host = host }, l);
    const r = try agent.sh(c, v.vmid, try guestProbeScript(a, managed), 60_000);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading {s}'s Alloy state failed: {s}", .{ v.name, try k.clean(ctx, edge.firstLine(r.err)) });
    const st = try parseGuest(a, r.out);
    var write: std.ArrayList(files.File) = .empty;
    for (managed) |f| {
        if (!std.mem.eql(u8, st.hashes.get(f.path) orelse "-", try files.sha256Hex(a, f.content))) try write.append(a, f);
    }
    return .{
        .vm = v,
        .managed = managed,
        .write = write.items,
        .restart = write.items.len > 0 or !std.mem.eql(u8, st.alloy, files.alloy_version) or !st.active or !st.timer,
        .from = if (std.mem.eql(u8, st.alloy, "-")) "not installed" else if (st.active) try std.fmt.allocPrint(a, "alloy {s}, running", .{st.alloy}) else try std.fmt.allocPrint(a, "alloy {s}, not running", .{st.alloy}),
    };
}

/// Write a guest's Alloy files and (re)start it with the facts timer.
/// Order: repository files, the package (it creates the `alloy` group),
/// Alloy's own files, then the start.
fn apply(c: *pve.Client, e: Enrollee) !void {
    for (e.write) |f| if (!files.needsAlloy(f)) try edge.writeFile(c, e.vm.vmid, f);
    try edge.run(c, e.vm.vmid, "installing alloy", files.enroll_install, step_timeout_ms);
    for (e.write) |f| if (files.needsAlloy(f)) try edge.writeFile(c, e.vm.vmid, f);
    try edge.run(c, e.vm.vmid, "starting alloy", files.enroll_start, step_timeout_ms);
}

/// `vm new`'s step: enroll a fresh guest when a watchdog exists. Null when
/// there is none (or the guest is the watchdog itself: `watch setup`).
pub fn enrollNew(ctx: *Context, c: *pve.Client, v: vms.Vm) !?[]const u8 {
    const w = try findWatchVm(c) orelse return null;
    if (w.vmid == v.vmid or roleOf(v.tags) == .watch) return null;
    const e = try enrollee(ctx, c, v, try watchHost(ctx, w), try lab(ctx, c, false));
    if (e.restart) try apply(c, e);
    return try std.fmt.allocPrint(ctx.arena, "pushes to {s}", .{w.name});
}

const EnrollOp = struct {
    c: *pve.Client,
    words: []const []const u8,
    all: bool,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    watch: vms.Vm = undefined,
    todo: []const Enrollee = &.{},
    skipped: []const []const u8 = &.{},
    ledger: exec.Ledger = .{},
    fp: []const u8 = "",

    pub fn read(op: *EnrollOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        op.watch = try findWatchVm(c) orelse return ctx.fail(error.NotFound, "no VM tagged role-watch; guests have nowhere to push (SPEC §9.9)", .{});
        const host = try watchHost(ctx, op.watch);
        const l = try lab(ctx, c, false);
        var targets: std.ArrayList(vms.Vm) = .empty;
        var skipped: std.ArrayList([]const u8) = .empty;
        if (op.all) {
            for (try vms.list(c)) |v| {
                if (v.template or !template.taggedWith(v.tags, vm_new.tag) or roleOf(v.tags) == .watch) continue;
                if (!v.running()) {
                    try skipped.append(a, try std.fmt.allocPrint(a, "{s} ({s})", .{ v.name, v.status }));
                    continue;
                }
                try targets.append(a, v);
            }
        } else {
            for (op.words) |w| {
                const v = try vms.resolve(c, w);
                if (v.template) return ctx.fail(error.Refused, "{s} is a template; the template carries Alloy for new guests", .{v.name});
                if (!template.taggedWith(v.tags, vm_new.tag)) return ctx.fail(error.Refused, "{s} was not created by artoo (no '{s}' tag)", .{ try k.clean(ctx, v.name), vm_new.tag });
                if (roleOf(v.tags) == .watch) return ctx.fail(error.Refused, "{s} is the watchdog itself; 'artoo watch setup' enrolls it", .{v.name});
                try targets.append(a, try ready(ctx, c, v));
            }
        }
        var todo: std.ArrayList(Enrollee) = .empty;
        var fp: std.ArrayList(u8) = .empty;
        for (targets.items) |v| {
            if (!try agent.ping(c, v.vmid)) {
                try skipped.append(a, try std.fmt.allocPrint(a, "{s} (agent not answering)", .{v.name}));
                continue;
            }
            const e = try enrollee(ctx, c, v, host, l);
            try fp.print(a, "{s}:{d}:{};", .{ v.name, e.write.len, e.restart });
            if (e.restart) try todo.append(a, e);
        }
        op.todo = todo.items;
        op.skipped = skipped.items;
        op.fp = fp.items;
        op.target = if (op.all) "all guests" else try std.mem.join(a, ", ", op.words);
    }

    pub fn plan(op: *EnrollOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        if (op.todo.len == 0) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        for (op.todo) |e| try changes.append(a, .{
            .field = e.vm.name,
            .from = e.from,
            .to = try std.fmt.allocPrint(a, "alloy {s} → {s}, {d} file(s) written", .{ files.alloy_version, op.watch.name, e.write.len }),
        });
        var notes: std.ArrayList([]const u8) = .empty;
        for (op.skipped) |s| try notes.append(a, try std.fmt.allocPrint(a, "Skipped: {s}.", .{s}));
        try notes.append(a, "Alloy reports nothing to Grafana Labs and reaches only private networks (systemd IPAddressDeny).");
        return .{
            .action = try std.fmt.allocPrint(a, "Enroll {d} guest(s) with {s}", .{ op.todo.len, op.watch.name }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{"Each guest runs Alloy and a facts timer, pushing metrics and its journal to the watchdog; nothing listens on the guests"}),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *EnrollOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *EnrollOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const first = l.steps.items.len;
        for (op.todo) |e| _ = try l.add(a, try std.fmt.allocPrint(a, "enroll {s}", .{e.vm.name}));
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        for (op.todo, first..) |e, i| {
            l.set(i, .unknown, "");
            try apply(op.c, e);
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} file(s)", .{e.write.len}));
        }
    }

    pub fn verify(op: *EnrollOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const host = try watchHost(ctx, op.watch);
        const l = try lab(ctx, op.c, false);
        for (op.todo) |e| {
            if ((try enrollee(ctx, op.c, e.vm, host, l)).restart) return false;
        }
        return op.ledger.complete();
    }

    pub fn done(op: *EnrollOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{d} guest(s) push to {s} — 'artoo watch status' shows them within a few minutes", .{ op.todo.len, op.watch.name }) catch "done";
    }
};

pub const enroll = struct {
    pub const name = "enroll";
    pub const summary = "Run Alloy on guests, pushing to the watchdog (idempotent)";
    pub const details =
        \\Installs Alloy at its pin where missing (guests from older templates),
        \\writes its configuration (journald → Loki, node metrics and artoo's
        \\facts → VictoriaMetrics; Caddy and cloudflared metrics on the edge) and
        \\starts it with the facts timer. Alloy reports nothing to Grafana Labs
        \\and reaches only private networks. New guests are enrolled by 'vm new'.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .help = "guests to enroll", .complete = .vm, .required = false, .variadic = true }};
    pub const flags = [_]cli.Flag{.{ .long = "all", .help = "Every running artoo guest" }};
    pub const examples = [_][]const u8{ "artoo watch enroll --all -n", "artoo watch enroll bespin jakku" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const words = args.rest("VM");
        const all = args.has("all");
        if (all == (words.len > 0)) return ctx.fail(error.Usage, "give VM names or --all", .{});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: EnrollOp = .{ .c = &c, .words = words, .all = all };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- secret

const Kind = enum {
    grafana,
    phone,

    fn label(kind: Kind) []const u8 {
        return switch (kind) {
            .grafana => "New Grafana admin password",
            .phone => "New password for ntfy user 'phone'",
        };
    }

    fn title(kind: Kind) []const u8 {
        return switch (kind) {
            .grafana => "Grafana's admin password",
            .phone => "the ntfy password of user 'phone'",
        };
    }
};

const SecretOp = struct {
    c: *pve.Client,
    kind: Kind,
    value: []const u8,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: vms.Vm = undefined,
    replacing: bool = false,

    pub fn read(op: *SecretOp, ctx: *Context) !void {
        op.vm = try watchVm(ctx, op.c);
        op.target = op.vm.name;
        const st = try probe(op.c, op.vm.vmid, &.{});
        switch (op.kind) {
            .grafana => if (!st.isActive("grafana-server")) return ctx.fail(error.Refused, "Grafana does not run on {s}; run 'artoo watch setup' first", .{op.vm.name}),
            .phone => {
                if (!st.auth) return ctx.fail(error.Refused, "{s} has no ntfy users yet; run 'artoo watch setup' first", .{op.vm.name});
                op.replacing = st.phone;
            },
        }
    }

    pub fn plan(op: *SecretOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const change: ui.blocks.Change = switch (op.kind) {
            .grafana => .{ .field = "admin", .from = "(hidden)", .to = "(hidden)" },
            .phone => .{ .field = "phone", .from = if (op.replacing) "(hidden)" else null, .to = "(hidden), read-only on topic '" ++ files.topic ++ "'" },
        };
        return .{
            .action = try std.fmt.allocPrint(a, "Set {s} on {s}", .{ op.kind.title(), op.vm.name }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{change}),
            .impact = try a.dupe([]const u8, &.{if (op.kind == .phone) "ntfy restarts (a few seconds); the phone's app logs in again" else "Grafana's admin login changes"}),
            .notes = try a.dupe([]const u8, &.{if (op.kind == .phone) "Only a bcrypt hash made on this Mac reaches the VM; artoo keeps no copy." else "Handed to Grafana's CLI on stdin; artoo keeps no copy."}),
        };
    }

    pub fn fingerprint(op: *SecretOp) []const u8 {
        return if (op.replacing) "replace" else "new";
    }

    pub fn send(op: *SecretOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        const id = op.vm.vmid;
        switch (op.kind) {
            .grafana => {
                const enc = std.base64.standard.Encoder;
                const b64 = try a.alloc(u8, enc.calcSize(op.value.len));
                _ = enc.encode(b64, op.value);
                const r = try agent.exec(c, id, &.{ "sh", "-c", files.reset_admin }, b64, 120_000);
                if (!r.ok()) return ctx.fail(error.Partial, "Grafana refused the password (exit {?d})", .{r.code});
            },
            .phone => {
                var buf: [bcrypt_len]u8 = undefined;
                const hash = try bcryptHash(ctx, op.value, &buf);
                try writeAuthEnv(c, id, try files.ntfyAuthEnv(a, files.grafana_hash_placeholder, hash, files.token_placeholder));
                try edge.run(c, id, "restarting ntfy", "systemctl restart ntfy", step_timeout_ms);
            },
        }
    }

    pub fn verify(op: *SecretOp, _: *Context) !bool {
        const st = try probe(op.c, op.vm.vmid, &.{});
        return switch (op.kind) {
            .grafana => st.isActive("grafana-server"),
            .phone => st.phone and st.isActive("ntfy"),
        };
    }

    pub fn done(op: *SecretOp) []const u8 {
        return switch (op.kind) {
            .grafana => "Grafana's admin password is set — sign in as 'admin'",
            .phone => "ntfy user 'phone' is set — log in with it in the ntfy app",
        };
    }
};

pub const secret = struct {
    pub const name = "secret";
    pub const summary = "Set a watchdog password (hidden prompt or --stdin)";
    pub const details =
        \\grafana: Grafana's admin password, handed to Grafana's CLI on stdin.
        \\phone: the ntfy login of the operator's phone (user 'phone', read-only
        \\on the alert topic); only its bcrypt hash, made here, reaches the VM.
        \\artoo never stores, prints or logs either (SPEC §9.9).
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "KIND", .help = "grafana | phone" }};
    pub const flags = [_]cli.Flag{.{ .long = "stdin", .help = "Read the password from standard input" }};
    pub const examples = [_][]const u8{ "artoo watch secret grafana", "artoo watch secret phone" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const kind = std.meta.stringToEnum(Kind, args.pos("KIND")) orelse return ctx.fail(error.Usage, "KIND must be grafana or phone", .{});
        const value = if (args.has("stdin"))
            std.mem.trimEnd(u8, try prompt.readAll(ctx.input, ctx.io, ctx.arena, 4096), "\r\n")
        else blk: {
            if (!try prompt.interactive(ctx.input, ctx.io)) return ctx.fail(error.NonInteractive, "not a terminal: pipe the password with --stdin", .{});
            const first = try prompt.askHidden(ctx.input, ctx.io, ctx.arena, ctx.err, kind.label());
            const again = try prompt.askHidden(ctx.input, ctx.io, ctx.arena, ctx.err, "Repeat it");
            if (!std.mem.eql(u8, first, again)) return ctx.fail(error.Usage, "the two entries differ; nothing was sent", .{});
            break :blk first;
        };
        if (!validPassword(value)) return ctx.fail(error.Usage, "the password must be 12-72 printable ASCII characters", .{});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SecretOp = .{ .c = &c, .kind = kind, .value = value };
        try exec.run(ctx, &op, .{});
    }
};

/// 12–72 printable ASCII (bcrypt's limit; no newline in the env file).
pub fn validPassword(s: []const u8) bool {
    if (s.len < 12 or s.len > 72) return false;
    for (s) |ch| if (ch < 0x21 or ch > 0x7e) return false;
    return true;
}

// ---------------------------------------------------------------- status

const status_script = std.fmt.comptimePrint(
    \\nft -j list counters table inet artoo_watch 2>/dev/null || echo '{{}}'
    \\echo '---'
    \\curl -fsS --max-time 10 --get --data-urlencode 'query=time() - max by (host) (tlast_over_time(node_boot_time_seconds[1d]))' http://localhost:{[vm]d}/api/v1/query 2>/dev/null || echo '{{}}'
    \\echo '---'
    \\curl -fsS --max-time 10 --get --data-urlencode 'query=time() - max(tlast_over_time(system_uptime{{object="nodes"}}[1d]))' http://localhost:{[vm]d}/api/v1/query 2>/dev/null || echo '{{}}'
    \\echo '---'
    \\curl -fsS --max-time 10 --get --data-urlencode 'query=sum by (host) (count_over_time({{host=~".+"}}[10m]))' http://localhost:{[loki]d}/loki/api/v1/query 2>/dev/null || echo '{{}}'
    \\
, .{ .vm = files.port_vm, .loki = files.port_loki });

/// host → value from a Prometheus/Loki instant-vector answer; `key` is the
/// label (null = the single unlabeled series, under "").
pub fn vectorBy(a: std.mem.Allocator, json: []const u8, key: ?[]const u8) !std.StringHashMapUnmanaged(f64) {
    var out: std.StringHashMapUnmanaged(f64) = .empty;
    const v = std.json.parseFromSliceLeaky(Value, a, std.mem.trim(u8, json, " \n"), .{}) catch return out;
    for (pve.items(pve.obj(pve.obj(v, "data"), "result"))) |r| {
        const label = if (key) |kk| pve.str(pve.obj(r, "metric"), kk) orelse continue else "";
        const pair = pve.items(pve.obj(r, "value"));
        if (pair.len != 2) continue;
        const text = switch (pair[1]) {
            .string => |s| s,
            else => continue,
        };
        try out.put(a, label, std.fmt.parseFloat(f64, text) catch continue);
    }
    return out;
}

/// Proxmox's metric server towards `address:8428` (InfluxDB over HTTP).
fn metricServer(c: *pve.Client, address: []const u8) !?[]const u8 {
    for (pve.items(try c.get("/cluster/metrics/server"))) |s| {
        if (!std.mem.eql(u8, pve.str(s, "server") orelse "", address)) continue;
        if (!std.mem.eql(u8, pve.str(s, "type") orelse "", "influxdb")) continue;
        if (pve.int(s, "port") != files.port_vm) continue;
        if (pve.flag(s, "disable")) continue;
        return pve.str(s, "id") orelse "";
    }
    return null;
}

fn age(a: std.mem.Allocator, seconds: f64) ![]const u8 {
    return std.fmt.allocPrint(a, "{f} ago", .{ui.values.duration(@intFromFloat(@max(seconds, 0)))});
}

pub const status = struct {
    pub const name = "status";
    pub const summary = "The watchdog's health and whether every guest reports (read-only)";
    pub const details =
        \\Blocked telemetry and outbound attempts first, then both firewalls, the
        \\pinned versions, services, configuration as rendered (every telemetry
        \\switch), the ntfy phone user, Proxmox's metric export, and per guest the
        \\age of its latest metrics and whether its journal arrives.
    ;
    pub const examples = [_][]const u8{ "artoo watch status", "artoo watch status -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        const a = ctx.arena;
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const v = try watchVm(ctx, &c);
        const l = try lab(ctx, &c, true);
        const managed = try managedFiles(ctx, v, l);
        const st = try probe(&c, v.vmid, managed);
        const r = try agent.sh(&c, v.vmid, status_script, 60_000);
        var parts = std.mem.splitSequence(u8, r.out, "---\n");
        const counters = parts.next() orelse "";
        const guest_ages = try vectorBy(a, parts.next() orelse "", "host");
        const pve_age = (try vectorBy(a, parts.next() orelse "", null)).get("");
        const logs = try vectorBy(a, parts.next() orelse "", "host");

        var checks: std.ArrayList(Check) = .empty;
        for ([_]struct { []const u8, []const u8 }{ .{ "telemetry blocked", "telemetry" }, .{ "drops to Proxmox", "to_pve" }, .{ "drops to UniFi", "to_gateway" }, .{ "drops to the LAN", "to_lan" } }) |p| {
            const n = edge.counter(a, counters, p[1]);
            try checks.append(a, if (n) |hits| .{
                .name = p[0],
                .status = if (hits == 0) .ok else .failed,
                .detail = if (hits == 0) "none" else try std.fmt.allocPrint(a, "{d} packet(s) — investigate", .{hits}),
            } else .{ .name = p[0], .status = .failed, .detail = "counter missing (firewall not loaded?)" });
        }
        const hs = try edge.readHost(&c, v);
        const hsteps = edge.hostSteps(&hostRules(l), hs);
        try checks.append(a, .{ .name = "host firewall", .status = if (hsteps.any()) .failed else .ok, .detail = if (hsteps.any()) "differs from SPEC §9.9 — run 'artoo watch setup'" else "Proxmox VM firewall as designed (on Proxmox)" });
        try checks.append(a, .{ .name = "firewall", .status = if (st.nft_loaded and st.nft_enabled) .ok else .failed, .detail = if (st.nft_loaded) (if (st.nft_enabled) "loaded, enabled" else "loaded, not enabled at boot") else "not loaded" });
        for (files.watch_packages) |p| {
            const have = st.version(p[0]);
            try checks.append(a, .{ .name = p[0], .status = if (std.mem.eql(u8, have, p[1])) .ok else .failed, .detail = try std.fmt.allocPrint(a, "{s} (pin {s})", .{ have, p[1] }) });
        }
        try checks.append(a, .{ .name = "victoriametrics", .status = if (std.mem.eql(u8, st.vm, files.vm_version)) .ok else .failed, .detail = try std.fmt.allocPrint(a, "{s} (pin {s})", .{ st.vm, files.vm_version }) });
        var down: std.ArrayList([]const u8) = .empty;
        for (services) |u| if (!st.isActive(u)) try down.append(a, u);
        try checks.append(a, .{ .name = "services", .status = if (down.items.len == 0) .ok else .failed, .detail = if (down.items.len == 0) "all running" else try std.fmt.allocPrint(a, "not running: {s}", .{try std.mem.join(a, ", ", down.items)}) });
        var drift: std.ArrayList([]const u8) = .empty;
        for (managed) |f| {
            if (!std.mem.eql(u8, st.hashes.get(f.path) orelse "-", try files.sha256Hex(a, f.content))) try drift.append(a, f.path);
        }
        try checks.append(a, .{
            .name = "configuration",
            .status = if (drift.items.len == 0) .ok else .failed,
            .detail = if (drift.items.len == 0) "as rendered: every telemetry switch off, retention 90 d metrics / 31 d logs" else try std.fmt.allocPrint(a, "{d} file(s) differ (first {s}) — run 'artoo watch setup'", .{ drift.items.len, drift.items[0] }),
        });
        try checks.append(a, .{ .name = "phone user", .status = if (st.phone) .ok else .warning, .detail = if (st.phone) "set" else "not set — 'artoo watch secret phone'" });
        if (l.services.len < 2) try checks.append(a, .{ .name = "service names", .status = .warning, .detail = "add 'svc add grafana <watch>:3000' and 'svc add ntfy <watch>:2586'" });

        const vcfg = try vms.config(&c, v.vmid);
        const address = life.staticAddress(vcfg) orelse "";
        const server = try metricServer(&c, address);
        try checks.append(a, .{
            .name = "Proxmox export",
            .status = if (server == null) .failed else if (pve_age) |s| (if (s <= silent_after_s) .ok else .failed) else .failed,
            .detail = if (server == null) try std.fmt.allocPrint(a, "no InfluxDB metric server towards {s}:{d} — run scripts/pve-metrics.sh (approved host change)", .{ address, files.port_vm }) else if (pve_age) |s| try age(a, s) else "configured, no sample yet",
        });

        for (try vms.list(&c)) |g| {
            if (g.template or !template.taggedWith(g.tags, vm_new.tag)) continue;
            const metrics = guest_ages.get(g.name);
            const has_logs = logs.contains(g.name);
            const label = try std.fmt.allocPrint(a, "{s}", .{g.name});
            if (!g.running()) {
                try checks.append(a, .{ .name = label, .status = .not_checked, .detail = try std.fmt.allocPrint(a, "{s}", .{g.status}) });
                continue;
            }
            const fresh = if (metrics) |s| s <= silent_after_s else false;
            try checks.append(a, .{
                .name = label,
                .status = if (fresh and has_logs) .ok else .failed,
                .detail = if (metrics == null) "never reported — 'artoo watch enroll'" else try std.fmt.allocPrint(a, "metrics {s}, logs {s}", .{ try age(a, metrics.?), if (has_logs) "arriving" else "none in 10 min" }),
            });
        }
        try checks.append(a, .{ .name = "reboot pending", .status = if (st.reboot) .warning else .ok, .detail = if (st.reboot) "yes — reboot when convenient" else "no" });
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, .{ .vm = v.name, .checks = checks.items }, .{ .collected_at = ctx.ui.now });
        try k.header(ctx, &c);
        try vm_new.renderChecks(ctx, checks.items);
        var failed: usize = 0;
        for (checks.items) |ch| failed += @intFromBool(ch.status == .failed);
        if (failed > 0) return ctx.fail(error.Partial, "{d} check(s) failed on {s}", .{ failed, v.name });
    }
};

// ---------------------------------------------------------------- forget

/// VictoriaMetrics on the watchdog, reached through its guest agent:
/// `8428` is open to the guest pool and Proxmox only (SPEC §9.9).
const metrics_url = "http://localhost:8428";

/// Series of `host` stored in the last 3 days (the alert rules look back
/// 1 day). Without `start`, `/api/v1/series` covers only recent minutes.
pub fn hostSeries(c: *pve.Client, w: vms.Vm, host: []const u8) !usize {
    const ctx = c.ctx;
    const sel = try std.fmt.allocPrint(ctx.arena, "match[]={{host=\"{s}\"}}", .{host});
    const r = try agent.exec(c, w.vmid, &.{ "curl", "-fsS", "-G", metrics_url ++ "/api/v1/series", "--data-urlencode", sel, "--data-urlencode", "start=-3d" }, null, 60_000);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading {s}'s series on {s} failed: {s}", .{ host, w.name, try k.clean(ctx, edge.firstLine(if (r.err.len > 0) r.err else r.out)) });
    const v = std.json.parseFromSliceLeaky(Value, ctx.arena, r.out, .{}) catch
        return ctx.fail(error.Protocol, "VictoriaMetrics on {s} sent an unexpected series answer", .{w.name});
    return pve.items(pve.obj(v, "data")).len;
}

/// Delete every series of `host` (SPEC §9.9) and check none is left; its
/// alerts resolve at the next evaluation. Returns how many were deleted.
pub fn forgetHost(c: *pve.Client, w: vms.Vm, host: []const u8) !usize {
    const ctx = c.ctx;
    const before = try hostSeries(c, w, host);
    if (before == 0) return 0;
    const sel = try std.fmt.allocPrint(ctx.arena, "match[]={{host=\"{s}\"}}", .{host});
    const r = try agent.exec(c, w.vmid, &.{ "curl", "-fsS", "-X", "POST", metrics_url ++ "/api/v1/admin/tsdb/delete_series", "--data-urlencode", sel }, null, 60_000);
    if (!r.ok()) return ctx.fail(error.Partial, "deleting {s}'s series on {s} failed: {s}", .{ host, w.name, try k.clean(ctx, edge.firstLine(if (r.err.len > 0) r.err else r.out)) });
    const left = try hostSeries(c, w, host);
    if (left > 0) return ctx.fail(error.Partial, "{d} series of {s} remain on {s} after the delete", .{ left, host, w.name });
    return before;
}

const ForgetOp = struct {
    c: *pve.Client,
    host: []const u8,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    w: vms.Vm = undefined,
    series: usize = 0,
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *ForgetOp, ctx: *Context) !void {
        op.target = op.host;
        op.w = try watchVm(ctx, op.c);
        if (std.mem.eql(u8, op.w.name, op.host)) return ctx.fail(error.Refused, "{s} is the watchdog itself", .{op.host});
        switch (try vms.find(try vms.list(op.c), ctx.arena, op.host)) {
            .missing => {},
            else => return ctx.fail(error.Refused, "VM {s} still exists: its metrics would come back; 'artoo vm rm {s}' forgets it with the VM", .{ op.host, op.host }),
        }
        op.series = try hostSeries(op.c, op.w, op.host);
        op.fp = try std.fmt.allocPrint(ctx.arena, "{d}", .{op.series});
    }

    pub fn plan(op: *ForgetOp, ctx: *Context) !?exec.Plan {
        if (op.series == 0) return null;
        const a = ctx.arena;
        return .{
            .action = try std.fmt.allocPrint(a, "Forget {s} in the watchdog", .{op.host}),
            .risk = .destructive,
            .target = try std.fmt.allocPrint(a, "VictoriaMetrics on {s} (through the guest agent)", .{op.w.name}),
            .changes = try a.dupe(ui.blocks.Change, &.{.{ .field = "metrics", .from = try std.fmt.allocPrint(a, "{d} series with host={s}", .{ op.series, op.host }), .to = null }}),
            .impact = try a.dupe([]const u8, &.{try std.fmt.allocPrint(a, "{s}'s metric history is gone; its alerts resolve at the next evaluation (1 min)", .{op.host})}),
            .notes = try a.dupe([]const u8, &.{"Its logs in Loki stay until retention removes them (31 days); no alert reads them."}),
        };
    }

    pub fn fingerprint(op: *ForgetOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *ForgetOp, ctx: *Context) !void {
        const i = try op.ledger.add(ctx.arena, "delete series");
        op.ledger.set(i, .unknown, "");
        const n = forgetHost(op.c, op.w, op.host) catch |err| {
            op.ledger.set(i, .failed, ctx.diag orelse @errorName(err));
            return err;
        };
        op.ledger.set(i, .done, try std.fmt.allocPrint(ctx.arena, "{d} series", .{n}));
    }

    pub fn verify(op: *ForgetOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        return (try hostSeries(op.c, op.w, op.host)) == 0;
    }

    pub fn done(op: *ForgetOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} forgotten by {s}", .{ op.host, op.w.name }) catch "done";
    }
};

pub const forget = struct {
    pub const name = "forget";
    pub const summary = "Delete a removed guest's metrics so its alerts resolve";
    pub const details =
        \\For a guest that no longer exists (removed before 'vm rm' did this, or by
        \\hand): deletes every series with host=HOST from VictoriaMetrics on the
        \\watchdog, so 'Guest silent' and other alerts about it resolve. Refused
        \\while a VM of that name exists. Type HOST to confirm, or --yes --confirm
        \\HOST.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "HOST", .help = "The removed guest's name (the host label)" }};
    pub const flags = [_]cli.Flag{.{ .long = "confirm", .kind = .string, .metavar = "HOST", .help = "Non-interactive confirmation (with --yes)" }};
    pub const examples = [_][]const u8{ "artoo watch forget eadu", "artoo watch forget eadu --yes --confirm eadu" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const host = args.pos("HOST");
        if (!guest_names.valid(host)) return ctx.fail(error.Usage, "invalid host '{s}': one DNS label (a guest name)", .{host});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: ForgetOp = .{ .c = &c, .host = host };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const group = cli.group("watch", "The watchdog VM: metrics, logs, alerts to the phone (SPEC §9.9)", &.{
    cli.leaf(setup),
    cli.leaf(status),
    cli.leaf(enroll),
    cli.leaf(secret),
    cli.leaf(forget),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;

const test_lab: files.Lab = .{
    .pve = "192.168.1.10",
    .gateway = "192.168.1.1",
    .lan = "192.168.1.0/24",
    .pool = "192.168.1.200-192.168.1.254",
    .edge = "192.168.1.200",
    .domain = "lab.example.com",
    .services = &.{ .{ .name = "grafana" }, .{ .name = "ntfy" } },
};

test "plannedSteps: a fresh VM needs everything, in safe order; a converged one nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const managed = try files.watchFiles(a, test_lab, try grafana.dashboardFiles(a), try grafana.rulesYaml(a));
    const fresh = try parseState(a, "users no\nnft no\nnftenabled no\nvm -\nadmin no\ntoken no\nauth no\nphone no\nreboot no\ntailscale yes\n");
    const s = try plannedSteps(a, managed, fresh);
    try testing.expectEqual(managed.len, s.write.len);
    try testing.expect(s.tailscale and s.accounts and s.firewall and s.packages and s.vm and s.secrets and s.auth and s.alloy);
    try testing.expectEqual(@as(usize, 4), s.restart.len);

    var out: std.ArrayList(u8) = .empty;
    for (managed) |f| try out.print(a, "file {s} {s}\n", .{ f.path, try files.sha256Hex(a, f.content) });
    for (files.watch_packages) |p| try out.print(a, "pkg {s} {s}\n", .{ p[0], p[1] });
    for (services) |u| try out.print(a, "active {s} yes\n", .{u});
    try out.print(a, "users yes\nnft yes\nnftenabled yes\nvm {s}\nadmin yes\ntoken yes\nauth yes\nphone yes\nreboot no\ntailscale no\n", .{files.vm_version});
    try testing.expect(!(try plannedSteps(a, managed, try parseState(a, out.items))).any());

    // A dashboard artoo no longer renders is removed (Grafana restarts).
    var stale = try parseState(a, out.items);
    try stale.dashboards.append(a, "/etc/grafana/dashboards/artoo-pve.json");
    try stale.dashboards.append(a, grafana.lab_board_path);
    const p = try plannedSteps(a, managed, stale);
    try testing.expectEqual(@as(usize, 1), p.prune.len);
    try testing.expectEqualStrings("/etc/grafana/dashboards/artoo-pve.json", p.prune[0]);
    try testing.expectEqualStrings("grafana-server", p.restart[0]);

    // A changed Grafana file restarts Grafana only.
    var edited = try parseState(a, out.items);
    try edited.hashes.put(a, "/etc/grafana/grafana.ini", "0");
    const one = try plannedSteps(a, managed, edited);
    try testing.expectEqual(@as(usize, 1), one.write.len);
    try testing.expectEqual(@as(usize, 1), one.restart.len);
    try testing.expectEqualStrings("grafana-server", one.restart[0]);
    try testing.expect(!one.packages and !one.alloy and !one.firewall);
}

test "hostRules: never Proxmox, ingest only from pool and Proxmox, UI only via the edge" {
    const rules = hostRules(test_lab);
    var pve_drop: ?usize = null;
    var first_web: ?usize = null;
    for (rules, 0..) |r, i| {
        if (std.mem.eql(u8, r.type, "out") and std.mem.eql(u8, r.dest, "192.168.1.10")) pve_drop = i;
        if (std.mem.eql(u8, r.type, "out") and std.mem.eql(u8, r.dport, "80,443")) first_web = i;
        if (std.mem.eql(u8, r.type, "in") and std.mem.eql(u8, r.dport, "3000,2586")) try testing.expectEqualStrings("192.168.1.200", r.source);
        if (std.mem.eql(u8, r.type, "in") and std.mem.eql(u8, r.dport, "22")) try testing.expectEqualStrings("192.168.1.10", r.source);
    }
    try testing.expect(pve_drop.? < first_web.?);
}

test "vectorBy: hosts and the unlabeled series" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const by = try vectorBy(a, "{\"status\":\"success\",\"data\":{\"resultType\":\"vector\",\"result\":[{\"metric\":{\"host\":\"naboo\"},\"value\":[1760000000,\"12.5\"]},{\"metric\":{},\"value\":[1,\"3\"]}]}}", "host");
    try testing.expectEqual(@as(f64, 12.5), by.get("naboo").?);
    try testing.expectEqual(@as(usize, 1), by.count());
    const one = try vectorBy(a, "{\"data\":{\"result\":[{\"metric\":{},\"value\":[1,\"42\"]}]}}", null);
    try testing.expectEqual(@as(f64, 42), one.get("").?);
    try testing.expectEqual(@as(usize, 0), (try vectorBy(a, "{}", "host")).count());
}

test "validPassword" {
    try testing.expect(validPassword("correct-horse-battery"));
    try testing.expect(!validPassword("short"));
    try testing.expect(!validPassword("has a space in it"));
    try testing.expect(!validPassword(&@as([73]u8, @splat('x'))));
}

test "roleOf" {
    try testing.expectEqual(files.Role.edge, roleOf("artoo;role-edge;ssh-jump"));
    try testing.expectEqual(files.Role.watch, roleOf("artoo;role-watch"));
    try testing.expectEqual(files.Role.search, roleOf("artoo;role-search"));
    try testing.expectEqual(files.Role.plain, roleOf("artoo"));
}

test "watch setup -n: finds the role-watch VM, plans every step, writes nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const testkit = @import("../testkit.zig");
    const ok = struct {
        fn agent(al: std.mem.Allocator, out: []const u8) ![]const u8 {
            return std.json.Stringify.valueAlloc(al, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
        }
    };
    const list = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;ssh-jump\"},{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch;ssh-jump\"}]}";
    const pid = "{\"data\":{\"pid\":42}}";
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        // watchVm: list, ping
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        // lab: list (edge), edge config; svc dump: list, ping, agent exec + status
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = "{\"data\":{\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\"}}" } },
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try ok.agent(a, "==artoo== /etc/caddy/services/grafana.caddy\n# artoo service grafana -> scarif:3000\n@svc-grafana host grafana.apps.lab.example.com\nhandle @svc-grafana {\n    reverse_proxy scarif.lab.example.com:3000\n}\n\n==caddy== active\n") } },
        // probe
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try ok.agent(a, "users no\nnft no\nnftenabled no\nvm -\nadmin no\ntoken no\nauth no\nphone no\nreboot no\n") } },
        // host firewall: config, options, rules, ipsets
        .{ .respond = .{ .body = "{\"data\":{\"net0\":\"virtio=BC:24:11:AB:CD:01,bridge=vmbr0\",\"ipconfig0\":\"ip=192.168.1.202/24,gw=192.168.1.1\",\"digest\":\"d1\"}}" } },
        .{ .respond = .{ .body = "{\"data\":{}}" } },
        .{ .respond = .{ .body = "{\"data\":[]}" } },
        .{ .respond = .{ .body = "{\"data\":[]}" } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    const exit = g.h.run(&root, "watch setup -n");
    if (exit != .ok) std.debug.print("stderr:\n{s}\n", .{g.h.stderr()});
    try testing.expectEqual(testkit.Exit.ok, exit);
    try testing.expectEqual(@as(usize, 14), g.sent());
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Set up watchdog VM scarif (202)",
        "accounts         (none) → system users grafana, loki, victoriametrics, alloy, ntfy (before any package)",
        "(none) → /etc/grafana/grafana.ini",
        "packages",
        "grafana 13.2.3, loki 3.7.8, alloy 1.20.1-1, ntfy 2.29.0 (held by apt pins)",
        "victoriametrics  (none) → v1.153.0 from its release tarball, SHA-256 checked",
        "alloy            (none) → pushes scarif's metrics and journal, probes 1 service(s)",
        "host firewall    (none) → Proxmox VM firewall: 16 rules, only source 192.168.1.202",
        "Dry run: nothing was sent.",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "watch forget: a removed guest's series deleted and verified; the watchdog itself and bad names refused" {
    const testkit = @import("../testkit.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const out_of = struct {
        fn f(ar: std.mem.Allocator, out: []const u8) ![]const u8 {
            return std.json.Stringify.valueAlloc(ar, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
        }
    }.f;
    const list = "{\"data\":[{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"}]}";
    const pid = "{\"data\":{\"pid\":42}}";
    const ping = "{\"data\":{\"result\":{}}}";
    const two = try out_of(a, "{\"status\":\"success\",\"data\":[{},{}]}");
    const none = try out_of(a, "{\"status\":\"success\",\"data\":[]}");
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = list } }, .{ .respond = .{ .body = ping } }, .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = pid } }, .{ .respond = .{ .body = two } }, // read
        .{ .respond = .{ .body = pid } }, .{ .respond = .{ .body = two } }, // before
        .{ .respond = .{ .body = pid } }, .{ .respond = .{ .body = try out_of(a, "") } }, // delete
        .{ .respond = .{ .body = pid } }, .{ .respond = .{ .body = none } }, // after
        .{ .respond = .{ .body = pid } }, .{ .respond = .{ .body = none } }, // verify
        .{ .respond = .{ .body = list } }, .{ .respond = .{ .body = ping } }, // forget scarif
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "watch forget eadu -y --confirm eadu"));
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Forget eadu in the watchdog  ▲ destructive\n",
        "metrics  2 series with host=eadu → (removed)\n",
        "✓ delete series  done  2 series",
        "✓ eadu forgotten by scarif",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expect(std.mem.find(u8, g.body(7), "delete_series&command=--data-urlencode&command=match%5B%5D%3D%7Bhost%3D%22eadu%22%7D") != null);
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "watch forget scarif -n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "is the watchdog itself") != null);
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "watch forget Bad_Name -n"));
    try testing.expectEqual(@as(usize, 15), g.sent());
}
