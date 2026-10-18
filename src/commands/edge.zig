//! `artoo edge setup|secret|status` (SPEC §9.7): the hardened edge VM,
//! configured through the guest agent (root, authenticated by the Proxmox
//! API): rendered files written over stdin, fixed scripts, a step ledger.
//! The edge VM is the one VM tagged `role-edge`.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const exec = @import("../exec.zig");
const prompt = @import("../prompt.zig");
const secrets = @import("../secrets.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const files = @import("../edge/files.zig");
const cf = @import("../cloudflare/client.zig");
const tunnels = @import("../cloudflare/tunnel.zig");
const vm_cmd = @import("vm.zig");
const vm_new = @import("vm_new.zig");
const life = @import("vm_life.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

pub const role = "edge";
/// Generous: the Caddy build compiles Caddy and its dependencies.
const build_timeout_ms = 45 * 60 * 1000;
const step_timeout_ms = 10 * 60 * 1000;

/// The VM tagged `role-edge` (exactly one), running, agent answering.
pub fn edgeVm(ctx: *Context, c: *pve.Client) !vms.Vm {
    return edgeVmFrom(ctx, c, try vms.list(c));
}

/// `edgeVm` from a VM list already read.
pub fn edgeVmFrom(ctx: *Context, c: *pve.Client, list: []const vms.Vm) !vms.Vm {
    var found: ?vms.Vm = null;
    for (list) |v| {
        const r = vm_cmd.roleOf(v.tags) orelse continue;
        if (!std.mem.eql(u8, r, role) or v.template) continue;
        if (found != null) return ctx.fail(error.Refused, "several VMs carry role-edge ({s}, {s}); keep one", .{ found.?.name, v.name });
        found = v;
    }
    const v = found orelse return ctx.fail(error.NotFound, "no VM tagged role-edge; create it with 'artoo vm new bespin --role edge --ssh-jump' (SPEC §9.7)", .{});
    if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first", .{ v.name, v.status });
    if (!try agent.ping(c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer", .{v.name});
    return v;
}

pub fn addresses(ctx: *Context) !files.Addresses {
    const cfg = try ctx.config();
    const a = ctx.arena;
    const gw = config.parseCidr(cfg.guests.gateway) orelse return ctx.fail(error.ConfigInvalid, "guests.gateway is not A/N", .{});
    const mask: u32 = ~@as(u32, 0) << @intCast(32 - @as(u32, gw.prefix));
    return .{
        .pve = cfg.pve.ssh_host,
        .gateway = try vm_new.ip4Text(a, gw.address),
        .lan = try std.fmt.allocPrint(a, "{s}/{d}", .{ try vm_new.ip4Text(a, gw.address & mask), gw.prefix }),
        .pool = cfg.guests.address_pool,
    };
}

pub fn appsDomain(ctx: *Context) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "apps.{s}", .{(try ctx.config()).guests.domain});
}

/// Write one file in the guest: content base64 on stdin, atomic rename.
/// Large files go in parts of `files.part_bytes` (Proxmox caps the
/// agent's input), assembled beside the target and moved into place last.
pub fn writeFile(c: *pve.Client, vmid: u32, f: files.File) !void {
    const ctx = c.ctx;
    if (f.content.len <= files.part_bytes) {
        const r = try agent.exec(c, vmid, &.{ "sh", "-c", files.write_file, "sh", f.path, f.mode, f.owner }, try b64Of(ctx.arena, f.content), 60_000);
        if (!r.ok()) return ctx.fail(error.Partial, "writing {s} failed: {s}", .{ f.path, try k.clean(ctx, firstLine(r.err)) });
        return;
    }
    var at: usize = 0;
    while (at < f.content.len) : (at += files.part_bytes) {
        const part = f.content[at..@min(at + files.part_bytes, f.content.len)];
        const r = try agent.exec(c, vmid, &.{ "sh", "-c", files.write_part, "sh", f.path, if (at == 0) "first" else "next" }, try b64Of(ctx.arena, part), 60_000);
        if (!r.ok()) return ctx.fail(error.Partial, "writing {s} failed: {s}", .{ f.path, try k.clean(ctx, firstLine(r.err)) });
    }
    const r = try agent.exec(c, vmid, &.{ "sh", "-c", files.write_finish, "sh", f.path, f.mode, f.owner }, null, 60_000);
    if (!r.ok()) return ctx.fail(error.Partial, "writing {s} failed: {s}", .{ f.path, try k.clean(ctx, firstLine(r.err)) });
}

fn b64Of(a: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const out = try a.alloc(u8, enc.calcSize(bytes.len));
    return enc.encode(out, bytes);
}

/// A fixed script as root; its stderr's first line on failure.
pub fn run(c: *pve.Client, vmid: u32, what: []const u8, script: []const u8, timeout_ms: u64) !void {
    return runWatched(c, vmid, what, script, timeout_ms, null);
}

/// `run`, reporting the script's stage file (`agent.Watch`).
pub fn runWatched(c: *pve.Client, vmid: u32, what: []const u8, script: []const u8, timeout_ms: u64, watch: ?agent.Watch) !void {
    const ctx = c.ctx;
    const r = try agent.shWatched(c, vmid, script, timeout_ms, watch);
    if (!r.ok()) return ctx.fail(error.Partial, "{s} failed (exit {?d}): {s}", .{ what, r.code, try k.clean(ctx, lastLine(if (r.err.len > 0) r.err else r.out)) });
}

pub fn firstLine(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \r\n");
    return t[0 .. std.mem.findScalar(u8, t, '\n') orelse t.len];
}

fn lastLine(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \r\n");
    return t[if (std.mem.findScalarLast(u8, t, '\n')) |i| i + 1 else 0..];
}

// ---------------------------------------------------------------- probe

/// What the guest looks like, from one read-only script.
const State = struct {
    /// path → sha256 hex ("-" when absent).
    hashes: std.StringHashMapUnmanaged([]const u8) = .empty,
    caddy: []const u8 = "-",
    caddy_module: bool = false,
    tailscale: bool = false,
    cloudflared: bool = false,
    golang: bool = false,
    nft_loaded: bool = false,
    nft_enabled: bool = false,
    caddy_user: bool = false,
    cloudflared_user: bool = false,
    /// Tunnel ID inside the stored token (the token itself never leaves
    /// the VM), or "-".
    tunnel_id: []const u8 = "-",
    cloudflared_active: bool = false,
    dns_secret: bool = false,
    caddy_active: bool = false,
    reboot: bool = false,
    raw: []const u8 = "",
};

fn probeScript(a: std.mem.Allocator, managed: []const files.File) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    try s.appendSlice(a, "for f in");
    for (managed) |f| try s.print(a, " {s}", .{f.path});
    try s.appendSlice(a,
        \\; do h=$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1); echo "file $f ${h:--}"; done
        \\v=$(/usr/local/bin/caddy version 2>/dev/null | cut -d' ' -f1); echo "caddy ${v:--}"
        \\/usr/local/bin/caddy list-modules 2>/dev/null | grep -qx dns.providers.cloudflare && echo "caddymod yes" || echo "caddymod no"
        \\for p in tailscale cloudflared
    );
    try s.print(a, " {s}", .{files.go_package});
    try s.appendSlice(a,
        \\; do case "$(dpkg-query -W -f='${Status}' "$p" 2>/dev/null)" in *"ok installed") echo "pkg $p yes";; *) echo "pkg $p no";; esac; done
        \\nft list table inet artoo_edge >/dev/null 2>&1 && echo "nft yes" || echo "nft no"
        \\systemctl is-enabled nftables >/dev/null 2>&1 && echo "nftenabled yes" || echo "nftenabled no"
        \\getent passwd caddy >/dev/null && echo "caddyuser yes" || echo "caddyuser no"
        \\getent passwd cloudflared >/dev/null && echo "cfduser yes" || echo "cfduser no"
        \\t=$(sed -n 's/^TUNNEL_TOKEN=//p' /etc/cloudflared/tunnel.env 2>/dev/null | base64 -d 2>/dev/null | grep -o '"t":"[0-9a-f-]*"' | cut -d'"' -f4); echo "tunnelid ${t:--}"
        \\systemctl is-active cloudflared >/dev/null 2>&1 && echo "cfdactive yes" || echo "cfdactive no"
        \\test -e /etc/caddy/cloudflare.env && echo "dnssecret yes" || echo "dnssecret no"
        \\systemctl is-active caddy >/dev/null 2>&1 && echo "caddyactive yes" || echo "caddyactive no"
        \\test -e /var/run/reboot-required && echo "reboot yes" || echo "reboot no"
        \\
    );
    return s.items;
}

fn probe(c: *pve.Client, vmid: u32, managed: []const files.File) !State {
    const ctx = c.ctx;
    const a = ctx.arena;
    const r = try agent.sh(c, vmid, try probeScript(a, managed), 60_000);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading the edge VM's state failed: {s}", .{try k.clean(ctx, firstLine(r.err))});
    return parseState(a, r.out);
}

pub fn parseState(a: std.mem.Allocator, out: []const u8) !State {
    var st: State = .{ .raw = out };
    var lines = std.mem.tokenizeScalar(u8, out, '\n');
    while (lines.next()) |line| {
        var w = std.mem.tokenizeScalar(u8, line, ' ');
        const key = w.next() orelse continue;
        const v1 = w.next() orelse continue;
        const v2 = w.next();
        const yes = std.mem.eql(u8, v1, "yes");
        if (std.mem.eql(u8, key, "file")) {
            try st.hashes.put(a, v1, v2 orelse "-");
        } else if (std.mem.eql(u8, key, "caddy")) {
            st.caddy = v1;
        } else if (std.mem.eql(u8, key, "caddymod")) {
            st.caddy_module = yes;
        } else if (std.mem.eql(u8, key, "pkg")) {
            const on = v2 != null and std.mem.eql(u8, v2.?, "yes");
            if (std.mem.eql(u8, v1, "tailscale")) st.tailscale = on;
            if (std.mem.eql(u8, v1, "cloudflared")) st.cloudflared = on;
            if (std.mem.eql(u8, v1, files.go_package)) st.golang = on;
        } else if (std.mem.eql(u8, key, "nft")) {
            st.nft_loaded = yes;
        } else if (std.mem.eql(u8, key, "nftenabled")) {
            st.nft_enabled = yes;
        } else if (std.mem.eql(u8, key, "caddyuser")) {
            st.caddy_user = yes;
        } else if (std.mem.eql(u8, key, "cfduser")) {
            st.cloudflared_user = yes;
        } else if (std.mem.eql(u8, key, "tunnelid")) {
            st.tunnel_id = v1;
        } else if (std.mem.eql(u8, key, "cfdactive")) {
            st.cloudflared_active = yes;
        } else if (std.mem.eql(u8, key, "dnssecret")) {
            st.dns_secret = yes;
        } else if (std.mem.eql(u8, key, "caddyactive")) {
            st.caddy_active = yes;
        } else if (std.mem.eql(u8, key, "reboot")) {
            st.reboot = yes;
        }
    }
    return st;
}

// ---------------------------------------------------------------- host firewall

/// One Proxmox VM firewall rule (the fields artoo sets).
pub const Rule = struct {
    type: []const u8,
    action: []const u8,
    macro: []const u8 = "",
    source: []const u8 = "",
    dest: []const u8 = "",
    proto: []const u8 = "",
    dport: []const u8 = "",
    comment: []const u8,

    pub fn eql(r: Rule, o: Rule) bool {
        inline for (.{ "type", "action", "macro", "source", "dest", "proto", "dport" }) |f|
            if (!std.mem.eql(u8, @field(r, f), @field(o, f))) return false;
        return true;
    }
};

/// The §9.7 policy as Proxmox VM rules, first match wins: the host-side
/// copy of the guest's nftables, which root inside the VM cannot change.
pub fn hostRules(ad: files.Addresses) [16]Rule {
    return .{
        .{ .type = "in", .action = "ACCEPT", .source = ad.pve, .proto = "tcp", .dport = "22", .comment = "artoo: SSH only from Proxmox" },
        .{ .type = "in", .action = "ACCEPT", .source = ad.lan, .proto = "tcp", .dport = "80,443", .comment = "artoo: HTTP(S) from the LAN" },
        .{ .type = "in", .action = "ACCEPT", .macro = "Ping", .source = ad.lan, .comment = "artoo: ping from the LAN" },
        .{ .type = "out", .action = "DROP", .dest = ad.pve, .comment = "artoo: never Proxmox" },
        .{ .type = "out", .action = "ACCEPT", .dest = ad.gateway, .proto = "udp", .dport = "53", .comment = "artoo: DNS on UniFi" },
        .{ .type = "out", .action = "ACCEPT", .dest = ad.gateway, .proto = "tcp", .dport = "53", .comment = "artoo: DNS on UniFi" },
        .{ .type = "out", .action = "DROP", .dest = ad.gateway, .comment = "artoo: nothing else on UniFi" },
        .{ .type = "out", .action = "DROP", .dest = ad.pool, .proto = "tcp", .dport = "22", .comment = "artoo: no SSH to guests" },
        .{ .type = "out", .action = "ACCEPT", .dest = ad.pool, .proto = "tcp", .comment = "artoo: guest services" },
        .{ .type = "out", .action = "DROP", .dest = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16", .comment = "artoo: no other private IPv4" },
        .{ .type = "out", .action = "DROP", .dest = "fc00::/7,fe80::/10", .comment = "artoo: no private IPv6" },
        .{ .type = "out", .action = "ACCEPT", .proto = "tcp", .dport = "80,443", .comment = "artoo: web (ACME, APIs, apt)" },
        .{ .type = "out", .action = "ACCEPT", .proto = "tcp", .dport = "7844", .comment = "artoo: Cloudflare Tunnel" },
        .{ .type = "out", .action = "ACCEPT", .proto = "udp", .dport = "123,443,7844", .comment = "artoo: NTP, QUIC, tunnel" },
        .{ .type = "out", .action = "ACCEPT", .macro = "Ping", .comment = "artoo: ping out" },
        .{ .type = "out", .action = "DROP", .comment = "artoo: everything else" },
    };
}

/// Options set on the VM firewall (values as Proxmox returns them).
pub const host_options = [_]struct { []const u8, []const u8 }{
    .{ "enable", "1" },        .{ "ipfilter", "1" }, .{ "macfilter", "1" }, .{ "policy_in", "DROP" },
    .{ "policy_out", "DROP" }, .{ "dhcp", "0" },     .{ "ndp", "1" },       .{ "radv", "0" },
};

pub const HostState = struct {
    rules: []const Rule = &.{},
    options_ok: bool = false,
    ipset_ok: bool = false,
    ipset_exists: bool = false,
    nic_ok: bool = false,
    net0: []const u8 = "",
    address: []const u8 = "",
};

pub const HostSteps = struct {
    rules: bool = false,
    ipset: bool = false,
    nic: bool = false,
    options: bool = false,

    pub fn any(h: HostSteps) bool {
        return h.rules or h.ipset or h.nic or h.options;
    }
};

fn fieldText(a: std.mem.Allocator, v: Value, key: []const u8) ![]const u8 {
    const x = pve.obj(v, key);
    return switch (x) {
        .string => |t| t,
        .integer => |n| try std.fmt.allocPrint(a, "{d}", .{n}),
        else => "",
    };
}

pub fn readHost(c: *pve.Client, vm: vms.Vm) !HostState {
    const ctx = c.ctx;
    const a = ctx.arena;
    var hs: HostState = .{};
    const cfg = try vms.config(c, vm.vmid);
    hs.net0 = pve.str(cfg, "net0") orelse "";
    hs.address = life.staticAddress(cfg) orelse return ctx.fail(error.Refused, "{s} has no static address (ipconfig0)", .{vm.name});
    hs.nic_ok = std.mem.find(u8, hs.net0, "firewall=1") != null;
    const opts = try c.get(try c.nodePath("/qemu/{d}/firewall/options", .{vm.vmid}));
    hs.options_ok = true;
    for (host_options) |o| {
        if (!std.mem.eql(u8, try fieldText(a, opts, o[0]), o[1])) hs.options_ok = false;
    }
    var rules: std.ArrayList(Rule) = .empty;
    for (pve.items(try c.get(try c.nodePath("/qemu/{d}/firewall/rules", .{vm.vmid})))) |r| {
        try rules.append(a, .{
            .type = try fieldText(a, r, "type"),
            .action = try fieldText(a, r, "action"),
            .macro = try fieldText(a, r, "macro"),
            .source = try fieldText(a, r, "source"),
            .dest = try fieldText(a, r, "dest"),
            .proto = try fieldText(a, r, "proto"),
            .dport = try fieldText(a, r, "dport"),
            .comment = try fieldText(a, r, "comment"),
        });
    }
    hs.rules = rules.items;
    for (pve.items(try c.get(try c.nodePath("/qemu/{d}/firewall/ipset", .{vm.vmid})))) |set| {
        if (!std.mem.eql(u8, pve.str(set, "name") orelse "", "ipfilter-net0")) continue;
        hs.ipset_exists = true;
        const entries = pve.items(try c.get(try c.nodePath("/qemu/{d}/firewall/ipset/ipfilter-net0", .{vm.vmid})));
        hs.ipset_ok = entries.len == 1 and std.mem.eql(u8, pve.str(entries[0], "cidr") orelse "", hs.address);
    }
    return hs;
}

pub fn hostSteps(want: []const Rule, hs: HostState) HostSteps {
    const same = hs.rules.len == want.len and for (hs.rules, want) |h, w| {
        if (!h.eql(w)) break false;
    } else true;
    return .{ .rules = !same, .ipset = !hs.ipset_ok, .nic = !hs.nic_ok, .options = !hs.options_ok };
}

/// Rules, IP set and NIC first; the options (enable, DROP policies) last,
/// so the VM is never filtered by a half-written rule set.
pub fn applyHost(c: *pve.Client, vm: vms.Vm, want: []const Rule, hs: HostState, h: HostSteps) !void {
    const a = c.ctx.arena;
    const id = vm.vmid;
    if (h.rules) {
        var n = hs.rules.len;
        while (n > 0) : (n -= 1) _ = try c.send(.DELETE, try c.nodePath("/qemu/{d}/firewall/rules/0", .{id}), &.{});
        // Proxmox inserts new rules at the top: add them last to first.
        var i = want.len;
        while (i > 0) {
            i -= 1;
            const r = want[i];
            var params: std.ArrayList(pve.Param) = .empty;
            try params.appendSlice(a, &.{ .{ .name = "type", .value = r.type }, .{ .name = "action", .value = r.action }, .{ .name = "enable", .value = "1" }, .{ .name = "comment", .value = r.comment } });
            inline for (.{ "macro", "source", "dest", "proto", "dport" }) |f| {
                if (@field(r, f).len > 0) try params.append(a, .{ .name = f, .value = @field(r, f) });
            }
            _ = try c.send(.POST, try c.nodePath("/qemu/{d}/firewall/rules", .{id}), params.items);
        }
    }
    if (h.ipset) {
        if (hs.ipset_exists) _ = try c.send(.DELETE, try c.nodePath("/qemu/{d}/firewall/ipset/ipfilter-net0?force=1", .{id}), &.{});
        _ = try c.send(.POST, try c.nodePath("/qemu/{d}/firewall/ipset", .{id}), &.{ .{ .name = "name", .value = "ipfilter-net0" }, .{ .name = "comment", .value = "artoo: the VM's only source address" } });
        _ = try c.send(.POST, try c.nodePath("/qemu/{d}/firewall/ipset/ipfilter-net0", .{id}), &.{.{ .name = "cidr", .value = hs.address }});
    }
    if (h.nic) {
        const cfg = try vms.config(c, id);
        _ = try c.send(.PUT, try c.nodePath("/qemu/{d}/config", .{id}), &.{
            .{ .name = "net0", .value = try std.fmt.allocPrint(a, "{s},firewall=1", .{hs.net0}) },
            .{ .name = "digest", .value = pve.str(cfg, "digest") orelse "" },
        });
    }
    if (h.options) {
        var params: std.ArrayList(pve.Param) = .empty;
        for (host_options) |o| try params.append(a, .{ .name = o[0], .value = o[1] });
        _ = try c.send(.PUT, try c.nodePath("/qemu/{d}/firewall/options", .{id}), params.items);
    }
}

// ---------------------------------------------------------------- setup

const Steps = struct {
    /// Files whose content differs.
    write: []const files.File = &.{},
    sysctl: bool = false,
    firewall: bool = false,
    tailscale: bool = false,
    cloudflared: bool = false,
    account: bool = false,
    build: bool = false,
    service: bool = false,
    /// cloudflared's unit changed: reload, restart when the tunnel runs.
    tunnel_service: bool = false,

    fn any(s: Steps) bool {
        return s.write.len > 0 or s.sysctl or s.firewall or s.tailscale or s.cloudflared or s.account or s.build or s.service or s.tunnel_service;
    }
};

pub fn plannedSteps(a: std.mem.Allocator, managed: []const files.File, st: State) !Steps {
    var write: std.ArrayList(files.File) = .empty;
    var changed_sysctl = false;
    var changed_nft = false;
    var changed_caddy = false;
    var changed_cloudflared = false;
    var changed_apt = false;
    for (managed) |f| {
        const want = try files.sha256Hex(a, f.content);
        if (std.mem.eql(u8, st.hashes.get(f.path) orelse "-", want)) continue;
        try write.append(a, f);
        if (std.mem.endsWith(u8, f.path, "90-artoo-edge.conf")) changed_sysctl = true;
        if (std.mem.eql(u8, f.path, "/etc/nftables.conf")) changed_nft = true;
        if (std.mem.startsWith(u8, f.path, "/etc/caddy/") or std.mem.endsWith(u8, f.path, "/caddy.service")) changed_caddy = true;
        if (std.mem.endsWith(u8, f.path, "/cloudflared.service")) changed_cloudflared = true;
        if (std.mem.startsWith(u8, f.path, "/etc/apt/") or std.mem.startsWith(u8, f.path, "/usr/share/keyrings/")) changed_apt = true;
    }
    const built = std.mem.eql(u8, st.caddy, files.caddy_version) and st.caddy_module;
    return .{
        .write = write.items,
        .sysctl = changed_sysctl,
        .firewall = changed_nft or !st.nft_loaded or !st.nft_enabled,
        .tailscale = st.tailscale,
        .cloudflared = !st.cloudflared or changed_apt,
        .account = !st.caddy_user or !st.cloudflared_user,
        .build = !built or st.golang,
        .service = changed_caddy or !built or (st.dns_secret and !st.caddy_active),
        .tunnel_service = changed_cloudflared,
    };
}

const SetupOp = struct {
    c: *pve.Client,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: vms.Vm = undefined,
    managed: []const files.File = &.{},
    state: State = .{},
    steps: Steps = .{},
    host: HostState = .{},
    host_rules: []const Rule = &.{},
    host_steps: HostSteps = .{},
    ledger: exec.Ledger = .{},
    fp: []const u8 = "",

    pub fn read(op: *SetupOp, ctx: *Context) !void {
        op.vm = try edgeVm(ctx, op.c);
        op.target = op.vm.name;
        const ad = try addresses(ctx);
        op.managed = try files.all(ctx.arena, ad, try appsDomain(ctx));
        op.state = try probe(op.c, op.vm.vmid, op.managed);
        op.steps = try plannedSteps(ctx.arena, op.managed, op.state);
        op.host_rules = try ctx.arena.dupe(Rule, &hostRules(ad));
        op.host = try readHost(op.c, op.vm);
        op.host_steps = hostSteps(op.host_rules, op.host);
        op.fp = try std.fmt.allocPrint(ctx.arena, "{s}|{s}|{}{}{}{}", .{ op.state.raw, op.host.net0, op.host_steps.rules, op.host_steps.ipset, op.host_steps.nic, op.host_steps.options });
    }

    pub fn plan(op: *SetupOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const s = op.steps;
        const h = op.host_steps;
        if (!s.any() and !h.any()) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        for (s.write) |f| try changes.append(a, .{ .field = "file", .from = if (std.mem.eql(u8, op.state.hashes.get(f.path) orelse "-", "-")) null else "differs", .to = f.path });
        if (s.sysctl) try changes.append(a, .{ .field = "kernel", .from = null, .to = "network hardening sysctls applied" });
        if (s.firewall) try changes.append(a, .{ .field = "firewall", .from = if (op.state.nft_loaded) "loaded" else null, .to = "nftables policy loaded and enabled (SSH only from Proxmox)" });
        if (s.tailscale) try changes.append(a, .{ .field = "tailscale", .from = "installed", .to = null });
        if (s.cloudflared) try changes.append(a, .{ .field = "cloudflared", .from = if (op.state.cloudflared) "installed" else null, .to = "from Cloudflare's signed repository" });
        if (s.account) try changes.append(a, .{ .field = "account", .from = null, .to = "system users caddy and cloudflared, /var/lib/caddy, /var/log/caddy, /etc/cloudflared" });
        if (s.build) try changes.append(a, .{ .field = "caddy", .from = if (std.mem.eql(u8, op.state.caddy, "-")) null else op.state.caddy, .to = try std.fmt.allocPrint(a, "{s} + {s}@{s}, built from source (Go removed after)", .{ files.caddy_version, files.cloudflare_module, files.cloudflare_module_version }) });
        if (s.service) try changes.append(a, .{ .field = "service", .from = null, .to = if (op.state.dns_secret) "caddy (re)started" else "caddy installed, starts after 'artoo edge secret dns'" });
        if (s.tunnel_service) try changes.append(a, .{ .field = "tunnel", .from = null, .to = if (op.state.cloudflared_active) "cloudflared restarted with its new unit" else "cloudflared unit loaded; it starts with 'artoo edge tunnel'" });
        if (h.any()) try changes.append(a, .{
            .field = "host firewall",
            .from = if (op.host.options_ok and op.host.nic_ok) "differs" else null,
            .to = try std.fmt.allocPrint(a, "Proxmox VM firewall: {d} rules, only source {s}, MAC filter, DROP policies, NIC firewall=1", .{ op.host_rules.len, op.host.address }),
        });
        var notes: std.ArrayList([]const u8) = .empty;
        if (s.build) try notes.append(a, "The Caddy build takes several minutes (Go module downloads and compile).");
        try notes.append(a, "Commands run as root through the guest agent; steps stop at the first failure and re-running continues.");
        return .{
            .action = try std.fmt.allocPrint(a, "Set up edge VM {s} ({d})", .{ op.vm.name, op.vm.vmid }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{"The edge VM's firewall, packages and Caddy change, and its own Proxmox firewall rules on Proxmox; other guests and Proxmox's settings are untouched"}),
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
        const s_write = if (s.write.len > 0) try l.add(a, "write files") else null;
        const s_sysctl = if (s.sysctl) try l.add(a, "apply sysctls") else null;
        const s_fw = if (s.firewall) try l.add(a, "load firewall") else null;
        const s_ts = if (s.tailscale) try l.add(a, "remove tailscale") else null;
        const s_cfd = if (s.cloudflared) try l.add(a, "install cloudflared") else null;
        const s_acct = if (s.account) try l.add(a, "caddy account") else null;
        const s_build = if (s.build) try l.add(a, "build caddy") else null;
        const s_svc = if (s.service) try l.add(a, "caddy service") else null;
        const s_cfd_svc = if (s.tunnel_service) try l.add(a, "cloudflared unit") else null;
        const s_host = if (op.host_steps.any()) try l.add(a, "host firewall") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (s_write) |i| {
            l.set(i, .unknown, "");
            for (s.write) |f| try writeFile(c, id, f);
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} file(s)", .{s.write.len}));
        }
        if (s_sysctl) |i| {
            try run(c, id, "sysctl", "sysctl --system >/dev/null", step_timeout_ms);
            l.set(i, .done, "");
        }
        if (s_fw) |i| {
            l.set(i, .unknown, "");
            try run(c, id, "the firewall",
                \\set -e
                \\command -v nft >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y nftables
                \\nft -c -f /etc/nftables.conf
                \\systemctl enable nftables >/dev/null 2>&1
                \\nft -f /etc/nftables.conf
            , step_timeout_ms);
            l.set(i, .done, "inet artoo_edge");
        }
        if (s_ts) |i| {
            try run(c, id, "removing tailscale", "DEBIAN_FRONTEND=noninteractive apt-get purge -y tailscale >/dev/null && rm -f /etc/apt/sources.list.d/tailscale.list /etc/apt/cloud-init.gpg.d/tailscale.gpg", step_timeout_ms);
            l.set(i, .done, "");
        }
        if (s_cfd) |i| {
            l.set(i, .unknown, "");
            try run(c, id, "installing cloudflared", "set -e; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y cloudflared >/dev/null", step_timeout_ms);
            l.set(i, .done, "");
        }
        if (s_acct) |i| {
            try run(c, id, "the caddy account", files.caddy_prepare, step_timeout_ms);
            l.set(i, .done, "");
        }
        if (s_build) |i| {
            l.set(i, .unknown, "");
            try runWatched(c, id, "the Caddy build", files.build_script, build_timeout_ms, .{ .file = files.build_stage_file, .note = l.noter(i) });
            l.set(i, .done, files.caddy_version);
        }
        if (s_svc) |i| {
            l.set(i, .unknown, "");
            try run(c, id, "the caddy service",
                \\set -e
                \\systemctl daemon-reload
                \\if test -e /etc/caddy/cloudflare.env; then systemctl enable caddy >/dev/null 2>&1; systemctl restart caddy; fi
            , step_timeout_ms);
            l.set(i, .done, if (op.state.dns_secret) "restarted" else "waits for 'edge secret dns'");
        }
        if (s_cfd_svc) |i| {
            l.set(i, .unknown, "");
            try run(c, id, "the cloudflared unit",
                \\set -e
                \\systemctl daemon-reload
                \\if test -e /etc/cloudflared/tunnel.env; then systemctl enable cloudflared >/dev/null 2>&1; systemctl restart cloudflared; fi
            , step_timeout_ms);
            l.set(i, .done, if (op.state.cloudflared_active) "restarted" else "loaded");
        }
        if (s_host) |i| {
            l.set(i, .unknown, "");
            try applyHost(c, op.vm, op.host_rules, op.host, op.host_steps);
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} rules on Proxmox", .{op.host_rules.len}));
        }
    }

    pub fn verify(op: *SetupOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const after = try probe(op.c, op.vm.vmid, op.managed);
        const left = try plannedSteps(ctx.arena, op.managed, after);
        const host_left = hostSteps(op.host_rules, try readHost(op.c, op.vm));
        return op.ledger.complete() and !left.any() and !host_left.any();
    }

    pub fn done(op: *SetupOp) []const u8 {
        const next = if (op.state.dns_secret) "'artoo edge status' to check" else "next: 'artoo edge secret dns' (once), then 'artoo edge status'";
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} set up — {s}", .{ op.vm.name, next }) catch "done";
    }
};

pub const setup = struct {
    pub const name = "setup";
    pub const summary = "Harden and configure the edge VM (idempotent)";
    pub const details =
        \\Brings the VM tagged role-edge to SPEC §9.7: kernel hardening, the
        \\nftables policy (SSH only from Proxmox; no route to Proxmox or UniFi's
        \\other ports or the LAN beyond the guest pool), Tailscale removed,
        \\cloudflared from Cloudflare's signed repository, Caddy built from
        \\pinned sources with the Cloudflare DNS module, its sandboxed service
        \\and Caddyfile, and the same policy as the VM's Proxmox firewall on Proxmox
        \\(rules, source-address and MAC filter, NIC firewall=1) — which root
        \\inside the VM cannot change. Only the steps the observed state needs are
        \\planned.
    ;
    pub const examples = [_][]const u8{ "artoo edge setup -n", "artoo edge setup -y" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SetupOp = .{ .c = &c };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- secret

const SecretOp = struct {
    c: *pve.Client,
    value: []const u8,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: vms.Vm = undefined,
    replacing: bool = false,
    caddy_active: bool = false,

    pub fn read(op: *SecretOp, ctx: *Context) !void {
        op.vm = try edgeVm(ctx, op.c);
        op.target = op.vm.name;
        const st = try probe(op.c, op.vm.vmid, &.{});
        if (!st.caddy_user or !std.mem.eql(u8, st.caddy, files.caddy_version))
            return ctx.fail(error.Refused, "{s} is not set up yet; run 'artoo edge setup' first", .{op.vm.name});
        op.replacing = st.dns_secret;
    }

    pub fn plan(op: *SecretOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        return .{
            .action = try std.fmt.allocPrint(a, "Store the edge DNS-01 token on {s}", .{op.vm.name}),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{
                .{ .field = "secret", .from = if (op.replacing) "(hidden)" else null, .to = "(hidden) → /etc/caddy/cloudflare.env, 0640 root:caddy" },
                .{ .field = "service", .from = null, .to = "caddy enabled and restarted; it requests *.apps certificate" },
            }),
            .impact = try a.dupe([]const u8, &.{"The token exists only on the edge VM (and in Cloudflare); artoo keeps no copy"}),
        };
    }

    pub fn fingerprint(op: *SecretOp) []const u8 {
        return if (op.replacing) "replace" else "new";
    }

    pub fn send(op: *SecretOp, ctx: *Context) !void {
        const content = try std.fmt.allocPrint(ctx.arena, "CF_API_TOKEN={s}\n", .{op.value});
        try writeFile(op.c, op.vm.vmid, .{ .path = "/etc/caddy/cloudflare.env", .mode = "0640", .owner = "root:caddy", .content = content });
        try run(op.c, op.vm.vmid, "starting caddy", "set -e; systemctl daemon-reload; systemctl enable caddy >/dev/null 2>&1; systemctl restart caddy", step_timeout_ms);
    }

    pub fn verify(op: *SecretOp, _: *Context) !bool {
        const st = try probe(op.c, op.vm.vmid, &.{});
        op.caddy_active = st.caddy_active;
        return st.dns_secret and st.caddy_active;
    }

    pub fn done(_: *SecretOp) []const u8 {
        return "token stored on the edge VM; caddy is running — 'artoo edge status' shows the certificate";
    }
};

pub const secret = struct {
    pub const name = "secret";
    pub const summary = "Store a token on the edge VM only (hidden prompt or --stdin)";
    pub const details =
        \\dns: the edge's own Cloudflare account token (Specified Domains →
        \\example.com; DNS Edit + Zone Read) for the *.apps wildcard via DNS-01.
        \\The value goes over the guest agent's stdin into a root-only file;
        \\artoo never stores, prints or logs it (SPEC §9.7).
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "KIND", .help = "dns" }};
    pub const flags = [_]cli.Flag{.{ .long = "stdin", .help = "Read the token from standard input" }};
    pub const examples = [_][]const u8{"artoo edge secret dns"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        if (!std.mem.eql(u8, args.pos("KIND"), "dns")) return ctx.fail(error.Usage, "KIND must be dns (the tunnel token arrives with the tunnel, SPEC §15)", .{});
        const value = if (args.has("stdin"))
            try prompt.readAll(ctx.input, ctx.io, ctx.arena, 4096)
        else blk: {
            if (!try prompt.interactive(ctx.input, ctx.io)) return ctx.fail(error.NonInteractive, "not a terminal: pipe the token with --stdin", .{});
            break :blk try prompt.askHidden(ctx.input, ctx.io, ctx.arena, ctx.err, "Edge DNS-01 token");
        };
        if (!secrets.validSecret(value)) return ctx.fail(error.Usage, "the token must be one line of 1-4096 printable characters", .{});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SecretOp = .{ .c = &c, .value = value };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- tunnel

const cloudflared_unit_file: files.File = .{ .path = "/etc/systemd/system/cloudflared.service", .mode = "0644", .owner = "root:root", .content = files.cloudflared_unit };

const TunnelOp = struct {
    c: *pve.Client,
    cfc: *cf.Client,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .cloudflare,
    target: []const u8 = "",
    vm: vms.Vm = undefined,
    state: State = .{},
    tunnel: ?tunnels.Tunnel = null,
    create: bool = false,
    write_token: bool = false,
    start: bool = false,
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},
    connections: usize = 0,

    pub fn read(op: *TunnelOp, ctx: *Context) !void {
        const cfg = try ctx.config();
        op.target = cfg.cloudflare.tunnel;
        op.vm = try edgeVm(ctx, op.c);
        op.state = try probe(op.c, op.vm.vmid, &.{cloudflared_unit_file});
        const unit_ok = std.mem.eql(u8, op.state.hashes.get(cloudflared_unit_file.path) orelse "-", try files.sha256Hex(ctx.arena, files.cloudflared_unit));
        if (!op.state.cloudflared or !op.state.cloudflared_user or !unit_ok)
            return ctx.fail(error.Refused, "{s} is not ready for the tunnel (cloudflared, its user and unit); run 'artoo edge setup' first", .{op.vm.name});
        op.tunnel = try tunnels.find(op.cfc, op.target);
        op.fp = try std.fmt.allocPrint(ctx.arena, "{s}|{s}", .{ op.state.raw, if (op.tunnel) |t| t.id else "absent" });
    }

    pub fn plan(op: *TunnelOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        op.create = op.tunnel == null;
        op.write_token = op.create or !std.mem.eql(u8, op.state.tunnel_id, op.tunnel.?.id);
        op.start = op.write_token or !op.state.cloudflared_active;
        if (!op.create and !op.write_token and !op.start) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (op.create) try changes.append(a, .{ .field = "tunnel", .from = null, .to = try std.fmt.allocPrint(a, "{s}, remotely managed (Cloudflare account of {s})", .{ op.target, op.cfc.zone_name }) });
        if (op.write_token) try changes.append(a, .{
            .field = "token",
            .from = if (std.mem.eql(u8, op.state.tunnel_id, "-")) null else "(hidden, another tunnel)",
            .to = try std.fmt.allocPrint(a, "(hidden) → /etc/cloudflared/tunnel.env on {s}, 0640 root:cloudflared", .{op.vm.name}),
        });
        if (op.start) try changes.append(a, .{ .field = "service", .from = if (op.state.cloudflared_active) "running" else null, .to = "cloudflared enabled and (re)started" });
        return .{
            .action = try std.fmt.allocPrint(a, "Connect {s} to Cloudflare Tunnel {s}", .{ op.vm.name, op.target }),
            .target = try std.fmt.allocPrint(a, "Cloudflare account ({s}) + edge VM {s} ({d})", .{ op.cfc.zone_name, op.vm.name, op.vm.vmid }),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{"An outbound-only connection from the edge VM to Cloudflare; nothing is public until 'artoo cf tunnel route add'"}),
            .notes = try a.dupe([]const u8, &.{"The token goes from Cloudflare's API straight to the VM: never displayed, logged or stored on this Mac."}),
        };
    }

    pub fn fingerprint(op: *TunnelOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *TunnelOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const s_create = if (op.create) try l.add(a, "create tunnel") else null;
        const s_token = if (op.write_token) try l.add(a, "deliver token") else null;
        const s_start = if (op.start) try l.add(a, "start cloudflared") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (s_create) |i| {
            l.set(i, .unknown, "");
            op.tunnel = try tunnels.create(op.cfc, op.target);
            l.set(i, .done, op.tunnel.?.id);
        }
        if (s_token) |i| {
            l.set(i, .unknown, "");
            const tok = try tunnels.token(op.cfc, op.tunnel.?.id);
            const content = try std.fmt.allocPrint(a, "TUNNEL_TOKEN={s}\n", .{tok});
            try writeFile(op.c, op.vm.vmid, .{ .path = "/etc/cloudflared/tunnel.env", .mode = "0640", .owner = "root:cloudflared", .content = content });
            l.set(i, .done, "/etc/cloudflared/tunnel.env");
        }
        if (s_start) |i| {
            l.set(i, .unknown, "");
            try run(op.c, op.vm.vmid, "starting cloudflared", "set -e; systemctl daemon-reload; systemctl enable cloudflared >/dev/null 2>&1; systemctl restart cloudflared", step_timeout_ms);
            l.set(i, .done, "");
        }
    }

    /// The tunnel reports connections once cloudflared registered (bounded).
    pub fn verify(op: *TunnelOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const id = op.tunnel.?.id;
        var tries: usize = 0;
        while (tries < 15) : (tries += 1) {
            op.connections = (try tunnels.get(op.cfc, id)).connections;
            if (op.connections > 0) break;
            try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 2000)), .awake);
        }
        const st = try probe(op.c, op.vm.vmid, &.{});
        return op.connections > 0 and st.cloudflared_active and std.mem.eql(u8, st.tunnel_id, id);
    }

    pub fn done(op: *TunnelOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} runs tunnel {s} ({d} connection(s)) — public names: 'artoo cf tunnel route add HOST SERVICE'", .{ op.vm.name, op.target, op.connections }) catch "done";
    }
};

pub const tunnel = struct {
    pub const name = "tunnel";
    pub const summary = "Create the lab's Cloudflare Tunnel and connect the edge VM (idempotent)";
    pub const details =
        \\Creates the remotely managed tunnel cloudflare.tunnel when it does not
        \\exist, fetches its token from Cloudflare and writes it through the guest
        \\agent into a root-only file on the edge VM, then starts cloudflared
        \\under artoo's sandboxed unit. The token is never displayed, logged or
        \\stored on this Mac (SPEC §9.7). Needs 'artoo edge setup' first.
    ;
    pub const examples = [_][]const u8{ "artoo edge tunnel -n", "artoo edge tunnel -y" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var cfc = try cf.Client.open(ctx);
        defer cfc.deinit();
        var op: TunnelOp = .{ .c = &c, .cfc = &cfc };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- status

const status_script =
    \\nft -j list counters table inet artoo_edge 2>/dev/null || echo '{}'
    \\echo '---'
    \\c=$(find /var/lib/caddy -name '*.crt' -path '*wildcard_*' 2>/dev/null | head -1)
    \\if [ -n "$c" ]; then openssl x509 -noout -subject -enddate -in "$c" 2>/dev/null; else echo "nocert"; fi
    \\echo '---'
    \\systemctl is-active cloudflared 2>/dev/null || true
    \\echo '---'
    \\journalctl -u ssh --since -24h -q 2>/dev/null | grep -cE 'Failed|Invalid user' || true
    \\
;

pub const Check = vm_new.Check;

/// Named counter packets from `nft -j list counters`.
pub fn counter(a: std.mem.Allocator, json: []const u8, want: []const u8) ?i64 {
    const v = std.json.parseFromSliceLeaky(Value, a, json, .{}) catch return null;
    const items = pve.items(pve.obj(v, "nftables"));
    for (items) |it| {
        const cn = pve.obj(it, "counter");
        if (cn == .null) continue;
        if (std.mem.eql(u8, pve.str(cn, "name") orelse "", want)) return pve.int(cn, "packets");
    }
    return null;
}

pub const status = struct {
    pub const name = "status";
    pub const summary = "The edge VM's health and signs of compromise (read-only)";
    pub const details =
        \\Drop counters towards Proxmox and UniFi first (any hit is a sign of
        \\compromise), then the firewall, Caddy and its module, the wildcard
        \\certificate, cloudflared, failed SSH logins (24 h) and pending reboot.
    ;
    pub const examples = [_][]const u8{ "artoo edge status", "artoo edge status -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const h = try health(ctx, &c);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, h, .{ .collected_at = ctx.ui.now });
        try k.header(ctx, &c);
        try vm_new.renderChecks(ctx, h.checks);
        const failed = vm_new.failures(h.checks);
        if (failed > 0) return ctx.fail(error.Partial, "{d} check(s) failed on {s}", .{ failed, h.vm });
    }
};

/// The edge VM's checks, drop counters first (`edge status`, `status`).
pub const Health = struct { vm: []const u8, checks: []const Check };

pub fn health(ctx: *Context, c: *pve.Client) !Health {
    return healthOf(ctx, c, try edgeVm(ctx, c));
}

/// `health` for an edge VM already found with `edgeVm`.
pub fn healthOf(ctx: *Context, c: *pve.Client, v: vms.Vm) !Health {
    const a = ctx.arena;
    const st = try probe(c, v.vmid, &.{});
    const r = try agent.sh(c, v.vmid, status_script, 60_000);
    var parts = std.mem.splitSequence(u8, r.out, "---\n");
    const counters = parts.next() orelse "";
    const cert = std.mem.trim(u8, parts.next() orelse "", " \n");
    const cfd = std.mem.trim(u8, parts.next() orelse "", " \n");
    const ssh_fail = std.mem.trim(u8, parts.next() orelse "", " \n");
    var checks: std.ArrayList(Check) = .empty;
    for ([_]struct { []const u8, []const u8 }{ .{ "to Proxmox", "to_pve" }, .{ "to UniFi", "to_gateway" }, .{ "to the LAN", "to_lan" } }) |p| {
        const n = counter(a, counters, p[1]);
        try checks.append(a, if (n) |hits| .{
            .name = try std.fmt.allocPrint(a, "drops {s}", .{p[0]}),
            .status = if (hits == 0) .ok else .failed,
            .detail = if (hits == 0) "none" else try std.fmt.allocPrint(a, "{d} packet(s) blocked — investigate", .{hits}),
        } else .{ .name = try std.fmt.allocPrint(a, "drops {s}", .{p[0]}), .status = .failed, .detail = "counter missing (firewall not loaded?)" });
    }
    const hs = try readHost(c, v);
    const hsteps = hostSteps(&hostRules(try addresses(ctx)), hs);
    try checks.append(a, .{ .name = "host firewall", .status = if (hsteps.any()) .failed else .ok, .detail = if (hsteps.any()) "differs from SPEC §9.7 — run 'artoo edge setup'" else "Proxmox VM firewall as designed (on Proxmox)" });
    try checks.append(a, .{ .name = "firewall", .status = if (st.nft_loaded and st.nft_enabled) .ok else .failed, .detail = if (st.nft_loaded) (if (st.nft_enabled) "loaded, enabled" else "loaded, not enabled at boot") else "not loaded" });
    const pinned = std.mem.eql(u8, st.caddy, files.caddy_version);
    try checks.append(a, .{ .name = "caddy", .status = if (pinned and st.caddy_module) .ok else .failed, .detail = try std.fmt.allocPrint(a, "{s}{s}, {s}", .{ st.caddy, if (st.caddy_module) " + cloudflare" else " (no cloudflare module)", if (st.caddy_active) "running" else "not running" }) });
    try checks.append(a, .{ .name = "certificate", .status = if (std.mem.eql(u8, cert, "nocert")) .failed else .ok, .detail = if (std.mem.eql(u8, cert, "nocert")) (if (st.dns_secret) "not issued yet" else "needs 'artoo edge secret dns'") else try k.clean(ctx, try std.mem.replaceOwned(u8, a, cert, "\n", "; ")) });
    try checks.append(a, .{ .name = "cloudflared", .status = if (st.cloudflared) .ok else .failed, .detail = if (!st.cloudflared) "not installed" else if (std.mem.eql(u8, cfd, "active")) "connected (service active)" else "installed; tunnel not configured yet (SPEC §15)" });
    try checks.append(a, .{ .name = "tailscale removed", .status = if (st.tailscale) .failed else .ok, .detail = if (st.tailscale) "still installed" else "" });
    try checks.append(a, .{ .name = "failed SSH (24 h)", .status = if (ssh_fail.len == 0 or std.mem.eql(u8, ssh_fail, "0")) .ok else .warning, .detail = if (ssh_fail.len == 0) "0" else try k.clean(ctx, ssh_fail) });
    try checks.append(a, .{ .name = "reboot pending", .status = if (st.reboot) .warning else .ok, .detail = if (st.reboot) "yes — reboot when convenient" else "no" });
    return .{ .vm = v.name, .checks = checks.items };
}

pub const group = cli.group("edge", "The edge VM: hardened HTTPS and tunnel endpoint (SPEC §9.7)", &.{
    cli.leaf(setup),
    cli.leaf(secret),
    cli.leaf(tunnel),
    cli.leaf(status),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "plannedSteps: a fresh VM needs everything; a converged one nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const managed = try files.all(a, .{ .pve = "192.168.1.10", .gateway = "192.168.1.1", .lan = "192.168.1.0/24", .pool = "192.168.1.200-192.168.1.254" }, "apps.lab.example.com");
    const fresh = try parseState(a, "caddy -\ncaddymod no\npkg tailscale yes\npkg cloudflared no\nnft no\nnftenabled no\ncaddyuser no\ndnssecret no\ncaddyactive no\nreboot no\n");
    const s = try plannedSteps(a, managed, fresh);
    try testing.expectEqual(managed.len, s.write.len);
    try testing.expect(s.sysctl and s.firewall and s.tailscale and s.cloudflared and s.account and s.build and s.service);

    var out: std.ArrayList(u8) = .empty;
    for (managed) |f| try out.print(a, "file {s} {s}\n", .{ f.path, try files.sha256Hex(a, f.content) });
    try out.print(a, "caddy {s}\ncaddymod yes\npkg tailscale no\npkg cloudflared yes\npkg {s} no\nnft yes\nnftenabled yes\ncaddyuser yes\ncfduser yes\ndnssecret yes\ncaddyactive yes\nreboot no\n", .{ files.caddy_version, files.go_package });
    const done_state = try parseState(a, out.items);
    try testing.expect(!(try plannedSteps(a, managed, done_state)).any());
}

test "writeFile: a part's base64 stays under Proxmox's 65536-character input cap" {
    try testing.expect(std.base64.standard.Encoder.calcSize(files.part_bytes) < 65536);
    try testing.expect(std.mem.find(u8, files.write_part, "base64 -d >> \"$p\"") != null);
    try testing.expect(std.mem.find(u8, files.write_finish, "mv -f \"$p\" \"$1\"") != null);
}

test "counter: named counters from nft -j" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const json =
        \\{"nftables":[{"metainfo":{"version":"1.1.3"}},{"counter":{"family":"inet","name":"to_pve","table":"artoo_edge","handle":1,"packets":0,"bytes":0}},{"counter":{"family":"inet","name":"to_lan","table":"artoo_edge","handle":3,"packets":4,"bytes":240}}]}
    ;
    try testing.expectEqual(@as(?i64, 0), counter(arena.allocator(), json, "to_pve"));
    try testing.expectEqual(@as(?i64, 4), counter(arena.allocator(), json, "to_lan"));
    try testing.expect(counter(arena.allocator(), json, "to_gateway") == null);
}

test "edge setup -n: finds the role-edge VM, probes once, plans every step, writes nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fresh = "caddy -\ncaddymod no\npkg tailscale yes\npkg cloudflared no\npkg golang-1.26-go no\nnft no\nnftenabled no\ncaddyuser no\ndnssecret no\ncaddyactive no\nreboot no\n";
    const status_body = try std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = fresh, .@"err-data" = "" } }, .{});
    const testkit = @import("../testkit.zig");
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;ssh-jump\"},{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"}]}" } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = status_body } },
        .{ .respond = .{ .body = "{\"data\":{\"net0\":\"virtio=BC:24:11:AB:CD:EF,bridge=vmbr0\",\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\",\"digest\":\"d1\"}}" } },
        .{ .respond = .{ .body = "{\"data\":{}}" } },
        .{ .respond = .{ .body = "{\"data\":[]}" } },
        .{ .respond = .{ .body = "{\"data\":[]}" } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "edge setup -n"));
    try testing.expectEqual(@as(usize, 8), g.sent());
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/qemu/200/firewall/rules HTTP/1.1", g.request(6));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/200/agent/exec HTTP/1.1", g.request(2));
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Set up edge VM bespin (200)",
        "file           (none) → /etc/nftables.conf",
        "firewall       (none) → nftables policy loaded and enabled (SSH only from Proxmox)",
        "tailscale      installed → (removed)",
        "caddy          (none) → v2.11.7 + github.com/caddy-dns/cloudflare@v0.2.4, built from source (Go removed after)",
        "host firewall  (none) → Proxmox VM firewall: 16 rules, only source 192.168.1.200, MAC filter, DROP policies, NIC firewall=1",
        "Dry run: nothing was sent.",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "hostRules: Proxmox and UniFi are dropped before any outbound accept; SSH in only from Proxmox" {
    const rules = hostRules(.{ .pve = "192.168.1.10", .gateway = "192.168.1.1", .lan = "192.168.1.0/24", .pool = "192.168.1.200-192.168.1.254" });
    var first_out_accept: ?usize = null;
    var pve_drop: ?usize = null;
    for (rules, 0..) |r, i| {
        if (std.mem.eql(u8, r.type, "out") and std.mem.eql(u8, r.action, "ACCEPT") and first_out_accept == null and !std.mem.eql(u8, r.dport, "53")) first_out_accept = i;
        if (std.mem.eql(u8, r.type, "out") and std.mem.eql(u8, r.dest, "192.168.1.10")) pve_drop = i;
        if (std.mem.eql(u8, r.type, "in") and std.mem.eql(u8, r.dport, "22")) try testing.expectEqualStrings("192.168.1.10", r.source);
    }
    try testing.expect(pve_drop.? < first_out_accept.?);
    try testing.expectEqualStrings("DROP", rules[rules.len - 1].action);
}

test "edge tunnel -y: creates the tunnel, token straight to the VM, never in the output" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const testkit = @import("../testkit.zig");
    const ok = struct {
        fn agent(al: std.mem.Allocator, out: []const u8) ![]const u8 {
            return std.json.Stringify.valueAlloc(al, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
        }
    };
    const unit_line = try std.fmt.allocPrint(a, "file /etc/systemd/system/cloudflared.service {s}\n", .{try files.sha256Hex(a, files.cloudflared_unit)});
    const before = try std.fmt.allocPrint(a, "{s}caddy v2.11.7\npkg cloudflared yes\ncfduser yes\ntunnelid -\ncfdactive no\n", .{unit_line});
    const pid = "{\"data\":{\"pid\":42}}";
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"}]}" } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try ok.agent(a, before) } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":[{\"id\":\"Z1\",\"name\":\"example.com\",\"account\":{\"id\":\"A1\"}}],\"result_info\":{\"count\":1,\"total_count\":1}}" } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":[],\"result_info\":{\"count\":0,\"total_count\":0}}" } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":{\"id\":\"T1\",\"name\":\"bespin\",\"status\":\"inactive\"}}" } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":\"SECRETTOKEN\"}" } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try ok.agent(a, "") } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try ok.agent(a, "") } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"result\":{\"id\":\"T1\",\"name\":\"bespin\",\"status\":\"healthy\",\"connections\":[{}]}}" } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try ok.agent(a, "pkg cloudflared yes\ncfduser yes\ntunnelid T1\ncfdactive yes\n") } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "edge tunnel -y"));
    try testing.expectEqual(@as(usize, 15), g.sent());
    try testing.expectEqualStrings("POST /accounts/A1/cfd_tunnel HTTP/1.1", g.request(6));
    try testing.expectEqualStrings("{\"name\":\"lab\",\"config_src\":\"cloudflare\"}", g.body(6));
    try testing.expectEqualStrings("GET /accounts/A1/cfd_tunnel/T1/token HTTP/1.1", g.request(7));
    // The token travels base64-encoded as the agent's stdin, nowhere else.
    const enc = std.base64.standard.Encoder;
    const b64 = try a.alloc(u8, enc.calcSize("TUNNEL_TOKEN=SECRETTOKEN\n".len));
    _ = enc.encode(b64, "TUNNEL_TOKEN=SECRETTOKEN\n");
    const form = try pve.form(a, &.{.{ .name = "input-data", .value = b64 }});
    try testing.expect(std.mem.find(u8, g.body(8), form) != null);
    try testing.expect(std.mem.find(u8, g.h.stdout(), "SECRETTOKEN") == null);
    try testing.expect(std.mem.find(u8, g.h.stderr(), "SECRETTOKEN") == null);
    try testing.expect(std.mem.find(u8, g.h.stdout(), "bespin runs tunnel lab (1 connection(s))") != null);
}
