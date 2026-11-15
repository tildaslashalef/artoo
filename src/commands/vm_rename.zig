//! `artoo vm rename OLD NEW` (SPEC §9.18): a guest's name is also its
//! hostname, its UniFi client record and DNS record, its pinned host key
//! and ssh_config block, its password entry, the service upstreams and
//! fence exceptions that name it, its tailnet name and the watchdog's
//! series. Every place is one ledger step that looks at observed state
//! first, so a run that stopped half way is continued by running the same
//! command again (the VM is then found under NEW).

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const config_cmd = @import("config.zig");
const exec = @import("../exec.zig");
const exposure = @import("../exposure.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const unifi = @import("../unifi/client.zig");
const dns = @import("../unifi/dns.zig");
const classic = @import("../unifi/classic.zig");
const names = @import("../guest/names.zig");
const known_hosts = @import("../guest/known_hosts.zig");
const vm_ssh = @import("vm_ssh.zig");
const vm_cmd = @import("vm.zig");
const life = @import("vm_life.zig");
const template = @import("template.zig");
const svc = @import("svc.zig");
const edge = @import("edge.zig");
const vm_fence = @import("vm_fence.zig");
const watch = @import("watch.zig");
const ts_cmd = @import("ts.zig");
const tsapi = @import("../tailscale/client.zig");
const tn = @import("../tailscale/tailnet.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

/// Hostname and `/etc/hosts` (fields equal to `$2`, or starting `$2.`,
/// become `$1`/`$1.…`; comments and other lines kept byte for byte).
const guest_script =
    \\set -eu
    \\hostnamectl set-hostname "$1"
    \\awk -v new="$1" -v old="$2" '/^[[:space:]]*#/ || NF < 2 { print; next }
    \\{ for (i = 2; i <= NF; i++) { if ($i == old) $i = new; else if (index($i, old ".") == 1) $i = new substr($i, length(old) + 1) } print }' /etc/hosts > /etc/hosts.artoo-new
    \\cat /etc/hosts.artoo-new > /etc/hosts
    \\rm -f /etc/hosts.artoo-new
    \\
;

const tailnet_script =
    \\set -eu
    \\tailscale set --hostname="$1"
    \\
;

/// What the guest's places hold now.
const Observed = struct {
    vm: vms.Vm,
    cfg: Value,
    digest: []const u8,
    mac: ?[]const u8,
    address: ?[]const u8,
    hostname: []const u8,
    hosts_old: bool,
    record: ?classic.Record,
    dns_old: ?dns.ARecord,
    dns_new: ?dns.ARecord,
    dns_note: ?[]const u8,
    secret_old: bool,
    secret_new: bool,
    key_old: ?[]const u8,
    key_new: ?[]const u8,
    ssh_old: bool,
    ssh_new: bool,
    edge_vm: ?vms.Vm,
    routes: []const svc.Route,
    fence_entries: usize,
    fenced: []const []const u8,
    on_tailnet: bool,
    ts_state: ?ts_cmd.GuestState,
    device: ?tn.Device,
    watch_vm: ?vms.Vm,
    old_series: usize,
    watch_note: ?[]const u8,
};

/// Which steps still have work.
const Pending = struct {
    proxmox: bool,
    guest: bool,
    unifi: bool,
    dns_add: bool,
    dns_rm: bool,
    secret: bool,
    ssh: bool,
    services: bool,
    fence: bool,
    tailnet: bool,
    watch: bool,

    fn any(p: Pending) bool {
        inline for (@typeInfo(Pending).@"struct".field_names) |n| if (@field(p, n)) return true;
        return false;
    }
};

fn hostsName(line: []const u8, name: []const u8) bool {
    const t = std.mem.trimStart(u8, line, " \t");
    if (t.len == 0 or t[0] == '#') return false;
    var it = std.mem.tokenizeAny(u8, t, " \t\r");
    _ = it.next() orelse return false;
    while (it.next()) |f| {
        if (std.mem.eql(u8, f, name)) return true;
        if (std.mem.startsWith(u8, f, name) and f.len > name.len and f[name.len] == '.') return true;
    }
    return false;
}

/// `/etc/hosts` has a line naming `name` (alone or as `name.…`).
pub fn hostsNames(text: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |l| if (hostsName(l, name)) return true;
    return false;
}

/// `guests.fence_allow_out` with every `VM` or `PEER` equal to `old`
/// renamed; null when nothing names it.
pub fn renameFenceList(a: std.mem.Allocator, s: []const u8, old: []const u8, new: []const u8) !?[]const u8 {
    const list = (try config.fenceAllows(a, s)) orelse return null;
    var hit = false;
    var out: std.ArrayList(u8) = .empty;
    for (list, 0..) |f, i| {
        const vm = if (std.mem.eql(u8, f.vm, old)) new else f.vm;
        const peer = if (std.mem.eql(u8, f.peer, old)) new else f.peer;
        hit = hit or vm.ptr != f.vm.ptr or peer.ptr != f.peer.ptr;
        try out.print(a, "{s}{s} {s} {s} {s}", .{ if (i > 0) "; " else "", vm, peer, f.proto, f.ports });
    }
    return if (hit) out.items else null;
}

const RenameOp = struct {
    c: *pve.Client,
    u: *unifi.Client,
    old: []const u8,
    new: []const u8,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    tsc: ?tsapi.Client = null,
    o: Observed = undefined,
    p: Pending = undefined,
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    fn observe(op: *RenameOp, ctx: *Context) !Observed {
        const a = ctx.arena;
        const cfg = try ctx.config();
        const list = try vms.list(op.c);
        var under_old: ?vms.Vm = null;
        var under_new: ?vms.Vm = null;
        var n_old: usize = 0;
        var n_new: usize = 0;
        for (list) |v| {
            if (std.ascii.eqlIgnoreCase(v.name, op.old)) {
                under_old = v;
                n_old += 1;
            }
            if (std.ascii.eqlIgnoreCase(v.name, op.new)) {
                under_new = v;
                n_new += 1;
            }
        }
        if (n_old > 1 or n_new > 1) return ctx.fail(error.Refused, "more than one VM is named {s}; rename them by VMID with 'artoo vm set' first", .{if (n_old > 1) op.old else op.new});
        // Under NEW alone: a rename that stopped after Proxmox's step.
        const v = if (under_old) |x| blk: {
            if (under_new) |y| return ctx.fail(error.Refused, "a VM named {s} already exists ({d})", .{ op.new, y.vmid });
            break :blk x;
        } else under_new orelse return ctx.fail(error.NotFound, "no VM named {s} (nor {s}, which a stopped rename would have left)", .{ op.old, op.new });
        if (v.template) return ctx.fail(error.Refused, "{s} is a template; templates are not renamed this way", .{v.name});
        if (!template.taggedWith(v.tags, "artoo")) return ctx.fail(error.Refused, "{s} is not an artoo guest (no tag artoo); a foreign VM is renamed with 'artoo vm set {s} name={s}'", .{ v.name, v.name, op.new });
        if (vm_cmd.roleOf(v.tags)) |r| if (std.mem.eql(u8, r, "edge") or std.mem.eql(u8, r, "watch"))
            return ctx.fail(error.Refused, "{s} carries role-{s}: its name sits in firewall rules and every guest's Alloy configuration (SPEC §9.7, §9.9); rebuild it instead", .{ v.name, r });
        if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; its hostname is changed inside, so start it first", .{ v.name, v.status });
        if (!try agent.ping(op.c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer", .{v.name});
        const vcfg = try vms.config(op.c, v.vmid);
        const mac = try classic.netMac(a, pve.str(vcfg, "net0") orelse "");
        const address = life.staticAddress(vcfg);

        // Guest.
        const g = try agent.sh(op.c, v.vmid, "hostname; echo ---; cat /etc/hosts", 60_000);
        if (!g.ok()) return ctx.fail(error.Protocol, "reading the hostname of {s} failed: {s}", .{ v.name, try k.clean(ctx, edge.firstLine(g.err)) });
        const sep = std.mem.find(u8, g.out, "\n---\n") orelse return ctx.fail(error.Protocol, "unexpected hostname answer from {s}", .{v.name});
        const hostname = std.mem.trim(u8, g.out[0..sep], " \r\n");

        // UniFi: the record by MAC; NEW on another client refuses.
        const records = try classic.records(op.u);
        const record = if (mac) |m| classic.find(records, m) else null;
        for (records) |r| if (std.ascii.eqlIgnoreCase(r.name, op.new) and (mac == null or !std.ascii.eqlIgnoreCase(r.mac, mac.?)))
            return ctx.fail(error.Refused, "the UniFi client record {s} ({s}) is already named {s}", .{ try k.clean(ctx, r.mac), try k.clean(ctx, r.id), op.new });

        // DNS: the machine-name records; only this guest's are touched.
        const all = try dns.list(op.u);
        const old_fqdn = try dns.fqdn(a, op.old, cfg.guests.domain);
        const new_fqdn = try dns.fqdn(a, op.new, cfg.guests.domain);
        var dns_old = dns.find(all, old_fqdn);
        var dns_note: ?[]const u8 = null;
        if (dns_old) |r| if (address == null or !std.mem.eql(u8, r.ipv4, address.?)) {
            dns_note = try std.fmt.allocPrint(a, "{s} {s} {s} kept: it is not {s}'s address", .{ old_fqdn, ctx.ui.glyphs.arrow, try k.clean(ctx, r.ipv4), v.name });
            dns_old = null;
        };
        const dns_new = dns.find(all, new_fqdn);
        if (dns_new) |r| if (address == null or !std.mem.eql(u8, r.ipv4, address.?))
            return ctx.fail(error.Refused, "{s} already points at {s}; remove it first ('artoo dns rm {s}')", .{ new_fqdn, try k.clean(ctx, r.ipv4), new_fqdn });

        // Secret store.
        const store = try ctx.secretStore();
        const s_old = try std.fmt.allocPrint(a, "guest/{s}", .{op.old});
        const s_new = try std.fmt.allocPrint(a, "guest/{s}", .{op.new});
        const secret_old = try store.exists(ctx.io, a, s_old);
        const secret_new = try store.exists(ctx.io, a, s_new);
        if (secret_old and secret_new) {
            const x = (try store.get(ctx.io, a, s_old)) orelse "";
            const y = (try store.get(ctx.io, a, s_new)) orelse "";
            if (!std.mem.eql(u8, x, y)) return ctx.fail(error.Refused, "{s} and {s} both exist and differ; keep the right one with 'artoo auth' / 'artoo vm password' first", .{ s_old, s_new });
        }

        // SSH.
        const key_old = try known_hosts.lookup(ctx, op.old);
        const key_new = try known_hosts.lookup(ctx, op.new);
        if (key_old != null and key_new != null and !std.mem.eql(u8, key_old.?, key_new.?))
            return ctx.fail(error.Refused, "{s} pins another host key under {s}; remove it first", .{ known_hosts.default_path, op.new });
        var ssh_old = false;
        var ssh_new = false;
        if (try vm_ssh.present(ctx)) {
            ssh_old = try vm_ssh.hasBlock(ctx, op.old);
            ssh_new = try vm_ssh.hasBlock(ctx, op.new);
        }

        // Services on the edge.
        var edge_vm: ?vms.Vm = null;
        for (list) |x| {
            const r = vm_cmd.roleOf(x.tags) orelse continue;
            if (std.mem.eql(u8, r, edge.role) and !x.template) edge_vm = x;
        }
        var routes: std.ArrayList(svc.Route) = .empty;
        if (edge_vm) |e| {
            if (!e.running()) return ctx.fail(error.Refused, "the edge VM {s} is {s}: the services that name {s} cannot be read; start it first", .{ e.name, e.status, op.old });
            const view = try svc.readEdge(op.c, e.vmid, try svc.domains(ctx));
            for (view.routes) |r| if (std.ascii.eqlIgnoreCase(r.vm, op.old)) {
                if (!r.managed()) return ctx.fail(error.Refused, "the route of service {s} on {s} was edited by hand; fix it first", .{ r.name, e.name });
                try routes.append(a, r);
            };
        }

        // Fence exceptions, and the fences that render them.
        const entries = (try config.fenceAllows(a, cfg.guests.fence_allow_out)) orelse return ctx.fail(error.ConfigInvalid, "guests.fence_allow_out is malformed", .{});
        var fence_entries: usize = 0;
        var fenced: std.ArrayList([]const u8) = .empty;
        if (template.taggedWith(v.tags, vm_fence.tag)) try fenced.append(a, op.new);
        for (entries) |f| {
            const names_vm = std.mem.eql(u8, f.vm, op.old);
            const names_peer = std.mem.eql(u8, f.peer, op.old);
            if (!names_vm and !names_peer) continue;
            fence_entries += 1;
            if (names_peer and !names_vm) if (vm_fence.fencedNamed(list, f.vm)) |x| {
                var seen = false;
                for (fenced.items) |n| seen = seen or std.mem.eql(u8, n, x.name);
                if (!seen) try fenced.append(a, x.name);
            };
        }

        // Tailnet.
        const role = vm_cmd.roleOf(v.tags);
        const on_tailnet = template.taggedWith(v.tags, "tailnet") or (role != null and std.mem.eql(u8, role.?, "router"));
        var ts_state: ?ts_cmd.GuestState = null;
        var device: ?tn.Device = null;
        if (on_tailnet) {
            ts_state = try ts_cmd.guestState(op.c, v.vmid);
            if (ts_state.?.running() and ts_state.?.node_id.len > 0 and try tsapi.configured(ctx)) {
                if (op.tsc == null) op.tsc = try tsapi.Client.open(ctx, .main);
                device = try tn.getDevice(&op.tsc.?, ts_state.?.node_id);
            }
        }

        // Watchdog.
        var watch_vm: ?vms.Vm = null;
        var old_series: usize = 0;
        var watch_note: ?[]const u8 = null;
        if (!watch.unwatched(v.tags)) if (try watch.findWatchVm(op.c)) |w| if (w.vmid != v.vmid) {
            if (!w.running()) {
                watch_note = try std.fmt.allocPrint(a, "Watchdog {s} is {s}: run 'artoo watch enroll {s}' and 'artoo watch forget {s}' once it runs", .{ w.name, w.status, op.new, op.old });
            } else {
                watch_vm = w;
                old_series = try watch.hostSeries(op.c, w, op.old);
            }
        };

        return .{
            .vm = v,
            .cfg = vcfg,
            .digest = pve.str(vcfg, "digest") orelse "",
            .mac = mac,
            .address = address,
            .hostname = hostname,
            .hosts_old = hostsNames(g.out[sep + 5 ..], op.old),
            .record = record,
            .dns_old = dns_old,
            .dns_new = dns_new,
            .dns_note = dns_note,
            .secret_old = secret_old,
            .secret_new = secret_new,
            .key_old = key_old,
            .key_new = key_new,
            .ssh_old = ssh_old,
            .ssh_new = ssh_new,
            .edge_vm = edge_vm,
            .routes = routes.items,
            .fence_entries = fence_entries,
            .fenced = fenced.items,
            .on_tailnet = on_tailnet,
            .ts_state = ts_state,
            .device = device,
            .watch_vm = watch_vm,
            .old_series = old_series,
            .watch_note = watch_note,
        };
    }

    fn pending(op: *const RenameOp, o: Observed) Pending {
        var p: Pending = .{
            .proxmox = !std.mem.eql(u8, o.vm.name, op.new),
            .guest = !std.mem.eql(u8, o.hostname, op.new) or o.hosts_old,
            .unifi = if (o.record) |r| !std.mem.eql(u8, r.name, op.new) else false,
            .dns_add = o.dns_old != null and o.dns_new == null,
            .dns_rm = o.dns_old != null,
            .secret = o.secret_old,
            .ssh = o.key_old != null or o.ssh_old,
            .services = o.routes.len > 0,
            .fence = o.fence_entries > 0,
            .tailnet = blk: {
                const s = o.ts_state orelse break :blk false;
                if (s.running() and !std.ascii.eqlIgnoreCase(s.hostname, op.new)) break :blk true;
                if (o.device) |d| break :blk !std.ascii.eqlIgnoreCase(d.machine, op.new);
                break :blk false;
            },
            .watch = o.watch_vm != null and o.old_series > 0,
        };
        // Follow-ups that are no-ops alone: a fence re-derived and the
        // guest enrolled again, both only alongside another step.
        const other = p.any();
        if (other and o.fenced.len > 0) p.fence = true;
        if (other and o.watch_vm != null) p.watch = true;
        return p;
    }

    pub fn read(op: *RenameOp, ctx: *Context) !void {
        op.target = op.old;
        op.o = try op.observe(ctx);
        op.p = op.pending(op.o);
        const o = op.o;
        op.fp = try std.fmt.allocPrint(ctx.arena, "{s}|{s}|{s}|{}|{}|{}|{}|{d}|{d}|{d}", .{
            o.vm.name,    o.digest,        o.hostname,   o.hosts_old, o.record != null, o.dns_old != null, o.secret_old,
            o.routes.len, o.fence_entries, o.old_series,
        });
    }

    pub fn plan(op: *RenameOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const o = op.o;
        const p = op.p;
        if (!p.any()) return null;
        const arrow = ctx.ui.glyphs.arrow;
        const none = "not present";
        var ch: std.ArrayList(ui.blocks.Change) = .empty;
        const same = struct {
            fn f(al: std.mem.Allocator, what: []const u8) ![]const u8 {
                return std.fmt.allocPrint(al, "{s} (done)", .{what});
            }
        }.f;
        try ch.append(a, .{ .field = "Proxmox", .from = if (p.proxmox) try std.fmt.allocPrint(a, "name {s}", .{o.vm.name}) else try same(a, "name"), .to = try std.fmt.allocPrint(a, "name {s} ({d}, digest-guarded)", .{ op.new, o.vm.vmid }) });
        try ch.append(a, .{ .field = "guest", .from = if (p.guest) try std.fmt.allocPrint(a, "hostname {s}{s}", .{ try k.clean(ctx, o.hostname), if (o.hosts_old) ", /etc/hosts" else "" }) else try same(a, "hostname"), .to = try std.fmt.allocPrint(a, "hostname {s} and /etc/hosts (agent)", .{op.new}) });
        try ch.append(a, if (o.record) |r| .{ .field = "UniFi", .from = if (p.unifi) try std.fmt.allocPrint(a, "client {s} ({s})", .{ try k.clean(ctx, r.name), r.mac }) else try same(a, "client record"), .to = try std.fmt.allocPrint(a, "client {s} (PUT rest/user, matched by MAC)", .{op.new}) } else .{ .field = "UniFi", .from = none, .to = "nothing to change" });
        const cfg = try ctx.config();
        const new_fqdn = try dns.fqdn(a, op.new, cfg.guests.domain);
        try ch.append(a, if (o.dns_old) |r| .{ .field = "DNS", .from = try std.fmt.allocPrint(a, "{s} {s} {s}", .{ try k.clean(ctx, r.domain), arrow, r.ipv4 }), .to = try std.fmt.allocPrint(a, "{s} {s} {s} (added first)", .{ new_fqdn, arrow, r.ipv4 }) } else if (o.dns_new != null) .{ .field = "DNS", .from = try same(a, new_fqdn), .to = new_fqdn } else .{ .field = "DNS", .from = none, .to = "nothing to change" });
        try ch.append(a, if (o.secret_old) .{ .field = "secret store", .from = try std.fmt.allocPrint(a, "guest/{s}", .{op.old}), .to = try std.fmt.allocPrint(a, "guest/{s} (read back before guest/{s} is removed)", .{ op.new, op.old }) } else if (o.secret_new) .{ .field = "secret store", .from = try same(a, "password"), .to = try std.fmt.allocPrint(a, "guest/{s}", .{op.new}) } else .{ .field = "secret store", .from = none, .to = "nothing to change" });
        try ch.append(a, if (p.ssh) .{ .field = "SSH", .from = try std.fmt.allocPrint(a, "{s}{s}{s}", .{ if (o.key_old != null) "pinned key" else "", if (o.key_old != null and o.ssh_old) " and " else "", if (o.ssh_old) "ssh_config block" else "" }), .to = try std.fmt.allocPrint(a, "HostKeyAlias {s}{s}", .{ op.new, if (o.ssh_old) ", Host block rewritten" else "" }) } else .{ .field = "SSH", .from = if (o.key_new != null or o.ssh_new) try same(a, "pinned key") else none, .to = if (o.key_new != null or o.ssh_new) op.new else none });
        if (o.routes.len > 0) {
            for (o.routes) |r| try ch.append(a, .{ .field = "service", .from = try std.fmt.allocPrint(a, "{s} {s} {s}:{d}", .{ r.name, arrow, op.old, r.port }), .to = try std.fmt.allocPrint(a, "{s}:{d} (on {s}, as svc set)", .{ op.new, r.port, o.edge_vm.?.name }) });
        } else try ch.append(a, .{ .field = "service", .from = none, .to = "nothing to change" });
        try ch.append(a, if (o.fence_entries > 0) .{ .field = "fence", .from = try std.fmt.allocPrint(a, "{d} guests.fence_allow_out entr{s} naming {s}", .{ o.fence_entries, if (o.fence_entries == 1) "y" else "ies", op.old }), .to = try std.fmt.allocPrint(a, "naming {s}; fences re-derived ({s})", .{ op.new, if (o.fenced.len > 0) try std.mem.join(a, ", ", o.fenced) else "none fenced" }) } else if (p.fence) .{ .field = "fence", .from = "unchanged entries", .to = try std.fmt.allocPrint(a, "fences re-derived ({s}), applied where they differ", .{try std.mem.join(a, ", ", o.fenced)}) } else .{ .field = "fence", .from = none, .to = "nothing to change" });
        try ch.append(a, if (o.ts_state) |s| .{ .field = "tailnet", .from = if (p.tailnet) try std.fmt.allocPrint(a, "{s}{s}", .{ if (s.running()) try k.clean(ctx, s.hostname) else "not joined", if (o.device) |d| try std.fmt.allocPrint(a, " (device {s})", .{try k.clean(ctx, d.name)}) else "" }) else try same(a, "tailnet name"), .to = try std.fmt.allocPrint(a, "{s} (tailscale set --hostname{s})", .{ op.new, if (op.tsc != null) ", checked with the API" else "" }) } else .{ .field = "tailnet", .from = none, .to = "nothing to change" });
        try ch.append(a, if (o.watch_vm) |w| .{ .field = "watchdog", .from = try std.fmt.allocPrint(a, "{d} series of {s} on {s}", .{ o.old_series, op.old, w.name }), .to = try std.fmt.allocPrint(a, "watch enroll {s}, then {s}'s series deleted", .{ op.new, op.old }) } else .{ .field = "watchdog", .from = none, .to = "nothing to change" });
        var notes: std.ArrayList([]const u8) = .empty;
        if (!p.proxmox) try notes.append(a, try std.fmt.allocPrint(a, "{s} is already {s} on Proxmox: this run continues a rename that stopped.", .{ op.old, op.new }));
        if (o.dns_note) |n| try notes.append(a, n);
        if (o.watch_note) |n| try notes.append(a, n);
        try notes.append(a, "Steps run in this order, each checking observed state first; after a failure run the same command again to continue.");
        try notes.append(a, "The UniFi rename uses PUT rest/user/{_id} with the name alone: expected from the classic API, not yet verified live.");
        return .{
            .action = try std.fmt.allocPrint(a, "Rename guest {s} ({d}) {s} {s}", .{ op.old, o.vm.vmid, arrow, op.new }),
            .risk = .destructive,
            .target = try std.fmt.allocPrint(a, "VM {d} on {s} + UniFi + this machine", .{ o.vm.vmid, op.c.node }),
            .changes = ch.items,
            .impact = try a.dupe([]const u8, &.{
                try std.fmt.allocPrint(a, "Other machines keep {s} in their known_hosts, ssh_config and password copies until they run 'artoo vm ssh-config' and receive the password again", .{op.old}),
                try std.fmt.allocPrint(a, "Metrics history stays under {s} in Loki; it is not carried over", .{op.old}),
            }),
            .recovery = try std.fmt.allocPrint(a, "artoo vm rename {s} {s}", .{ op.new, op.old }),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *RenameOp) []const u8 {
        return op.fp;
    }

    /// A failure after the first step is exit 8 (what is done and what is
    /// left is in the ledger); an unknown outcome stays exit 7.
    pub fn send(op: *RenameOp, ctx: *Context) !void {
        op.steps(ctx) catch |err| {
            switch (err) {
                error.OutOfMemory, error.Canceled, error.OutcomeUnknown, error.Partial => return err,
                else => {},
            }
            var done_n: usize = 0;
            for (op.ledger.steps.items) |s| done_n += @intFromBool(s.state == .done);
            if (done_n == 0) return err;
            const why = ctx.diag orelse @errorName(err);
            return ctx.fail(error.Partial, "the rename stopped after {d} step{s}: {s}; run 'artoo vm rename {s} {s}' again to continue", .{ done_n, if (done_n == 1) "" else "s", why, op.old, op.new });
        };
    }

    fn steps(op: *RenameOp, ctx: *Context) !void {
        const a = ctx.arena;
        const o = op.o;
        const p = op.p;
        const l = &op.ledger;
        const cfg = try ctx.config();
        const s_pve = if (p.proxmox) try l.add(a, "rename on Proxmox") else null;
        const s_guest = if (p.guest) try l.add(a, "set the hostname") else null;
        const s_unifi = if (p.unifi) try l.add(a, "rename the client record") else null;
        const s_dns_add = if (p.dns_add) try l.add(a, "add DNS record") else null;
        const s_dns_rm = if (p.dns_rm) try l.add(a, "remove old DNS record") else null;
        const s_secret = if (p.secret) try l.add(a, "move the password") else null;
        const s_ssh = if (p.ssh) try l.add(a, "move the pinned key") else null;
        const s_svc = if (p.services) try l.add(a, "move the services") else null;
        const s_fence = if (p.fence) try l.add(a, "update the fences") else null;
        const s_ts = if (p.tailnet) try l.add(a, "rename on the tailnet") else null;
        const s_watch = if (p.watch) try l.add(a, "move the watchdog series") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        const vmid = o.vm.vmid;

        if (s_pve) |i| {
            l.set(i, .unknown, "");
            _ = try op.c.send(.PUT, try op.c.nodePath("/qemu/{d}/config", .{vmid}), &.{
                .{ .name = "name", .value = op.new },
                .{ .name = "digest", .value = o.digest },
            });
            l.set(i, .done, op.new);
        }
        if (s_guest) |i| {
            l.set(i, .unknown, "");
            const r = try agent.exec(op.c, vmid, &.{ "sh", "-c", guest_script, "sh", op.new, op.old }, null, 60_000);
            if (!r.ok()) {
                l.set(i, .failed, "");
                return ctx.fail(error.Partial, "setting the hostname of {s} failed (exit {?d}): {s}", .{ op.new, r.code, try k.clean(ctx, edge.firstLine(r.err)) });
            }
            l.set(i, .done, op.new);
        }
        if (s_unifi) |i| {
            l.set(i, .unknown, "");
            try classic.rename(op.u, o.record.?.id, op.new);
            l.set(i, .done, o.record.?.mac);
        }
        const new_fqdn = try dns.fqdn(a, op.new, cfg.guests.domain);
        if (s_dns_add) |i| {
            l.set(i, .unknown, "");
            try dns.create(op.u, new_fqdn, o.dns_old.?.ipv4, dns.default_ttl);
            l.set(i, .done, new_fqdn);
        }
        if (s_dns_rm) |i| {
            l.set(i, .unknown, "");
            try dns.delete(op.u, o.dns_old.?.id);
            l.set(i, .done, try k.clean(ctx, o.dns_old.?.domain));
        }
        if (s_secret) |i| {
            const store = try ctx.secretStore();
            const s_old = try std.fmt.allocPrint(a, "guest/{s}", .{op.old});
            const s_new = try std.fmt.allocPrint(a, "guest/{s}", .{op.new});
            l.set(i, .unknown, "");
            if (!o.secret_new) {
                const pw = try store.require(ctx.io, a, s_old);
                try store.set(ctx.io, a, s_new, pw);
                const back = (try store.get(ctx.io, a, s_new)) orelse "";
                if (!std.mem.eql(u8, back, pw)) {
                    l.set(i, .failed, "read-back differs");
                    return ctx.fail(error.Partial, "{s} did not read back as written; {s} is kept", .{ s_new, s_old });
                }
            }
            _ = try store.delete(ctx.io, a, s_old);
            l.set(i, .done, s_new);
        }
        if (s_ssh) |i| {
            l.set(i, .unknown, "");
            if (o.key_old) |key| {
                if (o.key_new == null) try known_hosts.record(ctx, op.new, key);
                try known_hosts.record(ctx, op.old, null);
            }
            if (o.ssh_old) {
                if (vm_ssh.blockOf(op.new, o.cfg)) |b| try vm_ssh.put(ctx, op.new, b);
                try vm_ssh.put(ctx, op.old, null);
            }
            l.set(i, .done, if (o.ssh_old) "known_hosts, ssh_config" else "known_hosts");
        }
        if (s_svc) |i| {
            const e = o.edge_vm.?;
            const d = try svc.domains(ctx);
            l.set(i, .unknown, "");
            for (o.routes) |r| {
                const content = try svc.renderRoute(a, d, r.name, op.new, r.port, r.health);
                const enc = std.base64.standard.Encoder;
                const b64 = try a.alloc(u8, enc.calcSize(content.len));
                _ = enc.encode(b64, content);
                const res = try agent.exec(op.c, e.vmid, &.{ "sh", "-c", svc.apply_script, "sh", r.name }, b64, 120_000);
                if (!res.ok()) {
                    l.set(i, .failed, r.name);
                    return ctx.fail(error.Partial, "moving service {s} on {s} failed (exit {?d}): {s}", .{ r.name, e.name, res.code, try k.clean(ctx, std.mem.trim(u8, res.err, " \n")) });
                }
            }
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} on {s}", .{ o.routes.len, e.name }));
        }
        if (s_fence) |i| {
            l.set(i, .unknown, "");
            if (try renameFenceList(a, cfg.guests.fence_allow_out, op.old, op.new)) |text| try saveFenceList(ctx, text);
            var applied: usize = 0;
            for (o.fenced) |name| {
                const v = try vms.resolve(op.c, name);
                const want = try vm_fence.derive(ctx, op.c, v);
                const st = try vm_fence.readState(op.c, v, want);
                if (st.converged()) continue;
                try vm_fence.apply(op.c, v, want, st);
                applied += 1;
            }
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} entr{s}, {d} fence{s} applied", .{ o.fence_entries, if (o.fence_entries == 1) "y" else "ies", applied, if (applied == 1) "" else "s" }));
        }
        if (s_ts) |i| {
            l.set(i, .unknown, "");
            const s = o.ts_state.?;
            if (s.running() and !std.ascii.eqlIgnoreCase(s.hostname, op.new)) {
                const r = try agent.exec(op.c, vmid, &.{ "sh", "-c", tailnet_script, "sh", op.new }, null, 60_000);
                if (!r.ok()) {
                    l.set(i, .failed, "");
                    return ctx.fail(error.Partial, "tailscale set --hostname failed on {s}: {s}", .{ op.new, try k.clean(ctx, edge.firstLine(r.err)) });
                }
            }
            var detail: []const u8 = op.new;
            if (op.tsc) |*t| if (s.node_id.len > 0) {
                // A name set by hand in the console does not follow the
                // hostname: rename the device itself then (SPEC §19).
                if (try tn.getDevice(t, s.node_id)) |d| if (!std.ascii.eqlIgnoreCase(d.machine, op.new)) {
                    try tn.renameDevice(t, d.id, op.new);
                    detail = try std.fmt.allocPrint(a, "{s} (device renamed through the API)", .{op.new});
                };
            };
            l.set(i, .done, detail);
        }
        if (s_watch) |i| {
            const w = o.watch_vm.?;
            l.set(i, .unknown, "");
            _ = try watch.enrollNew(ctx, op.c, try vms.resolve(op.c, op.new));
            const n = try watch.forgetHost(op.c, w, op.old);
            l.set(i, .done, try std.fmt.allocPrint(a, "enrolled on {s}, {d} old series deleted", .{ w.name, n }));
        }
    }

    pub fn verify(op: *RenameOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        if (!op.ledger.complete()) return false;
        const o = try op.observe(ctx);
        const left = op.pending(o);
        if (left.any()) return false;
        // The places that must now carry NEW.
        if (!std.mem.eql(u8, o.vm.name, op.new) or !std.mem.eql(u8, o.hostname, op.new)) return false;
        if (o.record) |r| if (!std.mem.eql(u8, r.name, op.new)) return false;
        if (op.o.dns_old != null and o.dns_new == null) return false;
        if ((op.o.secret_old or op.o.secret_new) and !o.secret_new) return false;
        if (op.o.key_old != null and o.key_new == null) return false;
        return true;
    }

    pub fn done(op: *RenameOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} is now {s} everywhere artoo keeps it; check it with 'artoo vm verify {s}'", .{ op.old, op.new, op.new }) catch "renamed";
    }
};

/// `guests.fence_allow_out` written back to the config file (and to this
/// invocation's view of it, which the fences are derived from).
fn saveFenceList(ctx: *Context, text: []const u8) !void {
    const l = try config_cmd.loaded(ctx);
    var msg: []const u8 = "";
    const value = (try config.assign(&l.config, ctx.arena, "guests.fence_allow_out", .{ .string = text }, &msg)) orelse
        return ctx.fail(error.ConfigInvalid, "the renamed guests.fence_allow_out is invalid: {s}", .{msg});
    try config_cmd.save(ctx, l.path, try config.edit(ctx.arena, &l.tree, "guests.fence_allow_out", value));
}

pub const rename = struct {
    pub const name = "rename";
    pub const summary = "Rename an artoo guest everywhere its name lives (high impact)";
    pub const details =
        \\Proxmox, the guest's hostname and /etc/hosts, the UniFi client record,
        \\the DNS record (NEW added before OLD is removed), the guest/<name>
        \\password, the pinned host key and ssh_config, the services and fence
        \\exceptions naming it, its tailnet name and the watchdog's series — one
        \\ledger step each, in that order. Each step checks observed state
        \\first: after a failure, the same command continues. Refused for
        \\role-edge and role-watch (rebuild those), templates, foreign VMs and
        \\stopped guests. Interactive: type OLD to confirm. Non-interactive:
        \\--yes --confirm OLD.
    ;
    pub const positionals = [_]cli.Positional{
        .{ .name = "OLD", .help = "The guest's current name", .complete = .vm },
        .{ .name = "NEW", .help = "Its new name (one DNS label, checked as vm new checks it)" },
    };
    pub const flags = [_]cli.Flag{.{ .long = "confirm", .kind = .string, .metavar = "OLD", .help = "Non-interactive confirmation (with --yes)" }};
    pub const examples = [_][]const u8{ "artoo vm rename naboo hoth -n", "artoo vm rename naboo hoth --yes --confirm naboo" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const old = args.pos("OLD");
        const new = args.pos("NEW");
        if (!names.valid(new)) return ctx.fail(error.Usage, "NEW must be one lowercase DNS label (letter first; letters, digits, single hyphens; 2-{d} characters), got '{s}'", .{ names.max_len, new });
        if (!names.valid(old)) return ctx.fail(error.Usage, "OLD must be the guest's name, got '{s}'", .{old});
        if (std.mem.eql(u8, old, new)) return ctx.fail(error.Usage, "OLD and NEW are the same", .{});
        if (names.isReserved(new) or exposure.protected(try ctx.config(), new, null) != null)
            return ctx.fail(error.Refused, "'{s}' names the lab's infrastructure or equipment; choose another name", .{new});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var u = try unifi.Client.open(ctx);
        defer u.deinit();
        var op: RenameOp = .{ .c = &c, .u = &u, .old = old, .new = new };
        defer if (op.tsc) |*t| t.deinit();
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const commands = [_]cli.Command{cli.leaf(rename)};

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "hostsNames and renameFenceList" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect(hostsNames("127.0.0.1 localhost\n127.0.1.1 naboo.lab.example.com naboo\n", "naboo"));
    try testing.expect(!hostsNames("127.0.0.1 localhost\n# naboo\n127.0.1.1 naboo2\n", "naboo"));
    try testing.expectEqualStrings("naboo 192.168.1.10 tcp 8006; hoth dagobah udp 53", (try renameFenceList(a, "scarif 192.168.1.10 tcp 8006; hoth dagobah udp 53", "scarif", "naboo")).?);
    try testing.expectEqualStrings("hoth naboo tcp 5432", (try renameFenceList(a, "hoth scarif tcp 5432", "scarif", "naboo")).?);
    try testing.expect(try renameFenceList(a, "hoth dagobah udp 53", "scarif", "naboo") == null);
}

const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const R = testkit.Gateway.FakeServer.Route;
const root = cli.group("artoo", "test", &.{@import("vm.zig").group});

fn rt(match: []const u8, body: []const u8) R {
    return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
}

fn agentOut(a: std.mem.Allocator, code: i64, out: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = code, .@"out-data" = out, .@"err-data" = "" } }, .{});
}

const list_old = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":202,\"name\":\"bespin\",\"status\":\"stopped\",\"tags\":\"artoo;role-edge\",\"template\":1}]}";
const list_new = "{\"data\":[{\"vmid\":201,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo\"}]}";
const cfg_body = "{\"data\":{\"name\":\"naboo\",\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0\",\"ipconfig0\":\"ip=192.168.1.230/24,gw=192.168.1.1\",\"tags\":\"artoo\",\"digest\":\"d1\"}}";
const sites = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"S1\",\"internalReference\":\"default\",\"name\":\"Default\"}]}";
const users_old = "{\"meta\":{\"rc\":\"ok\"},\"data\":[{\"_id\":\"U1\",\"mac\":\"bc:24:11:00:00:01\",\"name\":\"naboo\"}]}";
const users_new = "{\"meta\":{\"rc\":\"ok\"},\"data\":[{\"_id\":\"U1\",\"mac\":\"bc:24:11:00:00:01\",\"name\":\"hoth\"}]}";
const dns_old_body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R1\",\"enabled\":true,\"domain\":\"naboo.lab.example.com\",\"ipv4Address\":\"192.168.1.230\",\"ttlSeconds\":300}]}";
const dns_new_body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R2\",\"enabled\":true,\"domain\":\"hoth.lab.example.com\",\"ipv4Address\":\"192.168.1.230\",\"ttlSeconds\":300}]}";
const test_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVkZXZ0ZXN0a2V5Zm9ydGhlcmVuYW1ldGVzdHM";

fn renameReads(a: std.mem.Allocator, list: []const u8, users: []const u8, records: []const u8, host: []const u8, site: bool) ![]const R {
    var out: std.ArrayList(R) = .empty;
    try out.appendSlice(a, &.{
        rt("GET /api2/json/nodes/pve/qemu HTTP", list),
        rt("agent/ping", "{\"data\":{\"result\":{}}}"),
        rt("GET /api2/json/nodes/pve/qemu/201/config", cfg_body),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        rt("exec-status", try agentOut(a, 0, try std.fmt.allocPrint(a, "{s}\n---\n127.0.0.1 localhost\n127.0.1.1 {s}.lab.example.com {s}\n", .{ host, host, host }))),
        rt("rest/user HTTP", users),
    });
    if (site) try out.append(a, rt("GET /v1/sites?", sites));
    try out.appendSlice(a, &.{
        rt("GET /v1/sites/S1/dns/policies", records),
        rt("GET /api2/json/nodes/pve/qemu HTTP", list),
    });
    return out.items;
}

test "vm rename: every place moves to NEW, one ledger step each, verified by a fresh read" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list_old, users_old, dns_old_body, "naboo", true));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
        rt("DELETE /v1/sites/S1/dns/policies/R1", ""),
    });
    try routes.appendSlice(a, try renameReads(a, list_new, users_new, dns_new_body, "hoth", false));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try g.mem.map.put(g.h.arena.allocator(), "guest/naboo", "naboo-password");
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/known_hosts", .data = "naboo " ++ test_key ++ "\ndagobah " ++ test_key ++ "\n" });
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    const out = g.h.stdout();
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ out, g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    for ([_][]const u8{
        "rename on Proxmox",
        "set the hostname",
        "rename the client record",
        "add DNS record",
        "remove old DNS record",
        "move the password",
        "move the pinned key",
        "naboo is now hoth everywhere artoo keeps it",
    }) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
    for (g.srv.received) |req| if (req) |q| {
        if (std.mem.startsWith(u8, q, "PUT /api2/json/nodes/pve/qemu/201/config")) try testing.expect(std.mem.endsWith(u8, q, "name=hoth&digest=d1"));
        if (std.mem.startsWith(u8, q, "PUT /proxy/network/api/s/default/rest/user/U1")) try testing.expect(std.mem.endsWith(u8, q, "{\"name\":\"hoth\"}"));
        if (std.mem.startsWith(u8, q, "POST /v1/sites/S1/dns/policies")) try testing.expect(std.mem.find(u8, q, "\"domain\":\"hoth.lab.example.com\",\"ipv4Address\":\"192.168.1.230\"") != null);
    };
    try testing.expectEqualStrings("naboo-password", g.mem.map.get("guest/hoth").?);
    try testing.expect(g.mem.map.get("guest/naboo") == null);
    const kh = try g.tmp.dir.readFileAlloc(testing.io, ".artoo/known_hosts", a, .limited(1 << 16));
    try testing.expectEqualStrings("dagobah " ++ test_key ++ "\nhoth " ++ test_key ++ "\n", kh);
    try testing.expect(std.mem.find(u8, out, "naboo-password") == null);
}

test "vm rename: refusals before any write — edge, watch, foreign, stopped, taken NEW, protected NEW" {
    const cases = [_]struct { line: []const u8, code: Exit }{
        .{ .line = "vm rename bespin hoth -y --confirm bespin", .code = .refused },
        .{ .line = "vm rename scarif hoth -y --confirm scarif", .code = .refused },
        .{ .line = "vm rename endor hoth -y --confirm endor", .code = .refused },
        .{ .line = "vm rename kessel hoth -y --confirm kessel", .code = .refused },
        .{ .line = "vm rename naboo dagobah -y --confirm naboo", .code = .refused },
        .{ .line = "vm rename naboo pve -y --confirm naboo", .code = .refused },
        .{ .line = "vm rename naboo Bad_Name -y --confirm naboo", .code = .usage },
    };
    for (cases) |cs| {
        var g: testkit.Gateway = undefined;
        try g.initRoutes(&.{rt("GET /api2/json/nodes/pve/qemu HTTP", "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":202,\"name\":\"dagobah\",\"status\":\"running\",\"tags\":\"artoo;role-router\"},{\"vmid\":204,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"},{\"vmid\":205,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"},{\"vmid\":206,\"name\":\"kessel\",\"status\":\"stopped\",\"tags\":\"artoo\"},{\"vmid\":207,\"name\":\"endor\",\"status\":\"running\",\"tags\":\"\"}]}")});
        defer g.deinit();
        const got = g.h.run(&root, cs.line);
        if (got != cs.code) std.debug.print("{s}: {s}\n", .{ cs.line, g.h.stderr() });
        try testing.expectEqual(cs.code, got);
        for (g.srv.received) |req| if (req) |q| try testing.expect(std.mem.startsWith(u8, q, "GET "));
    }
}

test "vm rename: run again after a stop, it continues under NEW; a finished rename is a no-op" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Proxmox and the hostname were done; UniFi, DNS and the secret were not.
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list_new, users_old, dns_old_body, "hoth", true));
    try routes.appendSlice(a, &.{
        rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
        rt("DELETE /v1/sites/S1/dns/policies/R1", ""),
    });
    try routes.appendSlice(a, try renameReads(a, list_new, users_new, dns_new_body, "hoth", false));
    try routes.appendSlice(a, try renameReads(a, list_new, users_new, dns_new_body, "hoth", true));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try g.mem.map.put(g.h.arena.allocator(), "guest/naboo", "naboo-password");
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expect(std.mem.find(u8, g.h.stdout(), "naboo is already hoth on Proxmox: this run continues a rename that stopped.") != null);
    for (g.srv.received) |req| if (req) |q| try testing.expect(!std.mem.startsWith(u8, q, "PUT /api2/json/nodes/pve/qemu/201/config"));
    try testing.expectEqualStrings("naboo-password", g.mem.map.get("guest/hoth").?);
    // Everything done: nothing to change (exit 5).
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "vm rename: a service whose upstream is OLD moves to NEW:PORT on the edge, as svc set writes it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d: svc.Domains = .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" };
    const dump = struct {
        fn f(al: std.mem.Allocator, dd: svc.Domains, vm: []const u8) ![]const u8 {
            return std.fmt.allocPrint(al, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{try svc.renderRoute(al, dd, "grafana", vm, 3000, .{})});
        }
    }.f;
    const list = "{\"data\":[{\"vmid\":201,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":204,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"}]}";
    const pass = struct {
        fn f(al: std.mem.Allocator, l: []const u8, site: bool, edge_out: []const u8) ![]const R {
            var out: std.ArrayList(R) = .empty;
            const reads = try renameReads(al, l, users_new, dns_new_body, "hoth", site);
            // The edge is read between DNS and the watchdog's lookup.
            try out.appendSlice(al, reads[0 .. reads.len - 1]);
            try out.appendSlice(al, &.{
                rt("POST /api2/json/nodes/pve/qemu/204/agent/exec HTTP", "{\"data\":{\"pid\":50}}"),
                rt("qemu/204/agent/exec-status", try agentOut(al, 0, edge_out)),
            });
            try out.append(al, reads[reads.len - 1]);
            return out.items;
        }
    }.f;
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try pass(a, list, true, try dump(a, d, "naboo")));
    try routes.appendSlice(a, &.{
        rt("POST /api2/json/nodes/pve/qemu/204/agent/exec HTTP", "{\"data\":{\"pid\":51}}"),
        rt("qemu/204/agent/exec-status", try agentOut(a, 0, "")),
    });
    try routes.appendSlice(a, try pass(a, list, false, try dump(a, d, "hoth")));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expect(std.mem.find(u8, g.h.stdout(), "service       grafana → naboo:3000 → hoth:3000 (on bespin, as svc set)") != null);
    // The new route goes as base64 on the agent's stdin, named by the service.
    const want = try svc.renderRoute(a, d, "grafana", "hoth", 3000, .{});
    const enc = std.base64.standard.Encoder;
    const b64 = try a.alloc(u8, enc.calcSize(want.len));
    _ = enc.encode(b64, want);
    var sent = false;
    for (g.srv.received) |req| if (req) |q| if (std.mem.find(u8, q, "command=grafana") != null) {
        sent = true;
        var esc: std.ArrayList(u8) = .empty;
        for (b64) |ch| if (ch == '+' or ch == '/' or ch == '=') try esc.print(a, "%{X:0>2}", .{ch}) else try esc.append(a, ch);
        try testing.expect(std.mem.find(u8, q, esc.items) != null);
    };
    try testing.expect(sent);
}

test "vm rename: a failure after the first step is exit 8 and says how to continue" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list_old, users_old, dns_old_body, "naboo", true));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        .{ .match = "PUT /proxy/network/api/s/default/rest/user/U1", .behavior = .{ .respond = .{ .status = 400, .body = "{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.Invalid\"},\"data\":[]}" } } },
    });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expect(std.mem.find(u8, g.h.stderr(), "the rename stopped after 2 steps") != null);
    try testing.expect(std.mem.find(u8, g.h.stderr(), "run 'artoo vm rename naboo hoth' again to continue") != null);
    try testing.expect(std.mem.find(u8, g.h.stdout(), "✓ set the hostname") != null);
    // Nothing after the failed step ran: the password stays under OLD.
    try testing.expect(g.mem.map.get("guest/hoth") == null);
}
