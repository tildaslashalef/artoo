//! `artoo vm rename OLD NEW`: a guest's name is also its
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
const rex_hosts = @import("../rex/hosts.zig");

const Context = app.Context;
const Value = std.json.Value;

/// Hostname and `/etc/hosts` (fields equal to `$2`, or starting `$2.`,
/// become `$1`/`$1.…`; comments and other lines kept byte for byte). A
/// line's trailing CR (a file written on Windows) is taken off before the
/// fields are compared and put back after.
const guest_script =
    \\set -eu
    \\hostnamectl set-hostname "$1"
    \\awk -v new="$1" -v old="$2" '{ cr = ""; if (sub(/\r$/, "")) cr = "\r" }
    \\/^[[:space:]]*#/ || NF < 2 { printf "%s%s\n", $0, cr; next }
    \\{ for (i = 2; i <= NF; i++) { if ($i == old) $i = new; else if (index($i, old ".") == 1) $i = new substr($i, length(old) + 1) } printf "%s%s\n", $0, cr }' /etc/hosts > /etc/hosts.artoo-new
    \\cat /etc/hosts.artoo-new > /etc/hosts
    \\rm -f /etc/hosts.artoo-new
    \\if systemctl is-active --quiet alloy; then systemctl restart alloy; fi
    \\
;

/// How often (every 5 s, so up to 2 min) the watchdog is asked for NEW's
/// samples before OLD's series may be deleted.
const watch_polls = 24;

/// After `tailscale set --hostname`, how often (every 2 s, so about 30 s)
/// the device is read before artoo renames it through the API.
const tailnet_polls = 15;

const tailnet_script =
    \\set -eu
    \\tailscale set --hostname="$1"
    \\
;

/// What the guest's places hold now.
const Observed = struct {
    vm: vms.Vm,
    /// Proxmox's VM list as read.
    list: []const vms.Vm,
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
    /// Every route on the edge, and those whose upstream is OLD.
    edge_routes: []const svc.Route,
    routes: []const svc.Route,
    fence_entries: usize,
    fenced: []const []const u8,
    on_tailnet: bool,
    ts_state: ?ts_cmd.GuestState,
    device: ?tn.Device,
    /// Why the Tailscale API is left out (a broken credential).
    ts_note: ?[]const u8,
    /// The VM tagged `role-watch`, in any state.
    watch_vm: ?vms.Vm,
    /// It runs and its agent answers.
    watch_ready: bool,
    /// Why the watchdog step does not apply (no-watch, never enrolled, no
    /// watchdog); null when it does.
    watch_skip: ?[]const u8,
    /// The `host` label the guest's Alloy reports with ("" never enrolled).
    label: []const u8,
    old_series: usize,
    /// The watchdog's probes still name OLD as a service's upstream.
    probes_old: bool,
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

/// A fence the plan shows and the fence step applies: its rules as the
/// renamed lab derives them.
const FenceWant = struct { name: []const u8, rules: []const edge.Rule };

fn sameRules(x: []const edge.Rule, y: []const edge.Rule) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| if (!p.eql(q)) return false;
    return true;
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
    /// False for verify's read: a finished rename leaves no trace of OLD.
    check_trace: bool = true,
    /// OLD's Rex host on this machine, when artoo recorded it (SPEC §20.8).
    rex: ?rex_hosts.Recorded = null,
    fence_want: []const FenceWant = &.{},

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
        // Found only under NEW: a stopped rename, if the VM still carries a
        // trace of OLD (checked once everything is read).
        const continuation = under_old == null;
        if (v.template) return ctx.fail(error.Refused, "{s} is a template; templates are not renamed this way", .{v.name});
        if (!template.taggedWith(v.tags, "artoo")) return ctx.fail(error.Refused, "{s} is not an artoo guest (no tag artoo); a foreign VM is renamed with 'artoo vm set {s} name={s}'", .{ v.name, v.name, op.new });
        if (vm_cmd.roleOf(v.tags)) |r| if (std.mem.eql(u8, r, "edge") or std.mem.eql(u8, r, "watch"))
            return ctx.fail(error.Refused, "{s} carries role-{s}: its name sits in firewall rules and every guest's Alloy configuration; rebuild it instead", .{ v.name, r });
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
        const hosts_old = hostsNames(g.out[sep + 5 ..], op.old);

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
        // Before the rename began, a password under NEW is another
        // guest's leftover.
        if (!continuation and secret_new) return ctx.fail(error.Refused, "{s} already exists; it belongs to no guest being renamed — remove it first ('artoo auth rm {s}' or 'artoo vm password')", .{ s_new, s_new });
        if (secret_old and secret_new) {
            const x = (try store.get(ctx.io, a, s_old)) orelse "";
            const y = (try store.get(ctx.io, a, s_new)) orelse "";
            if (!std.mem.eql(u8, x, y)) return ctx.fail(error.Refused, "{s} and {s} both exist and differ; keep the right one with 'artoo auth' / 'artoo vm password' first", .{ s_old, s_new });
        }

        // SSH.
        const key_old = try known_hosts.lookup(ctx, op.old);
        const key_new = try known_hosts.lookup(ctx, op.new);
        if (!continuation and key_new != null) return ctx.fail(error.Refused, "{s} already pins a host key under {s}; remove that line first", .{ known_hosts.default_path, op.new });
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
        var edge_routes: []const svc.Route = &.{};
        if (edge_vm) |e| {
            if (!e.running()) return ctx.fail(error.Refused, "the edge VM {s} is {s}: the services that name {s} cannot be read; start it first", .{ e.name, e.status, op.old });
            const view = try svc.readEdge(op.c, e.vmid, try svc.domains(ctx));
            edge_routes = view.routes;
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
            // An entry already naming NEW is another guest's, unless this
            // is a stopped rename whose fence step ran (no OLD left).
            if (std.mem.eql(u8, f.vm, op.new) or std.mem.eql(u8, f.peer, op.new)) {
                var names_old = false;
                for (entries) |x| names_old = names_old or std.mem.eql(u8, x.vm, op.old) or std.mem.eql(u8, x.peer, op.old);
                if (!continuation or names_old) return ctx.fail(error.Refused, "guests.fence_allow_out already names {s} ({s} {s} {s} {s}); fix it first ('artoo config set guests.fence_allow_out')", .{ op.new, f.vm, f.peer, f.proto, f.ports });
            }
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
        var ts_note: ?[]const u8 = null;
        if (on_tailnet) {
            ts_state = try ts_cmd.guestState(op.c, v.vmid);
            if (ts_state.?.running() and ts_state.?.node_id.len > 0 and try tsapi.configured(ctx)) {
                // A credential that does not work leaves out only the API
                // part: the guest's own 'tailscale set' still runs.
                const got: TailnetView = op.tailnetDevice(ctx, ts_state.?.node_id) catch |err| switch (err) {
                    error.OutOfMemory, error.Canceled => |e| return e,
                    else => blk: {
                        ts_note = try std.fmt.allocPrint(a, "The Tailscale API did not answer ({s}): the tailnet step runs 'tailscale set --hostname' only; check the device afterwards with 'artoo ts device show {s}'.", .{ ctx.diag orelse @errorName(err), op.new });
                        ctx.diag = null;
                        if (op.tsc) |*t| t.deinit();
                        op.tsc = null;
                        break :blk .{};
                    },
                };
                device = got.own;
                // Tailscale would give the guest NEW-1: refuse instead.
                if (got.taken) |d| return ctx.fail(error.Refused, "the tailnet device {s} ({s}) is already named {s}; rename or remove it first ('artoo ts device rename|rm')", .{ try k.clean(ctx, d.name), try k.clean(ctx, d.id), op.new });
            }
        }

        // Watchdog: the guest's Alloy names it by the label 'watch enroll'
        // rendered; the watchdog keeps OLD's series and probes naming OLD.
        var watch_vm: ?vms.Vm = null;
        var watch_ready = false;
        var watch_skip: ?[]const u8 = null;
        var label: []const u8 = "";
        var old_series: usize = 0;
        var probes_old = false;
        if (watch.unwatched(v.tags)) {
            watch_skip = "tagged no-watch";
        } else if (try watch.findWatchVm(op.c)) |w| {
            watch_vm = w;
            label = try watch.guestLabel(op.c, v);
            watch_ready = w.running() and try agent.ping(op.c, w.vmid);
            if (watch_ready) {
                old_series = try watch.hostSeries(op.c, w, op.old);
                probes_old = try watch.probesName(op.c, w, op.old);
            }
            if (label.len == 0 and old_series == 0 and !probes_old) watch_skip = "never enrolled";
        } else watch_skip = "no VM tagged role-watch";

        if (continuation and op.check_trace) {
            const traced = std.ascii.eqlIgnoreCase(hostname, op.old) or hosts_old or
                (record != null and std.ascii.eqlIgnoreCase(record.?.name, op.old)) or dns_old != null or
                (ts_state != null and std.ascii.eqlIgnoreCase(ts_state.?.hostname, op.old)) or
                (device != null and std.ascii.eqlIgnoreCase(device.?.machine, op.old)) or
                std.ascii.eqlIgnoreCase(label, op.old);
            if (!traced) return ctx.fail(error.Refused, "no VM is named {s}, and {s} carries no trace of it (hostname, /etc/hosts, UniFi record, {s}'s DNS record at its address, tailnet name): nothing to continue — a finished rename, or another guest", .{ op.old, v.name, op.old });
        }

        return .{
            .vm = v,
            .list = list,
            .cfg = vcfg,
            .digest = pve.str(vcfg, "digest") orelse "",
            .mac = mac,
            .address = address,
            .hostname = hostname,
            .hosts_old = hosts_old,
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
            .edge_routes = edge_routes,
            .routes = routes.items,
            .fence_entries = fence_entries,
            .fenced = fenced.items,
            .on_tailnet = on_tailnet,
            .ts_state = ts_state,
            .device = device,
            .ts_note = ts_note,
            .watch_vm = watch_vm,
            .watch_ready = watch_ready,
            .watch_skip = watch_skip,
            .label = label,
            .old_series = old_series,
            .probes_old = probes_old,
        };
    }

    const TailnetView = struct { own: ?tn.Device = null, taken: ?tn.Device = null };

    /// The guest's device by the node ID it reports, and another device
    /// already named NEW, if any.
    fn tailnetDevice(op: *RenameOp, ctx: *Context, node_id: []const u8) !TailnetView {
        if (op.tsc == null) op.tsc = try tsapi.Client.open(ctx, .main);
        const own = try tn.getDevice(&op.tsc.?, node_id);
        var taken: ?tn.Device = null;
        for (try tn.devices(&op.tsc.?)) |d| {
            if (!std.mem.eql(u8, d.id, node_id) and std.ascii.eqlIgnoreCase(d.machine, op.new)) taken = d;
        }
        return .{ .own = own, .taken = taken };
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
            // A stopped watchdog leaves the step pending, never skipped.
            .watch = o.watch_skip == null and (!o.watch_ready or !std.ascii.eqlIgnoreCase(o.label, op.new) or o.old_series > 0 or o.probes_old),
        };
        // A fence re-derived is a no-op alone: only alongside another step.
        if (p.any() and o.fenced.len > 0) p.fence = true;
        return p;
    }

    pub fn read(op: *RenameOp, ctx: *Context) !void {
        op.target = op.old;
        op.o = try op.observe(ctx);
        op.p = op.pending(op.o);
        op.rex = try rex_hosts.recordedHost(ctx, op.old);
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
        if (!p.any() and !op.rexPending()) return null;
        const arrow = ctx.ui.glyphs.arrow;
        const none = "not present";
        var ch: std.ArrayList(ui.blocks.Change) = .empty;
        const same = struct {
            fn f(al: std.mem.Allocator, what: []const u8) ![]const u8 {
                return std.fmt.allocPrint(al, "{s} (done)", .{what});
            }
        }.f;
        try ch.append(a, .{ .field = "Proxmox", .from = if (p.proxmox) try std.fmt.allocPrint(a, "name {s}", .{o.vm.name}) else try same(a, "name"), .to = try std.fmt.allocPrint(a, "name {s} ({d}, digest-guarded)", .{ op.new, o.vm.vmid }) });
        const cfg = try ctx.config();
        const new_fqdn = try dns.fqdn(a, op.new, cfg.guests.domain);
        try ch.append(a, if (o.dns_old) |r| .{ .field = "DNS", .from = try std.fmt.allocPrint(a, "{s} {s} {s}", .{ try k.clean(ctx, r.domain), arrow, r.ipv4 }), .to = try std.fmt.allocPrint(a, "{s} {s} {s} (added first; {s} removed last)", .{ new_fqdn, arrow, r.ipv4, try k.clean(ctx, r.domain) }) } else if (o.dns_new != null) .{ .field = "DNS", .from = try same(a, new_fqdn), .to = new_fqdn } else .{ .field = "DNS", .from = none, .to = "nothing to change" });
        if (o.routes.len > 0) {
            for (o.routes) |r| try ch.append(a, .{ .field = "service", .from = try std.fmt.allocPrint(a, "{s} {s} {s}:{d}", .{ r.name, arrow, op.old, r.port }), .to = try std.fmt.allocPrint(a, "{s}:{d} (on {s}, as svc set)", .{ op.new, r.port, o.edge_vm.?.name }) });
        } else try ch.append(a, .{ .field = "service", .from = none, .to = "nothing to change" });
        try ch.append(a, if (p.ssh) .{ .field = "SSH", .from = try std.fmt.allocPrint(a, "{s}{s}{s}", .{ if (o.key_old != null) "pinned key" else "", if (o.key_old != null and o.ssh_old) " and " else "", if (o.ssh_old) "ssh_config block" else "" }), .to = try std.fmt.allocPrint(a, "HostKeyAlias {s}{s}", .{ op.new, if (o.ssh_old) ", Host block rewritten" else "" }) } else .{ .field = "SSH", .from = if (o.key_new != null or o.ssh_new) try same(a, "pinned key") else none, .to = if (o.key_new != null or o.ssh_new) op.new else none });
        try ch.append(a, if (o.secret_old) .{ .field = "secret store", .from = try std.fmt.allocPrint(a, "guest/{s}", .{op.old}), .to = try std.fmt.allocPrint(a, "guest/{s} (read back before guest/{s} is removed)", .{ op.new, op.old }) } else if (o.secret_new) .{ .field = "secret store", .from = try same(a, "password"), .to = try std.fmt.allocPrint(a, "guest/{s}", .{op.new}) } else .{ .field = "secret store", .from = none, .to = "nothing to change" });
        if (op.rex != null) try ch.append(a, try op.rexChange(ctx));
        try ch.append(a, if (o.fence_entries > 0) .{ .field = "fence", .from = try std.fmt.allocPrint(a, "{d} guests.fence_allow_out entr{s} naming {s}", .{ o.fence_entries, if (o.fence_entries == 1) "y" else "ies", op.old }), .to = try std.fmt.allocPrint(a, "naming {s}; fences re-derived ({s})", .{ op.new, if (o.fenced.len > 0) try std.mem.join(a, ", ", o.fenced) else "none fenced" }) } else if (p.fence) .{ .field = "fence", .from = "unchanged entries", .to = try std.fmt.allocPrint(a, "fences re-derived ({s}), applied where they differ", .{try std.mem.join(a, ", ", o.fenced)}) } else .{ .field = "fence", .from = none, .to = "nothing to change" });
        try op.fenceDiffs(ctx, &ch);
        try ch.append(a, if (o.ts_state) |s| .{ .field = "tailnet", .from = if (p.tailnet) try std.fmt.allocPrint(a, "{s}{s}", .{ if (s.running()) try k.clean(ctx, s.hostname) else "not joined", if (o.device) |d| try std.fmt.allocPrint(a, " (device {s})", .{try k.clean(ctx, d.name)}) else "" }) else try same(a, "tailnet name"), .to = try std.fmt.allocPrint(a, "{s} (tailscale set --hostname{s})", .{ op.new, if (op.tsc != null) ", checked with the API" else "" }) } else .{ .field = "tailnet", .from = none, .to = "nothing to change" });
        try ch.append(a, try op.watchChange(ctx));
        try ch.append(a, .{ .field = "guest", .from = if (p.guest) try std.fmt.allocPrint(a, "hostname {s}{s}", .{ try k.clean(ctx, o.hostname), if (o.hosts_old) ", /etc/hosts" else "" }) else try same(a, "hostname"), .to = try std.fmt.allocPrint(a, "hostname {s} and /etc/hosts (agent)", .{op.new}) });
        try ch.append(a, if (o.record) |r| .{ .field = "UniFi", .from = if (p.unifi) try std.fmt.allocPrint(a, "client {s} ({s})", .{ try k.clean(ctx, r.name), r.mac }) else try same(a, "client record"), .to = try std.fmt.allocPrint(a, "client {s} (PUT rest/user, matched by MAC)", .{op.new}) } else .{ .field = "UniFi", .from = none, .to = "nothing to change" });
        var notes: std.ArrayList([]const u8) = .empty;
        if (!p.proxmox) try notes.append(a, try std.fmt.allocPrint(a, "{s} is already {s} on Proxmox: this run continues a rename that stopped.", .{ op.old, op.new }));
        if (o.dns_note) |n| try notes.append(a, n);
        if (p.watch) if (o.watch_vm) |w| {
            if (!o.watch_ready) {
                try notes.append(a, try std.fmt.allocPrint(a, "The watchdog {s} is {s}: its step stays pending and the run ends with exit 8; start {s}, then run 'artoo vm rename {s} {s}' again.", .{ w.name, if (w.running()) "not answering (guest agent)" else w.status, w.name, op.old, op.new }));
            } else {
                try notes.append(a, try std.fmt.allocPrint(a, "Alerts active for {s} (a pending reboot, the root filesystem, …) resolve when its series are deleted, and fire again under {s} while still true.", .{ op.old, op.new }));
                try notes.append(a, try std.fmt.allocPrint(a, "Loki keeps {s}'s logs under host={s} until retention removes them; they are not carried over.", .{ op.old, op.old }));
            }
        };
        if (o.ts_note) |n| try notes.append(a, n);
        if (op.rex) |r| if (r.skipped()) |why|
            try notes.append(a, try std.fmt.allocPrint(a, "Rex host {s} kept: {s}; 'artoo rex hosts sync' replaces it with {s} later.", .{ r.label, why, op.new }));
        try notes.append(a, "Steps run in this order, each checking observed state first; after a failure run the same command again to continue.");
        try notes.append(a, "The UniFi rename uses PUT rest/user/{_id} with the name alone: expected from the classic API, not yet verified live.");
        try notes.append(a, try std.fmt.allocPrint(a, "Cloud-init's instance ID follows the name: at {s}'s next boot (a reboot too) cloud-init starts over as a new instance, regenerates the SSH host keys and runs its first-boot commands again. 'ssh {s}' then refuses the new key: compare the fingerprint it shows with the one 'artoo vm ssh-config --repin {s} -n' reads through the guest agent, then re-pin without -n.", .{ op.new, op.new, op.new }));
        return .{
            .action = try std.fmt.allocPrint(a, "Rename guest {s} ({d}) {s} {s}", .{ op.old, o.vm.vmid, arrow, op.new }),
            .risk = .destructive,
            .target = try std.fmt.allocPrint(a, "VM {d} on {s} + UniFi + this machine", .{ o.vm.vmid, op.c.node }),
            .changes = ch.items,
            .impact = try a.dupe([]const u8, &.{
                try std.fmt.allocPrint(a, "Other machines keep {s} in their known_hosts, ssh_config and password copies until they run 'artoo vm ssh-config' and receive the password again", .{op.old}),
                try std.fmt.allocPrint(a, "{s}'s metric history on the watchdog is deleted once {s} reports; its logs stay under {s} in Loki", .{ op.old, op.new, op.old }),
            }),
            .recovery = try std.fmt.allocPrint(a, "artoo vm rename {s} {s}", .{ op.new, op.old }),
            .notes = notes.items,
        };
    }

    /// The rule diff of every fence the fence step re-applies, as the
    /// renamed lab derives it (the VM under NEW, routes and
    /// `guests.fence_allow_out` naming NEW); kept for the step.
    fn fenceDiffs(op: *RenameOp, ctx: *Context, ch: *std.ArrayList(ui.blocks.Change)) !void {
        const a = ctx.arena;
        const o = op.o;
        if (o.fenced.len == 0) return;
        const cfg = try ctx.config();
        const allow = (try renameFenceList(a, cfg.guests.fence_allow_out, op.old, op.new)) orelse cfg.guests.fence_allow_out;
        const list = try a.dupe(vms.Vm, o.list);
        for (list) |*x| if (x.vmid == o.vm.vmid) {
            x.name = op.new;
        };
        const routes = try a.dupe(svc.Route, o.edge_routes);
        for (routes) |*r| if (std.ascii.eqlIgnoreCase(r.vm, op.old)) {
            r.vm = op.new;
        };
        const edge_addr = if (o.edge_vm) |e| try svc.edgeAddress(op.c, e) else null;
        const lab = try vm_fence.labFor(ctx, op.c, list, o.edge_vm, edge_addr, routes);
        var wants: std.ArrayList(FenceWant) = .empty;
        for (o.fenced) |name| {
            const x = for (list) |y| {
                if (!y.template and std.ascii.eqlIgnoreCase(y.name, name)) break y;
            } else continue;
            const want = try vm_fence.rules(a, try vm_fence.inputsWith(ctx, op.c, lab, x, routes, allow));
            try wants.append(a, .{ .name = x.name, .rules = want });
            const have = (try vm_fence.readState(op.c, x, want)).host.rules;
            var changed = false;
            for (0..@max(have.len, want.len)) |i| {
                const h: ?edge.Rule = if (i < have.len) have[i] else null;
                const w: ?edge.Rule = if (i < want.len) want[i] else null;
                if (h != null and w != null and h.?.eql(w.?)) continue;
                changed = true;
                try ch.append(a, .{
                    .field = try std.fmt.allocPrint(a, "fence {s} rule {d}", .{ x.name, i + 1 }),
                    .from = if (h) |r| try k.clean(ctx, try std.fmt.allocPrint(a, "{s} ({s})", .{ try vm_fence.describe(a, r), r.comment })) else null,
                    .to = if (w) |r| try std.fmt.allocPrint(a, "{s} ({s})", .{ try vm_fence.describe(a, r), r.comment }) else null,
                });
            }
            if (!changed) try ch.append(a, .{ .field = try std.fmt.allocPrint(a, "fence {s}", .{x.name}), .from = try std.fmt.allocPrint(a, "{d} rules", .{have.len}), .to = "rules unchanged" });
        }
        op.fence_want = wants.items;
    }

    /// OLD's recorded Rex host is renamed (Rex reachable).
    fn rexPending(op: *const RenameOp) bool {
        const r = op.rex orelse return false;
        return r.rex() != null;
    }

    /// `ssh://<guests.user>@<NEW's fqdn>`.
    fn rexEndpoint(op: *const RenameOp, ctx: *Context) ![]const u8 {
        const cfg = try ctx.config();
        return rex_hosts.endpoint(ctx.arena, cfg.guests.user, try dns.fqdn(ctx.arena, op.new, cfg.guests.domain));
    }

    /// The Rex host's plan line.
    fn rexChange(op: *const RenameOp, ctx: *Context) !ui.blocks.Change {
        const a = ctx.arena;
        const r = op.rex.?;
        const field = "Rex host";
        if (r.skipped() != null) return .{ .field = field, .from = r.label, .to = "kept (no Rex here; see the note)" };
        const h = r.listed orelse return .{ .field = field, .from = try std.fmt.allocPrint(a, "{s} in {s} (no such host now)", .{ r.label, rex_hosts.record_path }), .to = "dropped from the record" };
        return .{
            .field = field,
            .from = try std.fmt.allocPrint(a, "{s} ({s})", .{ try k.clean(ctx, h.label), try k.clean(ctx, try std.mem.join(a, ", ", h.endpoints)) }),
            .to = try std.fmt.allocPrint(a, "{s} ({s})", .{ op.new, try op.rexEndpoint(ctx) }),
        };
    }

    /// `rex hosts edit OLD --label NEW --endpoint E`, then the record;
    /// skipped without Rex. A failure fails only this step: its reason
    /// is returned for the end of the run.
    fn renameRexHost(op: *RenameOp, ctx: *Context, i: usize) !?[]const u8 {
        const a = ctx.arena;
        const l = &op.ledger;
        const r = op.rex.?;
        const x = r.rex() orelse {
            l.set(i, .skipped, r.skipped().?);
            return null;
        };
        var record = try rex_hosts.without(a, r.record, r.label);
        const ep = try op.rexEndpoint(ctx);
        if (r.listed != null) {
            l.set(i, .unknown, "");
            x.edit(r.label, op.new, ep) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    const why = ctx.diag orelse @errorName(err);
                    ctx.diag = null;
                    l.set(i, .failed, why);
                    return why;
                },
            };
            record = try rex_hosts.with(a, record, op.new);
        }
        rex_hosts.saveRecord(ctx, record) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => {
                const why = ctx.diag orelse @errorName(err);
                ctx.diag = null;
                l.set(i, .failed, why);
                return why;
            },
        };
        l.set(i, .done, if (r.listed != null) ep else try std.fmt.allocPrint(a, "{s} not listed; dropped from the record", .{r.label}));
        return null;
    }

    /// The watchdog's plan line.
    fn watchChange(op: *const RenameOp, ctx: *Context) !ui.blocks.Change {
        const a = ctx.arena;
        const o = op.o;
        const field = "watchdog";
        if (o.watch_skip) |why| return .{ .field = field, .from = "skipped", .to = why };
        const w = o.watch_vm.?;
        if (!o.watch_ready) return .{ .field = field, .from = try std.fmt.allocPrint(a, "{s} is {s}", .{ w.name, if (w.running()) "not answering" else w.status }), .to = "pending until it runs (exit 8; run this command again)" };
        if (!op.p.watch) return .{ .field = field, .from = "watchdog (done)", .to = try std.fmt.allocPrint(a, "Alloy reports as {s}", .{op.new}) };
        return .{
            .field = field,
            .from = try std.fmt.allocPrint(a, "Alloy reports as {s}; {d} series of {s} on {s}{s}", .{ if (o.label.len > 0) try k.clean(ctx, o.label) else "-", o.old_series, op.old, w.name, if (o.probes_old) try std.fmt.allocPrint(a, "; probes name {s}", .{op.old}) else "" }),
            .to = try std.fmt.allocPrint(a, "{s}re-enrolled as {s}, then (once {s}'s samples arrive, up to 2 min) {s}'s series deleted", .{ if (o.probes_old or o.routes.len > 0) "probes re-rendered, " else "", op.new, op.new, op.old }),
        };
    }

    pub fn fingerprint(op: *RenameOp) []const u8 {
        return op.fp;
    }

    /// A failure after the first step is exit 8 (what is done and what is
    /// left is in the ledger); an unknown outcome stays exit 7. Both name
    /// the re-run that continues. A step that ended in a definitive answer
    /// (a refusal, a failed command) is failed, never unknown.
    pub fn send(op: *RenameOp, ctx: *Context) !void {
        op.steps(ctx) catch |err| {
            if (err == error.OutOfMemory or err == error.Canceled) return err;
            const why = ctx.diag orelse @errorName(err);
            const unknown = err == error.OutcomeUnknown;
            const l = &op.ledger;
            if (!unknown) for (l.steps.items, 0..) |s, i| if (s.state == .unknown) l.set(i, .failed, if (s.detail.len > 0) s.detail else why);
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
            var done_n: usize = 0;
            for (l.steps.items) |s| done_n += @intFromBool(s.state == .done);
            if (done_n == 0) return err;
            const s_word = if (done_n == 1) "" else "s";
            if (unknown) return ctx.fail(error.OutcomeUnknown, "the rename stopped after {d} step{s} with an unknown outcome: {s}; check that place, then run 'artoo vm rename {s} {s}' again to continue", .{ done_n, s_word, why, op.old, op.new });
            return ctx.fail(error.Partial, "the rename stopped after {d} step{s}: {s}; run 'artoo vm rename {s} {s}' again to continue", .{ done_n, s_word, why, op.old, op.new });
        };
    }

    fn steps(op: *RenameOp, ctx: *Context) !void {
        const a = ctx.arena;
        const o = op.o;
        const p = op.p;
        const l = &op.ledger;
        const cfg = try ctx.config();
        // NEW resolves before anything points at it; OLD's places that
        // mark a stopped rename (hostname, UniFi record, OLD's DNS record)
        // go last, OLD's DNS record very last.
        const s_pve = if (p.proxmox) try l.add(a, "rename on Proxmox") else null;
        const s_dns_add = if (p.dns_add) try l.add(a, "add DNS record") else null;
        const s_svc = if (p.services) try l.add(a, "move the services") else null;
        const s_ssh = if (p.ssh) try l.add(a, "move the pinned key") else null;
        const s_secret = if (p.secret) try l.add(a, "move the password") else null;
        const s_rex = if (op.rex != null) try l.add(a, "rename the Rex host") else null;
        const s_fence = if (p.fence) try l.add(a, "update the fences") else null;
        const s_ts = if (p.tailnet) try l.add(a, "rename on the tailnet") else null;
        const s_watch = if (p.watch) try l.add(a, "move the watchdog series") else null;
        const s_guest = if (p.guest) try l.add(a, "set the hostname") else null;
        const s_unifi = if (p.unifi) try l.add(a, "rename the client record") else null;
        const s_dns_rm = if (p.dns_rm) try l.add(a, "remove old DNS record") else null;
        // (On failure `send` settles the running step and shows the ledger.)
        const vmid = o.vm.vmid;

        if (s_pve) |i| {
            l.set(i, .unknown, "");
            _ = try op.c.send(.PUT, try op.c.nodePath("/qemu/{d}/config", .{vmid}), &.{
                .{ .name = "name", .value = op.new },
                .{ .name = "digest", .value = o.digest },
            });
            l.set(i, .done, op.new);
        }
        const new_fqdn = try dns.fqdn(a, op.new, cfg.guests.domain);
        if (s_dns_add) |i| {
            l.set(i, .unknown, "");
            try dns.create(op.u, new_fqdn, o.dns_old.?.ipv4, dns.default_ttl);
            l.set(i, .done, new_fqdn);
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
        if (s_ssh) |i| {
            l.set(i, .unknown, "");
            if (o.key_old) |key| {
                if (o.key_new == null) try known_hosts.record(ctx, op.new, key);
                try known_hosts.record(ctx, op.old, null);
            }
            if (o.ssh_old) {
                // NEW's block as 'vm ssh-config' writes it; OLD's goes only
                // once NEW's is there.
                const b = try vm_ssh.blockFor(op.c, op.new, o.vm, o.cfg) orelse {
                    l.set(i, .failed, "no address for the ssh_config block");
                    return ctx.fail(error.Partial, "no usable address of {s} for its ssh_config block; {s}'s block is kept — run 'artoo vm ssh-config' once it has one", .{ op.new, op.old });
                };
                try vm_ssh.put(ctx, op.new, b);
                try vm_ssh.put(ctx, op.old, null);
            }
            l.set(i, .done, if (o.ssh_old) "known_hosts, ssh_config" else "known_hosts");
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
        // A failure fails only this step; the run goes on and ends exit 8.
        const rex_failed = if (s_rex) |i| try op.renameRexHost(ctx, i) else null;
        if (s_fence) |i| {
            l.set(i, .unknown, "");
            if (try renameFenceList(a, cfg.guests.fence_allow_out, op.old, op.new)) |text| try saveFenceList(ctx, text);
            var applied: usize = 0;
            for (o.fenced) |name| {
                const v = try vms.resolve(op.c, name);
                const want = try vm_fence.derive(ctx, op.c, v);
                // Only the rules the plan showed are applied.
                for (op.fence_want) |fw| if (std.ascii.eqlIgnoreCase(fw.name, v.name) and !sameRules(fw.rules, want)) {
                    l.set(i, .failed, v.name);
                    return ctx.fail(error.Partial, "the fence of {s} derives differently than the plan showed (the lab changed meanwhile); nothing applied to it — review with 'artoo vm fence {s} -n'", .{ v.name, v.name });
                };
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
            var set = false;
            if (s.running() and !std.ascii.eqlIgnoreCase(s.hostname, op.new)) {
                const r = try agent.exec(op.c, vmid, &.{ "sh", "-c", tailnet_script, "sh", op.new }, null, 60_000);
                if (!r.ok()) {
                    l.set(i, .failed, "");
                    return ctx.fail(error.Partial, "tailscale set --hostname failed on {s}: {s}", .{ op.new, try k.clean(ctx, edge.firstLine(r.err)) });
                }
                set = true;
            }
            var detail: []const u8 = op.new;
            if (op.tsc) |*t| if (s.node_id.len > 0) {
                // The control plane takes a moment to show the new
                // hostname; only a name set by hand in the console keeps
                // the old one — then the device itself is renamed.
                var tries: usize = 0;
                while (true) : (tries += 1) {
                    const d = (try tn.getDevice(t, s.node_id)) orelse break;
                    if (std.ascii.eqlIgnoreCase(d.machine, op.new)) break;
                    if (!set or tries >= tailnet_polls) {
                        try tn.renameDevice(t, d.id, op.new);
                        detail = try std.fmt.allocPrint(a, "{s} (device renamed through the API)", .{op.new});
                        break;
                    }
                    l.note(i, "waiting for the control plane to show the new name");
                    try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 2000)), .awake);
                }
            };
            l.set(i, .done, detail);
        }
        // A stopped watchdog: the step stays pending; the other steps run
        // and the run ends with exit 8 (the guest's Alloy label, still
        // OLD, lets the re-run continue).
        var watch_blocked = false;
        if (s_watch) |i| {
            const w = o.watch_vm.?;
            if (!o.watch_ready) {
                watch_blocked = true;
                l.set(i, .failed, try std.fmt.allocPrint(a, "pending: {s} is {s}", .{ w.name, if (w.running()) "not answering" else w.status }));
            } else {
                l.set(i, .unknown, "");
                try op.moveWatch(ctx, i, w);
            }
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
        if (s_dns_rm) |i| {
            l.set(i, .unknown, "");
            try dns.delete(op.u, o.dns_old.?.id);
            l.set(i, .done, try k.clean(ctx, o.dns_old.?.domain));
        }
        if (watch_blocked) {
            const w = o.watch_vm.?;
            return ctx.fail(error.Partial, "the watchdog {s} is {s}, so its step is pending ({s}'s Alloy still reports as {s}); start {s}", .{ w.name, if (w.running()) "not answering" else w.status, op.new, if (o.label.len > 0) try k.clean(ctx, o.label) else op.old, w.name });
        }
        if (rex_failed) |why| return ctx.fail(error.Partial, "the Rex host {s} was not renamed ({s}); 'artoo rex hosts sync' replaces it with {s}", .{ op.rex.?.label, why, op.new });
    }

    /// The watchdog step: the probes re-rendered for the
    /// services that moved, the guest re-enrolled under NEW, then — only
    /// once NEW's samples arrive — OLD's series deleted as 'watch forget'.
    fn moveWatch(op: *RenameOp, ctx: *Context, i: usize, w: vms.Vm) !void {
        const a = ctx.arena;
        const o = op.o;
        const l = &op.ledger;
        var what: std.ArrayList(u8) = .empty;
        if ((o.probes_old or o.routes.len > 0) and o.edge_vm != null) {
            l.note(i, "re-rendering the probes");
            if (try watch.refreshProbes(ctx, op.c, w)) try what.appendSlice(a, "probes re-rendered, ");
        }
        if (!std.ascii.eqlIgnoreCase(o.label, op.new)) {
            l.note(i, try std.fmt.allocPrint(a, "re-enrolling as {s}", .{op.new}));
            _ = try watch.enrollNew(ctx, op.c, try vms.resolve(op.c, op.new));
            try what.print(a, "re-enrolled as {s}", .{op.new});
        } else try what.print(a, "enrolled as {s}", .{op.new});
        if (o.old_series > 0) {
            // Never forget OLD before NEW reports: until then OLD's series
            // are all the watchdog has of this guest.
            var tries: usize = 0;
            while (true) : (tries += 1) {
                const n = watch.hostSeriesSince(op.c, w, op.new, "-5m") catch |err| return op.forgetLater(ctx, i, w, err);
                if (n > 0) break;
                if (tries >= watch_polls) {
                    l.set(i, .failed, try std.fmt.allocPrint(a, "no samples from {s} yet", .{op.new}));
                    return ctx.fail(error.Partial, "{s} sent no samples to {s} within 2 minutes; {s}'s series are kept — once {s} reports, 'artoo watch forget {s}' deletes them", .{ op.new, w.name, op.old, op.new, op.old });
                }
                l.note(i, try std.fmt.allocPrint(a, "waiting for {s}'s samples", .{op.new}));
                try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 5000)), .awake);
            }
            const n = watch.forgetHost(op.c, w, op.old) catch |err| return op.forgetLater(ctx, i, w, err);
            try what.print(a, ", {d} series of {s} deleted", .{ n, op.old });
        }
        l.set(i, .done, try std.fmt.allocPrint(a, "{s} on {s}", .{ what.items, w.name }));
    }

    /// A failure between the re-enrollment and the forget: OLD's series
    /// stay, and 'watch forget OLD' (or the re-run) deletes them.
    fn forgetLater(op: *RenameOp, ctx: *Context, i: usize, w: vms.Vm, err: anyerror) anyerror {
        if (err == error.OutOfMemory or err == error.Canceled) return err;
        const why = ctx.diag orelse @errorName(err);
        op.ledger.set(i, .failed, why);
        return ctx.fail(error.Partial, "{s}; {s}'s series may remain on {s} — 'artoo watch forget {s}' deletes them", .{ why, op.old, w.name, op.old });
    }

    pub fn verify(op: *RenameOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        if (!op.ledger.complete()) return false;
        op.check_trace = false;
        const o = try op.observe(ctx);
        const left = op.pending(o);
        if (left.any()) return false;
        // The places that must now carry NEW.
        if (!std.mem.eql(u8, o.vm.name, op.new) or !std.mem.eql(u8, o.hostname, op.new)) return false;
        if (o.record) |r| if (!std.mem.eql(u8, r.name, op.new)) return false;
        if (op.o.dns_old != null and o.dns_new == null) return false;
        if ((op.o.secret_old or op.o.secret_new) and !o.secret_new) return false;
        if (op.o.key_old != null and o.key_new == null) return false;
        if (op.o.ssh_old and (o.ssh_old or !o.ssh_new)) return false;
        if (op.rexPending()) {
            const rec = try rex_hosts.loadRecord(ctx);
            if (rex_hosts.has(rec, op.old)) return false;
            if (op.rex.?.listed != null and !rex_hosts.has(rec, op.new)) return false;
        }
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
    pub const summary = "Rename a guest everywhere its name lives (high-impact)";
    pub const details =
        \\An artoo guest's name is also its hostname, DNS and UniFi records,
        \\pinned key, password entry and more; this command changes all of
        \\them, one step each, in this order:
        \\  - the VM's name in Proxmox
        \\  - the DNS record for NEW
        \\  - the services routed to it
        \\  - the pinned host key and ~/.artoo/ssh_config
        \\  - the stored password guest/NAME
        \\  - its Rex host on this machine, when 'artoo rex hosts sync' added
        \\    it (skipped with a note without a running Rex)
        \\  - the fence exceptions that name it
        \\  - its tailnet name and the watchdog
        \\  - the guest's hostname and /etc/hosts
        \\  - the UniFi client record
        \\  - last, the DNS record for OLD is removed
        \\
        \\Each step checks the current state first, so after a failure the
        \\same command picks up where it stopped.
        \\
        \\Refused: the edge VM and the watchdog (rebuild those), templates,
        \\VMs artoo did not create, and stopped guests.
        \\
        \\Type OLD to confirm, or pass --yes --confirm OLD.
    ;
    pub const positionals = [_]cli.Positional{
        .{ .name = "OLD", .help = "The guest's current name", .complete = .vm },
        .{ .name = "NEW", .help = "Its new name (one DNS label, as for vm new)" },
    };
    pub const flags = [_]cli.Flag{.{ .long = "confirm", .kind = .string, .metavar = "OLD", .help = "The guest's current name, to confirm with --yes" }};
    pub const examples = [_][]const u8{ "artoo vm rename naboo hoth -n", "artoo vm rename naboo hoth", "artoo vm rename naboo hoth --yes --confirm naboo" };

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
    // CRLF lines: the CR is no part of the last name.
    try testing.expect(hostsNames("127.0.0.1 localhost\r\n127.0.1.1 naboo\r\n", "naboo"));
    try testing.expect(hostsNames("127.0.1.1 naboo.lab.example.com\r\n", "naboo"));
    try testing.expectEqualStrings("naboo 192.168.1.10 tcp 8006; hoth dagobah udp 53", (try renameFenceList(a, "scarif 192.168.1.10 tcp 8006; hoth dagobah udp 53", "scarif", "naboo")).?);
    try testing.expectEqualStrings("hoth naboo tcp 5432", (try renameFenceList(a, "hoth scarif tcp 5432", "scarif", "naboo")).?);
    try testing.expect(try renameFenceList(a, "hoth dagobah udp 53", "scarif", "naboo") == null);
}

const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const FakeRunner = @import("../secrets/common.zig").FakeRunner;
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
        "at hoth's next boot (a reboot too) cloud-init starts over as a new instance",
        "'artoo vm ssh-config --repin hoth -n'",
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
        fn f(al: std.mem.Allocator, l: []const u8, users: []const u8, site: bool, edge_out: []const u8) ![]const R {
            var out: std.ArrayList(R) = .empty;
            const reads = try renameReads(al, l, users, dns_new_body, "hoth", site);
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
    // A stopped rename: the UniFi record still names OLD (its trace).
    try routes.appendSlice(a, try pass(a, list, users_old, true, try dump(a, d, "naboo")));
    try routes.appendSlice(a, &.{
        rt("POST /api2/json/nodes/pve/qemu/204/agent/exec HTTP", "{\"data\":{\"pid\":51}}"),
        rt("qemu/204/agent/exec-status", try agentOut(a, 0, "")),
        rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
    });
    try routes.appendSlice(a, try pass(a, list, users_new, false, try dump(a, d, "hoth")));
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

test "vm rename: a guest without a static address gets NEW's ssh_config block from the agent's address" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dhcp_cfg = "{\"data\":{\"name\":\"naboo\",\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0\",\"tags\":\"artoo\",\"digest\":\"d1\"}}";
    const ifaces = "{\"data\":{\"result\":[{\"name\":\"lo\",\"ip-addresses\":[{\"ip-address\":\"127.0.0.1\",\"ip-address-type\":\"ipv4\",\"prefix\":8}]},{\"name\":\"eth0\",\"ip-addresses\":[{\"ip-address\":\"192.168.1.231\",\"ip-address-type\":\"ipv4\",\"prefix\":24}]}]}}";
    const none = "{\"meta\":{\"rc\":\"ok\"},\"data\":[]}";
    const no_dns = "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}";
    const reads = struct {
        fn f(al: std.mem.Allocator, list: []const u8, cfg: []const u8, host: []const u8, site: bool) ![]const R {
            var out: std.ArrayList(R) = .empty;
            try out.appendSlice(al, &.{
                rt("GET /api2/json/nodes/pve/qemu HTTP", list),
                rt("agent/ping", "{\"data\":{\"result\":{}}}"),
                rt("GET /api2/json/nodes/pve/qemu/201/config", cfg),
                rt("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
                rt("exec-status", try agentOut(al, 0, try std.fmt.allocPrint(al, "{s}\n---\n127.0.0.1 localhost\n", .{host}))),
                rt("rest/user HTTP", none),
            });
            if (site) try out.append(al, rt("GET /v1/sites?", sites));
            try out.appendSlice(al, &.{
                rt("GET /v1/sites/S1/dns/policies", no_dns),
                rt("GET /api2/json/nodes/pve/qemu HTTP", list),
            });
            return out.items;
        }
    }.f;
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try reads(a, list_old, dhcp_cfg, "naboo", true));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("agent/ping", "{\"data\":{\"result\":{}}}"),
        rt("agent/network-get-interfaces", ifaces),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        rt("exec-status", try agentOut(a, 0, "")),
    });
    try routes.appendSlice(a, try reads(a, list_new, dhcp_cfg, "hoth", false));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/ssh_config", .data = "Host naboo naboo.lab.example.com\n  HostName 192.168.1.231\n  HostKeyAlias naboo\n" });
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const text = try g.tmp.dir.readFileAlloc(testing.io, ".artoo/ssh_config", a, .limited(1 << 16));
    try testing.expect(std.mem.find(u8, text, "Host hoth hoth.lab.example.com\n  HostName 192.168.1.231\n") != null);
    try testing.expect(std.mem.find(u8, text, "Host naboo") == null);
}

/// A rename of naboo to hoth that only touches Proxmox and the hostname
/// (and the Rex host): the routes for one run, then its verify.
fn rexRenameRoutes(a: std.mem.Allocator) ![]const R {
    const cfg = "{\"data\":{\"name\":\"naboo\",\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0\",\"tags\":\"artoo;rex\",\"digest\":\"d1\"}}";
    const none = "{\"meta\":{\"rc\":\"ok\"},\"data\":[]}";
    const no_dns = "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}";
    const reads = struct {
        fn f(al: std.mem.Allocator, list: []const u8, c: []const u8, host: []const u8, site: bool) ![]const R {
            var out: std.ArrayList(R) = .empty;
            try out.appendSlice(al, &.{
                rt("GET /api2/json/nodes/pve/qemu HTTP", list),
                rt("agent/ping", "{\"data\":{\"result\":{}}}"),
                rt("GET /api2/json/nodes/pve/qemu/201/config", c),
                rt("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
                rt("exec-status", try agentOut(al, 0, try std.fmt.allocPrint(al, "{s}\n---\n127.0.0.1 localhost\n", .{host}))),
                rt("rest/user HTTP", none),
            });
            if (site) try out.append(al, rt("GET /v1/sites?", sites));
            try out.appendSlice(al, &.{
                rt("GET /v1/sites/S1/dns/policies", no_dns),
                rt("GET /api2/json/nodes/pve/qemu HTTP", list),
            });
            return out.items;
        }
    }.f;
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try reads(a, list_old, cfg, "naboo", true));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        rt("exec-status", try agentOut(a, 0, "")),
    });
    try routes.appendSlice(a, try reads(a, list_new, cfg, "hoth", false));
    return routes.items;
}

test "vm rename: the recorded Rex host is renamed, its endpoint NEW's machine name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.initRoutes(try rexRenameRoutes(a));
    defer g.deinit();
    const rh = @import("rex_hosts.zig");
    const exe = try rh.fakeRex(&g);
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/rex-hosts.json", .data = "{\"labels\":[\"naboo\",\"tatooine\"]}\n" });
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(&.{ exe, "hosts", "list", "--json", "--autostart=false" }, null, .{ .stdout = try rh.listJson(a, &.{.{ .label = "naboo", .endpoints = &.{"ssh://artoo@naboo.lab.example.com"} }}) });
    try fake.expect(&.{ exe, "hosts", "edit", "naboo", "--label", "hoth", "--endpoint", "ssh://artoo@hoth.lab.example.com", "--autostart=false" }, null, .{});
    g.h.hooks.runner = fake.runner();
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try fake.done();
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    for ([_][]const u8{
        "Rex host      naboo (ssh://artoo@naboo.lab.example.com) → hoth (ssh://artoo@hoth.lab.example.com)\n",
        "✓ rename the Rex host  done  ssh://artoo@hoth.lab.example.com",
    }) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
    try testing.expectEqualStrings("{\n  \"labels\": [\n    \"hoth\",\n    \"tatooine\"\n  ]\n}\n", try g.tmp.dir.readFileAlloc(testing.io, ".artoo/rex-hosts.json", a, .limited(1 << 16)));
}

test "vm rename: a failed Rex host rename fails only its step; the rest runs, exit 8 names rex hosts sync" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try rexRenameRoutes(a));
    // No verify read after a failed step.
    routes.items.len -= 8;
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    const rh = @import("rex_hosts.zig");
    const exe = try rh.fakeRex(&g);
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/rex-hosts.json", .data = "{\"labels\":[\"naboo\"]}\n" });
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(&.{ exe, "hosts", "list", "--json", "--autostart=false" }, null, .{ .stdout = try rh.listJson(a, &.{.{ .label = "naboo", .endpoints = &.{"ssh://artoo@naboo.lab.example.com"} }}) });
    try fake.expect(&.{ exe, "hosts", "edit", "naboo", "--label", "hoth", "--endpoint", "ssh://artoo@hoth.lab.example.com", "--autostart=false" }, null, .{ .code = 1, .stderr = "a host called hoth exists\n" });
    g.h.hooks.runner = fake.runner();
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    try fake.done();
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expect(std.mem.find(u8, g.h.stdout(), "✓ set the hostname") != null);
    try testing.expect(std.mem.find(u8, g.h.stderr(), "the Rex host naboo was not renamed ('rex hosts edit' failed (exit 1): a host called hoth exists); 'artoo rex hosts sync' replaces it with hoth") != null);
    try testing.expectEqualStrings("{\"labels\":[\"naboo\"]}\n", try g.tmp.dir.readFileAlloc(testing.io, ".artoo/rex-hosts.json", a, .limited(1 << 16)));
}

test "vm rename: without a running Rex the Rex host step is skipped with a note" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.initRoutes(try rexRenameRoutes(a));
    defer g.deinit();
    const exe = try @import("rex_hosts.zig").fakeRex(&g);
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/rex-hosts.json", .data = "{\"labels\":[\"naboo\"]}\n" });
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(&.{ exe, "hosts", "list", "--json", "--autostart=false" }, null, .{ .code = 1, .stderr = "no server\n" });
    g.h.hooks.runner = fake.runner();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    try fake.done();
    const out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "Rex host naboo kept: no running Rex on this machine ('rex hosts list' failed (exit 1): no server); 'artoo rex hosts sync' replaces it with hoth later.") != null);
    try testing.expect(std.mem.find(u8, out, "rename the Rex host  skipped  no running Rex") != null);
}

test "vm rename: the /etc/hosts rewrite keeps a line's CR out of the comparison and puts it back" {
    // Run the script's awk program when this machine has awk (its
    // behaviour is the point); the script must carry the CR handling.
    try testing.expect(std.mem.find(u8, guest_script, "if (sub(/\\r$/, \"\")) cr = \"\\r\"") != null);
    const start = std.mem.find(u8, guest_script, "awk -v").?;
    const prog_start = std.mem.findScalarPos(u8, guest_script, start, '\'').? + 1;
    const prog_end = std.mem.findScalarPos(u8, guest_script, prog_start, '\'').?;
    const prog = guest_script[prog_start..prog_end];
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "hosts", .data = "127.0.0.1 localhost\r\n# naboo\r\n127.0.1.1 naboo.lab.example.com naboo\r\n127.0.1.2 naboo2\n" });
    const path = try tmp.dir.realPathFileAlloc(testing.io, "hosts", testing.allocator);
    defer testing.allocator.free(path);
    const res = std.process.run(testing.allocator, testing.io, .{ .argv = &.{ "awk", "-v", "new=hoth", "-v", "old=naboo", prog, path } }) catch return error.SkipZigTest;
    defer testing.allocator.free(res.stdout);
    defer testing.allocator.free(res.stderr);
    try testing.expectEqualStrings("127.0.0.1 localhost\r\n# naboo\r\n127.0.1.1 hoth.lab.example.com hoth\r\n127.0.1.2 naboo2\n", res.stdout);
}

test "vm rename: a failure after the first step is exit 8 and says how to continue" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list_old, users_old, dns_old_body, "naboo", true));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        .{ .match = "PUT /proxy/network/api/s/default/rest/user/U1", .behavior = .{ .respond = .{ .status = 400, .body = "{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.Invalid\"},\"data\":[]}" } } },
    });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expect(std.mem.find(u8, g.h.stderr(), "the rename stopped after 3 steps") != null);
    try testing.expect(std.mem.find(u8, g.h.stderr(), "run 'artoo vm rename naboo hoth' again to continue") != null);
    try testing.expect(std.mem.find(u8, g.h.stdout(), "✓ set the hostname") != null);
    // UniFi's 400 is a refusal: the step failed, it is not unknown.
    try testing.expect(std.mem.find(u8, g.h.stdout(), "rename the client record  failed") != null);
    // OLD's DNS record goes last: never removed by a run that stopped.
    for (g.srv.received) |req| if (req) |q| try testing.expect(!std.mem.startsWith(u8, q, "DELETE /v1/sites/S1/dns/policies"));
}

test "vm rename: a failure reported from inside a step also names the re-run" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list_old, users_old, dns_old_body, "naboo", true));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        rt("exec-status", try agentOut(a, 1, "")),
    });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "the rename stopped after 2 steps: setting the hostname of hoth failed") != null);
    try testing.expect(std.mem.find(u8, g.h.stderr(), "run 'artoo vm rename naboo hoth' again to continue") != null);
    var failed_line = false;
    var it = std.mem.splitScalar(u8, g.h.stdout(), '\n');
    while (it.next()) |ln| failed_line = failed_line or (std.mem.find(u8, ln, "set the hostname") != null and std.mem.find(u8, ln, "failed") != null);
    try testing.expect(failed_line);
}

test "vm rename: a VM under NEW alone continues only with a trace of OLD; leftovers under NEW refuse" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const Case = struct { list: []const u8, users: []const u8, dns: []const u8, host: []const u8, setup: enum { none, secret, key, fence }, want: []const u8 };
    const cases = [_]Case{
        // hoth is no stopped rename of naboo: nothing on it names naboo.
        .{ .list = list_new, .users = users_new, .dns = dns_new_body, .host = "hoth", .setup = .none, .want = "no VM is named naboo, and hoth carries no trace of it" },
        // Before the rename began, NEW's places hold another guest's leftovers.
        .{ .list = list_old, .users = users_old, .dns = dns_old_body, .host = "naboo", .setup = .secret, .want = "guest/hoth already exists" },
        .{ .list = list_old, .users = users_old, .dns = dns_old_body, .host = "naboo", .setup = .key, .want = "already pins a host key under hoth" },
        .{ .list = list_old, .users = users_old, .dns = dns_old_body, .host = "naboo", .setup = .fence, .want = "guests.fence_allow_out already names hoth" },
    };
    for (cases) |cs| {
        var g: testkit.Gateway = undefined;
        try g.initRoutes(try renameReads(a, cs.list, cs.users, cs.dns, cs.host, true));
        defer g.deinit();
        try g.tmp.dir.createDirPath(testing.io, ".artoo");
        switch (cs.setup) {
            .none => {},
            .secret => try g.mem.map.put(g.h.arena.allocator(), "guest/hoth", "someone-else"),
            .key => try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/known_hosts", .data = "hoth " ++ test_key ++ "\n" }),
            .fence => try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = "{\"schema_version\":1,\"guests\":{\"fence_allow_out\":\"hoth 192.168.1.50 tcp 5432\"}}\n" }),
        }
        try testing.expectEqual(Exit.refused, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
        if (std.mem.find(u8, g.h.stderr(), cs.want) == null) {
            std.debug.print("want {s}, got: {s}\n", .{ cs.want, g.h.stderr() });
            return error.TestUnexpectedResult;
        }
        for (g.srv.received) |req| if (req) |q| try testing.expect(std.mem.startsWith(u8, q, "GET ") or std.mem.find(u8, q, "/agent/") != null);
    }
}

test "vm rename: the plan shows the rule diff of every fence it re-applies" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const list = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":207,\"name\":\"endor\",\"status\":\"running\",\"tags\":\"artoo;fenced\"}]}";
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list, users_old, dns_old_body, "naboo", true));
    try routes.appendSlice(a, &.{
        // endor's exception names naboo: its address is read for the rule.
        rt("GET /api2/json/nodes/pve/qemu/201/config", cfg_body),
        rt("GET /api2/json/nodes/pve/qemu/207/config", "{\"data\":{\"name\":\"endor\",\"net0\":\"virtio=BC:24:11:00:00:07,bridge=vmbr0,firewall=1\",\"ipconfig0\":\"ip=192.168.1.240/24,gw=192.168.1.1\",\"tags\":\"artoo;fenced\",\"digest\":\"d7\"}}"),
        rt("GET /api2/json/nodes/pve/qemu/207/firewall/options", "{\"data\":{}}"),
        rt("GET /api2/json/nodes/pve/qemu/207/firewall/rules", "{\"data\":[{\"pos\":0,\"type\":\"out\",\"action\":\"ACCEPT\",\"dest\":\"192.168.1.230\",\"proto\":\"tcp\",\"dport\":\"5432\",\"comment\":\"artoo: allow-out naboo (config)\"}]}"),
        rt("GET /api2/json/nodes/pve/qemu/207/firewall/ipset", "{\"data\":[]}"),
    });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = "{\"schema_version\":1,\"guests\":{\"fence_allow_out\":\"endor naboo tcp 5432\"}}\n" });
    const code = g.h.run(&root, "vm rename naboo hoth -n");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    for ([_][]const u8{
        "1 guests.fence_allow_out entry naming naboo",
        "fence endor rule 1",
        "OUT ACCEPT tcp 5432 to 192.168.1.230 (artoo: allow-out naboo (config))",
        "allow-out hoth (config)",
    }) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
    // A dry run: the configuration still names naboo.
    const cfg = try g.tmp.dir.readFileAlloc(testing.io, ".artoo/config.json", a, .limited(1 << 16));
    try testing.expect(std.mem.find(u8, cfg, "endor naboo tcp 5432") != null);
}

const list_w_old = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":205,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"}]}";
const list_w_new = "{\"data\":[{\"vmid\":201,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":205,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"}]}";

fn onVm(a: std.mem.Allocator, vmid: u32, out: []const u8) ![2]R {
    return .{
        rt(try std.fmt.allocPrint(a, "POST /api2/json/nodes/pve/qemu/{d}/agent/exec HTTP", .{vmid}), "{\"data\":{\"pid\":60}}"),
        rt(try std.fmt.allocPrint(a, "qemu/{d}/agent/exec-status", .{vmid}), try agentOut(a, 0, out)),
    };
}

fn series(n: usize) []const u8 {
    return switch (n) {
        0 => "{\"status\":\"success\",\"data\":[]}",
        else => "{\"status\":\"success\",\"data\":[{},{},{}]}",
    };
}

/// The watchdog's part of a read: the guest's Alloy label, then (the
/// watchdog answering) OLD's series and the probes.
fn watchReads(a: std.mem.Allocator, out: *std.ArrayList(R), label: []const u8, old_series: usize) !void {
    try out.appendSlice(a, &try onVm(a, 201, label));
    try out.append(a, rt("qemu/205/agent/ping", "{\"data\":{\"result\":{}}}"));
    try out.appendSlice(a, &try onVm(a, 205, series(old_series)));
    try out.appendSlice(a, &try onVm(a, 205, ""));
}

/// Re-enrolling the guest under NEW: the lookups, its Alloy probe (no file
/// in place), every file written, the install and the start.
fn reenrollRoutes(a: std.mem.Allocator, out: *std.ArrayList(R)) !void {
    try out.appendSlice(a, &.{
        rt("GET /api2/json/nodes/pve/qemu HTTP", list_w_new),
        rt("GET /api2/json/nodes/pve/qemu HTTP", list_w_new),
    });
    const wfiles = @import("../watch/files.zig");
    const n = (try wfiles.guestFiles(a, .{ .name = "hoth", .watch_host = "scarif.lab.example.com" }, .{ .pve = "192.168.1.10", .gateway = "192.168.1.1", .lan = "192.168.1.0/24", .pool = "", .edge = "", .domain = "lab.example.com" })).len;
    for (0..n + 3) |_| try out.appendSlice(a, &try onVm(a, 201, ""));
}

fn writesTo(g: *testkit.Gateway, what: []const u8) usize {
    var n: usize = 0;
    for (g.srv.received) |req| if (req) |q| {
        if (std.mem.find(u8, q, what) != null) n += 1;
    };
    return n;
}

fn firstIndex(g: *testkit.Gateway, what: []const u8) ?usize {
    for (g.srv.received, 0..) |req, i| if (req) |q| if (std.mem.find(u8, q, what) != null) return i;
    return null;
}

test "vm rename: the watchdog re-enrolls NEW, waits for NEW's samples, only then forgets OLD" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list_w_old, users_old, dns_old_body, "naboo", true));
    try watchReads(a, &routes, "naboo", 3);
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
    });
    try reenrollRoutes(a, &routes);
    // NEW's samples: none yet, then some; then OLD's series deleted.
    try routes.appendSlice(a, &try onVm(a, 205, series(0)));
    try routes.appendSlice(a, &try onVm(a, 205, series(3)));
    try routes.appendSlice(a, &try onVm(a, 205, series(3)));
    try routes.appendSlice(a, &try onVm(a, 205, ""));
    try routes.appendSlice(a, &try onVm(a, 205, series(0)));
    try routes.appendSlice(a, &.{
        rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
        rt("DELETE /v1/sites/S1/dns/policies/R1", ""),
    });
    try routes.appendSlice(a, try renameReads(a, list_w_new, users_new, dns_new_body, "hoth", false));
    try watchReads(a, &routes, "hoth", 0);
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    for ([_][]const u8{
        "Alloy reports as naboo; 3 series of naboo on scarif",
        "re-enrolled as hoth, then (once hoth's samples arrive, up to 2 min) naboo's series deleted",
        "Alerts active for naboo",
        "Loki keeps naboo's logs under host=naboo",
        "re-enrolled as hoth, 3 series of naboo deleted on scarif",
    }) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
    // The order: enrolled (Alloy started), NEW asked twice, then the delete.
    const start = firstIndex(&g, "systemctl%20restart%20alloy") orelse firstIndex(&g, "systemctl+restart+alloy");
    const asked = firstIndex(&g, "start%3D-5m").?;
    const delete = firstIndex(&g, "delete_series").?;
    if (start) |s| try testing.expect(s < asked);
    try testing.expect(asked < delete);
    try testing.expectEqual(@as(usize, 2), writesTo(&g, "start%3D-5m"));
}

test "vm rename: no samples from NEW within the wait keeps OLD's series and names watch forget" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list_w_old, users_old, dns_old_body, "naboo", true));
    try watchReads(a, &routes, "naboo", 3);
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
    });
    try reenrollRoutes(a, &routes);
    for (0..watch_polls + 1) |_| try routes.appendSlice(a, &try onVm(a, 205, series(0)));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const err = g.h.stderr();
    try testing.expect(std.mem.find(u8, err, "hoth sent no samples to scarif within 2 minutes") != null);
    try testing.expect(std.mem.find(u8, err, "'artoo watch forget naboo' deletes them") != null);
    try testing.expect(std.mem.find(u8, err, "run 'artoo vm rename naboo hoth' again to continue") != null);
    try testing.expectEqual(@as(usize, 0), writesTo(&g, "delete_series"));
}

test "vm rename: a no-watch guest skips the watchdog step; a stopped watchdog leaves it pending" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    {
        const list = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;no-watch\"},{\"vmid\":205,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"}]}";
        const reads = try renameReads(a, list, users_old, dns_old_body, "naboo", true);
        var g: testkit.Gateway = undefined;
        // No watchdog lookup at all.
        try g.initRoutes(reads[0 .. reads.len - 1]);
        defer g.deinit();
        try testing.expectEqual(Exit.ok, g.h.run(&root, "vm rename naboo hoth -n"));
        try testing.expectEqual(@as(usize, 0), g.srv.unused());
        try testing.expect(std.mem.find(u8, g.h.stdout(), "tagged no-watch") != null);
        try testing.expectEqual(@as(usize, 0), writesTo(&g, "qemu/205"));
    }
    {
        const stopped_old = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":205,\"name\":\"scarif\",\"status\":\"stopped\",\"tags\":\"artoo;role-watch\"}]}";
        var routes: std.ArrayList(R) = .empty;
        try routes.appendSlice(a, try renameReads(a, stopped_old, users_old, dns_old_body, "naboo", true));
        try routes.appendSlice(a, &try onVm(a, 201, "naboo"));
        try routes.appendSlice(a, &.{
            rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
            rt("POST /v1/sites/S1/dns/policies", "{}"),
            rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
            rt("exec-status", try agentOut(a, 0, "")),
            rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
            rt("DELETE /v1/sites/S1/dns/policies/R1", ""),
        });
        var g: testkit.Gateway = undefined;
        try g.initRoutes(routes.items);
        defer g.deinit();
        try testing.expectEqual(Exit.partial, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
        try testing.expectEqual(@as(usize, 0), g.srv.unused());
        const out = g.h.stdout();
        try testing.expect(std.mem.find(u8, out, "scarif is stopped") != null);
        try testing.expect(std.mem.find(u8, out, "its step stays pending and the run ends with exit 8") != null);
        try testing.expect(std.mem.find(u8, out, "pending: scarif is stopped") != null);
        const err = g.h.stderr();
        try testing.expect(std.mem.find(u8, err, "the watchdog scarif is stopped, so its step is pending") != null);
        try testing.expect(std.mem.find(u8, err, "run 'artoo vm rename naboo hoth' again to continue") != null);
        // Nothing was asked of the stopped watchdog.
        try testing.expectEqual(@as(usize, 0), writesTo(&g, "qemu/205"));
    }
}

test "vm rename: a broken Tailscale credential is a note; the guest's own tailscale set still runs" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const status = struct {
        fn f(al: std.mem.Allocator, host: []const u8) ![]const u8 {
            return agentOut(al, 0, try std.fmt.allocPrint(al, "{{\"BackendState\":\"Running\",\"Self\":{{\"ID\":\"nN\",\"HostName\":\"{s}\",\"DNSName\":\"{s}.example.ts.net.\",\"Tags\":[\"tag:lab-guest\"]}}}}", .{ host, host }));
        }
    }.f;
    const reads = struct {
        fn f(al: std.mem.Allocator, list: []const u8, users: []const u8, records: []const u8, host: []const u8, site: bool, ts_host: []const u8) ![]const R {
            const base = try renameReads(al, list, users, records, host, site);
            var out: std.ArrayList(R) = .empty;
            try out.appendSlice(al, base[0 .. base.len - 1]);
            try out.appendSlice(al, &.{
                rt("agent/exec HTTP", "{\"data\":{\"pid\":44}}"),
                rt("exec-status", try status(al, ts_host)),
                .{ .match = "POST /oauth/token", .behavior = .{ .respond = .{ .status = 401, .body = "{\"message\":\"invalid client\"}" } } },
            });
            try out.append(al, base[base.len - 1]);
            return out.items;
        }
    }.f;
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try reads(a, list_ts_old, users_old, dns_old_body, "naboo", true, "naboo"));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":45}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":46}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
        rt("DELETE /v1/sites/S1/dns/policies/R1", ""),
    });
    try routes.appendSlice(a, try reads(a, list_ts_new, users_new, dns_new_body, "hoth", false, "hoth"));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try g.tailscaleConfig("");
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expect(std.mem.find(u8, g.h.stdout(), "The Tailscale API did not answer") != null);
    try testing.expect(std.mem.find(u8, g.h.stdout(), "runs 'tailscale set --hostname' only") != null);
    var set = false;
    for (g.srv.received) |req| if (req) |q| {
        set = set or std.mem.find(u8, q, "tailscale%20set%20--hostname") != null or std.mem.find(u8, q, "tailscale+set+--hostname") != null;
    };
    try testing.expect(set);
}

const list_ts_old = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;tailnet\"}]}";
const list_ts_new = "{\"data\":[{\"vmid\":201,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo;tailnet\"}]}";

fn tsStatus(a: std.mem.Allocator, host: []const u8) ![]const u8 {
    return agentOut(a, 0, try std.fmt.allocPrint(a, "{{\"BackendState\":\"Running\",\"Self\":{{\"ID\":\"nN\",\"HostName\":\"{s}\",\"DNSName\":\"{s}.example.ts.net.\",\"Tags\":[\"tag:lab-guest\"]}}}}", .{ host, host }));
}

fn tsDevice(a: std.mem.Allocator, host: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{{\"nodeId\":\"nN\",\"name\":\"{s}.example.ts.net\",\"tags\":[\"tag:lab-guest\"]}}", .{host});
}

/// The reads with a working Tailscale credential: the guest's status,
/// its device and the device list (another device named NEW, or none).
fn tsReads(a: std.mem.Allocator, list: []const u8, users: []const u8, records: []const u8, host: []const u8, site: bool, token: bool, others: []const u8) ![]const R {
    const base = try renameReads(a, list, users, records, host, site);
    var out: std.ArrayList(R) = .empty;
    try out.appendSlice(a, base[0 .. base.len - 1]);
    try out.appendSlice(a, &.{
        rt("agent/exec HTTP", "{\"data\":{\"pid\":44}}"),
        rt("exec-status", try tsStatus(a, host)),
    });
    if (token) try out.append(a, rt("POST /oauth/token", "{\"access_token\":\"tskey-access-xyz\",\"expires_in\":3600,\"scope\":\"devices:core\"}"));
    try out.appendSlice(a, &.{
        rt("GET /device/nN?", try tsDevice(a, host)),
        rt("GET /tailnet/-/devices", try std.fmt.allocPrint(a, "{{\"devices\":[{s}{s}{s}]}}", .{ try tsDevice(a, host), if (others.len > 0) "," else "", others })),
    });
    try out.append(a, base[base.len - 1]);
    return out.items;
}

test "vm rename: a tailnet name NEW already taken by another device refuses before any write" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.initRoutes(try tsReads(a, list_ts_old, users_old, dns_old_body, "naboo", true, true, "{\"nodeId\":\"nPhone\",\"name\":\"hoth.example.ts.net\"}"));
    defer g.deinit();
    try g.tailscaleConfig("");
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "the tailnet device hoth.example.ts.net (nPhone) is already named hoth") != null);
    for (g.srv.received) |req| if (req) |q| try testing.expect(std.mem.startsWith(u8, q, "GET ") or std.mem.startsWith(u8, q, "POST /oauth/token") or std.mem.find(u8, q, "/agent/") != null);
}

test "vm rename: the tailnet step waits for the control plane before renaming the device itself" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try tsReads(a, list_ts_old, users_old, dns_old_body, "naboo", true, true, ""));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":45}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        // Still the old name twice, then the new one: no API rename.
        rt("GET /device/nN?", try tsDevice(a, "naboo")),
        rt("GET /device/nN?", try tsDevice(a, "naboo")),
        rt("GET /device/nN?", try tsDevice(a, "hoth")),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":46}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
        rt("DELETE /v1/sites/S1/dns/policies/R1", ""),
    });
    try routes.appendSlice(a, try tsReads(a, list_ts_new, users_new, dns_new_body, "hoth", false, false, ""));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try g.tailscaleConfig("");
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    for (g.srv.received) |req| if (req) |q| try testing.expect(!std.mem.startsWith(u8, q, "POST /device/nN/name"));
}

test "vm rename: a hand-set tailnet name that never follows is renamed through the API after the wait" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try tsReads(a, list_ts_old, users_old, dns_old_body, "naboo", true, true, ""));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":45}}"),
        rt("exec-status", try agentOut(a, 0, "")),
    });
    for (0..tailnet_polls + 1) |_| try routes.append(a, rt("GET /device/nN?", try tsDevice(a, "naboo")));
    try routes.appendSlice(a, &.{
        rt("POST /device/nN/name", "{}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":46}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
        rt("DELETE /v1/sites/S1/dns/policies/R1", ""),
    });
    try routes.appendSlice(a, try tsReads(a, list_ts_new, users_new, dns_new_body, "hoth", false, false, ""));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try g.tailscaleConfig("");
    const code = g.h.run(&root, "vm rename naboo hoth -y --confirm naboo");
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ g.h.stdout(), g.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expect(std.mem.find(u8, g.h.stdout(), "device renamed through the API") != null);
}

test "vm rename: NEW's DNS record comes first, OLD's is removed last" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try renameReads(a, list_old, users_old, dns_old_body, "naboo", true));
    try routes.appendSlice(a, &.{
        rt("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        rt("POST /v1/sites/S1/dns/policies", "{}"),
        rt("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        rt("exec-status", try agentOut(a, 0, "")),
        rt("PUT /proxy/network/api/s/default/rest/user/U1", users_new),
        rt("DELETE /v1/sites/S1/dns/policies/R1", ""),
    });
    try routes.appendSlice(a, try renameReads(a, list_new, users_new, dns_new_body, "hoth", false));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try g.mem.map.put(g.h.arena.allocator(), "guest/naboo", "naboo-password");
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm rename naboo hoth -y --confirm naboo"));
    // The writes in order: Proxmox, NEW's record, (password, local), the
    // hostname, the UniFi record, OLD's record last.
    var writes: std.ArrayList([]const u8) = .empty;
    for (g.srv.received) |req| if (req) |q| if (!std.mem.startsWith(u8, q, "GET ") and std.mem.find(u8, q, "exec-status") == null) {
        const end = std.mem.findScalar(u8, q, ' ').?;
        const end2 = std.mem.findScalarPos(u8, q, end + 1, ' ').?;
        try writes.append(a, q[0..end2]);
    };
    const want = [_][]const u8{
        "PUT /api2/json/nodes/pve/qemu/201/config",
        "POST /v1/sites/S1/dns/policies",
        "POST /api2/json/nodes/pve/qemu/201/agent/exec",
        "PUT /proxy/network/api/s/default/rest/user/U1",
        "DELETE /v1/sites/S1/dns/policies/R1",
    };
    var n: usize = 0;
    for (writes.items) |w| {
        if (std.mem.eql(u8, w, "POST /api2/json/nodes/pve/qemu/201/agent/exec") and n != 2) continue;
        if (n < want.len and std.mem.eql(u8, w, want[n])) n += 1;
    }
    if (n != want.len) {
        for (writes.items) |w| std.debug.print("write: {s}\n", .{w});
        return error.TestUnexpectedResult;
    }
    try testing.expect(std.mem.find(u8, g.h.stdout(), "(added first; naboo.lab.example.com removed last)") != null);
}
