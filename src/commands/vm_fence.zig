//! `artoo vm fence VM [--off]` (SPEC §9.11): the Proxmox VE firewall on
//! an artoo guest's NIC — derived rules, the `ipfilter-net0` IP set, MAC
//! filter and DROP policies — written through the Proxmox API with the
//! machinery of the edge VM's host firewall (SPEC §9.7). Nothing inside
//! the guest changes. Guests fenced this way carry the tag `fenced`.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const exec = @import("../exec.zig");
const exposure = @import("../exposure.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const files = @import("../edge/files.zig");
const known_hosts = @import("../guest/known_hosts.zig");
const edge = @import("edge.zig");
const svc = @import("svc.zig");
const watch = @import("watch.zig");
const router = @import("router.zig");
const life = @import("vm_life.zig");
const vm_cmd = @import("vm.zig");
const vm_new = @import("vm_new.zig");
const template = @import("template.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;
const Rule = edge.Rule;

/// Marks a guest fenced by `vm fence` (SPEC §9.11).
pub const tag = "fenced";

const private_v4 = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16";
const private_v6 = "fc00::/7,fe80::/10";

// ---------------------------------------------------------------- rules

pub const Service = struct { name: []const u8, port: u16 };

/// One resolved outbound exception (`guests.fence_allow_out`).
pub const Exception = struct {
    /// As written in the config: a guest name or an address.
    peer: []const u8,
    /// The address or CIDR the rule names.
    dest: []const u8,
    proto: []const u8,
    ports: []const u8,
};

/// Everything the fence of one guest is derived from.
pub const Inputs = struct {
    ad: files.Addresses,
    /// The edge VM's address; null without an edge VM.
    edge: ?[]const u8 = null,
    /// Services whose upstream is this guest, by name.
    services: []const Service = &.{},
    ssh_jump: bool = false,
    /// The watchdog's address; null without one.
    watch: ?[]const u8 = null,
    allow: []const Exception = &.{},
};

/// The SPEC §9.11 rules, first match wins.
pub fn rules(a: std.mem.Allocator, in: Inputs) ![]const Rule {
    var out: std.ArrayList(Rule) = .empty;
    if (in.edge) |e| for (in.services) |s| try out.append(a, .{
        .type = "in",
        .action = "ACCEPT",
        .source = e,
        .proto = "tcp",
        .dport = try std.fmt.allocPrint(a, "{d}", .{s.port}),
        .comment = try std.fmt.allocPrint(a, "artoo: service {s} via the edge", .{s.name}),
    });
    try out.appendSlice(a, &.{
        if (in.ssh_jump)
            .{ .type = "in", .action = "ACCEPT", .source = in.ad.pve, .proto = "tcp", .dport = "22", .comment = "artoo: SSH only from Proxmox" }
        else
            .{ .type = "in", .action = "ACCEPT", .source = in.ad.lan, .proto = "tcp", .dport = "22", .comment = "artoo: SSH from the LAN" },
        .{ .type = "in", .action = "ACCEPT", .macro = "Ping", .source = in.ad.lan, .comment = "artoo: ping from the LAN" },
        .{ .type = "out", .action = "ACCEPT", .dest = in.ad.gateway, .proto = "udp", .dport = "53", .comment = "artoo: DNS on UniFi" },
        .{ .type = "out", .action = "ACCEPT", .dest = in.ad.gateway, .proto = "tcp", .dport = "53", .comment = "artoo: DNS on UniFi" },
    });
    if (in.watch) |w| try out.append(a, .{ .type = "out", .action = "ACCEPT", .dest = w, .proto = "tcp", .dport = "8428,3100", .comment = "artoo: metrics and logs to the watchdog" });
    for (in.allow) |x| try out.append(a, .{
        .type = "out",
        .action = "ACCEPT",
        .dest = x.dest,
        .proto = x.proto,
        .dport = x.ports,
        .comment = try std.fmt.allocPrint(a, "artoo: allow-out {s} (config)", .{x.peer}),
    });
    try out.appendSlice(a, &.{
        .{ .type = "out", .action = "DROP", .dest = private_v4, .comment = "artoo: no other private IPv4" },
        .{ .type = "out", .action = "DROP", .dest = private_v6, .comment = "artoo: no private IPv6" },
        .{ .type = "out", .action = "ACCEPT", .proto = "tcp", .dport = "80,443", .comment = "artoo: web" },
        .{ .type = "out", .action = "ACCEPT", .proto = "udp", .dport = "123", .comment = "artoo: NTP" },
        .{ .type = "out", .action = "ACCEPT", .macro = "Ping", .comment = "artoo: ping out" },
        .{ .type = "out", .action = "DROP", .comment = "artoo: everything else" },
    });
    return out.items;
}

/// `IN ACCEPT tcp 22 from 192.168.1.0/24`.
pub fn describe(a: std.mem.Allocator, r: Rule) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    for (r.type) |ch| try s.append(a, std.ascii.toUpper(ch));
    try s.print(a, " {s}", .{r.action});
    if (r.macro.len > 0) try s.print(a, " {s}", .{r.macro});
    if (r.proto.len > 0) try s.print(a, " {s}", .{r.proto});
    if (r.dport.len > 0) try s.print(a, " {s}", .{r.dport});
    if (r.source.len > 0) try s.print(a, " from {s}", .{r.source});
    if (r.dest.len > 0) try s.print(a, " to {s}", .{r.dest});
    return s.items;
}

/// The rule diff, position by position (`rule N  current → wanted`), and
/// how many positions are unchanged.
pub fn diff(a: std.mem.Allocator, have: []const Rule, want: []const Rule) !struct { changes: []const ui.blocks.Change, same: usize } {
    var changes: std.ArrayList(ui.blocks.Change) = .empty;
    var same: usize = 0;
    for (0..@max(have.len, want.len)) |i| {
        const h: ?Rule = if (i < have.len) have[i] else null;
        const w: ?Rule = if (i < want.len) want[i] else null;
        if (h != null and w != null and h.?.eql(w.?)) {
            same += 1;
            continue;
        }
        try changes.append(a, .{
            .field = try std.fmt.allocPrint(a, "rule {d}", .{i + 1}),
            .from = if (h) |x| try describe(a, x) else null,
            .to = if (w) |x| try describe(a, x) else null,
        });
    }
    return .{ .changes = changes.items, .same = same };
}

// ---------------------------------------------------------------- inputs

/// Why a VM cannot be fenced by `vm fence`, or null.
pub fn refusal(v: vms.Vm) ?[]const u8 {
    if (v.template) return "is a template";
    if (!template.taggedWith(v.tags, vm_new.tag)) return "was not created by artoo (no 'artoo' tag)";
    const r = vm_cmd.roleOf(v.tags) orelse return null;
    if (std.mem.eql(u8, r, edge.role)) return "is the edge VM: 'artoo edge setup' owns its fence (SPEC §9.7)";
    if (std.mem.eql(u8, r, watch.role)) return "is the watchdog: 'artoo watch setup' owns its fence (SPEC §9.9)";
    if (std.mem.eql(u8, r, router.role)) return "is the subnet router: a fence would break its forwarding (SPEC §9.8)";
    return null;
}

/// What every guest's fence shares: the lab's addresses, the edge's
/// routes, the watchdog. Read once per invocation.
pub const Lab = struct {
    ad: files.Addresses,
    list: []const vms.Vm,
    edge: ?vms.Vm = null,
    edge_addr: ?[]const u8 = null,
    routes: []const svc.Route = &.{},
    watch_addr: ?[]const u8 = null,
};

/// Reads the edge VM's routes (it must run when it exists: without them
/// the service rules are unknown) and the watchdog's address.
pub fn readLab(ctx: *Context, c: *pve.Client) !Lab {
    const list = try vms.list(c);
    var e: ?vms.Vm = null;
    for (list) |v| {
        const r = vm_cmd.roleOf(v.tags) orelse continue;
        if (std.mem.eql(u8, r, edge.role) and !v.template) e = v;
    }
    var routes: []const svc.Route = &.{};
    var edge_addr: ?[]const u8 = null;
    if (e) |ev| {
        if (!ev.running()) return ctx.fail(error.Refused, "the edge VM {s} is {s}: its service routes, and so the fence's inbound rules, are unknown; start it first", .{ ev.name, ev.status });
        routes = (try svc.readEdge(c, ev.vmid, try svc.domains(ctx))).routes;
        edge_addr = try svc.edgeAddress(c, ev);
    }
    return labFor(ctx, c, list, e, edge_addr, routes);
}

/// A `Lab` from reads the caller already made (`svc`).
pub fn labFor(ctx: *Context, c: *pve.Client, list: []const vms.Vm, e: ?vms.Vm, edge_addr: ?[]const u8, routes: []const svc.Route) !Lab {
    var lab: Lab = .{ .ad = try edge.addresses(ctx), .list = list, .edge = e, .edge_addr = edge_addr, .routes = routes };
    for (list) |v| {
        if (v.template or watch.roleOf(v.tags) != .watch) continue;
        lab.watch_addr = life.staticAddress(try vms.config(c, v.vmid)) orelse
            return ctx.fail(error.Refused, "the watchdog {s} has no static address (ipconfig0)", .{v.name});
    }
    return lab;
}

/// The inputs of `v`'s fence, with `routes` as the edge's route set.
pub fn inputsFor(ctx: *Context, c: *pve.Client, lab: Lab, v: vms.Vm, routes: []const svc.Route) !Inputs {
    const a = ctx.arena;
    const cfg = try ctx.config();
    var services: std.ArrayList(Service) = .empty;
    if (lab.edge_addr != null) for (routes) |r| {
        if (r.managed() and std.ascii.eqlIgnoreCase(r.vm, v.name)) try services.append(a, .{ .name = r.name, .port = r.port });
    };
    std.mem.sort(Service, services.items, {}, struct {
        fn lt(_: void, x: Service, y: Service) bool {
            return std.mem.lessThan(u8, x.name, y.name);
        }
    }.lt);
    const all = try config.fenceAllows(a, cfg.guests.fence_allow_out) orelse
        return ctx.fail(error.ConfigInvalid, "guests.fence_allow_out is malformed; see 'artoo config set guests.fence_allow_out'", .{});
    var allow: std.ArrayList(Exception) = .empty;
    const infra: exposure.Infra = .of(cfg);
    for (all) |x| {
        if (!std.ascii.eqlIgnoreCase(x.vm, v.name)) continue;
        if (std.ascii.eqlIgnoreCase(x.peer, v.name)) return ctx.fail(error.Refused, "guests.fence_allow_out: {s} names itself as a peer", .{v.name});
        const dest = if (x.peerIsAddress()) x.peer else blk: {
            const peer = for (lab.list) |p| {
                if (!p.template and std.mem.eql(u8, p.name, x.peer)) break p;
            } else return ctx.fail(error.Refused, "guests.fence_allow_out: no guest '{s}' (peer of {s})", .{ x.peer, v.name });
            break :blk life.staticAddress(try vms.config(c, peer.vmid)) orelse
                return ctx.fail(error.Refused, "guests.fence_allow_out: {s} has no static address (ipconfig0)", .{peer.name});
        };
        const net = config.parseIp4Net(dest) orelse return ctx.fail(error.Refused, "guests.fence_allow_out: '{s}' is not an IPv4 address", .{dest});
        for (infra.addresses[0..infra.n_addresses]) |p| {
            const pa = config.parseIp4Net(p) orelse continue;
            if (config.netContains(net, pa.address))
                return ctx.fail(error.Refused, "guests.fence_allow_out: {s} {s} reaches {s}, the Proxmox host or the gateway — never opened (SPEC §9.6)", .{ v.name, x.peer, p });
        }
        try allow.append(a, .{ .peer = x.peer, .dest = dest, .proto = x.proto, .ports = x.ports });
    }
    return .{
        .ad = lab.ad,
        .edge = lab.edge_addr,
        .services = services.items,
        .ssh_jump = known_hosts.wantsJump(v.tags),
        .watch = lab.watch_addr,
        .allow = allow.items,
    };
}

// ---------------------------------------------------------------- state

/// `net0` with `firewall=1` (on) or without any `firewall=` (off).
pub fn netWith(a: std.mem.Allocator, net0: []const u8, on: bool) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, net0, ',');
    while (it.next()) |part| {
        if (std.mem.startsWith(u8, part, "firewall=")) continue;
        if (out.items.len > 0) try out.append(a, ',');
        try out.appendSlice(a, part);
    }
    if (on) try out.appendSlice(a, ",firewall=1");
    return out.items;
}

/// `tags` with `fenced` added (on) or removed (off), `;`-separated.
pub fn tagsWith(a: std.mem.Allocator, tags: []const u8, on: bool) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, tags, ";, ");
    while (it.next()) |t| {
        if (std.mem.eql(u8, t, tag)) continue;
        if (out.items.len > 0) try out.append(a, ';');
        try out.appendSlice(a, t);
    }
    if (on) {
        if (out.items.len > 0) try out.append(a, ';');
        try out.appendSlice(a, tag);
    }
    return out.items;
}

/// One guest's fence as read, compared with what it should be.
pub const State = struct {
    host: edge.HostState,
    steps: edge.HostSteps,
    tagged: bool,
    tags: []const u8,

    pub fn converged(s: State) bool {
        return s.tagged and !s.steps.any();
    }
};

pub fn readState(c: *pve.Client, v: vms.Vm, want: []const Rule) !State {
    const hs = try edge.readHost(c, v);
    return .{ .host = hs, .steps = edge.hostSteps(want, hs), .tagged = template.taggedWith(v.tags, tag), .tags = v.tags };
}

/// The first difference, for drift messages.
pub fn firstDrift(a: std.mem.Allocator, s: State, want: []const Rule) ![]const u8 {
    if (s.steps.rules) {
        const d = try diff(a, s.host.rules, want);
        if (d.changes.len > 0) {
            const ch = d.changes[0];
            return std.fmt.allocPrint(a, "{s}: {s} instead of {s}", .{ ch.field, ch.from orelse "(none)", ch.to orelse "(none)" });
        }
    }
    if (s.steps.ipset) return "the IP set ipfilter-net0 is not the VM's address";
    if (s.steps.nic) return "net0 has no firewall=1";
    if (s.steps.options) return "the firewall options differ (enable, filters, DROP policies)";
    if (!s.tagged) return "no 'fenced' tag";
    return "";
}

/// Whether the datacenter firewall is on (VM firewalls apply only then);
/// null when it cannot be read.
pub fn datacenterOn(c: *pve.Client) ?bool {
    const opts = c.get("/cluster/firewall/options") catch return null;
    return switch (pve.obj(opts, "enable")) {
        .integer => |n| n == 1,
        .string => |t| std.mem.eql(u8, t, "1"),
        else => false,
    };
}

/// Apply `want` (SPEC §9.11 order): rules, IP set, NIC flag with the tag,
/// options last.
pub fn apply(c: *pve.Client, v: vms.Vm, want: []const Rule, s: State) !void {
    const a = c.ctx.arena;
    try edge.applyHost(c, v, want, s.host, .{ .rules = s.steps.rules, .ipset = s.steps.ipset });
    if (s.steps.nic or !s.tagged) {
        const cfg = try vms.config(c, v.vmid);
        var params: std.ArrayList(pve.Param) = .empty;
        if (s.steps.nic) try params.append(a, .{ .name = "net0", .value = try netWith(a, pve.str(cfg, "net0") orelse s.host.net0, true) });
        if (!s.tagged) try params.append(a, .{ .name = "tags", .value = try tagsWith(a, pve.str(cfg, "tags") orelse s.tags, true) });
        try params.append(a, .{ .name = "digest", .value = pve.str(cfg, "digest") orelse "" });
        _ = try c.send(.PUT, try c.nodePath("/qemu/{d}/config", .{v.vmid}), params.items);
    }
    if (s.steps.options) try edge.applyHost(c, v, want, s.host, .{ .options = true });
}

/// `v`'s wanted rules from a fresh read of the lab.
pub fn derive(ctx: *Context, c: *pve.Client, v: vms.Vm) ![]const Rule {
    const lab = try readLab(ctx, c);
    return rules(ctx.arena, try inputsFor(ctx, c, lab, v, lab.routes));
}

/// The fence check of `vm verify` (SPEC §9.11).
pub fn check(ctx: *Context, c: *pve.Client, v: vms.Vm) !vm_new.Check {
    const label = "fence";
    if (refusal(v) != null) return .{ .name = label, .status = .not_checked, .detail = "not a guest for 'vm fence'" };
    if (!template.taggedWith(v.tags, tag)) return .{ .name = label, .status = .not_checked, .detail = "not fenced" };
    const want = derive(ctx, c, v) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            const why = try k.clean(ctx, ctx.diag orelse @errorName(err));
            ctx.diag = null;
            return .{ .name = label, .status = .failed, .detail = why };
        },
    };
    const s = try readState(c, v, want);
    if (s.steps.any()) return .{ .name = label, .status = .failed, .detail = try std.fmt.allocPrint(ctx.arena, "drift — {s}; 'artoo vm fence {s}'", .{ try firstDrift(ctx.arena, s, want), v.name }) };
    if (datacenterOn(c) == false) return .{ .name = label, .status = .warning, .detail = "datacenter firewall off: the fence has no effect" };
    return .{ .name = label, .status = .ok, .detail = try std.fmt.allocPrint(ctx.arena, "{d} rules, only source {s}", .{ want.len, s.host.address }) };
}

// ---------------------------------------------------------------- command

const FenceOp = struct {
    c: *pve.Client,
    word: []const u8,
    off: bool,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: vms.Vm = undefined,
    want: []const Rule = &.{},
    inputs: Inputs = undefined,
    state: State = undefined,
    /// `--off`: firewall options artoo set that are still present.
    options_set: []const []const u8 = &.{},
    enabled: bool = false,
    dc_on: ?bool = null,
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *FenceOp, ctx: *Context) !void {
        const a = ctx.arena;
        op.vm = try vms.resolve(op.c, op.word);
        op.target = op.vm.name;
        if (refusal(op.vm)) |why| return ctx.fail(error.Refused, "{s} {s}", .{ try k.clean(ctx, op.vm.name), why });
        if (!op.off) {
            const lab = try readLab(ctx, op.c);
            op.inputs = try inputsFor(ctx, op.c, lab, op.vm, lab.routes);
            op.want = try rules(a, op.inputs);
        }
        op.state = try readState(op.c, op.vm, op.want);
        const opts = try op.c.get(try op.c.nodePath("/qemu/{d}/firewall/options", .{op.vm.vmid}));
        var set: std.ArrayList([]const u8) = .empty;
        for (edge.host_options) |o| {
            if (std.mem.eql(u8, o[0], "enable")) continue;
            if (pve.obj(opts, o[0]) != .null) try set.append(a, o[0]);
        }
        op.options_set = set.items;
        op.enabled = switch (pve.obj(opts, "enable")) {
            .integer => |n| n == 1,
            .string => |t| std.mem.eql(u8, t, "1"),
            else => false,
        };
        if (!op.off) op.dc_on = datacenterOn(op.c);
        const h = op.state.steps;
        op.fp = try std.fmt.allocPrint(a, "{s}|{s}|{d}|{}{}{}{}|{}", .{ op.state.host.net0, op.vm.tags, op.state.host.rules.len, h.rules, h.ipset, h.nic, h.options, op.enabled });
    }

    fn offNeeded(op: *FenceOp) bool {
        const hs = op.state.host;
        return op.enabled or op.options_set.len > 0 or hs.rules.len > 0 or hs.ipset_exists or hs.nic_ok or op.state.tagged;
    }

    pub fn plan(op: *FenceOp, ctx: *Context) !?exec.Plan {
        return if (op.off) op.planOff(ctx) else op.planOn(ctx);
    }

    fn planOn(op: *FenceOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const s = op.state;
        if (s.converged()) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        var notes: std.ArrayList([]const u8) = .empty;
        if (s.steps.rules) {
            const d = try diff(a, s.host.rules, op.want);
            try changes.appendSlice(a, d.changes);
            if (d.same > 0) try notes.append(a, try std.fmt.allocPrint(a, "{d} rule(s) unchanged; the whole list is rewritten.", .{d.same}));
            var foreign: usize = 0;
            for (s.host.rules) |r| foreign += @intFromBool(!std.mem.startsWith(u8, r.comment, "artoo:"));
            if (foreign > 0) try notes.append(a, try std.fmt.allocPrint(a, "{d} existing rule(s) were not written by artoo; they are replaced.", .{foreign}));
            if (op.enabled) try notes.append(a, "The guest's traffic drops for the moment between deleting and re-adding the rules.");
        }
        if (s.steps.ipset) try changes.append(a, .{ .field = "IP set", .from = if (s.host.ipset_exists) "differs" else null, .to = try std.fmt.allocPrint(a, "ipfilter-net0 = {s} (the only source address)", .{s.host.address}) });
        if (s.steps.nic) try changes.append(a, .{ .field = "NIC", .from = null, .to = "net0 firewall=1" });
        if (!s.tagged) try changes.append(a, .{ .field = "tag", .from = null, .to = tag });
        if (s.steps.options) try changes.append(a, .{ .field = "options", .from = if (op.enabled) "differ" else null, .to = "enable, ipfilter, macfilter, ndp; dhcp and radv off; policy in/out DROP (last)" });
        if (op.dc_on == false) try notes.append(a, "The datacenter firewall is off: the fence has no effect until it is on (scripts/pve-firewall.sh).");
        if (op.inputs.edge == null) try notes.append(a, "No edge VM: no service is let in.");
        var ins: std.ArrayList(u8) = .empty;
        for (op.inputs.services, 0..) |sv, i| try ins.print(a, "{s}{s} :{d}", .{ if (i > 0) ", " else "", sv.name, sv.port });
        return .{
            .action = try std.fmt.allocPrint(a, "Fence {s} ({d})", .{ op.vm.name, op.vm.vmid }),
            .risk = .destructive,
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{
                try std.fmt.allocPrint(a, "In: {s}{s}SSH from {s}, ping from the LAN", .{ if (ins.items.len > 0) ins.items else "", if (ins.items.len > 0) " via the edge; " else "", if (op.inputs.ssh_jump) "Proxmox only" else "the LAN" }),
                try std.fmt.allocPrint(a, "Out: DNS on UniFi{s}{s}, web and NTP; nothing else on the LAN", .{ if (op.inputs.watch != null) ", the watchdog" else "", if (op.inputs.allow.len > 0) ", the configured exceptions" else "" }),
                "Only the VM's own firewall on Proxmox changes; nothing inside the guest",
            }),
            // A takeover (rules already as derived) is undone by the tag alone.
            .recovery = if (s.steps.any())
                try std.fmt.allocPrint(a, "artoo vm fence {s} --off", .{op.vm.name})
            else
                try std.fmt.allocPrint(a, "artoo vm set {s} tags={s}", .{ op.vm.name, try tagsWith(a, op.vm.tags, false) }),
            .notes = notes.items,
        };
    }

    fn planOff(op: *FenceOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const hs = op.state.host;
        if (!op.offNeeded()) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (op.enabled or op.options_set.len > 0) try changes.append(a, .{ .field = "options", .from = if (op.enabled) "enabled" else "set", .to = "enable 0, others at Proxmox's defaults (first)" });
        for (hs.rules, 0..) |r, i| try changes.append(a, .{ .field = try std.fmt.allocPrint(a, "rule {d}", .{i + 1}), .from = try describe(a, r), .to = null });
        if (hs.ipset_exists) try changes.append(a, .{ .field = "IP set", .from = "ipfilter-net0", .to = null });
        if (hs.nic_ok) try changes.append(a, .{ .field = "NIC", .from = "net0 firewall=1", .to = null });
        if (op.state.tagged) try changes.append(a, .{ .field = "tag", .from = tag, .to = null });
        return .{
            .action = try std.fmt.allocPrint(a, "Remove the fence of {s} ({d})", .{ op.vm.name, op.vm.vmid }),
            .risk = .destructive,
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{"The guest is unfiltered on Proxmox; its own firewall (if any) is untouched"}),
            .recovery = try std.fmt.allocPrint(a, "artoo vm fence {s}", .{op.vm.name}),
        };
    }

    pub fn fingerprint(op: *FenceOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *FenceOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        const i = try l.add(a, if (op.off) "remove fence" else "write fence");
        l.set(i, .unknown, "");
        if (op.off) try op.sendOff() else try apply(op.c, op.vm, op.want, op.state);
        l.set(i, .done, if (op.off) "" else if (!op.state.steps.any()) "tag only; rules unchanged" else try std.fmt.allocPrint(a, "{d} rules on Proxmox", .{op.want.len}));
    }

    /// Options first (unfiltered at once), then rules, IP set, NIC, tag.
    fn sendOff(op: *FenceOp) !void {
        const c = op.c;
        const a = c.ctx.arena;
        const id = op.vm.vmid;
        const hs = op.state.host;
        if (op.enabled or op.options_set.len > 0) {
            var params: std.ArrayList(pve.Param) = .empty;
            try params.append(a, .{ .name = "enable", .value = "0" });
            if (op.options_set.len > 0) try params.append(a, .{ .name = "delete", .value = try std.mem.join(a, ",", op.options_set) });
            _ = try c.send(.PUT, try c.nodePath("/qemu/{d}/firewall/options", .{id}), params.items);
        }
        var n = hs.rules.len;
        while (n > 0) : (n -= 1) _ = try c.send(.DELETE, try c.nodePath("/qemu/{d}/firewall/rules/0", .{id}), &.{});
        if (hs.ipset_exists) _ = try c.send(.DELETE, try c.nodePath("/qemu/{d}/firewall/ipset/ipfilter-net0?force=1", .{id}), &.{});
        if (hs.nic_ok or op.state.tagged) {
            const cfg = try vms.config(c, id);
            var params: std.ArrayList(pve.Param) = .empty;
            if (hs.nic_ok) try params.append(a, .{ .name = "net0", .value = try netWith(a, pve.str(cfg, "net0") orelse hs.net0, false) });
            if (op.state.tagged) try params.append(a, .{ .name = "tags", .value = try tagsWith(a, pve.str(cfg, "tags") orelse op.vm.tags, false) });
            try params.append(a, .{ .name = "digest", .value = pve.str(cfg, "digest") orelse "" });
            _ = try c.send(.PUT, try c.nodePath("/qemu/{d}/config", .{id}), params.items);
        }
    }

    pub fn verify(op: *FenceOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        op.vm = try vms.resolve(op.c, op.word);
        op.state = try readState(op.c, op.vm, op.want);
        if (!op.off) return op.ledger.complete() and op.state.converged();
        const opts = try op.c.get(try op.c.nodePath("/qemu/{d}/firewall/options", .{op.vm.vmid}));
        const on = switch (pve.obj(opts, "enable")) {
            .integer => |n| n == 1,
            .string => |t| std.mem.eql(u8, t, "1"),
            else => false,
        };
        const hs = op.state.host;
        return op.ledger.complete() and !on and hs.rules.len == 0 and !hs.ipset_exists and !hs.nic_ok and !op.state.tagged;
    }

    pub fn done(op: *FenceOp) []const u8 {
        const a = op.c.ctx.arena;
        return (if (op.off)
            std.fmt.allocPrint(a, "{s} is no longer fenced", .{op.vm.name})
        else
            std.fmt.allocPrint(a, "{s} fenced — {d} rules, only source {s}; 'artoo vm verify {s}' to check", .{ op.vm.name, op.want.len, op.state.host.address, op.vm.name })) catch "done";
    }
};

pub const fence = struct {
    pub const name = "fence";
    pub const summary = "Put the Proxmox NIC firewall around a guest (high-impact)";
    pub const details =
        \\Writes the VM's own Proxmox VE firewall (SPEC §9.11), derived from the
        \\lab: in, each service routed to the guest from the edge VM, SSH (from
        \\Proxmox only for ssh-jump guests) and ping from the LAN; out, DNS on
        \\UniFi, the watchdog's 8428/3100, the exceptions in
        \\guests.fence_allow_out, then nothing private, then web, NTP and ping;
        \\everything else dropped. The IP set ipfilter-net0 holds only the VM's
        \\static address, with MAC filter and DROP policies; net0 gets
        \\firewall=1 and the VM the tag 'fenced'. Nothing inside the guest
        \\changes. The plan shows the full rule diff; type the VM name to
        \\confirm, or --yes --confirm VM. A converged fence is a no-op.
        \\
        \\--off removes it again: options off first, then rules, IP set, NIC
        \\flag and tag. The edge VM, the watchdog and the subnet router are
        \\refused (their setup owns their fence).
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name" }};
    pub const flags = [_]cli.Flag{
        .{ .long = "off", .help = "Remove the fence (rollback)" },
        .{ .long = "confirm", .kind = .string, .metavar = "VM", .help = "Non-interactive confirmation (with --yes)" },
    };
    pub const examples = [_][]const u8{ "artoo vm fence hoth -n", "artoo vm fence hoth --yes --confirm hoth", "artoo vm fence hoth --off" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: FenceOp = .{ .c = &c, .word = args.pos("VM"), .off = args.has("off") };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const commands = [_]cli.Command{cli.leaf(fence)};

// ---------------------------------------------------------------- svc

/// The fenced guest named `name` in `list`, or null.
pub fn fencedNamed(list: []const vms.Vm, name: []const u8) ?vms.Vm {
    for (list) |v| {
        if (v.template or !std.ascii.eqlIgnoreCase(v.name, name)) continue;
        if (template.taggedWith(v.tags, tag) and refusal(v) == null) return v;
    }
    return null;
}

/// A fenced guest whose fence a route change moves (`svc add|set|rm`,
/// SPEC §9.11): its wanted rules for the new route set and its state.
pub const Follow = struct {
    vm: vms.Vm,
    want: []const Rule,
    state: State,
    /// The new upstream (opened before the route) or the old one (closed
    /// after it).
    opens: bool,
};

pub fn follow(ctx: *Context, c: *pve.Client, lab: Lab, v: vms.Vm, routes: []const svc.Route, opens: bool) !?Follow {
    const want = try rules(ctx.arena, try inputsFor(ctx, c, lab, v, routes));
    const st = try readState(c, v, want);
    if (st.converged()) return null;
    return .{ .vm = v, .want = want, .state = st, .opens = opens };
}

/// `routes` with service `name` routed to `vm:port`, or removed (`vm` null).
pub fn routesWith(a: std.mem.Allocator, routes: []const svc.Route, name: []const u8, vm: ?[]const u8, port: u16) ![]const svc.Route {
    var out: std.ArrayList(svc.Route) = .empty;
    for (routes) |r| if (!std.mem.eql(u8, r.name, name)) try out.append(a, r);
    if (vm) |n| try out.append(a, .{ .name = name, .vm = n, .port = port });
    return out.items;
}

/// Plan lines for a follow: the rules it adds and removes (as sets).
pub fn followChanges(a: std.mem.Allocator, f: Follow, out: *std.ArrayList(ui.blocks.Change)) !void {
    const field = try std.fmt.allocPrint(a, "fence {s}", .{f.vm.name});
    for (f.state.host.rules) |h| {
        if (!containsRule(f.want, h)) try out.append(a, .{ .field = field, .from = try describe(a, h), .to = null });
    }
    for (f.want) |w| {
        if (!containsRule(f.state.host.rules, w)) try out.append(a, .{ .field = field, .from = null, .to = try describe(a, w) });
    }
    if (f.state.steps.ipset or f.state.steps.nic or f.state.steps.options) try out.append(a, .{ .field = field, .from = "drift", .to = "IP set, NIC and options as 'vm fence' writes them" });
}

fn containsRule(list: []const Rule, r: Rule) bool {
    for (list) |x| if (x.eql(r)) return true;
    return false;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const R = testkit.Gateway.FakeServer.Route;

pub const test_ad: files.Addresses = .{ .pve = "192.168.1.10", .gateway = "192.168.1.1", .lan = "192.168.1.0/24", .pool = "192.168.1.200-192.168.1.254" };

test "rules: a plain guest — SSH and ping from the LAN, DNS, nothing private, web, NTP" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rs = try rules(a, .{ .ad = test_ad });
    try testing.expectEqual(@as(usize, 10), rs.len);
    try testing.expectEqualStrings("IN ACCEPT tcp 22 from 192.168.1.0/24", try describe(a, rs[0]));
    try testing.expectEqualStrings("IN ACCEPT Ping from 192.168.1.0/24", try describe(a, rs[1]));
    try testing.expectEqualStrings("OUT ACCEPT udp 53 to 192.168.1.1", try describe(a, rs[2]));
    try testing.expectEqualStrings("OUT ACCEPT tcp 53 to 192.168.1.1", try describe(a, rs[3]));
    try testing.expectEqualStrings("OUT DROP to " ++ private_v4, try describe(a, rs[4]));
    try testing.expectEqualStrings("OUT DROP to " ++ private_v6, try describe(a, rs[5]));
    try testing.expectEqualStrings("OUT ACCEPT tcp 80,443", try describe(a, rs[6]));
    try testing.expectEqualStrings("OUT ACCEPT udp 123", try describe(a, rs[7]));
    try testing.expectEqualStrings("OUT ACCEPT Ping", try describe(a, rs[8]));
    try testing.expectEqualStrings("OUT DROP", try describe(a, rs[9]));
}

test "rules: services via the edge first, SSH only from Proxmox for ssh-jump, watchdog and exceptions before the private drop" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rs = try rules(a, .{
        .ad = test_ad,
        .edge = "192.168.1.200",
        .services = &.{ .{ .name = "grafana", .port = 3000 }, .{ .name = "search", .port = 8080 } },
        .ssh_jump = true,
        .watch = "192.168.1.202",
        .allow = &.{.{ .peer = "hoth", .dest = "192.168.1.204", .proto = "tcp", .ports = "5432" }},
    });
    try testing.expectEqual(@as(usize, 14), rs.len);
    try testing.expectEqualStrings("IN ACCEPT tcp 3000 from 192.168.1.200", try describe(a, rs[0]));
    try testing.expectEqualStrings("artoo: service grafana via the edge", rs[0].comment);
    try testing.expectEqualStrings("IN ACCEPT tcp 8080 from 192.168.1.200", try describe(a, rs[1]));
    try testing.expectEqualStrings("IN ACCEPT tcp 22 from 192.168.1.10", try describe(a, rs[2]));
    try testing.expectEqualStrings("OUT ACCEPT tcp 8428,3100 to 192.168.1.202", try describe(a, rs[6]));
    try testing.expectEqualStrings("OUT ACCEPT tcp 5432 to 192.168.1.204", try describe(a, rs[7]));
    try testing.expectEqualStrings("OUT DROP to " ++ private_v4, try describe(a, rs[8]));
    // No outbound accept to Proxmox anywhere; every rule is artoo's.
    for (rs) |r| {
        try testing.expect(std.mem.startsWith(u8, r.comment, "artoo: "));
        if (std.mem.eql(u8, r.type, "out") and std.mem.eql(u8, r.action, "ACCEPT")) try testing.expect(!std.mem.eql(u8, r.dest, test_ad.pve));
    }
    // Services are dropped without an edge VM.
    try testing.expectEqual(@as(usize, 10), (try rules(a, .{ .ad = test_ad, .services = &.{.{ .name = "x", .port = 1 }} })).len);
}

test "diff: position by position, unchanged counted, comments ignored" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try rules(a, .{ .ad = test_ad });
    var have = try a.dupe(Rule, want[0..9]);
    have[0].comment = "hand-written";
    have[1] = .{ .type = "in", .action = "ACCEPT", .proto = "tcp", .dport = "8080", .comment = "" };
    const d = try diff(a, have, want);
    try testing.expectEqual(@as(usize, 8), d.same);
    try testing.expectEqual(@as(usize, 2), d.changes.len);
    try testing.expectEqualStrings("rule 2", d.changes[0].field);
    try testing.expectEqualStrings("IN ACCEPT tcp 8080", d.changes[0].from.?);
    try testing.expectEqualStrings("IN ACCEPT Ping from 192.168.1.0/24", d.changes[0].to.?);
    try testing.expect(d.changes[1].from == null);
    try testing.expectEqualStrings("OUT DROP", d.changes[1].to.?);
}

test "netWith, tagsWith" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1", try netWith(a, "virtio=BC:24:11:00:00:01,bridge=vmbr0", true));
    try testing.expectEqualStrings("virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1", try netWith(a, "virtio=BC:24:11:00:00:01,firewall=0,bridge=vmbr0", true));
    try testing.expectEqualStrings("virtio=BC:24:11:00:00:01,bridge=vmbr0", try netWith(a, "virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1", false));
    try testing.expectEqualStrings("artoo;ssh-jump;fenced", try tagsWith(a, "artoo;ssh-jump", true));
    try testing.expectEqualStrings("artoo;ssh-jump", try tagsWith(a, "artoo;fenced;ssh-jump", false));
    try testing.expectEqualStrings("fenced", try tagsWith(a, "", true));
}

const qemu_list = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;ssh-jump\"}," ++
    "{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"}," ++
    "{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch;ssh-jump\"}," ++
    "{\"vmid\":203,\"name\":\"dagobah\",\"status\":\"running\",\"tags\":\"artoo;role-router\"}," ++
    "{\"vmid\":204,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo\"}," ++
    "{\"vmid\":205,\"name\":\"kessel\",\"status\":\"running\",\"tags\":\"\"}," ++
    "{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"status\":\"stopped\",\"template\":1,\"tags\":\"artoo-template\"}]}";
const fenced_list = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;ssh-jump\"}," ++
    "{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;fenced\"}," ++
    "{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch;ssh-jump\"}]}";
const cfg_naboo = "{\"data\":{\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0\",\"ipconfig0\":\"ip=192.168.1.201/24,gw=192.168.1.1\",\"tags\":\"artoo\",\"digest\":\"d1\"}}";
const cfg_naboo_fenced = "{\"data\":{\"net0\":\"virtio=BC:24:11:00:00:01,bridge=vmbr0,firewall=1\",\"ipconfig0\":\"ip=192.168.1.201/24,gw=192.168.1.1\",\"tags\":\"artoo;fenced\",\"digest\":\"d2\"}}";
const all_options = "{\"data\":{\"enable\":1,\"ipfilter\":1,\"macfilter\":1,\"policy_in\":\"DROP\",\"policy_out\":\"DROP\",\"dhcp\":0,\"ndp\":1,\"radv\":0,\"digest\":\"o1\"}}";
const pid = "{\"data\":{\"pid\":42}}";
const empty = "{\"data\":[]}";

fn ok(match: []const u8, body: []const u8) R {
    return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
}

fn agentOut(a: std.mem.Allocator, out: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
}

/// The edge's route dump with one service, grafana → naboo:3000.
fn edgeDump(a: std.mem.Allocator) ![]const u8 {
    const d: svc.Domains = .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" };
    return agentOut(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==caddy== active\n", .{try svc.render(a, d, "grafana", "naboo", 3000)}));
}

/// Proxmox's answer to GET …/firewall/rules for `rs`, at positions 0…
pub fn rulesBody(a: std.mem.Allocator, rs: []const Rule) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, "{\"data\":[");
    for (rs, 0..) |r, i| {
        if (i > 0) try out.append(a, ',');
        try out.print(a, "{f}", .{std.json.fmt(.{ .pos = i, .type = r.type, .action = r.action, .macro = r.macro, .source = r.source, .dest = r.dest, .proto = r.proto, .dport = r.dport, .comment = r.comment, .enable = 1 }, .{})});
    }
    try out.appendSlice(a, "]}");
    return out.items;
}

/// The reads of `vm fence naboo` before the plan (one service, a watchdog).
fn onReads(a: std.mem.Allocator, list: []const u8, cfg: []const u8, options: []const u8, rules_body: []const u8, ipset: []const u8) ![]const R {
    return a.dupe(R, &.{
        ok("GET /api2/json/nodes/pve/qemu ", list),
        ok("GET /api2/json/nodes/pve/qemu ", list),
        ok("POST /api2/json/nodes/pve/qemu/200/agent/exec ", pid),
        ok("/qemu/200/agent/exec-status", try edgeDump(a)),
        ok("/qemu/200/config ", "{\"data\":{\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\"}}"),
        ok("/qemu/202/config ", "{\"data\":{\"ipconfig0\":\"ip=192.168.1.202/24,gw=192.168.1.1\"}}"),
        ok("/qemu/201/config ", cfg),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", options),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/rules ", rules_body),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset ", ipset),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", options),
        ok("/cluster/firewall/options ", "{\"data\":{\"enable\":1}}"),
    });
}

const root = cli.group("artoo", "t", &.{vm_cmd.group});

fn expectLines(out: []const u8, lines: []const []const u8) !void {
    for (lines) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "vm fence -n: derived rules, the full diff, destructive, nothing sent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.initRoutes(try onReads(a, qemu_list, cfg_naboo, "{\"data\":{}}", empty, empty));
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm fence naboo -n"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try expectLines(g.h.stdout(), &.{
        "Plan · Fence naboo (201)  ▲ destructive",
        "rule 1   (none) → IN ACCEPT tcp 3000 from 192.168.1.200",
        "rule 2   (none) → IN ACCEPT tcp 22 from 192.168.1.0/24",
        "rule 6   (none) → OUT ACCEPT tcp 8428,3100 to 192.168.1.202",
        "rule 12  (none) → OUT DROP\n",
        "IP set   (none) → ipfilter-net0 = 192.168.1.201 (the only source address)",
        "NIC      (none) → net0 firewall=1",
        "tag      (none) → fenced",
        "In: grafana :3000 via the edge; SSH from the LAN, ping from the LAN",
        "Out: DNS on UniFi, the watchdog, web and NTP; nothing else on the LAN",
        "artoo vm fence naboo --off",
        "Dry run: nothing was sent.",
    });
}

test "vm fence -y: rules last to first, IP set, NIC with tag, options last; verified by read-back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try rules(a, .{ .ad = test_ad, .edge = "192.168.1.200", .services = &.{.{ .name = "grafana", .port = 3000 }}, .watch = "192.168.1.202" });
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try onReads(a, qemu_list, cfg_naboo, "{\"data\":{}}", empty, empty));
    for (want) |_| try routes.append(a, ok("POST /api2/json/nodes/pve/qemu/201/firewall/rules ", "{\"data\":null}"));
    try routes.appendSlice(a, &.{
        ok("POST /api2/json/nodes/pve/qemu/201/firewall/ipset ", "{\"data\":null}"),
        ok("POST /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", "{\"data\":null}"),
        ok("GET /api2/json/nodes/pve/qemu/201/config ", cfg_naboo),
        ok("PUT /api2/json/nodes/pve/qemu/201/config ", "{\"data\":null}"),
        ok("PUT /api2/json/nodes/pve/qemu/201/firewall/options ", "{\"data\":null}"),
        // read-back
        ok("GET /api2/json/nodes/pve/qemu ", fenced_list),
        ok("GET /api2/json/nodes/pve/qemu/201/config ", cfg_naboo_fenced),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", all_options),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/rules ", try rulesBody(a, want)),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset ", "{\"data\":[{\"name\":\"ipfilter-net0\"}]}"),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", "{\"data\":[{\"cidr\":\"192.168.1.201\"}]}"),
    });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    // Destructive: --yes alone is refused before anything is written.
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "vm fence naboo -y --confirm hoth"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "does not match") != null);
    g.srv.stop();
    try g.srv.startRoutes(testing.io, routes.items);
    g.h.hooks.pve_base = try g.srv.url(g.h.arena.allocator(), "");
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm fence naboo -y --confirm naboo"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    // Writes after the 12 reads: the last rule first, the options last.
    const first_post = 12;
    try testing.expect(std.mem.find(u8, g.body(first_post), "everything") != null);
    try testing.expect(std.mem.find(u8, g.body(first_post + want.len - 1), "dport=3000") != null);
    const put_cfg = first_post + want.len + 3;
    try testing.expectEqualStrings("PUT /api2/json/nodes/pve/qemu/201/config HTTP/1.1", g.request(put_cfg));
    try testing.expect(std.mem.find(u8, g.body(put_cfg), "firewall%3D1") != null);
    try testing.expect(std.mem.find(u8, g.body(put_cfg), "tags=artoo%3Bfenced") != null);
    try testing.expect(std.mem.find(u8, g.body(put_cfg), "digest=d1") != null);
    try testing.expectEqualStrings("PUT /api2/json/nodes/pve/qemu/201/firewall/options HTTP/1.1", g.request(put_cfg + 1));
    try testing.expect(std.mem.find(u8, g.h.stdout(), "naboo fenced — 12 rules, only source 192.168.1.201") != null);
}

test "vm fence: a converged fence is a no-op; a hand-written one with the same rules needs only the tag" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try rules(a, .{ .ad = test_ad, .edge = "192.168.1.200", .services = &.{.{ .name = "grafana", .port = 3000 }}, .watch = "192.168.1.202" });
    const hand = try a.dupe(Rule, want);
    for (hand) |*r| r.comment = "by hand";
    const ipset = "{\"data\":[{\"name\":\"ipfilter-net0\"}]}";
    const entries = ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", "{\"data\":[{\"cidr\":\"192.168.1.201\"}]}");
    var routes: std.ArrayList(R) = .empty;
    try routes.appendSlice(a, try onReads(a, fenced_list, cfg_naboo_fenced, all_options, try rulesBody(a, want), ipset));
    try routes.insert(a, 10, entries);
    const untagged = try std.mem.replaceOwned(u8, a, fenced_list, "artoo;fenced", "artoo");
    try routes.appendSlice(a, try onReads(a, untagged, cfg_naboo_fenced, all_options, try rulesBody(a, hand), ipset));
    try routes.insert(a, routes.items.len - 2, entries);
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "vm fence naboo -n"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "nothing to change") != null);
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm fence naboo -n"));
    const out = g.h.stdout();
    try expectLines(out, &.{ "tag  (none) → fenced", "Recovery  artoo vm set naboo tags=artoo\n", "Dry run: nothing was sent." });
    try testing.expect(std.mem.find(u8, out, "rule ") == null);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "vm fence --off -n: options first, every rule, IP set, NIC flag and tag removed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const two = try rules(a, .{ .ad = test_ad });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        ok("GET /api2/json/nodes/pve/qemu ", fenced_list),
        ok("/qemu/201/config ", cfg_naboo_fenced),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", all_options),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/rules ", try rulesBody(a, two[0..2])),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset ", "{\"data\":[{\"name\":\"ipfilter-net0\"}]}"),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", "{\"data\":[{\"cidr\":\"192.168.1.201\"}]}"),
        ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", all_options),
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm fence naboo --off -n"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try expectLines(g.h.stdout(), &.{
        "Plan · Remove the fence of naboo (201)  ▲ destructive",
        "options  enabled → enable 0, others at Proxmox's defaults (first)",
        "rule 1   IN ACCEPT tcp 22 from 192.168.1.0/24 → (removed)",
        "rule 2   IN ACCEPT Ping from 192.168.1.0/24 → (removed)",
        "IP set   ipfilter-net0 → (removed)",
        "NIC      net0 firewall=1 → (removed)",
        "tag      fenced → (removed)",
        "artoo vm fence naboo\n",
    });
}

test "vm fence: refuses role VMs, templates, foreign VMs; exceptions resolve guests and never reach Proxmox" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    var routes: std.ArrayList(R) = .empty;
    for (0..5) |_| try routes.append(a, ok("GET /api2/json/nodes/pve/qemu ", qemu_list));
    // An exception to hoth resolves its static address …
    try routes.appendSlice(a, try onReads(a, qemu_list, cfg_naboo, "{\"data\":{}}", empty, empty));
    try routes.insert(a, routes.items.len - 6, ok("/qemu/204/config ", "{\"data\":{\"ipconfig0\":\"ip=192.168.1.204/24,gw=192.168.1.1\"}}"));
    // … one to the gateway's subnet is refused before planning.
    try routes.appendSlice(a, (try onReads(a, qemu_list, cfg_naboo, "{\"data\":{}}", empty, empty))[0..6]);
    try g.initRoutes(routes.items);
    defer g.deinit();
    for ([_][]const u8{ "bespin", "scarif", "dagobah", "ubuntu-2604", "kessel" }, [_][]const u8{ "the edge VM", "the watchdog", "subnet router", "template", "not created by artoo" }) |vm, why| {
        try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, try std.fmt.allocPrint(a, "vm fence {s} -n", .{vm})));
        if (std.mem.find(u8, g.h.stderr(), why) == null) {
            std.debug.print("{s}: {s}\n", .{ vm, g.h.stderr() });
            return error.TestUnexpectedResult;
        }
    }
    const good = try g.file("good.json", "{\"schema_version\":1,\"guests\":{\"fence_allow_out\":\"naboo hoth tcp 5432; hoth 203.0.113.9 udp 51820\"}}");
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, try std.fmt.allocPrint(a, "vm fence naboo -n --config {s}", .{good})));
    try expectLines(g.h.stdout(), &.{ "rule 7   (none) → OUT ACCEPT tcp 5432 to 192.168.1.204", "the configured exceptions" });
    try testing.expect(std.mem.find(u8, g.h.stdout(), "51820") == null);
    const bad = try g.file("bad.json", "{\"schema_version\":1,\"guests\":{\"fence_allow_out\":\"naboo 192.168.0.0/16 tcp 22\"}}");
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, try std.fmt.allocPrint(a, "vm fence naboo -n --config {s}", .{bad})));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "never opened") != null);
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "vm show: the fence on, in drift, or a firewall not written by vm fence" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const want = try rules(a, .{ .ad = test_ad, .edge = "192.168.1.200", .services = &.{.{ .name = "grafana", .port = 3000 }}, .watch = "192.168.1.202" });
    const stopped = try std.mem.replaceOwned(u8, a, fenced_list, "\"name\":\"naboo\",\"status\":\"running\"", "\"name\":\"naboo\",\"status\":\"stopped\"");
    const ipset = "{\"data\":[{\"name\":\"ipfilter-net0\"}]}";
    const entries = "{\"data\":[{\"cidr\":\"192.168.1.201\"}]}";
    const naboo_pending = try vm_cmd.pendingOf(a, cfg_naboo_fenced);
    var routes: std.ArrayList(R) = .empty;
    for ([_][]const u8{ try rulesBody(a, want), empty }) |rules_body| {
        try routes.appendSlice(a, &.{
            ok("GET /api2/json/nodes/pve/qemu ", stopped),
            ok("/qemu/201/pending ", naboo_pending),
            ok("/qemu/201/snapshot ", empty),
            ok("GET /api2/json/nodes/pve/qemu ", stopped),
            ok("POST /api2/json/nodes/pve/qemu/200/agent/exec ", pid),
            ok("/qemu/200/agent/exec-status", try edgeDump(a)),
            ok("/qemu/200/config ", "{\"data\":{\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\"}}"),
            ok("/qemu/202/config ", "{\"data\":{\"ipconfig0\":\"ip=192.168.1.202/24,gw=192.168.1.1\"}}"),
            ok("/qemu/201/config ", cfg_naboo_fenced),
            ok("GET /api2/json/nodes/pve/qemu/201/firewall/options ", all_options),
            ok("GET /api2/json/nodes/pve/qemu/201/firewall/rules ", rules_body),
            ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset ", ipset),
            ok("GET /api2/json/nodes/pve/qemu/201/firewall/ipset/ipfilter-net0 ", entries),
        });
    }
    try routes.insert(a, 13, ok("/cluster/firewall/options ", "{\"data\":{\"enable\":1}}"));
    const hand = try std.mem.replaceOwned(u8, a, stopped, "artoo;fenced", "artoo");
    try routes.appendSlice(a, &.{ ok("GET /api2/json/nodes/pve/qemu ", hand), ok("/qemu/201/pending ", naboo_pending), ok("/qemu/201/snapshot ", empty) });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes.items);
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm show naboo"));
    try expectLines(g.h.stdout(), &.{"Fence      on (12 rules, only source 192.168.1.201)"});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm show naboo"));
    try expectLines(g.h.stdout(), &.{"Fence      drift — rule 1: (none) instead of IN ACCEPT tcp 3000 from 192.168.1.200; 'artoo vm fence naboo'"});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm show naboo"));
    try expectLines(g.h.stdout(), &.{"Fence      off (net0 firewall=1, not by 'vm fence')"});
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}
