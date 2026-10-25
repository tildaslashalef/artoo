//! `artoo vm new | verify | ssh | password` (SPEC §9.3–9.5, §7): a ready
//! Ubuntu guest from the template in one confirmed workflow, its read-only
//! readiness checks, SSH with the host key pinned through the guest agent,
//! and the per-guest password of the guest user (`guests.user`).

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const exec = @import("../exec.zig");
const files = @import("../files.zig");
const proc = @import("../proc.zig");
const prompt = @import("../prompt.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const tasks = @import("../pve/task.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const unifi = @import("../unifi/client.zig");
const catalog = @import("../unifi/catalog.zig");
const view = @import("../unifi/view.zig");
const dns = @import("../unifi/dns.zig");
const classic = @import("../unifi/classic.zig");
const crypt = @import("../guest/crypt512.zig");
const known_hosts = @import("../guest/known_hosts.zig");
const ssh_config = @import("../guest/ssh_config.zig");
const vm_ssh = @import("vm_ssh.zig");
const vendor = @import("../guest/vendor.zig");
const names = @import("../guest/names.zig");
const vm_role = @import("vm.zig").roleOf;
const exposure = @import("../exposure.zig");
const activity = @import("../activity.zig");
const template = @import("template.zig");
const storage = @import("storage.zig");
const life = @import("vm_life.zig");
const watch = @import("watch.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

/// Tag on every guest artoo creates (with the `guest/<name>` secret, the
/// marker that lets `vm new` continue an interrupted run).
pub const tag = "artoo";

const vm_arg: cli.Positional = .{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name" };

// ---------------------------------------------------------------- inputs

/// Presets (SPEC §9.1): vCPU, RAM in MiB, disk in GiB. 20 GiB is the
/// floor: a guest uses ~4 GiB after first boot and disks only grow.
pub const Size = enum {
    tiny,
    small,
    medium,
    large,
    xlarge,

    fn cores(s: Size) u32 {
        return switch (s) {
            .tiny => 1,
            .small, .medium => 2,
            .large => 4,
            .xlarge => 8,
        };
    }
    fn memory(s: Size) u64 {
        return switch (s) {
            .tiny => 1024,
            .small => 2048,
            .medium => 4096,
            .large => 8192,
            .xlarge => 16384,
        };
    }
    fn disk(s: Size) u64 {
        return switch (s) {
            .tiny, .small => 20,
            .medium => 40,
            .large => 80,
            .xlarge => 160,
        };
    }
};

/// SPEC §9.1: a valid label, never a protected or equipment name.
fn checkName(ctx: *Context, nm: []const u8) !void {
    if (!names.valid(nm)) return ctx.fail(error.Usage, "NAME must be one lowercase DNS label (letter first; letters, digits, single hyphens; 2-{d} characters), got '{s}'", .{ names.max_len, nm });
    if (names.isReserved(nm) or exposure.protected(try ctx.config(), nm, null) != null)
        return ctx.fail(error.Refused, "'{s}' names the lab's infrastructure or equipment; choose another name", .{nm});
}

/// A free curated name: no VM, no DNS record under the guest domain and
/// no UniFi client record carries it (SPEC §9.1).
fn pickName(ctx: *Context, c: *pve.Client) ![]const u8 {
    const a = ctx.arena;
    const domain = (try ctx.config()).guests.domain;
    var used: std.ArrayList([]const u8) = .empty;
    const infra: exposure.Infra = .of(try ctx.config());
    try used.appendSlice(a, infra.names[0..infra.n_names]);
    for (try vms.list(c)) |v| try used.append(a, v.name);
    var u = try unifi.Client.open(ctx);
    defer u.deinit();
    for (try dns.list(&u)) |r| {
        const label = std.mem.cutSuffix(u8, r.domain, domain) orelse continue;
        if (label.len > 1 and label[label.len - 1] == '.') try used.append(a, label[0 .. label.len - 1]);
    }
    for (try classic.records(&u)) |r| if (r.name.len > 0) try used.append(a, r.name);
    return (try names.pick(ctx.io, used.items)) orelse ctx.fail(error.Refused, "every curated name is taken; give NAME explicitly", .{});
}

/// `40` or `40G` (GiB).
pub fn parseGiB(s: []const u8) ?u64 {
    const digits = std.mem.trimEnd(u8, s, "gG");
    const n = std.fmt.parseInt(u64, digits, 10) catch return null;
    return if (n >= 4 and n <= 4096) n else null;
}

pub fn ip4(s: []const u8) ?u32 {
    const a = std.Io.net.Ip4Address.parse(s, 0) catch return null;
    return std.mem.readInt(u32, &a.bytes, .big);
}

pub fn ip4Text(arena: std.mem.Allocator, v: u32) ![]const u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    return std.fmt.allocPrint(arena, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
}

/// Host address inside the gateway's subnet (not network, broadcast or
/// the gateway itself).
pub fn usableIn(net: config.Cidr, v: u32) bool {
    const mask: u32 = ~@as(u32, 0) << @intCast(32 - @as(u32, net.prefix));
    if (v & mask != net.address & mask) return false;
    return v != net.address and v & ~mask != 0 and v & ~mask != ~mask;
}

/// Lowest address of `pool` that is usable and not in `used`.
pub fn pick(pool: config.Range, net: config.Cidr, used: []const u32) ?u32 {
    var v = pool.first;
    while (v <= pool.last) : (v += 1) {
        if (usableIn(net, v) and std.mem.findScalar(u32, used, v) == null) return v;
        if (v == std.math.maxInt(u32)) break;
    }
    return null;
}

/// PVE wants `sshkeys` URL-encoded inside the (form-encoded) value.
pub fn encodeKeys(arena: std.mem.Allocator, keys: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (keys) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try out.append(arena, ch);
        } else try out.print(arena, "%{X:0>2}", .{ch});
    }
    return out.items;
}

/// The public keys installed for the guest user: the operator's
/// (`guests.ssh_public_key`) first, then `guests.extra_ssh_keys`.
const PublicKeys = struct {
    /// One OpenSSH line per key, newline-separated (PVE `sshkeys`).
    lines: []const u8,
    /// Each extra key's comment (or its file name), for the plan.
    extra: []const []const u8,
};

fn publicKeys(ctx: *Context) !PublicKeys {
    const cfg = try ctx.config();
    var lines: std.ArrayList(u8) = .empty;
    try lines.appendSlice(ctx.arena, try keyLine(ctx, cfg.guests.ssh_public_key, "guests.ssh_public_key"));
    var extra: std.ArrayList([]const u8) = .empty;
    for (try config.pathList(ctx.arena, cfg.guests.extra_ssh_keys)) |p| {
        const line = try keyLine(ctx, p, "guests.extra_ssh_keys");
        if (std.mem.find(u8, lines.items, line) != null) continue;
        try lines.append(ctx.arena, '\n');
        try lines.appendSlice(ctx.arena, line);
        try extra.append(ctx.arena, keyComment(line) orelse std.fs.path.basename(p));
    }
    return .{ .lines = lines.items, .extra = extra.items };
}

/// One OpenSSH public key line from the file at `path` (`what` names
/// the config key in errors). A private key is refused, never echoed.
fn keyLine(ctx: *Context, path: []const u8, what: []const u8) ![]const u8 {
    const p = files.expandHome(ctx.arena, ctx.env, path) catch
        return ctx.fail(error.ConfigInvalid, "HOME is not set; cannot read {s}", .{what});
    const raw = std.Io.Dir.cwd().readFileAlloc(ctx.io, p, ctx.arena, .limited(16 * 1024)) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return ctx.fail(error.ConfigInvalid, "cannot read {s} ({s})", .{ what, ctx.tilde(p) }),
    };
    if (std.mem.find(u8, raw, "PRIVATE KEY") != null)
        return ctx.fail(error.ConfigInvalid, "{s} ({s}) is a private key; name the .pub file", .{ what, ctx.tilde(p) });
    const line = std.mem.trim(u8, raw, " \r\n");
    if (!validKeyLine(line))
        return ctx.fail(error.ConfigInvalid, "{s} is not one OpenSSH public key line", .{ctx.tilde(p)});
    return line;
}

fn validKeyLine(line: []const u8) bool {
    if (std.mem.findAny(u8, line, "\r\n") != null) return false;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    const kind = it.next() orelse return false;
    const blob = it.next() orelse return false;
    if (!std.mem.startsWith(u8, kind, "ssh-") and !std.mem.startsWith(u8, kind, "ecdsa-") and !std.mem.startsWith(u8, kind, "sk-")) return false;
    for (blob) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '+' and ch != '/' and ch != '=') return false;
    return true;
}

fn keyComment(line: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next();
    _ = it.next();
    const rest = std.mem.trim(u8, it.rest(), " ");
    return if (rest.len > 0) rest else null;
}

fn gateway(ctx: *Context) !config.Cidr {
    const cfg = try ctx.config();
    return config.parseCidr(cfg.guests.gateway) orelse ctx.fail(error.ConfigInvalid, "guests.gateway '{s}' is not A/N", .{cfg.guests.gateway});
}

fn secretName(ctx: *Context, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "guest/{s}", .{name});
}

/// `scsi0: …,size=20G` → bytes.
pub fn diskBytes(cfg: Value) ?u64 {
    const s = pve.str(cfg, "scsi0") orelse return null;
    var it = std.mem.tokenizeScalar(u8, s, ',');
    while (it.next()) |part| {
        const v = std.mem.cutPrefix(u8, part, "size=") orelse continue;
        if (v.len < 2) return null;
        const n = std.fmt.parseInt(u64, v[0 .. v.len - 1], 10) catch return null;
        return switch (v[v.len - 1]) {
            'T' => n << 40,
            'G' => n << 30,
            'M' => n << 20,
            'K' => n << 10,
            else => null,
        };
    }
    return null;
}

// ---------------------------------------------------------------- vm new

const Steps = struct {
    password: bool = false,
    clone: bool = false,
    configure: bool = false,
    reserve: bool = false,
    resize: bool = false,
    start: bool = false,
    dns: bool = false,
};

const NewOp = struct {
    c: *pve.Client,
    name: []const u8,
    size: Size,
    cores: u32,
    memory: u64,
    disk: u64,
    want_ip: ?[]const u8,
    want_id: ?u32,
    template_word: []const u8,
    no_dns: bool,
    /// `artoo`, plus `role-…` with --role.
    tags: []const u8 = tag,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    fqdn: []const u8 = "",
    net: config.Cidr = undefined,
    tmpl: vms.Vm = undefined,
    cicustom: []const u8 = "",
    existing: ?vms.Vm = null,
    cfg: Value = .null,
    secret: bool = false,
    vmid: u32 = 0,
    address: []const u8 = "",
    /// Classic `_id` of the guests' network (UniFi client records).
    network_id: []const u8 = "",
    steps: Steps = .{},
    /// The watchdog (role-watch) the guest is enrolled with (SPEC §9.9).
    watch_vm: ?[]const u8 = null,
    /// `~/.artoo/ssh_config` exists and gets the guest's block (SPEC §9.10).
    ssh_config: bool = false,
    state: []const u8 = "",
    ledger: exec.Ledger = .{},
    checks: []const Check = &.{},
    /// The pinned host key as a known_hosts line for other machines.
    host_line: ?[]const u8 = null,

    pub fn read(op: *NewOp, ctx: *Context) !void {
        const c = op.c;
        const cfg = try ctx.config();
        const a = ctx.arena;
        op.target = op.name;
        op.fqdn = try dns.fqdn(a, op.name, cfg.guests.domain);
        op.net = try gateway(ctx);
        op.steps = .{};
        op.existing = null;
        const all = try vms.list(c);
        op.watch_vm = null;
        if (!std.mem.endsWith(u8, op.tags, ";role-" ++ watch.role)) {
            for (all) |v| if (!v.template and watch.roleOf(v.tags) == .watch) {
                op.watch_vm = v.name;
            };
        }

        // Template: tagged, with its vendor snippet present on Proxmox.
        op.tmpl = switch (try vms.find(all, a, op.template_word)) {
            .vm => |v| v,
            else => return ctx.fail(error.Refused, "no template '{s}' on Proxmox; build it with 'artoo template build {s}'", .{ op.template_word, op.template_word }),
        };
        if (!op.tmpl.template) return ctx.fail(error.Refused, "{s} is a VM, not a template", .{op.template_word});
        const tcfg = try vms.config(c, op.tmpl.vmid);
        if (!template.tagged(pve.str(tcfg, "tags") orelse "")) return ctx.fail(error.Refused, "template {s} was not built by artoo", .{op.template_word});
        op.cicustom = pve.str(tcfg, "cicustom") orelse return ctx.fail(error.Refused, "template {s} has no vendor snippet; run 'artoo template build {s}'", .{ op.template_word, op.template_word });
        const snippet = std.mem.cutPrefix(u8, op.cicustom, "vendor=local:snippets/") orelse return ctx.fail(error.Refused, "template {s} has an unexpected cicustom '{s}'", .{ op.template_word, op.cicustom });
        for (try template.snippetFiles(c)) |f| {
            if (std.mem.eql(u8, f.name, snippet)) break;
        } else return ctx.fail(error.Refused, "the vendor snippet {s} of template {s} is missing on Proxmox; run 'artoo template build {s}'", .{ snippet, op.template_word, op.template_word });

        const store = try ctx.secretStore();
        op.secret = store.exists(ctx.io, a, try secretName(ctx, op.name)) catch false;

        switch (try vms.find(all, a, op.name)) {
            .ambiguous => return ctx.fail(error.Refused, "several VMs are named '{s}'", .{op.name}),
            .missing => {},
            .vm => |v| {
                const vcfg = try vms.config(c, v.vmid);
                if (v.template or !template.taggedWith(pve.str(vcfg, "tags") orelse "", tag) or !op.secret)
                    return ctx.fail(error.Refused, "a VM named '{s}' already exists ({d}) and was not created by artoo", .{ op.name, v.vmid });
                op.existing = v;
                op.cfg = vcfg;
            },
        }

        if (op.existing) |v| {
            // Continue an interrupted run from the observed state.
            op.vmid = v.vmid;
            const configured = std.mem.eql(u8, pve.str(op.cfg, "ciuser") orelse "", (try ctx.config()).guests.user) and pve.str(op.cfg, "cipassword") != null;
            if (life.staticAddress(op.cfg)) |addr| op.address = addr else try op.chooseAddress(ctx, all);
            op.steps.configure = !configured or life.staticAddress(op.cfg) == null;
            op.steps.resize = (diskBytes(op.cfg) orelse 0) < op.disk << 30;
            op.steps.start = !v.running();
        } else {
            op.vmid = if (op.want_id) |id| blk: {
                for (all) |v| if (v.vmid == id) return ctx.fail(error.Refused, "VMID {d} is taken", .{id});
                break :blk id;
            } else try vms.freeVmid(c, 200);
            try op.chooseAddress(ctx, all);
            const space = for (try storage.list(c)) |s| {
                if (std.mem.eql(u8, s.name, template.disk_storage)) break s.avail;
            } else null;
            if (space != null and space.? < op.disk << 30)
                return ctx.fail(error.Refused, "{s} has {f} free; the guest needs {d} GiB", .{ template.disk_storage, ui.values.bytes(space), op.disk });
            op.steps = .{ .password = true, .clone = true, .configure = true, .reserve = true, .resize = (op.tmpl.maxdisk orelse 0) < op.disk << 30, .start = true };
        }
        var u = try unifi.Client.open(ctx);
        defer u.deinit();
        op.network_id = try classic.networkId(&u, cfg.guests.gateway);
        if (op.existing != null) {
            // The clone's MAC decides whether its client record exists.
            const mac = try classic.netMac(a, pve.str(op.cfg, "net0") orelse "") orelse
                return ctx.fail(error.Refused, "VM {d} has no net0 MAC", .{op.vmid});
            if (classic.find(try classic.records(&u), mac)) |r| {
                if (!std.mem.eql(u8, r.name, op.name) or !std.mem.eql(u8, r.fixed_ip orelse "", op.address))
                    return ctx.fail(error.Refused, "UniFi's client record for {s} is named '{s}' with Fixed IP {s}, not {s} → {s}; fix or forget it in the UniFi UI", .{ mac, try k.clean(ctx, r.name), r.fixed_ip orelse "none", op.name, op.address });
            } else op.steps.reserve = true;
        }
        op.steps.dns = !op.no_dns;
        if (!op.no_dns) {
            if (dns.find(try dns.list(&u), op.fqdn)) |r| {
                if (op.existing == null or !std.mem.eql(u8, r.ipv4, op.address))
                    return ctx.fail(error.Refused, "a DNS record {s} → {s} already exists on UniFi", .{ r.domain, r.ipv4 });
                op.steps.dns = false;
            }
        }
        op.ssh_config = try vm_ssh.present(ctx);
        op.state = try std.fmt.allocPrint(a, "{d}:{s}:{s}", .{ op.vmid, op.address, pve.str(op.cfg, "digest") orelse "" });
    }

    /// `--ip`, or the lowest pool address nobody uses: no VM config, no
    /// DNS record, no Fixed IP on a client record, no connected client
    /// (SPEC §9.5).
    fn chooseAddress(op: *NewOp, ctx: *Context, all: []const vms.Vm) !void {
        const cfg = try ctx.config();
        const a = ctx.arena;
        var used: std.ArrayList(u32) = .empty;
        var who: std.ArrayList([]const u8) = .empty;
        for (all) |v| {
            if (v.template) continue;
            const addr = life.staticAddress(try vms.config(op.c, v.vmid)) orelse continue;
            try used.append(a, ip4(addr) orelse continue);
            try who.append(a, try std.fmt.allocPrint(a, "VM {s}", .{try k.clean(ctx, v.name)}));
        }
        var u = try unifi.Client.open(ctx);
        defer u.deinit();
        for (try dns.list(&u)) |r| {
            try used.append(a, ip4(r.ipv4) orelse continue);
            try who.append(a, try std.fmt.allocPrint(a, "DNS record {s}", .{try k.clean(ctx, r.domain)}));
        }
        for (try classic.records(&u)) |r| {
            try used.append(a, ip4(r.fixed_ip orelse continue) orelse continue);
            try who.append(a, try std.fmt.allocPrint(a, "Fixed IP of client {s}", .{try k.clean(ctx, if (r.name.len > 0) r.name else r.mac)}));
        }
        const clients = try unifi.list(&u, catalog.find("clients").?, .{ .all = true });
        for (clients.items) |cl| {
            try used.append(a, ip4(view.string(cl, "ipAddress") orelse continue) orelse continue);
            try who.append(a, try std.fmt.allocPrint(a, "client {s}", .{try k.clean(ctx, view.string(cl, "name") orelse view.string(cl, "macAddress") orelse "?")}));
        }
        if (op.want_ip) |w| {
            const v = ip4(w) orelse return ctx.fail(error.Usage, "--ip must be an IPv4 address, got '{s}'", .{w});
            if (!usableIn(op.net, v)) return ctx.fail(error.Usage, "--ip {s} is not a host address in {s}", .{ w, cfg.guests.gateway });
            if (std.mem.findScalar(u32, used.items, v)) |i| return ctx.fail(error.Refused, "{s} is in use ({s})", .{ w, who.items[i] });
            op.address = w;
            return;
        }
        const pool = config.parseRange(cfg.guests.address_pool) orelse return ctx.fail(error.ConfigInvalid, "guests.address_pool is not A-B", .{});
        const v = pick(pool, op.net, used.items) orelse return ctx.fail(error.Refused, "no free address in {s}", .{cfg.guests.address_pool});
        op.address = try ip4Text(a, v);
    }

    pub fn plan(op: *NewOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const gw = try ip4Text(a, op.net.address);
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (op.steps.clone) try changes.append(a, .{ .field = "VM", .from = null, .to = try std.fmt.allocPrint(a, "{d} {s}, full clone of {s} ({d})", .{ op.vmid, op.name, try k.clean(ctx, op.tmpl.name), op.tmpl.vmid }) });
        try changes.append(a, .{ .field = "size", .from = null, .to = try std.fmt.allocPrint(a, "{d} vCPU, {f} RAM, {d} GiB disk ({t})", .{ op.cores, ui.values.bytes(op.memory << 20), op.disk, op.size }) });
        try changes.append(a, .{ .field = "address", .from = null, .to = try std.fmt.allocPrint(a, "{s}/{d} via {s} (static)", .{ op.address, op.net.prefix, gw }) });
        const extra = (try publicKeys(ctx)).extra;
        try changes.append(a, .{ .field = "user", .from = null, .to = try std.fmt.allocPrint(a, "{s}: your SSH key; sudo password generated, kept in the Keychain", .{(try ctx.config()).guests.user}) });
        if (extra.len > 0) try changes.append(a, .{ .field = "more SSH keys", .from = null, .to = try std.mem.join(a, ", ", extra) });
        if (!std.mem.eql(u8, op.tags, tag)) try changes.append(a, .{ .field = "tags", .from = null, .to = op.tags });
        if (op.steps.reserve) try changes.append(a, .{ .field = "client record", .from = null, .to = try std.fmt.allocPrint(a, "{s}, Fixed IP {s} on UniFi (the VM's MAC)", .{ op.name, op.address }) });
        if (op.steps.dns) try changes.append(a, .{ .field = "DNS record", .from = null, .to = try std.fmt.allocPrint(a, "{s} {s} {s} on UniFi", .{ op.fqdn, ctx.ui.glyphs.arrow, op.address }) });
        try changes.append(a, .{ .field = "host key", .from = null, .to = try std.fmt.allocPrint(a, "{s} entry {s} (read through the guest agent)", .{ known_hosts.default_path, op.name }) });
        if (op.ssh_config) try changes.append(a, .{ .field = "ssh config", .from = null, .to = try std.fmt.allocPrint(a, "Host {s} in {s}", .{ op.name, ssh_config.default_path }) });
        if (op.watch_vm) |w| try changes.append(a, .{ .field = "watch", .from = null, .to = try std.fmt.allocPrint(a, "Alloy pushes metrics and the journal to {s}", .{w}) });
        var notes: std.ArrayList([]const u8) = .empty;
        if (op.existing != null) try notes.append(a, "Continuing an interrupted 'vm new': finished steps are skipped.");
        if (op.no_dns) try notes.append(a, "--no-dns: no DNS record; reach the guest by address.");
        try notes.append(a, "Cloud-init installs packages on first boot; the workflow waits for it (several minutes), then reboots the guest once if the updates ask for it.");
        try notes.append(a, "Steps run in order and stop at the first failure; nothing is undone automatically. Re-running continues.");
        return .{
            .action = try std.fmt.allocPrint(a, "Create guest {s} ({d})", .{ op.name, op.vmid }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{if (op.steps.dns) "A new VM on Proxmox; its client record and an A record on UniFi" else if (op.steps.reserve) "A new VM on Proxmox and its client record on UniFi" else "A new VM on Proxmox"}),
            .notes = notes.items,
            .recovery = try std.fmt.allocPrint(a, "artoo vm rm {s}", .{op.name}),
        };
    }

    pub fn fingerprint(op: *NewOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *NewOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        const st = op.steps;
        const l = &op.ledger;
        const s_password = if (st.password) try l.add(a, "generate password") else null;
        const s_clone = if (st.clone) try l.add(a, "clone template") else null;
        const s_config = if (st.configure) try l.add(a, "configure cloud-init") else null;
        const s_reserve = if (st.reserve) try l.add(a, "reserve address") else null;
        const s_resize = if (st.resize) try l.add(a, "resize disk") else null;
        const s_start = if (st.start) try l.add(a, "start VM") else null;
        const s_agent = try l.add(a, "wait for guest agent");
        const s_ci = try l.add(a, "wait for cloud-init");
        const s_reboot = try l.add(a, "reboot for updates");
        const s_key = try l.add(a, "pin SSH host key");
        const s_ssh = if (op.ssh_config) try l.add(a, "update ssh config") else null;
        const s_dns = if (st.dns) try l.add(a, "add DNS record") else null;
        const s_watch = if (op.watch_vm != null) try l.add(a, "enroll in watch") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        const store = try ctx.secretStore();
        const secret_name = try secretName(ctx, op.name);
        var hash_buf: [crypt.hash_buf_len]u8 = undefined;
        var hash: []const u8 = "";

        if (s_password) |i| {
            var pw: [crypt.password_len]u8 = undefined;
            try crypt.generatePassword(ctx.io, &pw, pw.len);
            store.set(ctx.io, a, secret_name, &pw) catch |err| {
                l.set(i, .failed, @errorName(err));
                return ctx.fail(error.SecretStoreUnavailable, "cannot store the password as {s}; nothing was created", .{secret_name});
            };
            hash = try hashOf(ctx, &hash_buf, &pw);
            l.set(i, .done, secret_name);
        }
        if (s_clone) |i| {
            l.set(i, .unknown, "");
            const params = [_]pve.Param{
                .{ .name = "newid", .value = try std.fmt.allocPrint(a, "{d}", .{op.vmid}) },
                .{ .name = "name", .value = op.name },
                .{ .name = "full", .value = "1" },
            };
            const upid = try tasks.upidOf(c, try c.send(.POST, try c.nodePath("/qemu/{d}/clone", .{op.tmpl.vmid}), &params), "the clone");
            l.set(i, .done, try k.waitTask(c, upid, 1800));
        }
        if (s_config) |i| {
            if (hash.len == 0) {
                const pw = try store.require(ctx.io, a, secret_name);
                hash = try hashOf(ctx, &hash_buf, pw);
            }
            const cfg = try vms.config(c, op.vmid);
            const gw = try ip4Text(a, op.net.address);
            l.set(i, .unknown, "");
            _ = try c.send(.PUT, try c.nodePath("/qemu/{d}/config", .{op.vmid}), &.{
                .{ .name = "cores", .value = try std.fmt.allocPrint(a, "{d}", .{op.cores}) },
                .{ .name = "memory", .value = try std.fmt.allocPrint(a, "{d}", .{op.memory}) },
                .{ .name = "ciuser", .value = (try ctx.config()).guests.user },
                .{ .name = "cipassword", .value = hash },
                .{ .name = "sshkeys", .value = try encodeKeys(a, (try publicKeys(ctx)).lines) },
                .{ .name = "ipconfig0", .value = try std.fmt.allocPrint(a, "ip={s}/{d},gw={s}", .{ op.address, op.net.prefix, gw }) },
                .{ .name = "nameserver", .value = gw },
                .{ .name = "searchdomain", .value = (try ctx.config()).guests.domain },
                .{ .name = "cicustom", .value = op.cicustom },
                .{ .name = "tags", .value = op.tags },
                .{ .name = "digest", .value = pve.str(cfg, "digest") orelse "" },
            });
            l.set(i, .done, op.address);
        }
        if (s_reserve) |i| {
            const mac = try classic.netMac(a, pve.str(try vms.config(c, op.vmid), "net0") orelse "") orelse {
                l.set(i, .failed, "no net0 MAC");
                return ctx.fail(error.Partial, "VM {d} has no net0 MAC; its address cannot be reserved", .{op.vmid});
            };
            var u = try unifi.Client.open(ctx);
            defer u.deinit();
            l.set(i, .unknown, "");
            try classic.reserve(&u, mac, op.name, op.network_id, op.address);
            l.set(i, .done, try std.fmt.allocPrint(a, "{s} {s} {s}", .{ mac, ctx.ui.glyphs.arrow, op.address }));
        }
        if (s_resize) |i| {
            l.set(i, .unknown, "");
            const data = try c.send(.PUT, try c.nodePath("/qemu/{d}/resize", .{op.vmid}), &.{
                .{ .name = "disk", .value = "scsi0" },
                .{ .name = "size", .value = try std.fmt.allocPrint(a, "{d}G", .{op.disk}) },
            });
            l.set(i, .done, if (data == .null) "done" else try k.waitTask(c, try tasks.upidOf(c, data, "the resize"), 300));
        }
        if (s_start) |i| {
            l.set(i, .unknown, "");
            const upid = try tasks.upidOf(c, try c.send(.POST, try c.nodePath("/qemu/{d}/status/start", .{op.vmid}), &.{}), "the start");
            l.set(i, .done, try k.waitTask(c, upid, 120));
        }
        try agent.waitReady(c, op.vmid, 900_000);
        l.set(s_agent, .done, "");
        {
            // Packages are installed before the agent itself, so this is
            // mostly the tail of the final stage.
            const r = try waitCloudInit(c, op.vmid, 1_800_000, l.noter(s_ci));
            const ch = try judgeCloudInit(ctx, r, "", "");
            l.set(s_ci, if (ch.status == .failed) .failed else .done, ch.detail);
        }
        try rebootForUpdates(c, op.vmid, l, s_reboot);
        {
            const line = try agent.readFile(c, op.vmid, known_hosts.host_key_file);
            const key = try known_hosts.keyOf(a, line) orelse {
                l.set(s_key, .failed, "no ed25519 host key");
                return ctx.fail(error.Partial, "guest {s} has no usable {s}", .{ op.name, known_hosts.host_key_file });
            };
            try known_hosts.record(ctx, op.name, key);
            op.host_line = try hostLine(a, op.name, if (op.no_dns) null else op.fqdn, op.address, key);
            l.set(s_key, .done, known_hosts.default_path);
        }
        if (s_ssh) |i| {
            // A failure fails only this step; 'vm ssh-config' repairs it.
            const block: ssh_config.Block = .{ .name = op.name, .address = op.address, .jump = known_hosts.wantsJump(op.tags) };
            if (vm_ssh.put(ctx, op.name, block)) {
                l.set(i, .done, ssh_config.default_path);
            } else |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    l.set(i, .failed, ctx.diag orelse @errorName(err));
                    ctx.diag = null;
                },
            }
        }
        if (s_dns) |i| {
            var u = try unifi.Client.open(ctx);
            defer u.deinit();
            l.set(i, .unknown, "");
            try dns.create(&u, op.fqdn, op.address, dns.default_ttl);
            l.set(i, .done, op.fqdn);
        }
        if (s_watch) |i| {
            l.set(i, .unknown, "");
            const detail = try watch.enrollNew(ctx, c, try vms.resolve(c, op.name));
            l.set(i, .done, detail orelse "no watchdog");
        }
    }

    pub fn verify(op: *NewOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const v = try vms.resolve(op.c, op.name);
        op.checks = try runChecks(ctx, op.c, v, try vms.config(op.c, v.vmid), op.no_dns, op.watch_vm);
        try ctx.out.writeAll("\n");
        try renderChecks(ctx, op.checks);
        return op.ledger.complete() and failures(op.checks) == 0;
    }

    pub fn done(op: *NewOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} ({d}) is ready at {s}{s}{s} — 'artoo vm ssh {s}'{s}{s}", .{
            op.name,                                                                       op.vmid,                op.address, if (op.no_dns) "" else ", ", if (op.no_dns) "" else op.fqdn, op.name,
            if (op.host_line != null) "\n  known_hosts line for other machines: " else "", op.host_line orelse "",
        }) catch "done";
    }
};

/// `NAME,FQDN,ADDRESS KEY`: one known_hosts line that pins the guest
/// under every name another machine may use for it.
fn hostLine(a: std.mem.Allocator, name: []const u8, fqdn: ?[]const u8, address: []const u8, key: []const u8) ![]const u8 {
    return if (fqdn) |f|
        std.fmt.allocPrint(a, "{s},{s},{s} {s}", .{ name, f, address, key })
    else
        std.fmt.allocPrint(a, "{s},{s} {s}", .{ name, address, key });
}

fn hashOf(ctx: *Context, buf: *[crypt.hash_buf_len]u8, pw: []const u8) ![]const u8 {
    var salt: [crypt.salt_len]u8 = undefined;
    try crypt.generateSalt(ctx.io, &salt);
    const h = crypt.sha512Crypt(buf, pw, &salt) catch return ctx.fail(error.Internal, "password hashing failed", .{});
    return ctx.arena.dupe(u8, h);
}

fn firstLine(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \r\n");
    return t[0 .. std.mem.findScalar(u8, t, '\n') orelse t.len];
}

pub const new = struct {
    pub const name = "new";
    pub const summary = "Create a ready Ubuntu guest from the template";
    pub const details =
        \\NAME is one DNS label (e.g. naboo); without it artoo picks a free name
        \\from its Star Wars / Middle-earth list. --role tags the purpose
        \\(role-ROLE). Sizes (vCPU/GiB RAM/GiB disk): tiny 1/1/20,
        \\small 2/2/20 (default), medium 2/4/40, large 4/8/80, xlarge 8/16/160;
        \\--cores, --memory and --disk override. The
        \\address is --ip or the lowest free one in guests.address_pool (no VM,
        \\DNS record, Fixed IP or connected client on it). One confirmation covers the
        \\workflow: password into the Keychain (guest/NAME, only its SHA-512 hash
        \\goes to Proxmox), full clone, cloud-init settings (your SSH key plus
        \\guests.extra_ssh_keys), a UniFi client
        \\record for the VM's MAC (name, Fixed IP), disk resize, start,
        \\wait for cloud-init, one reboot if the first boot's updates ask for it,
        \\host key pinned via the guest agent (and printed as a known_hosts line
        \\for other machines), DNS record
        \\NAME.<guests.domain> on UniFi, then 'vm verify'. Re-running continues
        \\an interrupted run.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "NAME", .complete = .guest_name, .help = "Guest name (default: a free curated name)", .required = false }};
    pub const flags = [_]cli.Flag{
        .{ .long = "size", .short = 's', .kind = .choice, .choices = &.{ "tiny", "small", "medium", "large", "xlarge" }, .default = "small", .help = "Size preset" },
        .{ .long = "cores", .kind = .int, .metavar = "N", .help = "vCPUs (overrides the size)" },
        .{ .long = "memory", .kind = .string, .metavar = "SIZE", .help = "RAM, e.g. 2G or 2048 (MiB)" },
        .{ .long = "disk", .kind = .string, .metavar = "GIB", .help = "Disk size in GiB, e.g. 40 or 40G" },
        .{ .long = "ip", .kind = .string, .metavar = "ADDR", .help = "Static address (default: lowest free in the pool)" },
        .{ .long = "id", .kind = .int, .metavar = "VMID", .help = "VMID (default: lowest free ≥ 200)" },
        .{ .long = "template", .kind = .string, .metavar = "T", .help = "Template (default: guests.template)" },
        .{ .long = "role", .kind = .string, .metavar = "ROLE", .help = "Purpose, tagged role-ROLE (e.g. edge, db)" },
        .{ .long = "ssh-jump", .help = "Reach it over SSH through Proxmox only (tag ssh-jump)" },
        .{ .long = "no-dns", .help = "Skip the DNS record on UniFi (the client record is still made)" },
    };
    pub const examples = [_][]const u8{ "artoo vm new -n", "artoo vm new naboo --role web -n", "artoo vm new bespin --role edge --size small --cores 1 -y", "artoo vm new hoth --size medium --disk 60 --no-dns -y" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        if (args.optPos("NAME")) |nm| try checkName(ctx, nm);
        const role = args.string("role");
        if (role) |r| if (!names.valid(r)) return ctx.fail(error.Usage, "--role must be one lowercase label (e.g. edge), got '{s}'", .{r});
        const size = args.choice("size", Size) orelse .small;
        const cores: u32 = if (args.int("cores")) |n| blk: {
            if (n < 1 or n > 64) return ctx.fail(error.Usage, "--cores must be 1-64, got {d}", .{n});
            break :blk @intCast(n);
        } else size.cores();
        const memory = if (args.string("memory")) |m| (life.parseMiB(m) orelse return ctx.fail(error.Usage, "--memory must be a size like 2G or 2048, got '{s}'", .{m})) else size.memory();
        if (memory < 512) return ctx.fail(error.Usage, "--memory must be at least 512 MiB", .{});
        const disk = if (args.string("disk")) |d| (parseGiB(d) orelse return ctx.fail(error.Usage, "--disk must be 4-4096 GiB, got '{s}'", .{d})) else size.disk();
        const want_id: ?u32 = if (args.int("id")) |id| blk: {
            if (id < 100 or id > 999_999_999) return ctx.fail(error.Usage, "--id must be 100-999999999, got {d}", .{id});
            break :blk @intCast(id);
        } else null;
        const cfg = try ctx.config();
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const nm = args.optPos("NAME") orelse try pickName(ctx, &c);
        var op: NewOp = .{
            .c = &c,
            .name = nm,
            .tags = try std.fmt.allocPrint(ctx.arena, "{s}{s}{s}{s}", .{
                tag,
                if (role != null) ";role-" else "",
                role orelse "",
                if (args.has("ssh-jump")) ";" ++ known_hosts.jump_tag else "",
            }),
            .size = size,
            .cores = cores,
            .memory = memory,
            .disk = disk,
            .want_ip = args.string("ip"),
            .want_id = want_id,
            .template_word = args.string("template") orelse cfg.guests.template,
            .no_dns = args.has("no-dns"),
        };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- verify

pub const Check = struct {
    name: []const u8,
    status: ui.style.Status,
    detail: []const u8 = "",
};

pub fn failures(checks: []const Check) usize {
    var n: usize = 0;
    for (checks) |ch| n += @intFromBool(ch.status == .failed);
    return n;
}

/// Shell snippets run as root through the guest agent; each prints what
/// the check compares.
const scripts = struct {
    const names = "hostname; hostname -f";
    fn account(a: std.mem.Allocator, user: []const u8) ![]const u8 {
        return std.fmt.allocPrint(a, "getent passwd {s} | cut -d: -f6,7; stat -c %U /home/{s}", .{ user, user });
    }
    fn sudo(a: std.mem.Allocator, user: []const u8) ![]const u8 {
        return std.fmt.allocPrint(a, "runuser -u {s} -- sudo -n true", .{user});
    }
    // `-G` (OpenSSH 10) needs neither host keys nor /run/sshd, which a
    // socket-activated sshd creates only on the first connection.
    const sshd = "sshd -G 2>&1 | grep -Ei '^(permitrootlogin|passwordauthentication) '";
    const cloud_init = "cloud-init status --format json";
    fn terminfo(a: std.mem.Allocator, user: []const u8) ![]const u8 {
        return std.fmt.allocPrint(a, "test -e /etc/terminfo/x/xterm-ghostty && infocmp -x xterm-ghostty >/dev/null && runuser -u {s} -- infocmp -x xterm-ghostty >/dev/null && tput -T xterm-ghostty colors", .{user});
    }
    const tools = "for t in fish tmux vim starship zoxide eza fzf rg fdfind jq htop git curl unzip tailscale; do command -v $t >/dev/null || printf '%s ' $t; done";
    /// The edge VM has no Tailscale (SPEC §9.7).
    const tools_edge = "for t in fish tmux vim starship zoxide eza fzf rg fdfind jq htop git curl unzip; do command -v $t >/dev/null || printf '%s ' $t; done";
    const tailscale_absent = "command -v tailscale || echo absent";
    /// `key value` lines for `judgeUpdates` (SPEC §9.1).
    const updates =
        \\d=$(apt-config dump)
        \\v() { printf '%s\n' "$d" | sed -n "s/^$1 \"\(.*\)\";$/\1/p" | tail -1; }
        \\echo "periodic $(v APT::Periodic::Unattended-Upgrade)"
        \\echo "reboot $(v Unattended-Upgrade::Automatic-Reboot)"
        \\echo "security $(printf '%s\n' "$d" | grep -c -- '-security')"
        \\echo "tailscale $(printf '%s\n' "$d" | grep -c 'origin=Tailscale')"
        \\echo "installed $(command -v tailscale >/dev/null && echo yes || echo no)"
        \\echo "timer $(systemctl is-enabled apt-daily-upgrade.timer 2>/dev/null)"
        \\echo "last $(stat -c %Y /var/lib/apt/periodic/unattended-upgrades-stamp /var/lib/apt/periodic/upgrade-stamp 2>/dev/null | sort -n | tail -1)"
        \\echo "now $(date +%s)"
    ;
    const reboot = "if [ -f /run/reboot-required ]; then echo yes; cat /run/reboot-required.pkgs 2>/dev/null; else echo no; fi";
};

fn payloadScript(arena: std.mem.Allocator, user: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, "stat -c '%U %n'");
    for (vendor.payload) |f| try out.print(arena, " {s}", .{try vendor.payloadPath(arena, user, f)});
    try out.print(arena, " /home/{s}/.local/bin/fd 2>&1", .{user});
    return out.items;
}

/// SPEC §9.4. Never mutates; `no_dns` leaves the DNS checks not checked;
/// `watched` names the watchdog the guest should push to (SPEC §9.9).
pub fn runChecks(ctx: *Context, c: *pve.Client, v: vms.Vm, cfg: Value, no_dns: bool, watched: ?[]const u8) ![]const Check {
    const a = ctx.arena;
    var out: std.ArrayList(Check) = .empty;
    const domain = (try ctx.config()).guests.domain;
    const user = (try ctx.config()).guests.user;
    const fqdn = try dns.fqdn(a, v.name, domain);
    const address = life.staticAddress(cfg);
    const st = try vms.status(c, v.vmid);
    const running = std.mem.eql(u8, pve.str(st, "status") orelse "", "running");
    try out.append(a, .{ .name = "VM running", .status = if (running) .ok else .failed, .detail = try k.clean(ctx, pve.str(st, "status") orelse "unknown") });
    const agent_ok = running and try agent.ping(c, v.vmid);
    try out.append(a, if (!running) .{ .name = "guest agent", .status = .not_checked } else .{ .name = "guest agent", .status = if (agent_ok) .ok else .failed, .detail = if (agent_ok) "" else "no answer" });

    const Guest = struct {
        name: []const u8,
        argv: []const []const u8,
        judge: *const fn (*Context, agent.Result, []const u8, []const u8) anyerror!Check,
    };
    // The edge and the watchdog run without Tailscale (SPEC §9.7, §9.9).
    const edge = if (vm_role(pve.str(cfg, "tags") orelse "")) |r| std.mem.eql(u8, r, "edge") or std.mem.eql(u8, r, watch.role) else false;
    const router = if (vm_role(pve.str(cfg, "tags") orelse "")) |r| std.mem.eql(u8, r, "router") else false;
    const guest_checks = [_]Guest{
        .{ .name = "cloud-init done", .argv = &.{ "sh", "-c", scripts.cloud_init }, .judge = judgeCloudInit },
        .{ .name = "hostname", .argv = &.{ "sh", "-c", scripts.names }, .judge = judgeNames },
        .{ .name = "user account", .argv = &.{ "sh", "-c", try scripts.account(a, user) }, .judge = judgeAccount },
        .{ .name = "payload files", .argv = &.{ "sh", "-c", try payloadScript(a, user) }, .judge = judgePayload },
        .{ .name = "sudo asks password", .argv = &.{ "sh", "-c", try scripts.sudo(a, user) }, .judge = judgeSudo },
        .{ .name = "sshd hardening", .argv = &.{ "sh", "-c", scripts.sshd }, .judge = judgeSshd },
        .{ .name = "Ghostty terminfo", .argv = &.{ "sh", "-c", try scripts.terminfo(a, user) }, .judge = judgeTerminfo },
        .{ .name = "tools", .argv = &.{ "sh", "-c", if (edge) scripts.tools_edge else scripts.tools }, .judge = judgeTools },
        if (edge)
            .{ .name = "tailscale removed", .argv = &.{ "sh", "-c", scripts.tailscale_absent }, .judge = judgeTailscaleAbsent }
        else if (router)
            .{ .name = "tailscale router", .argv = &.{ "tailscale", "status", "--json" }, .judge = judgeTailscaleRouter }
        else
            .{ .name = "tailscale not enrolled", .argv = &.{ "tailscale", "status", "--json" }, .judge = judgeTailscale },
        .{ .name = "unattended updates", .argv = &.{ "sh", "-c", scripts.updates }, .judge = judgeUpdates },
        .{ .name = "reboot pending", .argv = &.{ "sh", "-c", scripts.reboot }, .judge = judgeReboot },
    };
    for (guest_checks) |g| {
        if (!agent_ok) {
            try out.append(a, .{ .name = g.name, .status = .not_checked });
            continue;
        }
        const r = agent.exec(c, v.vmid, g.argv, null, 60_000) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => {
                try out.append(a, .{ .name = g.name, .status = .failed, .detail = try k.clean(ctx, ctx.diag orelse @errorName(err)) });
                ctx.diag = null;
                continue;
            },
        };
        var ch = try g.judge(ctx, r, v.name, fqdn);
        ch.name = g.name;
        try out.append(a, ch);
    }
    try out.append(a, try alloyCheck(ctx, c, v, agent_ok, watched));
    try out.append(a, try @import("vm_fence.zig").check(ctx, c, v));

    // From the workstation.
    if (address == null or !running) {
        try out.append(a, .{ .name = "SSH key login", .status = .not_checked, .detail = if (address == null) "no static address" else "" });
    } else {
        const runner = ctx.test_hooks.runner orelse proc.Runner{};
        const argv = try known_hosts.sshArgv(ctx, v.name, address.?, true, known_hosts.wantsJump(pve.str(cfg, "tags") orelse ""), &.{"true"});
        const r = runner.run(ctx.io, a, argv, null) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => proc.Result{ .code = null, .stdout = "", .stderr = "ssh could not run" },
        };
        try out.append(a, .{ .name = "SSH key login", .status = if (r.code == 0) .ok else .failed, .detail = if (r.code == 0) try std.fmt.allocPrint(a, "{s}@{s}", .{ user, address.? }) else try k.clean(ctx, firstLine(r.stderr)) });
    }
    // UniFi: the client record always, DNS unless --no-dns.
    var u_or: ?unifi.Client = unifi.Client.open(ctx) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => null,
    };
    defer if (u_or) |*u| u.deinit();
    const unreachable_detail = try k.clean(ctx, ctx.diag orelse "UniFi unreachable");
    ctx.diag = null;
    try out.append(a, try clientCheck(ctx, if (u_or) |*u| u else null, unreachable_detail, v.name, cfg, address));
    if (no_dns) {
        try out.append(a, .{ .name = "DNS record", .status = .not_checked, .detail = "--no-dns" });
        try out.append(a, .{ .name = "DNS answer", .status = .not_checked, .detail = "--no-dns" });
    } else {
        var record: ?dns.ARecord = null;
        const listed: ?[]const dns.ARecord = if (u_or) |*u| dns.list(u) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => null,
        } else null;
        if (listed) |rs| record = dns.find(rs, fqdn);
        const rec_ok = record != null and address != null and std.mem.eql(u8, record.?.ipv4, address.?);
        try out.append(a, if (listed == null)
            .{ .name = "DNS record", .status = .failed, .detail = if (u_or == null) unreachable_detail else try k.clean(ctx, ctx.diag orelse "UniFi unreachable") }
        else
            .{ .name = "DNS record", .status = if (rec_ok) .ok else .failed, .detail = if (record) |r| try std.fmt.allocPrint(a, "{s} {s} {s}", .{ try k.clean(ctx, r.domain), ctx.ui.glyphs.arrow, r.ipv4 }) else try std.fmt.allocPrint(a, "no record {s}", .{fqdn}) });
        ctx.diag = null;
        try out.append(a, try dnsAnswer(ctx, try ip4Text(a, (try gateway(ctx)).address), fqdn, address));
    }
    return out.items;
}

/// Alloy enrolled and running when a watchdog exists (SPEC §9.9).
fn alloyCheck(ctx: *Context, c: *pve.Client, v: vms.Vm, agent_ok: bool, watched: ?[]const u8) !Check {
    const label = "alloy enrolled";
    if (watch.roleOf(v.tags) == .watch) return .{ .name = label, .status = .not_checked, .detail = "the watchdog itself ('artoo watch status')" };
    const w = watched orelse return .{ .name = label, .status = .not_checked, .detail = "no watchdog VM" };
    if (!agent_ok) return .{ .name = label, .status = .not_checked };
    const r = try agent.sh(c, v.vmid, "test -e /etc/alloy/artoo.alloy || { echo 'not enrolled'; exit 1; }; systemctl is-active -q alloy || { echo 'not running'; exit 1; }", 60_000);
    return if (r.ok())
        .{ .name = label, .status = .ok, .detail = try std.fmt.allocPrint(ctx.arena, "pushes to {s}", .{w}) }
    else
        .{ .name = label, .status = .failed, .detail = try std.fmt.allocPrint(ctx.arena, "{s} — 'artoo watch enroll {s}'", .{ std.mem.trim(u8, r.out, " \n"), v.name }) };
}

/// UniFi's client record for the VM's MAC carries the VM's name and
/// its address as Fixed IP (SPEC §9.5).
fn clientCheck(ctx: *Context, u: ?*unifi.Client, unreachable_detail: []const u8, name: []const u8, cfg: Value, address: ?[]const u8) !Check {
    const a = ctx.arena;
    const label = "UniFi client";
    const mac = try classic.netMac(a, pve.str(cfg, "net0") orelse "") orelse return .{ .name = label, .status = .failed, .detail = "no net0 MAC" };
    const records = classic.records(u orelse return .{ .name = label, .status = .failed, .detail = unreachable_detail }) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            defer ctx.diag = null;
            return .{ .name = label, .status = .failed, .detail = try k.clean(ctx, ctx.diag orelse @errorName(err)) };
        },
    };
    const r = classic.find(records, mac) orelse return .{ .name = label, .status = .failed, .detail = try std.fmt.allocPrint(a, "no record for {s}", .{mac}) };
    const ok = std.mem.eql(u8, r.name, name) and address != null and std.mem.eql(u8, r.fixed_ip orelse "", address.?);
    return .{ .name = label, .status = if (ok) .ok else .failed, .detail = try std.fmt.allocPrint(a, "{s}, Fixed IP {s}", .{ if (r.name.len > 0) try k.clean(ctx, r.name) else "(no name)", r.fixed_ip orelse "off" }) };
}

/// `dig @<gateway> NAME` from the workstation (not checked without dig).
/// UniFi answers a new record a few seconds after it is created, so a
/// missing or different answer is asked again, bounded (`dns_tries`).
fn dnsAnswer(ctx: *Context, gw: []const u8, fqdn: []const u8, address: ?[]const u8) !Check {
    const a = ctx.arena;
    const runner = ctx.test_hooks.runner orelse proc.Runner{};
    const argv: []const []const u8 = &.{ "/usr/bin/dig", "+short", "+time=2", "+tries=1", try std.fmt.allocPrint(a, "@{s}", .{gw}), fqdn, "A" };
    var attempt: usize = 1;
    while (true) : (attempt += 1) {
        const r = runner.run(ctx.io, a, argv, null) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            error.NotFound => return .{ .name = "DNS answer", .status = .not_checked, .detail = "dig not installed" },
            else => return .{ .name = "DNS answer", .status = .failed, .detail = "dig failed to run" },
        };
        const got = firstLine(r.stdout);
        const ok = r.code == 0 and address != null and std.mem.eql(u8, got, address.?);
        if (ok or address == null or attempt == dns_tries)
            return .{ .name = "DNS answer", .status = if (ok) .ok else .failed, .detail = try std.fmt.allocPrint(a, "{s} answers {s}", .{ gw, if (got.len > 0) try k.clean(ctx, got) else "nothing" }) };
        try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 2000)), .awake);
    }
}

/// SPEC §9.3 step 6: a fresh guest whose first boot installed a newer
/// kernel reboots once, before it is in service; skipped otherwise.
fn rebootForUpdates(c: *pve.Client, vmid: u32, l: *exec.Ledger, i: usize) !void {
    const ctx = c.ctx;
    const want = try agent.sh(c, vmid, scripts.reboot, 60_000);
    var lines = std.mem.tokenizeAny(u8, want.out, "\r\n");
    if (!std.mem.eql(u8, lines.next() orelse "", "yes")) {
        l.set(i, .skipped, "not needed");
        return;
    }
    l.set(i, .unknown, "");
    const upid = try tasks.upidOf(c, try c.send(.POST, try c.nodePath("/qemu/{d}/status/reboot", .{vmid}), &.{}), "the reboot");
    _ = try k.waitTaskNoted(c, upid, 240, l.noter(i));
    l.note(i, "waiting for the guest agent");
    try agent.waitReady(c, vmid, 600_000);
    const after = try agent.sh(c, vmid, "uname -r; test -f /run/reboot-required && echo still || true", 60_000);
    var out = std.mem.tokenizeAny(u8, after.out, "\r\n");
    const kernel = try k.clean(ctx, out.next() orelse "?");
    if (std.mem.eql(u8, out.next() orelse "", "still")) {
        l.set(i, .failed, try std.fmt.allocPrint(ctx.arena, "still pending after the reboot (kernel {s})", .{kernel}));
        return ctx.fail(error.Partial, "VM {d} still wants a reboot after rebooting; check with 'artoo vm verify'", .{vmid});
    }
    l.set(i, .done, try std.fmt.allocPrint(ctx.arena, "kernel {s}", .{kernel}));
}

/// Poll `cloud-init status --format json` until cloud-init has finished,
/// reporting its `stage` ("stage modules-final") to `note`; before a stage
/// starts, `detail` (the datasource, seen live 2026-10-11).
/// Returns the last status for `judgeCloudInit`.
fn waitCloudInit(c: *pve.Client, vmid: u32, timeout_ms: u64, note: ?exec.Note) !agent.Result {
    const ctx = c.ctx;
    const started = std.Io.Clock.awake.now(ctx.io);
    while (true) {
        const r = try agent.sh(c, vmid, scripts.cloud_init, 60_000);
        const v = std.json.parseFromSliceLeaky(Value, ctx.arena, r.out, .{}) catch return r;
        const status = pve.str(v, "status") orelse return r;
        if (!std.mem.eql(u8, status, "running") and !std.mem.eql(u8, status, "not started")) return r;
        if (note) |n| {
            const said = if (pve.str(v, "stage")) |stage| try std.fmt.allocPrint(ctx.arena, "stage {s}", .{stage}) else pve.str(v, "detail") orelse status;
            n.say(try k.clean(ctx, said));
        }
        const waited = started.durationTo(std.Io.Clock.awake.now(ctx.io)).toMilliseconds();
        if (waited >= timeout_ms) return ctx.fail(error.WaitTimeout, "cloud-init in VM {d} still running after {d} s; check with 'artoo vm verify'", .{ vmid, timeout_ms / 1000 });
        try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 3000)), .awake);
    }
}

/// Attempts of the DNS answer check, 2 s apart.
const dns_tries = 6;

/// `cloud-init status --format json`: done with no errors is ok. Proxmox's
/// generated user-data uses the deprecated `user:` key, so 26.04 always
/// reports "degraded done": deprecations are only counted, warnings are a
/// warning, errors fail.
fn judgeCloudInit(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const a = ctx.arena;
    const v = std.json.parseFromSliceLeaky(Value, a, r.out, .{}) catch
        return .{ .name = "", .status = .failed, .detail = try k.clean(ctx, firstLine(if (r.out.len > 0) r.out else r.err)) };
    const status = pve.str(v, "status") orelse "unknown";
    const rec = pve.obj(v, "recoverable_errors");
    const errs = pve.items(pve.obj(v, "errors"));
    const rec_err = pve.items(pve.obj(rec, "ERROR"));
    const rec_crit = pve.items(pve.obj(rec, "CRITICAL"));
    const rec_warn = pve.items(pve.obj(rec, "WARNING"));
    const errors = unhandled(errs) + unhandled(rec_err) + unhandled(rec_crit);
    const warnings = unhandled(rec_warn);
    const handled_n = (errs.len + rec_err.len + rec_crit.len + rec_warn.len) - errors - warnings;
    const deprecated = pve.items(pve.obj(rec, "DEPRECATED")).len;
    var first = firstUnhandled(errs);
    if (first.len == 0) first = firstUnhandled(rec_err);
    if (first.len == 0) first = firstUnhandled(rec_crit);
    if (first.len == 0) first = firstUnhandled(rec_warn);
    const st: ui.style.Status = if (!std.mem.eql(u8, status, "done") or errors > 0) .failed else if (warnings > 0) .warning else .ok;
    var detail: std.ArrayList(u8) = .empty;
    try detail.print(a, "{s}", .{try k.clean(ctx, status)});
    if (errors > 0) try detail.print(a, ", {d} error(s)", .{errors});
    if (warnings > 0) try detail.print(a, ", {d} warning(s)", .{warnings});
    if (handled_n > 0) try detail.print(a, ", {d} first-boot network message(s) handled", .{handled_n});
    if (deprecated > 0) try detail.print(a, ", {d} deprecation(s)", .{deprecated});
    if (first.len > 0) try detail.print(a, ": {s}", .{try k.clean(ctx, firstLine(first)[0..@min(firstLine(first).len, 120)])});
    return .{ .name = "", .status = st, .detail = detail.items };
}

/// First-boot messages artoo handles itself (SPEC §9.1): the 26.04
/// initramfs brings the NIC up before cloud-init, so the rename to `eth0`
/// and the wait for the network fail; vendor `bootcmd` runs `netplan
/// apply`, and later boots have no initramfs network. The outcome (static
/// address, SSH) is checked separately.
const handled_first_boot = [_][]const u8{
    "Failed to wait for network",
    "Unable to rename interfaces",
    "Failed to rename devices",
};

fn handled(v: Value) bool {
    const t = textOf(v);
    for (handled_first_boot) |h| if (std.mem.find(u8, t, h) != null) return true;
    return false;
}

/// Entries of `list` that are not handled first-boot messages.
fn unhandled(list: []const Value) usize {
    var n: usize = 0;
    for (list) |v| n += @intFromBool(!handled(v));
    return n;
}

fn firstUnhandled(list: []const Value) []const u8 {
    for (list) |v| if (!handled(v)) return textOf(v);
    return "";
}

fn textOf(v: Value) []const u8 {
    return if (v == .string) v.string else "";
}

fn judgeNames(ctx: *Context, r: agent.Result, name: []const u8, fqdn: []const u8) !Check {
    var it = std.mem.tokenizeAny(u8, r.out, "\r\n");
    const short = it.next() orelse "";
    const full = it.next() orelse "";
    const ok = std.mem.eql(u8, short, name) and std.mem.eql(u8, full, fqdn);
    return .{ .name = "", .status = if (ok) .ok else .failed, .detail = try std.fmt.allocPrint(ctx.arena, "{s} / {s}", .{ try k.clean(ctx, short), try k.clean(ctx, full) }) };
}

fn judgeAccount(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    var it = std.mem.tokenizeAny(u8, r.out, "\r\n");
    const pw = it.next() orelse "";
    const owner = it.next() orelse "";
    const user = (try ctx.config()).guests.user;
    const ok = r.ok() and std.mem.eql(u8, pw, try std.fmt.allocPrint(ctx.arena, "/home/{s}:/usr/bin/fish", .{user})) and std.mem.eql(u8, owner, user);
    return .{ .name = "", .status = if (ok) .ok else .failed, .detail = try std.fmt.allocPrint(ctx.arena, "{s}, home owned by {s}", .{ try k.clean(ctx, pw), try k.clean(ctx, owner) }) };
}

fn judgePayload(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const user = (try ctx.config()).guests.user;
    const prefix = try std.fmt.allocPrint(ctx.arena, "{s} ", .{user});
    var bad: std.ArrayList(u8) = .empty;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, r.out, "\r\n");
    while (it.next()) |line| {
        n += 1;
        if (!std.mem.startsWith(u8, line, prefix)) try bad.print(ctx.arena, "{s}{s}", .{ if (bad.items.len > 0) "; " else "", try k.clean(ctx, line) });
    }
    const want = vendor.payload.len + 1;
    const ok = r.ok() and bad.items.len == 0 and n == want;
    return .{ .name = "", .status = if (ok) .ok else .failed, .detail = if (ok) try std.fmt.allocPrint(ctx.arena, "{d} files owned by {s}", .{ n, user }) else bad.items };
}

fn judgeSudo(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    // sudo: "a password is required"; sudo-rs (26.04): "interactive
    // authentication is required".
    const ok = !r.ok() and (std.mem.find(u8, r.err, "password is required") != null or std.mem.find(u8, r.err, "interactive authentication is required") != null);
    return .{ .name = "", .status = if (ok) .ok else .failed, .detail = if (ok) "sudo -n refused without a password" else try k.clean(ctx, if (r.ok()) "sudo works without a password" else firstLine(r.err)) };
}

fn judgeSshd(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const ok = std.mem.find(u8, r.out, "permitrootlogin no") != null and std.mem.find(u8, r.out, "passwordauthentication no") != null;
    var detail: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, r.out, "\r\n");
    while (it.next()) |line| try detail.print(ctx.arena, "{s}{s}", .{ if (detail.items.len > 0) ", " else "", try k.clean(ctx, line) });
    return .{ .name = "", .status = if (ok) .ok else .failed, .detail = detail.items };
}

fn judgeTerminfo(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const got = firstLine(r.out);
    const ok = r.ok() and std.mem.eql(u8, got, "256");
    return .{ .name = "", .status = if (ok) .ok else .failed, .detail = if (ok) try std.fmt.allocPrint(ctx.arena, "/etc/terminfo, root and {s}, 256 colors", .{(try ctx.config()).guests.user}) else try k.clean(ctx, if (got.len > 0) got else firstLine(r.err)) };
}

fn judgeTools(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const missing = std.mem.trim(u8, r.out, " \r\n");
    return .{ .name = "", .status = if (r.ok() and missing.len == 0) .ok else .failed, .detail = if (missing.len == 0) "all present" else try std.fmt.allocPrint(ctx.arena, "missing: {s}", .{try k.clean(ctx, missing)}) };
}

/// SPEC §9.1: failed when updates cannot run or would reboot; a warning
/// for a baseline without Tailscale's origin.
fn judgeUpdates(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const a = ctx.arena;
    var f: struct { periodic: []const u8 = "", reboot: []const u8 = "", security: []const u8 = "0", tailscale: []const u8 = "0", installed: []const u8 = "", timer: []const u8 = "", last: []const u8 = "", now: []const u8 = "" } = .{};
    var lines = std.mem.tokenizeScalar(u8, r.out, '\n');
    while (lines.next()) |line| {
        const sp = std.mem.findScalar(u8, line, ' ') orelse continue;
        const key = line[0..sp];
        const val = std.mem.trim(u8, line[sp + 1 ..], " \r");
        inline for (comptime std.meta.fieldNames(@TypeOf(f))) |name| {
            if (std.mem.eql(u8, key, name)) @field(f, name) = val;
        }
    }
    const fail = struct {
        fn c(detail: []const u8) Check {
            return .{ .name = "", .status = .failed, .detail = detail };
        }
    }.c;
    if (!std.mem.eql(u8, f.periodic, "1")) return fail("unattended upgrades off (APT::Periodic::Unattended-Upgrade)");
    if (std.mem.eql(u8, f.security, "0")) return fail("the -security pocket is not an allowed origin");
    if (!std.mem.eql(u8, f.timer, "enabled")) return fail(try std.fmt.allocPrint(a, "apt-daily-upgrade.timer {s}", .{if (f.timer.len > 0) try k.clean(ctx, f.timer) else "missing"}));
    if (std.mem.eql(u8, f.reboot, "true")) return fail("automatic reboot is on (the operator reboots, SPEC §9.1)");
    const last = std.fmt.parseInt(i64, f.last, 10) catch null;
    const now = std.fmt.parseInt(i64, f.now, 10) catch null;
    const when = if (last != null and now != null)
        try std.fmt.allocPrint(a, "last run {f} ago", .{ui.values.duration(@intCast(@max(0, now.? - last.?)))})
    else
        "not run yet";
    if (std.mem.eql(u8, f.installed, "yes") and std.mem.eql(u8, f.tailscale, "0"))
        return .{ .name = "", .status = .warning, .detail = try std.fmt.allocPrint(a, "security daily, {s}; Tailscale not among the origins (baseline before 2026-10-11)", .{when}) };
    return .{ .name = "", .status = .ok, .detail = try std.fmt.allocPrint(a, "security daily, no auto-reboot, {s}", .{when}) };
}

/// A reboot an update wants: a warning naming the packages.
fn judgeReboot(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    var lines = std.mem.tokenizeAny(u8, r.out, "\r\n");
    const first = lines.next() orelse return .{ .name = "", .status = .failed, .detail = "no answer" };
    if (std.mem.eql(u8, first, "no")) return .{ .name = "", .status = .ok, .detail = "no" };
    var pkgs: std.ArrayList([]const u8) = .empty;
    while (lines.next()) |p| {
        for (pkgs.items) |q| {
            if (std.mem.eql(u8, p, q)) break;
        } else try pkgs.append(ctx.arena, p);
    }
    const shown = pkgs.items[0..@min(pkgs.items.len, 3)];
    const more = if (pkgs.items.len > 3) try std.fmt.allocPrint(ctx.arena, " +{d}", .{pkgs.items.len - 3}) else "";
    return .{ .name = "", .status = .warning, .detail = try std.fmt.allocPrint(ctx.arena, "yes{s}{s}{s}{s} — 'artoo vm reboot' when convenient", .{
        if (shown.len > 0) " (" else "", try k.clean(ctx, try std.mem.join(ctx.arena, ", ", shown)), more, if (shown.len > 0) ")" else "",
    }) };
}

fn judgeTailscaleAbsent(_: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const absent = std.mem.eql(u8, std.mem.trim(u8, r.out, " \r\n"), "absent");
    return .{ .name = "", .status = if (absent) .ok else .failed, .detail = if (absent) "not installed (edge, watchdog)" else "still installed" };
}

fn judgeTailscale(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const v = std.json.parseFromSliceLeaky(Value, ctx.arena, r.out, .{}) catch
        return .{ .name = "", .status = .failed, .detail = try k.clean(ctx, firstLine(if (r.err.len > 0) r.err else r.out)) };
    const state = pve.str(v, "BackendState") orelse "unknown";
    const ok = std.mem.eql(u8, state, "NeedsLogin") or std.mem.eql(u8, state, "NoState") or std.mem.eql(u8, state, "Stopped");
    return .{ .name = "", .status = if (ok) .ok else .failed, .detail = try std.fmt.allocPrint(ctx.arena, "installed, {s}", .{try k.clean(ctx, state)}) };
}

/// The subnet router (SPEC §9.8): Running is ok; not enrolled yet is a
/// warning ('artoo router setup' follows 'vm new').
fn judgeTailscaleRouter(ctx: *Context, r: agent.Result, _: []const u8, _: []const u8) !Check {
    const v = std.json.parseFromSliceLeaky(Value, ctx.arena, r.out, .{}) catch
        return .{ .name = "", .status = .failed, .detail = try k.clean(ctx, firstLine(if (r.err.len > 0) r.err else r.out)) };
    const state = pve.str(v, "BackendState") orelse "unknown";
    if (std.mem.eql(u8, state, "Running")) return .{ .name = "", .status = .ok, .detail = "enrolled, running" };
    return .{ .name = "", .status = .warning, .detail = try std.fmt.allocPrint(ctx.arena, "{s} — next: 'artoo router setup'", .{try k.clean(ctx, state)}) };
}

pub fn renderChecks(ctx: *Context, checks: []const Check) !void {
    const rows = try ctx.arena.alloc([]const ui.table.Cell, checks.len);
    for (checks, rows) |ch, *row| {
        const cells = try ctx.arena.alloc(ui.table.Cell, 3);
        cells[0] = .{ .text = ch.name };
        cells[1] = try k.statusCell(ctx, ch.status, ch.status.word());
        cells[2] = .{ .text = ch.detail };
        row.* = cells;
    }
    try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
        .{ .title = "CHECK", .truncate = false },
        .{ .title = "STATUS", .truncate = false },
        .{ .title = "DETAIL", .min = 20 },
    }, rows);
}

pub const verify = struct {
    pub const name = "verify";
    pub const summary = "Read-only readiness checks of a guest";
    pub const details =
        \\Through the guest agent: cloud-init done, hostname and FQDN, the guest
        \\user's shell and home, payload files owned by it, sudo asking for a
        \\password, sshd without root or password login, Ghostty terminfo for
        \\root and the user,
        \\baseline tools, Tailscale installed but not enrolled, unattended security
        \\updates without automatic reboot, a pending reboot (warning), Alloy enrolled when a
        \\watchdog exists (SPEC §9.9). From here: SSH key
        \\login with the pinned host key, the DNS record on UniFi and its
        \\answer (dig @gateway). Any failed check exits 8. --all checks every artoo
        \\guest concurrently, one block each, then a summary.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name", .required = false }};
    pub const flags = [_]cli.Flag{
        .{ .long = "all", .short = 'a', .help = "Every artoo guest (tag artoo, not templates)" },
        .{ .long = "no-dns", .help = "Do not check DNS (guest created with --no-dns)" },
    };
    pub const examples = [_][]const u8{ "artoo vm verify web-01", "artoo vm verify --all", "artoo vm verify test-01 --no-dns -o json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        if (args.has("all")) {
            if (args.optPos("VM") != null) return ctx.fail(error.Usage, "give a VM or --all, not both", .{});
            return verifyAll(ctx, args.has("no-dns"));
        }
        const word = args.optPos("VM") orelse return ctx.fail(error.Usage, "missing VM (or --all)", .{});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const v = try vms.resolve(&c, word);
        if (v.template) return ctx.fail(error.Refused, "{s} is a template", .{try k.clean(ctx, v.name)});
        const w = try watch.findWatchVm(&c);
        const watched: ?[]const u8 = if (w != null and w.?.vmid != v.vmid) w.?.name else null;
        const checks = try runChecks(ctx, &c, v, try vms.config(&c, v.vmid), args.has("no-dns"), watched);
        const failed = failures(checks);
        if (ctx.json()) {
            const J = struct { check: []const u8, status: []const u8, detail: []const u8 };
            const out = try ctx.arena.alloc(J, checks.len);
            for (checks, out) |ch, *j| j.* = .{ .check = ch.name, .status = ch.status.word(), .detail = ch.detail };
            try ui.json.envelope(ctx.out, .pve, out, .{ .collected_at = ctx.ui.now, .vmid = v.vmid, .failed = failed });
        } else {
            try k.header(ctx, &c);
            try renderChecks(ctx, checks);
        }
        if (failed > 0) return ctx.fail(error.Partial, "{d} check{s} failed", .{ failed, if (failed == 1) "" else "s" });
    }
};

/// One guest of `vm verify --all`: its own `Context` copy (shared
/// thread-safe arena, own `diag`), as `status` (SPEC §11).
const VerifySlot = struct {
    ctx: Context,
    vm: vms.Vm,
    checks: []const Check = &.{},
    err: ?[]const u8 = null,
    /// The activity detail's count (SPEC §4.5); this guest's index in it.
    tally: ?*activity.Tally = null,
    index: usize = 0,
};

fn verifyOne(slot: *VerifySlot, watched: ?[]const u8, no_dns: bool) void {
    const ctx = &slot.ctx;
    defer if (slot.tally) |t| t.finish(ctx.io, slot.index);
    const run = struct {
        fn f(s: *VerifySlot, w: ?[]const u8, nd: bool) !void {
            var c = try pve.Client.open(&s.ctx);
            defer c.deinit();
            const mine = if (w) |name| (if (std.mem.eql(u8, name, s.vm.name)) null else w) else null;
            s.checks = try runChecks(&s.ctx, &c, s.vm, try vms.config(&c, s.vm.vmid), nd, mine);
        }
    }.f;
    run(slot, watched, no_dns) catch |err| {
        slot.err = ctx.diag orelse @errorName(err);
    };
}

fn verifyAll(ctx: *Context, no_dns: bool) !void {
    const a = ctx.arena;
    var c = try pve.Client.open(ctx);
    defer c.deinit();
    var slots: std.ArrayList(VerifySlot) = .empty;
    for (try vms.list(&c)) |v| {
        if (v.template or !template.taggedWith(v.tags, tag)) continue;
        try slots.append(a, .{ .ctx = ctx.*, .vm = v });
    }
    const w = try watch.findWatchVm(&c);
    const watched: ?[]const u8 = if (w) |x| x.name else null;
    const guest_names = try a.alloc([]const u8, slots.items.len);
    for (slots.items, guest_names) |s, *n| n.* = s.vm.name;
    var tally: activity.Tally = try .init(a, ctx.activity, guest_names);
    for (slots.items, 0..) |*s, i| {
        s.tally = &tally;
        s.index = i;
    }
    var group: std.Io.Group = .init;
    for (slots.items) |*s| group.concurrent(ctx.io, verifyOne, .{ s, watched, no_dns }) catch verifyOne(s, watched, no_dns);
    try group.await(ctx.io);

    var failed_guests: usize = 0;
    var warned_guests: usize = 0;
    for (slots.items) |s| {
        if (s.err != null or failures(s.checks) > 0) {
            failed_guests += 1;
        } else for (s.checks) |ch| {
            if (ch.status == .warning) {
                warned_guests += 1;
                break;
            }
        }
    }
    if (ctx.json()) {
        const J = struct { check: []const u8, status: []const u8, detail: []const u8 };
        const G = struct { vm: []const u8, vmid: u32, @"error": ?[]const u8, checks: []const J };
        const out = try a.alloc(G, slots.items.len);
        for (slots.items, out) |s, *g| {
            const js = try a.alloc(J, s.checks.len);
            for (s.checks, js) |ch, *j| j.* = .{ .check = ch.name, .status = ch.status.word(), .detail = ch.detail };
            g.* = .{ .vm = s.vm.name, .vmid = s.vm.vmid, .@"error" = s.err, .checks = js };
        }
        try ui.json.envelope(ctx.out, .pve, out, .{ .collected_at = ctx.ui.now, .failed = failed_guests });
    } else {
        try k.header(ctx, &c);
        if (slots.items.len == 0) try ctx.out.print("{s}No artoo guests.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
        for (slots.items, 0..) |s, i| {
            if (i > 0) try ctx.out.writeAll("\n");
            try ctx.out.print("{s}{s} ({d}){s}\n", .{ ctx.ui.palette.on(.title), try k.clean(ctx, s.vm.name), s.vm.vmid, ctx.ui.palette.off(.title) });
            if (s.err) |m| {
                try ctx.out.print("  {s}{s} {s}{s}\n", .{ ctx.ui.palette.on(.fail), ctx.ui.glyphs.fail, try k.clean(ctx, m), ctx.ui.palette.off(.fail) });
            } else try renderChecks(ctx, s.checks);
        }
        if (slots.items.len > 0) try ctx.out.print("\n{d} guest(s): {d} ok, {d} with warnings, {d} failed\n", .{ slots.items.len, slots.items.len - failed_guests - warned_guests, warned_guests, failed_guests });
    }
    if (failed_guests > 0) return ctx.fail(error.Partial, "{d} guest{s} failed verification", .{ failed_guests, if (failed_guests == 1) "" else "s" });
}

// ---------------------------------------------------------------- ssh

/// The guest's address (static config, else the agent's first IPv4).
fn addressOf(c: *pve.Client, v: vms.Vm, cfg: Value) ![]const u8 {
    if (life.staticAddress(cfg)) |a| return a;
    if (v.running()) {
        if (agent.ping(c, v.vmid) catch false) {
            for (try vms.agentAddresses(c, v.vmid)) |ad| if (!ad.ipv6) return ad.address;
        }
    }
    return c.ctx.fail(error.Refused, "no address known for {s}", .{v.name});
}

pub const ssh_cmd = struct {
    pub const name = "ssh";
    pub const summary = "SSH to a guest as the guest user (host key pinned via the guest agent)";
    pub const details =
        \\Runs ssh <guests.user>@<address> with StrictHostKeyChecking against the key recorded
        \\in ~/.artoo/known_hosts under the VM name; a missing entry is first read
        \\from the guest through the guest agent. Guests tagged ssh-jump are reached
        \\through root on Proxmox (pve.ssh_host), the only machine they accept SSH
        \\from. Words after -- are the command.
    ;
    pub const positionals = [_]cli.Positional{vm_arg};
    pub const trailing = "CMD";
    pub const examples = [_][]const u8{ "artoo vm ssh web-01", "artoo vm ssh web-01 -- uptime" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const v = try vms.resolve(&c, args.pos("VM"));
        if (v.template or v.name.len == 0) return ctx.fail(error.Refused, "{d} is not a named guest", .{v.vmid});
        const vcfg = try vms.config(&c, v.vmid);
        const address = try addressOf(&c, v, vcfg);
        const kh = std.Io.Dir.cwd().readFileAlloc(ctx.io, try known_hosts.path(ctx), ctx.arena, .limited(1 << 20)) catch "";
        if (!hasAlias(kh, v.name)) {
            if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first", .{ v.name, v.status });
            const key = try known_hosts.keyOf(ctx.arena, try agent.readFile(&c, v.vmid, known_hosts.host_key_file)) orelse
                return ctx.fail(error.Refused, "{s} has no usable {s}", .{ v.name, known_hosts.host_key_file });
            try known_hosts.record(ctx, v.name, key);
            try ctx.err.print("artoo: pinned the host key of {s} from the guest agent\n", .{v.name});
        }
        const argv = try known_hosts.sshArgv(ctx, v.name, address, false, known_hosts.wantsJump(pve.str(vcfg, "tags") orelse ""), args.trailing());
        try ctx.err.flush();
        try ctx.out.flush();
        const err = std.process.replace(ctx.io, .{ .argv = argv });
        return ctx.fail(error.Internal, "cannot run ssh: {t}", .{err});
    }
};

fn hasAlias(text: []const u8, alias: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        const first = line[0 .. std.mem.findScalar(u8, line, ' ') orelse line.len];
        if (std.mem.eql(u8, first, alias)) return true;
    }
    return false;
}

// ---------------------------------------------------------------- password

pub const password = struct {
    pub const name = "password";
    pub const summary = "Show the guest user's sudo password (terminal only)";
    pub const details = "For sudo and the console. Printed only to a terminal, after confirmation; never in JSON.";
    pub const positionals = [_]cli.Positional{vm_arg};
    pub const examples = [_][]const u8{"artoo vm password web-01"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        if (ctx.json()) return ctx.fail(error.Usage, "the password is never printed as JSON", .{});
        if (ctx.ui.width == null) return ctx.fail(error.Refused, "the password is printed only to a terminal", .{});
        const word = args.pos("VM");
        const store = try ctx.secretStore();
        // Accept a name without asking Proxmox when the entry exists.
        const nm = if (store.exists(ctx.io, ctx.arena, try secretName(ctx, word)) catch false) word else blk: {
            var c = try pve.Client.open(ctx);
            defer c.deinit();
            break :blk (try vms.resolve(&c, word)).name;
        };
        const secret_name = try secretName(ctx, nm);
        const pw = (try store.get(ctx.io, ctx.arena, secret_name)) orelse return ctx.fail(error.SecretMissing, "no stored password {s}", .{secret_name});
        try ctx.confirm("Show the password of {s}?", .{nm});
        try ctx.out.print("{s}\n", .{pw});
    }
};

pub const commands = [_]cli.Command{
    cli.leaf(new),
    cli.leaf(verify),
    cli.leaf(ssh_cmd),
    cli.leaf(password),
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "parseGiB, addresses" {
    try testing.expectEqual(@as(?u64, 40), parseGiB("40G"));
    try testing.expectEqual(@as(?u64, 20), parseGiB("20"));
    try testing.expect(parseGiB("2") == null);
    const net = config.parseCidr("192.168.1.1/24").?;
    try testing.expect(usableIn(net, ip4("192.168.1.200").?));
    try testing.expect(!usableIn(net, ip4("192.168.1.1").?));
    try testing.expect(!usableIn(net, ip4("192.168.1.255").?));
    try testing.expect(!usableIn(net, ip4("192.168.2.10").?));
    const pool = config.parseRange("192.168.1.200-192.168.1.202").?;
    try testing.expectEqual(ip4("192.168.1.201"), pick(pool, net, &.{ip4("192.168.1.200").?}));
    try testing.expect(pick(pool, net, &.{ ip4("192.168.1.200").?, ip4("192.168.1.201").?, ip4("192.168.1.202").? }) == null);
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    try testing.expectEqualStrings("192.168.1.201", try ip4Text(a.allocator(), ip4("192.168.1.201").?));
    try testing.expectEqualStrings("ssh-ed25519%20AAAA%2Bx%2F%3D%20me%40mac", try encodeKeys(a.allocator(), "ssh-ed25519 AAAA+x/= me@mac"));
}

test "size presets" {
    const want = [_]struct { Size, u32, u64, u64 }{
        .{ .tiny, 1, 1024, 20 },  .{ .small, 2, 2048, 20 },    .{ .medium, 2, 4096, 40 },
        .{ .large, 4, 8192, 80 }, .{ .xlarge, 8, 16384, 160 },
    };
    for (want) |w| {
        try testing.expectEqual(w[1], w[0].cores());
        try testing.expectEqual(w[2], w[0].memory());
        try testing.expectEqual(w[3], w[0].disk());
    }
}

test "diskBytes and hasAlias" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const cfg = try std.json.parseFromSliceLeaky(Value, a.allocator(), "{\"scsi0\":\"local-zfs:vm-200-disk-0,discard=on,size=3584M\"}", .{});
    try testing.expectEqual(@as(?u64, 3584 << 20), diskBytes(cfg));
    try testing.expect(hasAlias("db-01 k\nweb-01 ssh-ed25519 X\n", "web-01"));
    try testing.expect(!hasAlias("web-011 k\n", "web-01"));
}

const ci_deprecated =
    \\{"status":"done","extended_status":"degraded done","errors":[],"recoverable_errors":{"DEPRECATED":["'user' of type string is deprecated","'user' of type string is deprecated"]}}
;
const ci_first_boot =
    \\{"status":"done","extended_status":"degraded done","errors":[],"recoverable_errors":{"DEPRECATED":["a","b"],"ERROR":["Failed to wait for network: Unexpected error"],"WARNING":["Unable to rename interfaces"]}}
;
const ci_error =
    \\{"status":"done","extended_status":"error","errors":["Failed to run module apt-configure"],"recoverable_errors":{"ERROR":["Failed to wait for network: x"],"WARNING":["disk full"]}}
;

test "judges" {
    var h = try @import("../testkit.zig").Harness.init();
    defer h.deinit();
    var ctx: Context = .{ .arena = h.arena.allocator(), .gpa = testing.allocator, .io = testing.io, .out = &h.out.writer, .err = &h.err.writer, .env = &h.env };
    ctx.loaded = .{ .ok = .{ .path = "", .exists = false, .config = .{}, .tree = .empty } };
    try testing.expectEqual(ui.style.Status.ok, (try judgeCloudInit(&ctx, .{ .code = 2, .out = ci_deprecated, .err = "" }, "", "")).status);
    try testing.expectEqualStrings("done, 2 deprecation(s)", (try judgeCloudInit(&ctx, .{ .code = 2, .out = ci_deprecated, .err = "" }, "", "")).detail);
    const handled_ci = try judgeCloudInit(&ctx, .{ .code = 2, .out = ci_first_boot, .err = "" }, "", "");
    try testing.expectEqual(ui.style.Status.ok, handled_ci.status);
    try testing.expectEqualStrings("done, 2 first-boot network message(s) handled, 2 deprecation(s)", handled_ci.detail);
    const real = try judgeCloudInit(&ctx, .{ .code = 1, .out = ci_error, .err = "" }, "", "");
    try testing.expectEqual(ui.style.Status.failed, real.status);
    try testing.expectEqualStrings("done, 1 error(s), 1 warning(s), 1 first-boot network message(s) handled: Failed to run module apt-configure", real.detail);
    try testing.expectEqual(ui.style.Status.failed, (try judgeCloudInit(&ctx, .{ .code = 0, .out = "{\"status\":\"running\"}", .err = "" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.ok, (try judgeSudo(&ctx, .{ .code = 1, .out = "", .err = "sudo: interactive authentication is required\n" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.ok, (try judgeNames(&ctx, .{ .code = 0, .out = "web-01\nweb-01.lab.example.com\n", .err = "" }, "web-01", "web-01.lab.example.com")).status);
    try testing.expectEqual(ui.style.Status.ok, (try judgeAccount(&ctx, .{ .code = 0, .out = "/home/artoo:/usr/bin/fish\nartoo\n", .err = "" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.ok, (try judgeSudo(&ctx, .{ .code = 1, .out = "", .err = "sudo: a password is required\n" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.failed, (try judgeSudo(&ctx, .{ .code = 0, .out = "", .err = "" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.ok, (try judgeSshd(&ctx, .{ .code = 0, .out = "permitrootlogin no\npasswordauthentication no\n", .err = "" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.ok, (try judgeTerminfo(&ctx, .{ .code = 0, .out = "256\n", .err = "" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.failed, (try judgeTools(&ctx, .{ .code = 0, .out = "eza ", .err = "" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.ok, (try judgeTailscale(&ctx, .{ .code = 0, .out = "{\"BackendState\":\"NeedsLogin\"}", .err = "" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.failed, (try judgeTailscale(&ctx, .{ .code = 0, .out = "{\"BackendState\":\"Running\"}", .err = "" }, "", "")).status);
    var lines: std.ArrayList(u8) = .empty;
    for (vendor.payload) |f| try lines.print(ctx.arena, "artoo {s}\n", .{f.path});
    try lines.appendSlice(ctx.arena, "artoo /home/artoo/.local/bin/fd\n");
    try testing.expectEqual(ui.style.Status.ok, (try judgePayload(&ctx, .{ .code = 0, .out = lines.items, .err = "" }, "", "")).status);
    try testing.expectEqual(ui.style.Status.failed, (try judgePayload(&ctx, .{ .code = 0, .out = "root /home/artoo/.vimrc\n", .err = "" }, "", "")).status);
}

test "dnsAnswer waits for a fresh record, bounded" {
    var h = try @import("../testkit.zig").Harness.init();
    defer h.deinit();
    const a = h.arena.allocator();
    var ctx: Context = .{ .arena = a, .gpa = testing.allocator, .io = testing.io, .out = &h.out.writer, .err = &h.err.writer, .env = &h.env };
    ctx.test_hooks.poll_ms = 1;
    const dig: []const []const u8 = &.{ "/usr/bin/dig", "+short", "+time=2", "+tries=1", "@192.168.1.1", "web-01.lab.example.com", "A" };
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(dig, null, .{ .code = 0 });
    try fake.expect(dig, null, .{ .code = 0, .stdout = "192.168.1.201\n" });
    ctx.test_hooks.runner = fake.runner();
    const late = try dnsAnswer(&ctx, "192.168.1.1", "web-01.lab.example.com", "192.168.1.201");
    try fake.done();
    try testing.expectEqual(ui.style.Status.ok, late.status);
    try testing.expectEqualStrings("192.168.1.1 answers 192.168.1.201", late.detail);

    var never: FakeRunner = .{ .arena = a };
    for (0..dns_tries) |_| try never.expect(dig, null, .{ .code = 0 });
    ctx.test_hooks.runner = never.runner();
    const none = try dnsAnswer(&ctx, "192.168.1.1", "web-01.lab.example.com", "192.168.1.201");
    try never.done();
    try testing.expectEqual(ui.style.Status.failed, none.status);
    try testing.expectEqualStrings("192.168.1.1 answers nothing", none.detail);
}

const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const FakeRunner = @import("../secrets/common.zig").FakeRunner;

fn execStatus(a: std.mem.Allocator, code: i64, out: []const u8, err: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = code, .@"out-data" = out, .@"err-data" = err } }, .{});
}

test "vm new: address from the pool, clone, cloud-init config, waits, pinned host key, checks" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const upid = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:qmclone:9000:artoo@pve!cli:\"}";
    const ok = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}";
    const pid = "{\"data\":{\"pid\":42}}";
    const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIGb8kQvYwZp1n0Xo3m2cJ6d0n8wY1u5wQ7q8zT3kQ2rS";
    var payload_out: std.ArrayList(u8) = .empty;
    for (vendor.payload) |f| try payload_out.print(a, "artoo {s}\n", .{f.path});
    try payload_out.appendSlice(a, "artoo /home/artoo/.local/bin/fd\n");
    const B = testkit.Gateway.FakeServer.Behavior;
    const r = struct {
        fn body(s: []const u8) B {
            return .{ .respond = .{ .body = s } };
        }
    }.body;
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{
        r("{\"data\":[{\"vmid\":100,\"name\":\"web-01\",\"status\":\"running\"},{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"template\":1,\"status\":\"stopped\",\"maxdisk\":3758096384}]}"),
        r("{\"data\":{\"tags\":\"artoo-template\",\"cicustom\":\"vendor=local:snippets/artoo-vendor-0123456789ab.yaml\"}}"),
        r("{\"data\":[{\"volid\":\"local:snippets/artoo-vendor-0123456789ab.yaml\",\"size\":10}]}"),
        r("{\"data\":[{\"vmid\":100},{\"vmid\":9000}]}"),
        r("{\"data\":{\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\"}}"),
        r("{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"S1\",\"internalReference\":\"default\",\"name\":\"Default\"}]}"),
        r("{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R1\",\"enabled\":true,\"domain\":\"x.lab.example.com\",\"ipv4Address\":\"192.168.1.201\"}]}"),
        r("{\"meta\":{\"rc\":\"ok\"},\"data\":[{\"_id\":\"U9\",\"mac\":\"aa:bb:cc:00:00:09\",\"name\":\"Printer\",\"use_fixedip\":true,\"fixed_ip\":\"192.168.1.203\"},{\"_id\":\"U8\",\"mac\":\"aa:bb:cc:00:00:08\",\"use_fixedip\":false,\"fixed_ip\":\"192.168.1.205\"}]}"),
        r("{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"C1\",\"name\":\"TV\",\"ipAddress\":\"192.168.1.202\"}]}"),
        r(storage.storage_body),
        r("{\"meta\":{\"rc\":\"ok\"},\"data\":[{\"_id\":\"N0\",\"name\":\"WAN\"},{\"_id\":\"N1\",\"name\":\"Default\",\"ip_subnet\":\"192.168.1.1/24\"}]}"),
        r(upid), r(ok), // clone
        r("{\"data\":{\"digest\":\"d1\"}}"), r("{\"data\":null}"), // config
        r("{\"data\":{\"net0\":\"virtio=BC:24:11:AB:CD:EF,bridge=vmbr0\"}}"), r("{\"meta\":{\"rc\":\"ok\"},\"data\":[{\"_id\":\"U10\"}]}"), // reserve
        r(upid), r(ok), // resize
        r(upid), r(ok), // start
        r("{\"data\":{\"result\":{}}}"), // agent ping
        r(pid), r(try execStatus(a, 0, "{\"status\":\"running\",\"detail\":\"DataSourceNoCloud [seed=/dev/sr0]\",\"stage\":\"modules-final\"}", "")), // cloud-init still running
        r(pid), r(try execStatus(a, 2, ci_deprecated, "")), // cloud-init done
        r(pid), r(try execStatus(a, 0, "yes\nlinux-image-7.0.0-38-generic\nlinux-base\n", "")), // reboot wanted
        r(upid), r(ok), // reboot
        r("{\"data\":{\"result\":{}}}"), // agent back
        r(pid),                                                                                                                           r(try execStatus(a, 0, "7.0.0-38-generic\n", "")), // kernel, request gone
        r("{\"data\":{\"content\":\"ssh-ed25519 " ++ blob ++ " root@test-01\\n\"}}"),
        // verify
                                                            r("{\"data\":[{\"vmid\":200,\"name\":\"test-01\",\"status\":\"running\"},{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"template\":1}]}"),
        r("{\"data\":{\"ipconfig0\":\"ip=192.168.1.204/24,gw=192.168.1.1\",\"net0\":\"virtio=BC:24:11:AB:CD:EF,bridge=vmbr0\"}}"),        r("{\"data\":{\"status\":\"running\"}}"),
        r("{\"data\":{\"result\":{}}}"),                                                                                                  r(pid),
        r(try execStatus(a, 2, ci_deprecated, "")),                                                                                       r(pid),
        r(try execStatus(a, 0, "test-01\ntest-01.lab.example.com\n", "")),                                                                r(pid),
        r(try execStatus(a, 0, "/home/artoo:/usr/bin/fish\nartoo\n", "")),                                                                r(pid),
        r(try execStatus(a, 0, payload_out.items, "")),                                                                                   r(pid),
        r(try execStatus(a, 1, "", "sudo: a password is required\n")),                                                                    r(pid),
        r(try execStatus(a, 0, "permitrootlogin no\npasswordauthentication no\n", "")),                                                   r(pid),
        r(try execStatus(a, 0, "256\n", "")),                                                                                             r(pid),
        r(try execStatus(a, 0, "", "")),                                                                                                  r(pid),
        r(try execStatus(a, 0, "{\"BackendState\":\"NeedsLogin\"}", "")),                                                                 r(pid),
        r(try execStatus(a, 0, "periodic 1\nreboot false\nsecurity 2\ntailscale 1\ninstalled yes\ntimer enabled\nlast \nnow 100\n", "")), r(pid),
        r(try execStatus(a, 0, "no\n", "")),                                                                                              r("{\"meta\":{\"rc\":\"ok\"},\"data\":[{\"_id\":\"U10\",\"mac\":\"bc:24:11:ab:cd:ef\",\"name\":\"test-01\",\"use_fixedip\":true,\"fixed_ip\":\"192.168.1.204\"}]}"),
    });
    defer g.deinit();
    try g.tmp.dir.createDirPath(testing.io, ".ssh");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".ssh/id_ed25519.pub", .data = "ssh-ed25519 AAAAkey me@mac\n" });
    try g.tmp.dir.createDirPath(testing.io, ".artoo/keys");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/keys/pve.pub", .data = "ssh-ed25519 AAAAother root@pve-guests\n" });
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = "{\"schema_version\":1,\"guests\":{\"extra_ssh_keys\":\"~/.artoo/keys/pve.pub\"}}\n" });
    const home = g.h.env.get("HOME").?;
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(&.{
        "/usr/bin/ssh",      "-o",                        "HostKeyAlias=test-01", "-o",            try std.fmt.allocPrint(a, "UserKnownHostsFile={s}/.artoo/known_hosts", .{home}),
        "-o",                "StrictHostKeyChecking=yes", "-o",                   "BatchMode=yes", "-o",
        "ConnectTimeout=10", "artoo@192.168.1.204",       "--",                   "true",
    }, null, .{});
    g.h.hooks.runner = fake.runner();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});

    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm new Web"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm new web_01"));
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm new pve"));
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm new gateway"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm new naboo --role Web"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm new web-02 --access public"));
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm new test-01 --role web --no-dns -y"));
    try fake.done();
    try testing.expectEqualStrings("GET /proxy/network/api/s/default/rest/user HTTP/1.1", g.request(7));
    try testing.expectEqualStrings("GET /proxy/network/api/s/default/rest/networkconf HTTP/1.1", g.request(10));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/9000/clone HTTP/1.1", g.request(11));
    try testing.expectEqualStrings("newid=200&name=test-01&full=1", g.body(11));
    try testing.expectEqualStrings("POST /proxy/network/api/s/default/group/user HTTP/1.1", g.request(16));
    try testing.expectEqualStrings("{\"objects\":[{\"data\":{\"mac\":\"bc:24:11:ab:cd:ef\",\"name\":\"test-01\",\"use_fixedip\":true,\"network_id\":\"N1\",\"fixed_ip\":\"192.168.1.204\"}}]}", g.body(16));
    const put = g.body(14);
    for ([_][]const u8{
        "cores=2&memory=2048&ciuser=artoo&cipassword=%246%24",
        "&sshkeys=ssh-ed25519%2520AAAAkey%2520me%2540mac%250Assh-ed25519%2520AAAAother%2520root%2540pve-guests&ipconfig0=ip%3D192.168.1.204%2F24%2Cgw%3D192.168.1.1&nameserver=192.168.1.1",
        "&searchdomain=lab.example.com&cicustom=vendor%3Dlocal%3Asnippets%2Fartoo-vendor-0123456789ab.yaml&tags=artoo%3Brole-web&digest=d1",
    }) |want| {
        if (std.mem.find(u8, put, want) == null) {
            std.debug.print("missing: {s}\n--- body:\n{s}\n", .{ want, put });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqualStrings("disk=scsi0&size=20G", g.body(17));
    try testing.expectEqualStrings("command=sh&command=-c&command=cloud-init%20status%20--format%20json", g.body(22));
    try testing.expectEqualStrings("command=sh&command=-c&command=cloud-init%20status%20--format%20json", g.body(24));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/200/status/reboot HTTP/1.1", g.request(28));
    // Not a terminal: the stage is one dated line while the step runs.
    try testing.expect(std.mem.find(u8, g.h.stderr(), "  · wait for cloud-init  stage modules-final\n") != null);
    // The plaintext stays local: only the hash went out.
    const pw = g.mem.map.get("guest/test-01").?;
    try testing.expectEqual(@as(usize, crypt.password_len), pw.len);
    for (g.srv.received) |req| if (req) |q| try testing.expect(std.mem.find(u8, q, pw) == null);
    const kh = try std.Io.Dir.cwd().readFileAlloc(testing.io, try std.fmt.allocPrint(a, "{s}/.artoo/known_hosts", .{home}), a, .limited(4096));
    try testing.expectEqualStrings("test-01 ssh-ed25519 " ++ blob ++ "\n", kh);
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Create guest test-01 (200)\n",
        "address        (none) → 192.168.1.204/24 via 192.168.1.1 (static)\n",
        "more SSH keys  (none) → root@pve-guests\n",
        "✓ wait for cloud-init   done  done, 2 deprecation(s)",
        "✓ reboot for updates    done  kernel 7.0.0-38-generic",
        "✓ pin SSH host key      done",
        "✓ reserve address       done  bc:24:11:ab:cd:ef → 192.168.1.204",
        "client record  (none) → test-01, Fixed IP 192.168.1.204 on UniFi (the VM's MAC)\n",
        "UniFi client            ✓ ok           test-01, Fixed IP 192.168.1.204",
        "sudo asks password      ✓ ok           sudo -n refused",
        "unattended updates      ✓ ok           security daily, no auto-reboot, not run yet",
        "reboot pending          ✓ ok           no",
        "SSH key login           ✓ ok           artoo@192.168.1.204",
        "DNS record              – not checked  --no-dns",
        "✓ test-01 (200) is ready at 192.168.1.204",
        "\n  known_hosts line for other machines: test-01,192.168.1.204 ssh-ed25519 " ++ blob ++ "\n",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "public key lines: kinds, one line, comments" {
    try testing.expect(validKeyLine("ssh-ed25519 AAAAC3Nza root@pve-guests"));
    try testing.expect(validKeyLine("ecdsa-sha2-nistp256 AAAAE2Vj"));
    try testing.expect(!validKeyLine("ssh-ed25519"));
    try testing.expect(!validKeyLine("ssh-ed25519 AAAA\nssh-rsa BBBB"));
    try testing.expect(!validKeyLine("ssh-ed25519 AA'AA"));
    try testing.expect(!validKeyLine("-----BEGIN OPENSSH PRIVATE KEY-----"));
    try testing.expectEqualStrings("root@pve-guests", keyComment("ssh-ed25519 AAAA root@pve-guests").?);
    try testing.expect(keyComment("ssh-ed25519 AAAA") == null);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("naboo,naboo.lab.example.com,192.168.1.230 ssh-ed25519 K", try hostLine(arena.allocator(), "naboo", "naboo.lab.example.com", "192.168.1.230", "ssh-ed25519 K"));
    try testing.expectEqualStrings("hoth,192.168.1.231 ssh-ed25519 K", try hostLine(arena.allocator(), "hoth", null, "192.168.1.231", "ssh-ed25519 K"));
}

test "judgeUpdates and judgeReboot" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var h = try testkit.Harness.init();
    defer h.deinit();
    var ctx: Context = .{ .arena = arena.allocator(), .gpa = testing.allocator, .io = testing.io, .out = undefined, .err = undefined, .env = &h.env };
    const R = struct {
        fn of(out: []const u8) agent.Result {
            return .{ .code = 0, .out = out, .err = "" };
        }
    }.of;
    const base = "periodic 1\nreboot false\nsecurity 2\ntimer enabled\n";
    var c = try judgeUpdates(&ctx, R(base ++ "tailscale 1\ninstalled yes\nlast 1000\nnow 4600\n"), "", "");
    try testing.expectEqual(ui.style.Status.ok, c.status);
    try testing.expectEqualStrings("security daily, no auto-reboot, last run 1h ago", c.detail);
    c = try judgeUpdates(&ctx, R(base ++ "tailscale 0\ninstalled yes\nlast \nnow 4600\n"), "", "");
    try testing.expectEqual(ui.style.Status.warning, c.status);
    try testing.expect(std.mem.find(u8, c.detail, "not run yet; Tailscale not among the origins") != null);
    c = try judgeUpdates(&ctx, R(base ++ "tailscale 0\ninstalled no\n"), "", "");
    try testing.expectEqual(ui.style.Status.ok, c.status);
    c = try judgeUpdates(&ctx, R("periodic 1\nreboot true\nsecurity 2\ntimer enabled\n"), "", "");
    try testing.expectEqual(ui.style.Status.failed, c.status);
    c = try judgeUpdates(&ctx, R("periodic 0\nreboot false\nsecurity 2\ntimer enabled\n"), "", "");
    try testing.expectEqual(ui.style.Status.failed, c.status);
    c = try judgeUpdates(&ctx, R("periodic 1\nreboot false\nsecurity 0\ntimer enabled\n"), "", "");
    try testing.expectEqual(ui.style.Status.failed, c.status);
    c = try judgeUpdates(&ctx, R("periodic 1\nreboot false\nsecurity 2\ntimer disabled\n"), "", "");
    try testing.expectEqualStrings("apt-daily-upgrade.timer disabled", c.detail);

    c = try judgeReboot(&ctx, R("no\n"), "", "");
    try testing.expectEqual(ui.style.Status.ok, c.status);
    c = try judgeReboot(&ctx, R("yes\nlinux-image-7.0.0-39-generic\nlinux-base\nlinux-image-7.0.0-39-generic\n"), "", "");
    try testing.expectEqual(ui.style.Status.warning, c.status);
    try testing.expectEqualStrings("yes (linux-image-7.0.0-39-generic, linux-base) — 'artoo vm reboot' when convenient", c.detail);
}

test "vm verify --all: every artoo guest, concurrently; templates and foreign VMs skipped" {
    const list = "{\"data\":[{\"vmid\":100,\"name\":\"naboo\",\"status\":\"stopped\",\"tags\":\"artoo\"},{\"vmid\":101,\"name\":\"hoth\",\"status\":\"stopped\",\"tags\":\"artoo\"},{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"template\":1,\"tags\":\"artoo-template\"},{\"vmid\":150,\"name\":\"other\",\"status\":\"stopped\"}]}";
    const R = testkit.Gateway.FakeServer.Route;
    const ok = struct {
        fn r(match: []const u8, body: []const u8) R {
            return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
        }
    }.r;
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&[_]R{
        ok("/nodes/pve/qemu ", list),
        ok("/nodes/pve/qemu ", list),
        ok("/qemu/100/config ", "{\"data\":{\"tags\":\"artoo\"}}"),
        ok("/qemu/101/config ", "{\"data\":{\"tags\":\"artoo\"}}"),
        ok("/qemu/100/status/current ", "{\"data\":{\"status\":\"stopped\"}}"),
        ok("/qemu/101/status/current ", "{\"data\":{\"status\":\"stopped\"}}"),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm verify --all --no-dns"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    for ([_][]const u8{ "naboo (100)\n", "hoth (101)\n", "VM running", "\n2 guest(s): 0 ok, 0 with warnings, 2 failed\n" }) |want| {
        if (std.mem.find(u8, out, want) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ want, out });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expect(std.mem.find(u8, out, "other") == null and std.mem.find(u8, out, "ubuntu-2604") == null);
    try testing.expectEqualStrings("artoo: 2 guests failed verification\n", g.h.stderr());
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm verify naboo --all"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm verify"));
}

const reboot_probe = struct {
    pub const name = "probe";
    pub const summary = "rebootForUpdates probe";
    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var l: exec.Ledger = .{};
        const i = try l.add(ctx.arena, "reboot for updates");
        defer ctx.out.print("{s}|{s}\n", .{ @tagName(l.steps.items[i].state), l.steps.items[i].detail }) catch {};
        try rebootForUpdates(&c, 200, &l, i);
    }
};

test "rebootForUpdates: skipped when not wanted; a request left after the reboot fails" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const pid = "{\"data\":{\"pid\":42}}";
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try execStatus(a, 0, "no\n", "") } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try execStatus(a, 0, "yes\n", "") } },
        .{ .respond = .{ .body = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:qmreboot:200:artoo@pve!cli:\"}" } },
        .{ .respond = .{ .body = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":{}}}" } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try execStatus(a, 0, "7.0.0-38-generic\nstill\n", "") } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{cli.leaf(reboot_probe)});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "probe"));
    try testing.expectEqualStrings("skipped|not needed\n", g.h.stdout());
    try testing.expectEqual(Exit.partial, g.h.run(&root, "probe"));
    try testing.expectEqualStrings("failed|still pending after the reboot (kernel 7.0.0-38-generic)\n", g.h.stdout());
    try testing.expectEqual(@as(usize, 9), g.sent());
}
