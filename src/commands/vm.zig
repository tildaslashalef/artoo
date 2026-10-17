//! `artoo vm …` (SPEC §3.3): virtual machines on Proxmox. VM is a VMID or
//! an exact name; ambiguity lists the candidates.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const k = @import("node.zig");
const template = @import("template.zig");
const vm_new = @import("vm_new.zig");
const svc = @import("svc.zig");
const cf_tunnel = @import("cf_tunnel.zig");

const Context = app.Context;
const Value = std.json.Value;

const vm_arg = [_]cli.Positional{.{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name" }};

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "List VMs on Proxmox (templates with --all)";
    pub const flags = [_]cli.Flag{
        .{ .long = "all", .short = 'a', .help = "Include templates" },
        .{ .long = "status", .short = 's', .kind = .string, .metavar = "STATE", .help = "Only VMs in this state (running, stopped, …)" },
        .{ .long = "name", .kind = .string, .metavar = "GLOB", .help = "Only names matching (* and ?)" },
    };
    pub const examples = [_][]const u8{ "artoo vm ls", "artoo vm ls --all", "artoo vm ls -s running --name 'web-*'" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var shown: std.ArrayList(vms.Vm) = .empty;
        for (try vms.list(&c)) |v| {
            if (v.template and !args.has("all")) continue;
            if (args.string("status")) |s| if (!std.ascii.eqlIgnoreCase(s, v.status) or v.template) continue;
            if (args.string("name")) |g| if (!vms.globMatch(g, v.name)) continue;
            try shown.append(ctx.arena, v);
        }
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, shown.items, .{ .collected_at = ctx.ui.now, .node = c.node, .cpu_unit = "fraction of the VM's vCPUs" });
        try k.header(ctx, &c);
        if (shown.items.len == 0) {
            try ctx.out.print("{s}No VMs.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
            return;
        }
        const domain = (try ctx.config()).guests.domain;
        const rows = try ctx.arena.alloc([]const ui.table.Cell, shown.items.len);
        for (shown.items, rows) |v, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 9);
            cells[0] = .{ .text = try std.fmt.allocPrint(ctx.arena, "{d}", .{v.vmid}) };
            cells[1] = .{ .text = try k.clean(ctx, v.name) };
            cells[7] = if (roleOf(v.tags)) |r| .{ .text = try k.clean(ctx, r) } else .{ .text = "--", .role = .muted };
            cells[2] = try k.vmStatus(ctx, v.status, v.template);
            cells[3] = .{ .text = if (v.running() and v.cpu != null)
                try std.fmt.allocPrint(ctx.arena, "{f} of {d}", .{ ui.values.percent(v.cpu), @as(u64, @intFromFloat(v.cpus orelse 0)) })
            else
                "--" };
            cells[4] = .{ .text = if (v.running()) try k.fmt(ctx, ui.values.usedTotal(v.mem, v.maxmem)) else try k.fmt(ctx, ui.values.bytes(v.maxmem)), .role = if (v.running()) .text else .muted };
            cells[5] = .{ .text = if (v.running()) try k.fmt(ctx, ui.values.duration(v.uptime)) else "--" };
            cells[6] = .{ .text = try k.clean(ctx, v.tags) };
            std.mem.rotate(ui.table.Cell, cells[2..8], 5);
            // The machine name `vm new` gives every artoo guest (SPEC §9.6).
            cells[8] = if (!v.template and template.taggedWith(v.tags, vm_new.tag))
                .{ .text = try std.fmt.allocPrint(ctx.arena, "{s}.{s}", .{ try k.clean(ctx, v.name), domain }) }
            else
                .{ .text = "--", .role = .muted };
            std.mem.rotate(ui.table.Cell, cells[2..], 6);
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "VMID", .alignment = .right, .truncate = false },
            .{ .title = "NAME", .truncate = false },
            .{ .title = "HOST", .truncate = false },
            .{ .title = "ROLE" },
            .{ .title = "STATUS" },
            .{ .title = "CPU", .alignment = .right, .drop = 1 },
            .{ .title = "MEMORY", .drop = 1 },
            .{ .title = "UPTIME", .alignment = .right, .drop = 2 },
            .{ .title = "TAGS", .drop = 3 },
        }, rows);
    }
};

/// `artoo;role-edge` → `edge` (SPEC §9.1).
pub fn roleOf(tags: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeAny(u8, tags, ";, ");
    while (it.next()) |t| if (std.mem.cutPrefix(u8, t, "role-")) |r| return r;
    return null;
}

test "roleOf" {
    try std.testing.expectEqualStrings("edge", roleOf("artoo;role-edge").?);
    try std.testing.expect(roleOf("artoo") == null);
}

pub const Detail = struct {
    vm: vms.Vm,
    config: Value,
    snapshots: []const []const u8,
    /// Guest-agent addresses; null when not available (see `agent_note`).
    addresses: ?[]const vms.Address,
    agent_note: ?[]const u8,
};

pub fn detail(c: *pve.Client, word: []const u8) !Detail {
    const ctx = c.ctx;
    const v = try vms.resolve(c, word);
    const cfg = try vms.config(c, v.vmid);
    var snaps: std.ArrayList([]const u8) = .empty;
    for (try vms.snapshots(c, v.vmid)) |s| {
        const n = pve.str(s, "name") orelse continue;
        if (!std.mem.eql(u8, n, "current")) try snaps.append(ctx.arena, n);
    }
    var d: Detail = .{ .vm = v, .config = cfg, .snapshots = snaps.items, .addresses = null, .agent_note = null };
    if (!v.running()) {
        d.agent_note = "VM not running";
    } else if (!vms.agentEnabled(cfg)) {
        d.agent_note = "guest agent not enabled";
    } else {
        d.addresses = vms.agentAddresses(c, v.vmid) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => blk: {
                d.agent_note = try std.fmt.allocPrint(ctx.arena, "agent not answering ({s})", .{ctx.diag orelse @errorName(err)});
                ctx.diag = null;
                break :blk null;
            },
        };
    }
    return d;
}

pub const show = struct {
    pub const name = "show";
    pub const summary = "One VM: state, resources, network, cloud-init, snapshots";
    pub const positionals = vm_arg;
    pub const examples = [_][]const u8{ "artoo vm show web-01", "artoo vm show 100 -o json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const d = try detail(&c, args.pos("VM"));
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, d, .{ .collected_at = ctx.ui.now, .node = c.node });
        try k.header(ctx, &c);
        try render(ctx, d);
    }
};

fn cfgText(ctx: *Context, cfg: Value, key: []const u8) !?[]const u8 {
    if (cfg != .object) return null;
    const v = cfg.object.get(key) orelse return null;
    return switch (v) {
        .string => |s| try k.clean(ctx, s),
        .integer => |n| try std.fmt.allocPrint(ctx.arena, "{d}", .{n}),
        .float => |f| try std.fmt.allocPrint(ctx.arena, "{d}", .{f}),
        else => null,
    };
}

fn render(ctx: *Context, d: Detail) !void {
    const a = ctx.arena;
    const v = d.vm;
    const st = try k.vmStatus(ctx, v.status, v.template);
    var general: std.ArrayList(ui.blocks.Field) = .empty;
    try general.appendSlice(a, &.{
        .{ .key = "VMID", .value = try std.fmt.allocPrint(a, "{d}", .{v.vmid}) },
        .{ .key = "Status", .value = st.text, .role = st.role },
        .{ .key = "Uptime", .value = if (v.running()) try k.fmt(ctx, ui.values.duration(v.uptime)) else "--" },
        .{ .key = "Tags", .value = if (v.tags.len > 0) try k.clean(ctx, v.tags) else "--" },
    });
    if (v.lock) |l| try general.append(a, .{ .key = "Lock", .value = try k.clean(ctx, l), .role = .warn });
    if (try cfgText(ctx, d.config, "description")) |desc| try general.append(a, .{ .key = "Description", .value = desc });

    const cores = pve.int(d.config, "cores") orelse 1;
    const sockets = pve.int(d.config, "sockets") orelse 1;
    var res: std.ArrayList(ui.blocks.Field) = .empty;
    try res.appendSlice(a, &.{
        .{ .key = "vCPU", .value = try std.fmt.allocPrint(a, "{d}{s}", .{ cores * sockets, if (v.running() and v.cpu != null) try std.fmt.allocPrint(a, " ({f} used)", .{ui.values.percent(v.cpu)}) else "" }) },
        .{ .key = "Memory", .value = if (v.running()) try k.usage(ctx, v.mem, v.maxmem) else try k.fmt(ctx, ui.values.bytes(v.maxmem)) },
        .{ .key = "Disk", .value = try k.fmt(ctx, ui.values.bytes(v.maxdisk)) },
    });

    var net: std.ArrayList(ui.blocks.Field) = .empty;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const key = try std.fmt.allocPrint(a, "net{d}", .{i});
        if (try cfgText(ctx, d.config, key)) |n| try net.append(a, .{ .key = key, .value = n });
    }
    if (d.addresses) |addrs| {
        var text: std.ArrayList(u8) = .empty;
        for (addrs, 0..) |ad, j| {
            if (j > 0) try text.append(a, '\n');
            try text.print(a, "{s}/{d} ({s})", .{ try k.clean(ctx, ad.address), ad.prefix orelse 0, try k.clean(ctx, ad.interface) });
        }
        try net.append(a, .{ .key = "Addresses", .value = if (addrs.len > 0) text.items else "(none reported)" });
    } else try net.append(a, .{ .key = "Addresses", .value = try std.fmt.allocPrint(a, "not available: {s}", .{d.agent_note orelse "--"}), .role = .muted });
    if (net.items.len == 0) try net.append(a, .{ .key = "(none)", .value = "", .role = .muted });

    var ci: std.ArrayList(ui.blocks.Field) = .empty;
    for ([_][]const u8{ "ciuser", "ipconfig0", "nameserver", "searchdomain" }) |key| {
        if (try cfgText(ctx, d.config, key)) |x| try ci.append(a, .{ .key = key, .value = x });
    }
    if (d.config == .object and d.config.object.get("cipassword") != null) try ci.append(a, .{ .key = "cipassword", .value = "set (hidden)", .role = .muted });
    if (try cfgText(ctx, d.config, "sshkeys")) |keys| try ci.append(a, .{ .key = "sshkeys", .value = try std.fmt.allocPrint(a, "{d} key(s)", .{std.mem.count(u8, keys, "ssh-")}) });
    if (try cfgText(ctx, d.config, "cicustom")) |x| try ci.append(a, .{ .key = "cicustom", .value = x });
    if (ci.items.len == 0) try ci.append(a, .{ .key = "(not configured)", .value = "", .role = .muted });

    const snaps = if (d.snapshots.len == 0) "(none)" else try std.mem.join(a, ", ", d.snapshots);
    try ui.blocks.detail(ctx.out, &ctx.ui, &.{
        .{ .title = try std.fmt.allocPrint(a, "VM {s}", .{try k.clean(ctx, if (v.name.len > 0) v.name else "(unnamed)")}), .fields = general.items },
        .{ .title = "Resources", .fields = res.items },
        .{ .title = "Network", .fields = net.items },
        .{ .title = "Cloud-init", .fields = ci.items },
        .{ .title = "Snapshots", .fields = &.{.{ .key = "Names", .value = try k.clean(ctx, snaps), .role = if (d.snapshots.len == 0) .muted else .text }} },
    });
}

pub const config = struct {
    pub const name = "config";
    pub const summary = "A VM's full configuration (PVE keys, sorted)";
    pub const positionals = vm_arg;
    pub const examples = [_][]const u8{"artoo vm config web-01"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const v = try vms.resolve(&c, args.pos("VM"));
        const cfg = try vms.config(&c, v.vmid);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, cfg, .{ .collected_at = ctx.ui.now, .node = c.node, .vmid = v.vmid });
        try k.header(ctx, &c);
        var fields: std.ArrayList(ui.blocks.Field) = .empty;
        if (cfg == .object) {
            const keys = try ctx.arena.dupe([]const u8, cfg.object.keys());
            std.mem.sort([]const u8, keys, {}, struct {
                fn lt(_: void, x: []const u8, y: []const u8) bool {
                    return std.mem.lessThan(u8, x, y);
                }
            }.lt);
            for (keys) |key| {
                const text = (try cfgText(ctx, cfg, key)) orelse continue;
                const hidden = std.mem.eql(u8, key, "cipassword");
                try fields.append(ctx.arena, .{ .key = try k.clean(ctx, key), .value = if (hidden) "(hidden)" else text, .role = if (hidden or std.mem.eql(u8, key, "digest")) .muted else .text });
            }
        }
        try ui.blocks.detail(ctx.out, &ctx.ui, &.{.{ .title = try std.fmt.allocPrint(ctx.arena, "VM {d} {s}", .{ v.vmid, try k.clean(ctx, v.name) }), .fields = fields.items }});
    }
};

pub const urls = struct {
    pub const name = "urls";
    pub const summary = "A VM's web addresses: its services and their public hosts";
    pub const details =
        \\Read-only. Lists the services whose route on the edge VM points at the
        \\VM (SPEC §9.6) and the public hosts of the lab tunnel that reach each
        \\one (§15). If the edge VM or Cloudflare cannot be read, the command says
        \\so and exits 8.
    ;
    pub const positionals = vm_arg;
    pub const examples = [_][]const u8{ "artoo vm urls scarif", "artoo vm urls scarif -o json" };

    const Row = struct {
        service: []const u8,
        port: u16,
        url: []const u8,
        public: []const []const u8,
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const a = ctx.arena;
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const v = try vms.resolve(&c, args.pos("VM"));
        const d = try svc.domains(ctx);
        const at = try svc.routesAt(ctx, &c, v.name);
        var notes: std.ArrayList([]const u8) = .empty;
        if (at.note) |n| try notes.append(a, n);
        // Cloudflare is read only when there is a service to match.
        const public: cf_tunnel.Public = if (at.routes.len > 0) try cf_tunnel.publicRoutes(ctx) else .{};
        if (public.note) |n| try notes.append(a, n);

        var rows: std.ArrayList(Row) = .empty;
        for (at.routes) |r| {
            const hosts = try public.hostsFor(a, r.name);
            const shown = try a.alloc([]const u8, hosts.len);
            for (hosts, shown) |h, *o| o.* = try std.fmt.allocPrint(a, "https://{s}/", .{try k.clean(ctx, h)});
            try rows.append(a, .{
                .service = try k.clean(ctx, r.name),
                .port = r.port,
                .url = try std.fmt.allocPrint(a, "https://{s}/", .{try k.clean(ctx, try svc.fqdn(ctx, d, r.name))}),
                .public = shown,
            });
        }
        std.mem.sort(Row, rows.items, {}, struct {
            fn lt(_: void, x: Row, y: Row) bool {
                return std.mem.lessThan(u8, x.service, y.service);
            }
        }.lt);

        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .pve, .{ .vm = v.name, .vmid = v.vmid, .services = rows.items }, .{ .collected_at = ctx.ui.now, .node = c.node, .notes = notes.items });
        } else {
            try k.header(ctx, &c);
            const label = try k.clean(ctx, v.name);
            if (rows.items.len == 0) {
                if (at.note == null) try ctx.out.print("{s}No services point at {s}. Add one with 'artoo svc add NAME {s}:PORT'.{s}\n", .{ ctx.ui.palette.on(.muted), label, label, ctx.ui.palette.off(.muted) });
            } else {
                const cells = try a.alloc([]const ui.table.Cell, rows.items.len);
                for (rows.items, cells) |r, *row| {
                    const cs = try a.alloc(ui.table.Cell, 4);
                    cs[0] = .{ .text = r.service };
                    cs[1] = .{ .text = try std.fmt.allocPrint(a, "{d}", .{r.port}) };
                    cs[2] = .{ .text = r.url };
                    cs[3] = if (r.public.len > 0) .{ .text = try std.mem.join(a, ", ", r.public) } else .{ .text = "--", .role = .muted };
                    row.* = cs;
                }
                try ui.table.render(ctx.out, &ctx.ui, a, &.{
                    .{ .title = "SERVICE", .truncate = false },
                    .{ .title = "PORT", .alignment = .right },
                    .{ .title = "URL", .truncate = false },
                    .{ .title = "PUBLIC", .truncate = false, .drop = 1 },
                }, cells);
            }
            for (notes.items) |n| try ctx.out.print("{s}{s}{s}\n", .{ ctx.ui.palette.on(.muted), n, ctx.ui.palette.off(.muted) });
        }
        if (notes.items.len > 0) return ctx.fail(error.Partial, "{s}", .{notes.items[0]});
    }
};

pub const group = cli.group("vm", "Virtual machines on Proxmox", &([_]cli.Command{
    cli.leaf(ls),
    cli.leaf(show),
    cli.leaf(config),
    cli.leaf(urls),
} ++ @import("vm_life.zig").commands ++ @import("vm_new.zig").commands ++ @import("vm_ssh.zig").commands));

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");

pub const resources_body =
    \\{"data":[{"id":"qemu/100","type":"qemu","node":"pve","vmid":100,"name":"web-01","status":"running","template":0,"maxcpu":2,"cpu":0.125,"mem":1073741824,"maxmem":2147483648,"maxdisk":21474836480,"uptime":3720,"tags":"artoo"},
    \\ {"id":"qemu/9000","type":"qemu","node":"pve","vmid":9000,"name":"ubuntu-2604","status":"stopped","template":1,"maxcpu":1,"maxmem":1073741824,"maxdisk":21474836480},
    \\ {"id":"qemu/101","type":"qemu","node":"pve","vmid":101,"name":"db-01","status":"stopped","template":0,"maxcpu":1,"maxmem":1073741824}]}
;
pub const config_body =
    \\{"data":{"name":"web-01","cores":2,"sockets":1,"memory":"2048","agent":"1","net0":"virtio=BC:24:11:00:00:01,bridge=vmbr0","ciuser":"artoo",
    \\ "cipassword":"**********","ipconfig0":"ip=192.168.1.200/24,gw=192.168.1.1","sshkeys":"ssh-ed25519%20AAAA%20me","digest":"abc123"}}
;

test "vm ls: templates hidden unless --all; filters" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = resources_body } },
        .{ .respond = .{ .body = resources_body } },
        .{ .respond = .{ .body = resources_body } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm ls"));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/qemu HTTP/1.1", g.request(0));
    var out = g.h.stdout();
    if (std.mem.find(u8, out, " 100  web-01  web-01.lab.example.com  --    ● running  12.5% of 2  1.0 GiB / 2.0 GiB (50.0%)   1h 2m  artoo") == null) {
        std.debug.print("--- output:\n{s}\n", .{out});
        return error.TestUnexpectedResult;
    }
    try testing.expect(std.mem.find(u8, out, "ubuntu-2604") == null);
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm ls --all"));
    try testing.expect(std.mem.find(u8, g.h.stdout(), "○ template") != null);
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm ls -s stopped"));
    out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "db-01") != null and std.mem.find(u8, out, "web-01") == null);
    // Not an artoo guest: no machine name.
    try testing.expect(std.mem.find(u8, out, " 101  db-01  --  ") != null);
}

test "vm show: sections; agent addresses; hidden password" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = resources_body } },
        .{ .respond = .{ .body = config_body } },
        .{ .respond = .{ .body = "{\"data\":[{\"name\":\"current\"},{\"name\":\"pre-upgrade\",\"snaptime\":1791600000}]}" } },
        .{ .respond = .{ .body = "{\"data\":{\"result\":[{\"name\":\"lo\",\"ip-addresses\":[{\"ip-address\":\"127.0.0.1\",\"ip-address-type\":\"ipv4\",\"prefix\":8}]},{\"name\":\"eth0\",\"ip-addresses\":[{\"ip-address\":\"192.168.1.200\",\"ip-address-type\":\"ipv4\",\"prefix\":24},{\"ip-address\":\"fe80::1\",\"ip-address-type\":\"ipv6\",\"prefix\":64}]}]}}" } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm show web-01"));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/qemu/100/agent/network-get-interfaces HTTP/1.1", g.request(3));
    const out = g.h.stdout();
    for ([_][]const u8{
        "VM web-01\n",
        "  Addresses   192.168.1.200/24 (eth0)\n",
        "  cipassword  set (hidden)\n",
        "  sshkeys     1 key(s)\n",
        "  Names       pre-upgrade\n",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expect(std.mem.find(u8, out, "127.0.0.1") == null);
}

test "vm: unknown and ambiguous targets" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = resources_body } },
        .{ .respond = .{ .body = "{\"data\":[{\"type\":\"qemu\",\"node\":\"pve\",\"vmid\":1,\"name\":\"x\"},{\"type\":\"qemu\",\"node\":\"pve\",\"vmid\":2,\"name\":\"x\"}]}" } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "vm config nope"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "no VM 'nope' on pve") != null);
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "vm config x"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "2 VMs are named 'x'; use a VMID: 1, 2") != null);
}

fn agentOut(a: std.mem.Allocator, out: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
}

const urls_vms = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"},{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"},{\"vmid\":203,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"}]}";

fn edgeDump(a: std.mem.Allocator) ![]const u8 {
    const d: svc.Domains = .{ .apps = "apps.lab.example.com", .guests = "lab.example.com" };
    return agentOut(a, try std.fmt.allocPrint(a, "==artoo== /etc/caddy/services/ntfy.caddy\n{s}\n==artoo== /etc/caddy/services/grafana.caddy\n{s}\n==artoo== /etc/caddy/services/blog.caddy\n{s}\n==caddy== active\n", .{
        try svc.render(a, d, "ntfy", "scarif", 8080),
        try svc.render(a, d, "grafana", "scarif", 3000),
        try svc.render(a, d, "blog", "naboo", 80),
    }));
}

test "vm urls: services on the edge that point at the VM, with their public hosts" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = urls_vms } },
        .{ .respond = .{ .body = urls_vms } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try edgeDump(a) } },
        .{ .respond = .{ .body = cf_tunnel.zones_body } },
        .{ .respond = .{ .body = cf_tunnel.tunnels_body } },
        .{ .respond = .{ .body =
        \\{"success":true,"errors":[],"result":{"tunnel_id":"T1","version":3,"config":{"ingress":[{"hostname":"push.example.com","service":"https://localhost:443","originRequest":{"originServerName":"ntfy.apps.lab.example.com"}},{"hostname":"www.example.com","service":"https://localhost:443","originRequest":{"originServerName":"blog.apps.lab.example.com"}},{"service":"http_status:404"}]}}}
        } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm urls scarif"));
    try testing.expectEqual(@as(usize, 7), g.sent());
    const out = g.h.stdout();
    for ([_][]const u8{
        "SERVICE  PORT  URL                                    PUBLIC\n",
        "grafana  3000  https://grafana.apps.lab.example.com/  --\n",
        "ntfy     8080  https://ntfy.apps.lab.example.com/     https://push.example.com/\n",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expect(std.mem.find(u8, out, "blog") == null);
}

test "vm urls: no services skips Cloudflare; an unreadable Cloudflare is partial (exit 8)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const dump = try edgeDump(a);
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = urls_vms } },
        .{ .respond = .{ .body = urls_vms } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try agentOut(a, "==caddy== active\n") } },
        .{ .respond = .{ .body = urls_vms } },
        .{ .respond = .{ .body = urls_vms } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = dump } },
        .{ .respond = .{ .status = 403, .body = "{\"success\":false,\"errors\":[],\"result\":null}" } },
        .{ .respond = .{ .body = urls_vms } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "vm urls naboo"));
    try testing.expectEqual(@as(usize, 4), g.sent());
    try testing.expect(std.mem.find(u8, g.h.stdout(), "No services point at naboo. Add one with 'artoo svc add NAME naboo:PORT'.") != null);
    try testing.expectEqual(testkit.Exit.partial, g.h.run(&root, "vm urls naboo"));
    const out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "https://blog.apps.lab.example.com/  --\n") != null);
    try testing.expect(std.mem.find(u8, out, "Public routes not checked") != null);
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "vm urls nope"));
}
