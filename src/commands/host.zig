//! `artoo host show` (SPEC §3.3, §11): the Proxmox node — versions, boot,
//! CPU, load, memory, root filesystem, uptime. Read-only.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

pub const Host = struct {
    node: []const u8,
    version: ?[]const u8,
    release: ?[]const u8,
    kernel: ?[]const u8,
    boot_mode: ?[]const u8,
    secure_boot: ?bool,
    cpu_model: ?[]const u8,
    sockets: ?u64,
    cores: ?u64,
    threads: ?u64,
    /// Fraction of all host threads.
    cpu: ?f64,
    /// 1, 5, 15 minutes.
    load: [3]?f64,
    mem_used: ?u64,
    mem_total: ?u64,
    swap_used: ?u64,
    swap_total: ?u64,
    rootfs_used: ?u64,
    rootfs_total: ?u64,
    uptime: ?u64,
};

pub fn read(c: *pve.Client) !Host {
    const st = try c.get(try c.nodePath("/status", .{}));
    const ver = try c.get("/version");
    const cpu = pve.obj(st, "cpuinfo");
    const mem = pve.obj(st, "memory");
    const swap = pve.obj(st, "swap");
    const root = pve.obj(st, "rootfs");
    const boot = pve.obj(st, "boot-info");
    const load = pve.items(pve.obj(st, "loadavg"));
    var h: Host = .{
        .node = c.node,
        .version = pve.str(ver, "version"),
        .release = pve.str(ver, "release"),
        .kernel = pve.str(pve.obj(st, "current-kernel"), "release"),
        .boot_mode = pve.str(boot, "mode"),
        .secure_boot = if (pve.num(boot, "secureboot")) |s| s != 0 else null,
        .cpu_model = pve.str(cpu, "model"),
        .sockets = pve.uint(cpu, "sockets"),
        .cores = pve.uint(cpu, "cores"),
        .threads = pve.uint(cpu, "cpus"),
        .cpu = pve.num(st, "cpu"),
        .load = .{ null, null, null },
        .mem_used = pve.uint(mem, "used"),
        .mem_total = pve.uint(mem, "total"),
        .swap_used = pve.uint(swap, "used"),
        .swap_total = pve.uint(swap, "total"),
        .rootfs_used = pve.uint(root, "used"),
        .rootfs_total = pve.uint(root, "total"),
        .uptime = pve.uint(st, "uptime"),
    };
    for (load[0..@min(load.len, 3)], 0..) |l, i| h.load[i] = pve.numberOf(l);
    return h;
}

pub const show = struct {
    pub const name = "show";
    pub const summary = "Proxmox node: versions, CPU, load, memory, root filesystem, uptime";
    pub const examples = [_][]const u8{ "artoo host show", "artoo host show -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const h = try read(&c);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, h, .{ .collected_at = ctx.ui.now, .cpu_unit = "fraction of host threads" });
        try k.header(ctx, &c);
        try render(ctx, h);
    }
};

fn render(ctx: *Context, h: Host) !void {
    const a = ctx.arena;
    const na = "--";
    const load = if (h.load[0] != null)
        try std.fmt.allocPrint(a, "{d:.2}  {d:.2}  {d:.2}  (1, 5, 15 min)", .{ h.load[0].?, h.load[1] orelse 0, h.load[2] orelse 0 })
    else
        na;
    const boot = if (h.boot_mode) |m| try std.fmt.allocPrint(a, "{s}{s}", .{
        if (std.mem.eql(u8, m, "efi")) "UEFI" else try k.clean(ctx, m),
        if (h.secure_boot) |sb| (if (sb) ", Secure Boot on" else ", Secure Boot off") else "",
    }) else na;
    const topo = if (h.threads) |t| try std.fmt.allocPrint(a, "{d} socket(s), {d} cores, {d} threads", .{ h.sockets orelse 0, h.cores orelse 0, t }) else na;
    const swap = if (h.swap_total) |t| (if (t == 0) "none" else try k.usage(ctx, h.swap_used, h.swap_total)) else na;
    try ui.blocks.detail(ctx.out, &ctx.ui, &.{
        .{ .title = "Proxmox", .fields = &.{
            .{ .key = "Node", .value = try k.clean(ctx, h.node) },
            .{ .key = "Proxmox VE", .value = if (h.version) |v| try k.clean(ctx, v) else na },
            .{ .key = "Kernel", .value = if (h.kernel) |v| try k.clean(ctx, v) else na },
            .{ .key = "Boot", .value = boot },
            .{ .key = "Uptime", .value = try k.fmt(ctx, ui.values.duration(h.uptime)) },
        } },
        .{ .title = "CPU", .fields = &.{
            .{ .key = "Model", .value = if (h.cpu_model) |v| try k.clean(ctx, v) else na },
            .{ .key = "Topology", .value = topo },
            .{ .key = "Usage", .value = if (h.cpu) |cpu| try std.fmt.allocPrint(a, "{f} of host threads", .{ui.values.percent(cpu)}) else na },
            .{ .key = "Load", .value = load },
        } },
        .{ .title = "Memory", .fields = &.{
            .{ .key = "RAM", .value = try k.usage(ctx, h.mem_used, h.mem_total) },
            .{ .key = "Swap", .value = swap, .role = if (std.mem.eql(u8, swap, "none")) .muted else .text },
        } },
        .{ .title = "Storage", .fields = &.{
            .{ .key = "Root FS", .value = try k.usage(ctx, h.rootfs_used, h.rootfs_total) },
        } },
    });
}

// ---------------------------------------------------------------- health

const Check = enum { api, node, storage, tasks, zfs, services };

const Result = struct {
    check: []const u8,
    status: ui.style.Status,
    detail: []const u8,
};

/// Services that must run on a single-node PVE host (corosync is idle
/// without a cluster and is not checked).
const core_services = [_][]const u8{ "pve-cluster", "pvedaemon", "pveproxy", "pvestatd", "pvescheduler", "chrony", "cron" };

fn level(frac: ?f64, warn: f64, fail: f64) ui.style.Status {
    const f = frac orelse return .unknown;
    return if (f >= fail) .failed else if (f >= warn) .warning else .ok;
}

fn worst(a: ui.style.Status, b: ui.style.Status) ui.style.Status {
    const rank = struct {
        fn r(s: ui.style.Status) u8 {
            return switch (s) {
                .failed => 3,
                .warning, .unknown => 2,
                else => 1,
            };
        }
    }.r;
    return if (rank(b) > rank(a)) b else a;
}

fn runCheck(ctx: *Context, c: *pve.Client, check: Check) !Result {
    const a = ctx.arena;
    const name = @tagName(check);
    switch (check) {
        .api => {
            const v = try c.version();
            return .{ .check = name, .status = .ok, .detail = try std.fmt.allocPrint(a, "Proxmox VE {s}", .{try k.clean(ctx, v.version)}) };
        },
        .node => {
            const h = try read(c);
            const mem = ui.values.ratio(h.mem_used, h.mem_total);
            const root = ui.values.ratio(h.rootfs_used, h.rootfs_total);
            var st = worst(level(mem, 0.90, 0.97), level(root, 0.85, 0.95));
            const overloaded = h.load[0] != null and h.threads != null and h.load[0].? > @as(f64, @floatFromInt(h.threads.?));
            if (overloaded) st = worst(st, .warning);
            return .{ .check = name, .status = st, .detail = try std.fmt.allocPrint(a, "RAM {f}, root FS {f}, load {d:.2}{s}", .{
                ui.values.percent(mem), ui.values.percent(root), h.load[0] orelse 0, if (overloaded) " (above thread count)" else "",
            }) };
        },
        .storage => {
            var st: ui.style.Status = .ok;
            var detail: std.ArrayList(u8) = .empty;
            for (try @import("storage.zig").list(c)) |s| {
                const one: ui.style.Status = if (!s.enabled or !s.active) .failed else level(ui.values.ratio(s.used, s.total), 0.85, 0.95);
                st = worst(st, one);
                if (detail.items.len > 0) try detail.appendSlice(a, ", ");
                try detail.print(a, "{s} {s}", .{ try k.clean(ctx, s.name), if (!s.enabled) "disabled" else if (!s.active) "inactive" else try k.fmt(ctx, ui.values.percent(ui.values.ratio(s.used, s.total))) });
            }
            return .{ .check = name, .status = st, .detail = detail.items };
        },
        .tasks => {
            const day_ago = ctx.ui.now - 86400;
            var failed: usize = 0;
            var warned: usize = 0;
            for (try @import("task.zig").list(c, 100, .failed)) |t| {
                if ((t.start orelse 0) < day_ago) continue;
                switch (t.state()) {
                    .failed => failed += 1,
                    .warning => warned += 1,
                    else => {},
                }
            }
            return .{
                .check = name,
                .status = if (failed > 0 or warned > 0) .warning else .ok,
                .detail = try std.fmt.allocPrint(a, "last 24 h: {d} failed, {d} with warnings (artoo task ls --failed)", .{ failed, warned }),
            };
        },
        .zfs => {
            const pools = pve.items(try c.get(try c.nodePath("/disks/zfs", .{})));
            var st: ui.style.Status = if (pools.len == 0) .unknown else .ok;
            var detail: std.ArrayList(u8) = .empty;
            for (pools) |p| {
                const pool_health = pve.str(p, "health") orelse "unknown";
                if (!std.mem.eql(u8, pool_health, "ONLINE")) st = .failed;
                if (detail.items.len > 0) try detail.appendSlice(a, ", ");
                try detail.print(a, "{s} {s}", .{ try k.clean(ctx, pve.str(p, "name") orelse "?"), try k.clean(ctx, pool_health) });
            }
            return .{ .check = name, .status = st, .detail = if (pools.len == 0) "no ZFS pools reported" else detail.items };
        },
        .services => {
            const all = pve.items(try c.get(try c.nodePath("/services", .{})));
            var bad: std.ArrayList(u8) = .empty;
            for (core_services) |want| {
                const state = for (all) |svc| {
                    if (std.mem.eql(u8, pve.str(svc, "name") orelse "", want)) break pve.str(svc, "state") orelse "unknown";
                } else "missing";
                if (std.mem.eql(u8, state, "running")) continue;
                if (bad.items.len > 0) try bad.appendSlice(a, ", ");
                try bad.print(a, "{s} {s}", .{ want, try k.clean(ctx, state) });
            }
            return .{
                .check = name,
                .status = if (bad.items.len == 0) .ok else .failed,
                .detail = if (bad.items.len == 0) try std.fmt.allocPrint(a, "{d} core services running", .{core_services.len}) else bad.items,
            };
        },
    }
}

pub const health = struct {
    pub const name = "health";
    pub const summary = "Named health checks for Proxmox (default: all)";
    pub const details =
        \\Checks: api, node (RAM ≥90% warn/≥97% fail, root FS ≥85%/≥95%, load
        \\above threads), storage (inactive fails; ≥85%/≥95%), tasks (failures or
        \\warnings in the last 24 h warn), zfs (pool health ONLINE), services
        \\(pve-cluster, pvedaemon, pveproxy, pvestatd, pvescheduler, chrony, cron).
        \\Exit 8 when a check fails or cannot run; warnings do not fail. If the
        \\API itself is unreachable the usual network/auth exit applies.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "CHECK", .help = "api, node, storage, tasks, zfs, services", .required = false, .variadic = true }};
    pub const examples = [_][]const u8{ "artoo host health", "artoo host health zfs services" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var wanted: std.ArrayList(Check) = .empty;
        for (args.rest("CHECK")) |w| {
            const ch = std.meta.stringToEnum(Check, w) orelse return ctx.fail(error.Usage, "unknown check '{s}' (api, node, storage, tasks, zfs, services)", .{w});
            try wanted.append(ctx.arena, ch);
        }
        if (wanted.items.len == 0) try wanted.appendSlice(ctx.arena, std.enums.values(Check));
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        _ = try c.version(); // total failure keeps its own exit code
        var results: std.ArrayList(Result) = .empty;
        for (wanted.items) |ch| {
            const r = runCheck(ctx, &c, ch) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => blk: {
                    const msg = ctx.diag orelse @errorName(err);
                    ctx.diag = null;
                    break :blk Result{ .check = @tagName(ch), .status = .not_checked, .detail = try k.clean(ctx, msg) };
                },
            };
            try results.append(ctx.arena, r);
        }
        var failed: usize = 0;
        for (results.items) |r| failed += @intFromBool(r.status == .failed or r.status == .not_checked or r.status == .unknown);
        if (ctx.json()) {
            const J = struct { check: []const u8, status: []const u8, detail: []const u8 };
            const out = try ctx.arena.alloc(J, results.items.len);
            for (results.items, out) |r, *j| j.* = .{ .check = r.check, .status = r.status.word(), .detail = r.detail };
            try ui.json.envelope(ctx.out, .pve, out, .{ .collected_at = ctx.ui.now, .failed = failed });
        } else {
            try k.header(ctx, &c);
            const rows = try ctx.arena.alloc([]const ui.table.Cell, results.items.len);
            for (results.items, rows) |r, *row| {
                const cells = try ctx.arena.alloc(ui.table.Cell, 3);
                cells[0] = .{ .text = r.check };
                cells[1] = try k.statusCell(ctx, r.status, r.status.word());
                cells[2] = .{ .text = r.detail };
                row.* = cells;
            }
            try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
                .{ .title = "CHECK", .truncate = false },
                .{ .title = "STATUS", .truncate = false },
                .{ .title = "DETAIL", .min = 20 },
            }, rows);
        }
        if (failed > 0) return ctx.fail(error.Partial, "{d} check{s} failed or did not run", .{ failed, if (failed == 1) "" else "s" });
    }
};

pub const group = cli.group("host", "The Proxmox node (read-only)", &.{ cli.leaf(show), cli.leaf(health) });

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");

pub const status_body =
    \\{"data":{"boot-info":{"mode":"efi","secureboot":1},"cpu":0.0525,"cpuinfo":{"cores":8,"cpus":16,"model":"AMD Ryzen 7 7840HS w/ Radeon 780M Graphics","sockets":1},
    \\ "current-kernel":{"release":"7.0.14-22-pve"},"loadavg":["0.16","0.10","0.03"],"memory":{"total":68719476736,"used":3774898176},
    \\ "rootfs":{"total":1000204886016,"used":3842899968},"swap":{"free":0,"total":0,"used":0},"uptime":128611}}
;
pub const version_body =
    \\{"data":{"release":"9.2","repoid":"4f6e0ac86f9e8c7f","version":"9.2.21"}}
;

test "host show: sections and string-typed load" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{ .{ .respond = .{ .body = status_body } }, .{ .respond = .{ .body = version_body } } });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "host show"));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/status HTTP/1.1", g.request(0));
    try testing.expect(std.ascii.findIgnoreCase(g.srv.received[0].?, "authorization: PVEAPIToken=artoo@pve!cli=test-secret\r\n") != null);
    const out = g.h.stdout();
    try testing.expect(std.mem.startsWith(u8, out, "ARTOO · host show  pve · "));
    for ([_][]const u8{
        "  Proxmox VE  9.2.21\n",
        "  Boot        UEFI, Secure Boot on\n",
        "  Uptime      1d 11h\n",
        "  Topology    1 socket(s), 8 cores, 16 threads\n",
        "  Usage       5.3% of host threads\n",
        "  Load        0.16  0.10  0.03  (1, 5, 15 min)\n",
        "  Swap        none\n",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "host health: selected checks; a failed pool fails the run" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = version_body } },
        .{ .respond = .{ .body = "{\"data\":[{\"name\":\"rpool\",\"health\":\"DEGRADED\"}]}" } },
        .{ .respond = .{ .body = "{\"data\":[{\"name\":\"pve-cluster\",\"state\":\"running\"},{\"name\":\"pvedaemon\",\"state\":\"running\"},{\"name\":\"pveproxy\",\"state\":\"running\"},{\"name\":\"pvestatd\",\"state\":\"running\"},{\"name\":\"pvescheduler\",\"state\":\"running\"},{\"name\":\"chrony\",\"state\":\"running\"},{\"name\":\"cron\",\"state\":\"running\"},{\"name\":\"corosync\",\"state\":\"dead\"}]}" } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "host health disks"));
    try testing.expectEqual(testkit.Exit.partial, g.h.run(&root, "host health zfs services"));
    const out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "zfs       ✗ failed  rpool DEGRADED") != null);
    try testing.expect(std.mem.find(u8, out, "services  ✓ ok      7 core services running") != null);
}
