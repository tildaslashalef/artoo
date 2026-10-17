//! `artoo storage ls | show STORAGE` (SPEC §3.3, §11): storages on the
//! node with usage, and per-storage content. Read-only; no invented
//! totals (a storage without numbers shows `--`).

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

pub const Storage = struct {
    name: []const u8,
    type: []const u8,
    content: []const u8,
    used: ?u64,
    total: ?u64,
    avail: ?u64,
    active: bool,
    enabled: bool,
    shared: bool,
};

pub fn list(c: *pve.Client) ![]Storage {
    const data = try c.get(try c.nodePath("/storage", .{}));
    var out: std.ArrayList(Storage) = .empty;
    for (pve.items(data)) |s| try out.append(c.ctx.arena, from(s, pve.str(s, "storage") orelse continue));
    return out.items;
}

fn from(s: Value, name: []const u8) Storage {
    return .{
        .name = name,
        .type = pve.str(s, "type") orelse "",
        .content = pve.str(s, "content") orelse "",
        .used = pve.uint(s, "used"),
        .total = pve.uint(s, "total"),
        .avail = pve.uint(s, "avail"),
        .active = pve.flag(s, "active"),
        .enabled = pve.flag(s, "enabled"),
        .shared = pve.flag(s, "shared"),
    };
}

fn stateCell(ctx: *Context, s: Storage) !ui.table.Cell {
    if (!s.enabled) return k.statusCell(ctx, .stopped, "disabled");
    if (!s.active) return k.statusCell(ctx, .failed, "inactive");
    return k.statusCell(ctx, .ok, "active");
}

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "List storages on Proxmox with usage";
    pub const examples = [_][]const u8{ "artoo storage ls", "artoo storage ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const all = try list(&c);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, all, .{ .collected_at = ctx.ui.now, .node = c.node });
        try k.header(ctx, &c);
        const rows = try ctx.arena.alloc([]const ui.table.Cell, all.len);
        for (all, rows) |s, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 6);
            cells[0] = .{ .text = try k.clean(ctx, s.name) };
            cells[1] = .{ .text = try k.clean(ctx, s.type) };
            cells[2] = .{ .text = try k.clean(ctx, s.content) };
            cells[3] = .{ .text = try k.usage(ctx, s.used, s.total) };
            cells[4] = .{ .text = try k.fmt(ctx, ui.values.bytes(s.avail)) };
            cells[5] = try stateCell(ctx, s);
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "NAME", .truncate = false },
            .{ .title = "TYPE" },
            .{ .title = "CONTENT", .drop = 2 },
            .{ .title = "USED", .drop = 1 },
            .{ .title = "AVAIL", .alignment = .right },
            .{ .title = "STATE" },
        }, rows);
    }
};

pub const show = struct {
    pub const name = "show";
    pub const summary = "One storage: status and content by type";
    pub const positionals = [_]cli.Positional{.{ .name = "STORAGE", .help = "Storage name (see 'artoo storage ls')" }};
    pub const examples = [_][]const u8{"artoo storage show local-zfs"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const want = args.pos("STORAGE");
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const all = try list(&c);
        const s = for (all) |s| {
            if (std.mem.eql(u8, s.name, want)) break s;
        } else return ctx.fail(error.NotFound, "no storage '{s}' on {s} (see 'artoo storage ls')", .{ want, c.node });
        const content = pve.items(try c.get(try c.nodePath("/storage/{s}/content", .{try escapeSegment(ctx, s.name)})));
        const Group = struct { content: []const u8, count: usize, size: u64 };
        var groups: std.ArrayList(Group) = .empty;
        for (content) |v| {
            const kind = pve.str(v, "content") orelse "other";
            const size = pve.uint(v, "size") orelse 0;
            for (groups.items) |*g| {
                if (std.mem.eql(u8, g.content, kind)) {
                    g.count += 1;
                    g.size += size;
                    break;
                }
            } else try groups.append(ctx.arena, .{ .content = kind, .count = 1, .size = size });
        }
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, .{ .storage = s, .content = groups.items }, .{ .collected_at = ctx.ui.now, .node = c.node, .volumes = content.len });
        try k.header(ctx, &c);
        var fields: std.ArrayList(ui.blocks.Field) = .empty;
        try fields.appendSlice(ctx.arena, &.{
            .{ .key = "Type", .value = try k.clean(ctx, s.type) },
            .{ .key = "Content", .value = try k.clean(ctx, s.content) },
            .{ .key = "Used", .value = try k.usage(ctx, s.used, s.total) },
            .{ .key = "Available", .value = try k.fmt(ctx, ui.values.bytes(s.avail)) },
            .{ .key = "State", .value = (try stateCell(ctx, s)).text, .role = (try stateCell(ctx, s)).role },
            .{ .key = "Shared", .value = if (s.shared) "yes" else "no" },
        });
        var volumes: std.ArrayList(ui.blocks.Field) = .empty;
        for (groups.items) |g| try volumes.append(ctx.arena, .{
            .key = try k.clean(ctx, g.content),
            .value = try std.fmt.allocPrint(ctx.arena, "{d} volume(s), {f}", .{ g.count, ui.values.bytes(g.size) }),
        });
        if (volumes.items.len == 0) try volumes.append(ctx.arena, .{ .key = "(empty)", .value = "", .role = .muted });
        try ui.blocks.detail(ctx.out, &ctx.ui, &.{
            .{ .title = try std.fmt.allocPrint(ctx.arena, "Storage {s}", .{try k.clean(ctx, s.name)}), .fields = fields.items },
            .{ .title = "Content", .fields = volumes.items },
        });
    }
};

/// Percent-encode a path segment.
pub fn escapeSegment(ctx: *Context, s: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (s) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            try out.append(ctx.arena, ch);
        } else try out.print(ctx.arena, "%{X:0>2}", .{ch});
    }
    return out.items;
}

pub const group = cli.group("storage", "Storages on Proxmox (read-only)", &.{ cli.leaf(ls), cli.leaf(show) });

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");

pub const storage_body =
    \\{"data":[{"active":1,"avail":1927301955584,"content":"snippets,iso,import,backup,vztmpl","enabled":1,"shared":0,"storage":"local","total":1927302086656,"type":"dir","used":131072},
    \\ {"active":1,"avail":1927301959680,"content":"rootdir,images","enabled":1,"shared":0,"storage":"local-zfs","total":1927302057984,"type":"zfspool","used":21474836480}]}
;

test "storage ls and show" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = storage_body } },
        .{ .respond = .{ .body = storage_body } },
        .{ .respond = .{ .body = "{\"data\":[{\"content\":\"images\",\"size\":21474836480,\"volid\":\"local-zfs:vm-100-disk-0\"},{\"content\":\"images\",\"size\":4194304,\"volid\":\"local-zfs:vm-100-disk-1\"}]}" } },
        .{ .respond = .{ .body = storage_body } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{group});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "storage ls"));
    const out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "local-zfs  zfspool  rootdir,images") != null);
    try testing.expect(std.mem.find(u8, out, "20.0 GiB / 1.8 TiB (1.1%)") != null);
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "storage show local-zfs"));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/storage/local-zfs/content HTTP/1.1", g.request(2));
    try testing.expect(std.mem.find(u8, g.h.stdout(), "  images     2 volume(s), 20.0 GiB\n") != null);
    try testing.expectEqual(testkit.Exit.usage, g.h.run(&root, "storage show nope"));
}
