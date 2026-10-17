//! `artoo image ls | fetch IMAGE | rm IMAGE` (SPEC §3.3, §9.2): pinned
//! guest images in Proxmox's `local:import`. `fetch` has Proxmox download
//! the image itself and verify the pinned SHA-256 before keeping it; the
//! workstation never stores an image.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const tasks = @import("../pve/task.zig");
const images = @import("../guest/image.zig");
const storage = @import("storage.zig");
const k = @import("node.zig");

const Context = app.Context;
const Pin = images.Pin;

const confirm_flag: cli.Flag = .{ .long = "confirm", .kind = .string, .metavar = "TARGET", .help = "Non-interactive confirmation (with --yes)" };

/// A file in `local:import`.
pub const File = struct {
    volid: []const u8,
    file: []const u8,
    size: ?u64,
    format: []const u8,
    ctime: ?i64,
};

/// Files in the image storage's `import` content.
pub fn files(c: *pve.Client) ![]File {
    const data = try c.get(try c.nodePath("/storage/{s}/content?content=import", .{images.storage}));
    var out: std.ArrayList(File) = .empty;
    for (pve.items(data)) |v| {
        const volid = pve.str(v, "volid") orelse continue;
        try out.append(c.ctx.arena, .{
            .volid = volid,
            .file = images.fileOf(volid) orelse continue,
            .size = pve.uint(v, "size"),
            .format = pve.str(v, "format") orelse "",
            .ctime = pve.int(v, "ctime"),
        });
    }
    return out.items;
}

pub const State = enum {
    present,
    missing,
    /// The pinned name with another size: not the pinned build.
    mismatch,
    unpinned,
};

/// The pin's file on Proxmox and what it means.
pub fn lookup(all: []const File, p: *const Pin) struct { state: State, file: ?File } {
    for (all) |f| {
        if (std.mem.eql(u8, f.file, p.file)) return .{ .state = if (f.size == p.size) .present else .mismatch, .file = f };
    }
    return .{ .state = .missing, .file = null };
}

fn pinned(file: []const u8) bool {
    for (images.pins) |p| {
        if (std.mem.eql(u8, p.file, file)) return true;
    }
    return false;
}

const Row = struct {
    image: ?[]const u8,
    release: ?[]const u8,
    build: ?[]const u8,
    file: []const u8,
    volid: []const u8,
    size: ?u64,
    expected_size: ?u64,
    sha256: ?[]const u8,
    state: State,
};

fn rows(ctx: *Context, all: []const File) ![]Row {
    var out: std.ArrayList(Row) = .empty;
    inline for (&images.pins) |*p| {
        const hit = lookup(all, p);
        try out.append(ctx.arena, .{
            .image = p.name,
            .release = p.release,
            .build = p.build,
            .file = p.file,
            .volid = comptime p.volid(),
            .size = if (hit.file) |f| f.size else null,
            .expected_size = p.size,
            .sha256 = p.sha256,
            .state = hit.state,
        });
    }
    for (all) |f| {
        if (pinned(f.file)) continue;
        try out.append(ctx.arena, .{ .image = null, .release = null, .build = null, .file = f.file, .volid = f.volid, .size = f.size, .expected_size = null, .sha256 = null, .state = .unpinned });
    }
    return out.items;
}

fn stateCell(ctx: *Context, s: State) !ui.table.Cell {
    return switch (s) {
        .present => k.statusCell(ctx, .ok, "present"),
        .missing => k.statusCell(ctx, .not_checked, "not fetched"),
        .mismatch => k.statusCell(ctx, .failed, "size differs from pin"),
        .unpinned => k.statusCell(ctx, .warning, "unpinned"),
    };
}

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "Pinned images and the files in Proxmox's local:import";
    pub const examples = [_][]const u8{ "artoo image ls", "artoo image ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const all = try rows(ctx, try files(&c));
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, all, .{ .collected_at = ctx.ui.now, .node = c.node, .storage = images.storage });
        try k.header(ctx, &c);
        const table = try ctx.arena.alloc([]const ui.table.Cell, all.len);
        for (all, table) |r, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 6);
            cells[0] = .{ .text = r.image orelse "--" };
            cells[1] = .{ .text = r.release orelse "--" };
            cells[2] = .{ .text = r.build orelse "--" };
            cells[3] = .{ .text = try k.fmt(ctx, ui.values.bytes(r.size orelse r.expected_size)) };
            cells[4] = try stateCell(ctx, r.state);
            cells[5] = .{ .text = try k.clean(ctx, r.volid) };
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "IMAGE", .truncate = false },
            .{ .title = "RELEASE" },
            .{ .title = "BUILD", .drop = 2 },
            .{ .title = "SIZE", .alignment = .right },
            .{ .title = "STATE" },
            .{ .title = "VOLUME", .drop = 1 },
        }, table);
    }
};

/// Ask Proxmox to download `p` and verify its SHA-256 (one write); the UPID.
pub fn download(c: *pve.Client, p: *const Pin) ![]const u8 {
    const params = [_]pve.Param{
        .{ .name = "url", .value = p.url },
        .{ .name = "filename", .value = p.file },
        .{ .name = "content", .value = "import" },
        .{ .name = "checksum-algorithm", .value = "sha256" },
        .{ .name = "checksum", .value = p.sha256 },
        .{ .name = "verify-certificates", .value = "1" },
    };
    return tasks.upidOf(c, try c.send(.POST, try c.nodePath("/storage/{s}/download-url", .{images.storage}), &params), "the download");
}

fn pinOrFail(ctx: *Context, word: []const u8) !*const Pin {
    return images.find(word) orelse {
        var names: std.ArrayList(u8) = .empty;
        for (images.pins, 0..) |p, i| try names.print(ctx.arena, "{s}{s}", .{ if (i > 0) ", " else "", p.name });
        return ctx.fail(error.Usage, "'{s}' is not a pinned image (pinned: {s})", .{ word, names.items });
    };
}

// ---------------------------------------------------------------- fetch

const FetchOp = struct {
    c: *pve.Client,
    pin: *const Pin,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    state: State = .missing,
    upid: []const u8 = "",
    result: []const u8 = "",

    pub fn read(op: *FetchOp, _: *Context) !void {
        op.target = op.pin.name;
        op.state = lookup(try files(op.c), op.pin).state;
    }

    pub fn plan(op: *FetchOp, ctx: *Context) !?exec.Plan {
        const p = op.pin;
        switch (op.state) {
            .present => return null,
            .mismatch => return ctx.fail(error.Refused, "{s}:import/{s} exists but is not the pinned build (size differs); remove it with 'artoo image rm {s}' first", .{ images.storage, p.file, p.name }),
            .missing, .unpinned => {},
        }
        const a = ctx.arena;
        return .{
            .action = try std.fmt.allocPrint(a, "Fetch image {s} (Ubuntu {s}, build {s})", .{ p.name, p.release, p.build }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{.{
                .field = "image",
                .from = null,
                .to = try std.fmt.allocPrint(a, "{s}:import/{s} ({f})", .{ images.storage, p.file, ui.values.bytes(p.size) }),
            }}),
            .impact = try a.dupe([]const u8, &.{"Proxmox downloads the image itself; a few minutes depending on the link"}),
            .notes = try a.dupe([]const u8, &.{
                try std.fmt.allocPrint(a, "Source {s}", .{p.url}),
                try std.fmt.allocPrint(a, "Proxmox verifies SHA-256 {s} and keeps nothing that does not match.", .{p.sha256}),
            }),
            .recovery = try std.fmt.allocPrint(a, "artoo image rm {s}", .{p.name}),
        };
    }

    pub fn fingerprint(op: *FetchOp) []const u8 {
        return @tagName(op.state);
    }

    pub fn send(op: *FetchOp, _: *Context) !void {
        op.upid = try download(op.c, op.pin);
    }

    pub fn track(op: *FetchOp, _: *Context) !void {
        op.result = try k.waitTask(op.c, op.upid, 1800);
    }

    pub fn verify(op: *FetchOp, _: *Context) !bool {
        return lookup(try files(op.c), op.pin).state == .present;
    }

    pub fn done(op: *FetchOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} is on Proxmox as {s}:import/{s} ({s})", .{ op.pin.name, images.storage, op.pin.file, op.result }) catch "done";
    }
};

pub const fetch = struct {
    pub const name = "fetch";
    pub const summary = "Have Proxmox download and verify a pinned image";
    pub const details =
        \\Proxmox downloads the pinned build into local:import and checks its SHA-256
        \\before keeping it; nothing passes through the workstation. An image that
        \\is already present is left alone (exit 5).
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "IMAGE", .help = "Pinned image (see 'artoo image ls')" }};
    pub const examples = [_][]const u8{ "artoo image fetch ubuntu-2604 -n", "artoo image fetch ubuntu-2604 -y" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const p = try pinOrFail(ctx, args.pos("IMAGE"));
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: FetchOp = .{ .c = &c, .pin = p };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- rm

const RmOp = struct {
    c: *pve.Client,
    word: []const u8,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    file: ?File = null,
    upid: ?[]const u8 = null,
    result: []const u8 = "",

    /// A pin name or a file name in `local:import`.
    fn wanted(op: *RmOp) []const u8 {
        return if (images.find(op.word)) |p| p.file else op.word;
    }

    pub fn read(op: *RmOp, ctx: *Context) !void {
        op.target = op.word;
        op.file = null;
        for (try files(op.c)) |f| {
            if (std.mem.eql(u8, f.file, op.wanted())) op.file = f;
        }
        if (op.file == null and images.find(op.word) == null)
            return ctx.fail(error.NotFound, "no image '{s}' in {s}:import (see 'artoo image ls')", .{ op.word, images.storage });
    }

    pub fn plan(op: *RmOp, ctx: *Context) !?exec.Plan {
        const f = op.file orelse return null;
        const a = ctx.arena;
        const pinned_as = images.find(op.word);
        return .{
            .action = try std.fmt.allocPrint(a, "Remove image {s}", .{try k.clean(ctx, op.word)}),
            .risk = .destructive,
            .target = try k.nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{.{ .field = "image", .from = try std.fmt.allocPrint(a, "{s} ({f})", .{ try k.clean(ctx, f.volid), ui.values.bytes(f.size) }), .to = null }}),
            .impact = try a.dupe([]const u8, &.{"Templates keep their own disk copy; only new template builds need the image again"}),
            .recovery = if (pinned_as) |p| try std.fmt.allocPrint(a, "artoo image fetch {s}", .{p.name}) else null,
        };
    }

    pub fn fingerprint(op: *RmOp) []const u8 {
        return if (op.file) |f| f.volid else "";
    }

    pub fn send(op: *RmOp, ctx: *Context) !void {
        const c = op.c;
        const path = try c.nodePath("/storage/{s}/content/{s}", .{ images.storage, try storage.escapeSegment(ctx, op.file.?.volid) });
        const data = try c.send(.DELETE, path, &.{});
        // A UPID, or null when the deletion already finished.
        if (data != .null) op.upid = try tasks.upidOf(c, data, "the deletion");
    }

    pub fn track(op: *RmOp, _: *Context) !void {
        op.result = if (op.upid) |u| try k.waitTask(op.c, u, 300) else "done";
    }

    pub fn verify(op: *RmOp, _: *Context) !bool {
        for (try files(op.c)) |f| {
            if (std.mem.eql(u8, f.volid, op.file.?.volid)) return false;
        }
        return true;
    }

    pub fn done(op: *RmOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} removed ({s})", .{ op.file.?.volid, op.result }) catch "done";
    }
};

pub const rm = struct {
    pub const name = "rm";
    pub const summary = "Remove an image from Proxmox (destructive confirmation)";
    pub const details =
        \\IMAGE is a pinned name or a file name in local:import. Type the IMAGE word
        \\to confirm, or --yes --confirm IMAGE.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "IMAGE", .help = "Pinned image or file name in local:import" }};
    pub const flags = [_]cli.Flag{confirm_flag};
    pub const examples = [_][]const u8{ "artoo image rm ubuntu-2604", "artoo image rm old.qcow2 --yes --confirm old.qcow2" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: RmOp = .{ .c = &c, .word = args.pos("IMAGE") };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const group = cli.group("image", "Pinned guest images on Proxmox (never the workstation)", &.{ cli.leaf(ls), cli.leaf(fetch), cli.leaf(rm) });

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const root = cli.group("artoo", "t", &.{group});

const pin = images.pins[0];
const pin_volid = pin.volid();
pub const present_body = std.fmt.comptimePrint(
    \\{{"data":[{{"volid":"{s}","content":"import","format":"qcow2","size":{d},"ctime":1790000000}},
    \\ {{"volid":"local:import/old.qcow2","content":"import","format":"qcow2","size":1048576}}]}}
, .{ pin_volid, pin.size });
const empty_body = "{\"data\":[]}";
const upid_body = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:download:" ++ pin.file ++ ":artoo@pve!cli:\"}";
const task_ok = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}";

test "image ls: pins against local:import, unpinned files flagged" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = present_body } },
        .{ .respond = .{ .body = empty_body } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "image ls"));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/storage/local/content?content=import HTTP/1.1", g.request(0));
    const out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "ubuntu-2604  26.04    20260927  825.0 MiB  ✓ present") != null);
    try testing.expect(std.mem.find(u8, out, "▲ unpinned") != null);
    try testing.expectEqual(Exit.ok, g.h.run(&root, "-o json image ls"));
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, g.h.stdout(), .{});
    defer parsed.deinit();
    const first = parsed.value.object.get("data").?.array.items[0].object;
    try testing.expectEqualStrings("missing", first.get("state").?.string);
    try testing.expect(first.get("size").? == .null);
}

test "image fetch: Proxmox downloads with the pinned checksum; present is a no-op" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = empty_body } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = present_body } },
        .{ .respond = .{ .body = present_body } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.usage, g.h.run(&root, "image fetch ubuntu-2404"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "pinned: ubuntu-2604") != null);
    try testing.expectEqual(Exit.ok, g.h.run(&root, "image fetch ubuntu-2604 -y"));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/storage/local/download-url HTTP/1.1", g.request(1));
    try testing.expectEqualStrings("url=https%3A%2F%2Fcloud-images.ubuntu.com%2Freleases%2Fresolute%2Frelease-20260927%2Fubuntu-26.04-server-cloudimg-amd64.img" ++
        "&filename=ubuntu-26.04-20260927-amd64.qcow2&content=import&checksum-algorithm=sha256&checksum=" ++ pin.sha256 ++ "&verify-certificates=1", g.body(1));
    const out = g.h.stdout();
    try testing.expect(std.mem.startsWith(u8, out, "Plan · Fetch image ubuntu-2604 (Ubuntu 26.04, build 20260927)\n"));
    try testing.expect(std.mem.find(u8, out, "✓ ubuntu-2604 is on Proxmox as local:import/ubuntu-26.04-20260927-amd64.qcow2 (task download:") != null);
    try testing.expectEqual(Exit.refused, g.h.run(&root, "image fetch ubuntu-2604 -y"));
    try testing.expectEqual(@as(usize, 5), g.sent());
}

test "image fetch: a same-named file of another size is refused" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{.{ .respond = .{ .body = "{\"data\":[{\"volid\":\"" ++ pin_volid ++ "\",\"size\":12}]}" } }});
    defer g.deinit();
    try testing.expectEqual(Exit.refused, g.h.run(&root, "image fetch ubuntu-2604 -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "not the pinned build") != null);
}

test "image rm: destructive, by pin or file name, deletion verified" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = present_body } },
        .{ .respond = .{ .body = present_body } },
        .{ .respond = .{ .body = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:imgdel:local%3Aimport%2Fold.qcow2:artoo@pve!cli:\"}" } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":[{\"volid\":\"" ++ pin_volid ++ "\",\"size\":1}]}" } },
        .{ .respond = .{ .body = empty_body } },
        .{ .respond = .{ .body = empty_body } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.refused, g.h.run(&root, "image rm old.qcow2 -y"));
    try testing.expectEqual(Exit.ok, g.h.run(&root, "image rm old.qcow2 --yes --confirm old.qcow2"));
    try testing.expectEqualStrings("DELETE /api2/json/nodes/pve/storage/local/content/local%3Aimport%2Fold.qcow2 HTTP/1.1", g.request(2));
    try testing.expect(std.mem.find(u8, g.h.stdout(), "✓ local:import/old.qcow2 removed (task imgdel:") != null);
    try testing.expectEqual(Exit.usage, g.h.run(&root, "image rm nope.qcow2 -y"));
    try testing.expectEqual(Exit.refused, g.h.run(&root, "image rm ubuntu-2604 --yes --confirm ubuntu-2604"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "nothing to change") != null);
}
