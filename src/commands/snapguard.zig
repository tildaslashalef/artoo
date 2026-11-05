//! Snapshots before changes (SPEC §9.16): the `artoo-` naming, the cap
//! and storage-headroom refusals, the snapshot step a guest-changing
//! workflow runs first, prune selection and rollback blockers. A snapshot
//! is a rollback point, not a backup; artoo never deletes one to make
//! room and never schedules one.

const std = @import("std");
const app = @import("../app.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const tasks = @import("../pve/task.zig");
const storage = @import("storage.zig");
const vm_disk = @import("vm_disk.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;
const Allocator = std.mem.Allocator;
const build_version = @import("build_options").version;

/// Reserved for snapshots artoo takes; `vm snap add` refuses it.
pub const prefix = "artoo-";
/// A storage above this share used takes no `--snapshot` (ZFS slows
/// sharply when nearly full).
pub const headroom_pct: u64 = 80;

pub fn owned(name: []const u8) bool {
    return std.mem.startsWith(u8, name, prefix);
}

/// `artoo-<action>-YYYYMMDDTHHMMZ` (UTC), at most 40 characters.
pub fn snapName(arena: Allocator, action: []const u8, epoch: i64) ![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(epoch, 0)) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(arena, prefix ++ "{s}-{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}Z", .{
        action, yd.year, md.month.numeric(), @as(u8, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(),
    });
}

pub const Snap = struct {
    name: []const u8,
    parent: ?[]const u8 = null,
    /// `snaptime`, seconds since the epoch.
    time: ?i64 = null,
    ram: bool = false,
    description: []const u8 = "",
};

/// A VM's snapshots from `GET …/snapshot`, without `current`.
pub fn parse(arena: Allocator, list: []const Value) ![]Snap {
    var out: std.ArrayList(Snap) = .empty;
    for (list) |s| {
        const name = pve.str(s, "name") orelse continue;
        if (std.mem.eql(u8, name, "current")) continue;
        try out.append(arena, .{
            .name = name,
            .parent = pve.str(s, "parent"),
            .time = pve.int(s, "snaptime"),
            .ram = pve.flag(s, "vmstate"),
            .description = pve.str(s, "description") orelse "",
        });
    }
    return out.items;
}

pub fn read(c: *pve.Client, vmid: u32) ![]Snap {
    return parse(c.ctx.arena, try vms.snapshots(c, vmid));
}

pub fn ownedCount(snaps: []const Snap) usize {
    var n: usize = 0;
    for (snaps) |s| n += @intFromBool(owned(s.name));
    return n;
}

fn olderFirst(_: void, x: Snap, y: Snap) bool {
    return (x.time orelse 0) < (y.time orelse 0);
}

/// Artoo-owned snapshots `vm snap prune` removes, oldest first: beyond
/// the newest `keep`, and any older than `max_age_s`. Operator snapshots
/// are never selected.
pub fn pruneSelect(arena: Allocator, snaps: []const Snap, keep: usize, max_age_s: i64, now: i64) ![]Snap {
    var mine: std.ArrayList(Snap) = .empty;
    for (snaps) |s| if (owned(s.name)) try mine.append(arena, s);
    std.mem.sort(Snap, mine.items, {}, olderFirst);
    const beyond = mine.items.len -| keep;
    var out: std.ArrayList(Snap) = .empty;
    for (mine.items, 0..) |s, i| {
        const old = if (s.time) |t| now - t > max_age_s else false;
        if (i < beyond or old) try out.append(arena, s);
    }
    return out.items;
}

/// Artoo-owned snapshots older than `max_age_s`.
pub fn stale(arena: Allocator, snaps: []const Snap, max_age_s: i64, now: i64) ![]Snap {
    var out: std.ArrayList(Snap) = .empty;
    for (snaps) |s| if (owned(s.name)) if (s.time) |t| if (now - t > max_age_s) try out.append(arena, s);
    return out.items;
}

/// The snapshots taken after `target`: on ZFS each of them blocks a
/// rollback to `target` (SPEC §17.2), oldest first.
pub fn blockers(arena: Allocator, snaps: []const Snap, target: []const u8) ![]Snap {
    var t: ?i64 = null;
    for (snaps) |s| if (std.mem.eql(u8, s.name, target)) {
        t = s.time;
    };
    const when = t orelse return &.{};
    var out: std.ArrayList(Snap) = .empty;
    for (snaps) |s| if (s.time) |st| if (st > when) try out.append(arena, s);
    std.mem.sort(Snap, out.items, {}, olderFirst);
    return out.items;
}

pub fn overHeadroom(used: u64, total: u64) bool {
    return total > 0 and used * 100 > total * headroom_pct;
}

/// The storages holding a VM's disks (CD-ROMs and empty drives left out),
/// each once.
pub fn diskStorages(arena: Allocator, cfg: Value) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (cfg != .object) return out.items;
    var it = cfg.object.iterator();
    while (it.next()) |e| {
        const key = e.key_ptr.*;
        const disk = vm_disk.validSlot(key) or std.mem.eql(u8, key, "efidisk0") or std.mem.eql(u8, key, "tpmstate0");
        if (!disk or e.value_ptr.* != .string) continue;
        const v = e.value_ptr.string;
        if (std.mem.find(u8, v, "media=cdrom") != null) continue;
        const st = vms.driveStorage(v) orelse continue;
        for (out.items) |have| {
            if (std.mem.eql(u8, have, st)) break;
        } else try out.append(arena, st);
    }
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);
    return out.items;
}

/// The storages of `cfg`'s disks with their type and usage from the
/// node's storage list.
pub fn vmStorages(c: *pve.Client, cfg: Value) ![]const storage.Storage {
    const names = try diskStorages(c.ctx.arena, cfg);
    const all = try storage.list(c);
    var out: std.ArrayList(storage.Storage) = .empty;
    for (names) |n| {
        for (all) |s| if (std.mem.eql(u8, s.name, n)) {
            try out.append(c.ctx.arena, s);
            break;
        };
    }
    return out.items;
}

pub fn rollbackCommand(arena: Allocator, vm: []const u8, snap: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "artoo vm snap rollback {s} {s}", .{ vm, snap });
}

/// `--snapshot` on a guest-changing workflow: `read` refuses before any
/// write, `decorate` adds the snapshot to the plan, `take` is the
/// workflow's first ledger step, `annotate` names the rollback after a
/// later step failed.
pub const Guard = struct {
    /// `upgrade`, `edge`, `router`, `watch`: the name's middle part.
    action: []const u8,
    /// `vm upgrade`: in the description.
    command: []const u8,
    label: []const u8 = "",
    vmid: u32 = 0,
    name: []const u8 = "",
    taken: bool = false,

    pub fn read(g: *Guard, ctx: *Context, c: *pve.Client, vm: vms.Vm) !void {
        const a = ctx.arena;
        g.vmid = vm.vmid;
        g.label = try k.clean(ctx, vm.name);
        const keep = (try ctx.config()).guests.snapshot_keep;
        const snaps = try read_(c, vm.vmid);
        const n = ownedCount(snaps);
        if (n >= keep) return ctx.fail(error.Refused, "{s} holds {d} artoo snapshot(s) (keep {d}): 'artoo vm snap prune {s}' first, or run without --snapshot", .{ g.label, n, keep, g.label });
        for (try vmStorages(c, try vms.config(c, vm.vmid))) |s| {
            const used = s.used orelse continue;
            const total = s.total orelse continue;
            if (overHeadroom(used, total)) return ctx.fail(error.Refused, "storage {s} is {d}% used (above {d}%): no snapshot is taken there; free space first, or run without --snapshot", .{ try k.clean(ctx, s.name), used * 100 / total, headroom_pct });
        }
        g.name = try snapName(a, g.action, ctx.ui.now);
        for (snaps) |s| if (std.mem.eql(u8, s.name, g.name))
            return ctx.fail(error.Refused, "{s} already has a snapshot '{s}'; run again in a minute", .{ g.label, g.name });
    }

    pub fn rollback(g: *const Guard, arena: Allocator) ![]const u8 {
        return rollbackCommand(arena, g.label, g.name);
    }

    /// The plan with the snapshot as its first change, the rollback as
    /// its recovery and what the snapshot does not cover as a note.
    pub fn decorate(g: *const Guard, ctx: *Context, pl: exec.Plan) !exec.Plan {
        const a = ctx.arena;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        try changes.append(a, .{ .field = "snapshot", .from = null, .to = try std.fmt.allocPrint(a, "{s} (no RAM), taken first", .{g.name}) });
        try changes.appendSlice(a, pl.changes);
        var notes: std.ArrayList([]const u8) = .empty;
        try notes.appendSlice(a, pl.notes);
        try notes.append(a, "The snapshot covers the guest's disks and configuration, not its Proxmox firewall rules; 'artoo vm snap prune' removes it when no longer needed.");
        var out = pl;
        out.changes = changes.items;
        out.notes = notes.items;
        const rb = try g.rollback(a);
        out.recovery = if (pl.recovery) |r| try std.fmt.allocPrint(a, "{s} (the guest); {s}", .{ rb, r }) else rb;
        return out;
    }

    /// The snapshot step: POST, task tracked, the snapshot in the list.
    /// A failure here stops the workflow before its own steps.
    pub fn take(g: *Guard, ctx: *Context, c: *pve.Client, l: *exec.Ledger) !void {
        const a = ctx.arena;
        const i = try l.add(a, "snapshot");
        l.set(i, .unknown, g.name);
        const description = try std.fmt.allocPrint(a, "artoo {s}: {s}", .{ build_version, g.command });
        const data = c.send(.POST, try c.nodePath("/qemu/{d}/snapshot", .{g.vmid}), &.{
            .{ .name = "snapname", .value = g.name },
            .{ .name = "description", .value = description },
        }) catch |err| {
            l.set(i, if (err == error.OutcomeUnknown) .unknown else .failed, g.name);
            return err;
        };
        const upid = tasks.upidOf(c, data, "the snapshot request") catch |err| {
            l.set(i, .unknown, g.name);
            return err;
        };
        _ = k.waitTaskNoted(c, upid, 600, l.noter(i)) catch |err| {
            l.set(i, if (err == error.TaskFailed) .failed else .unknown, g.name);
            return err;
        };
        for (try read_(c, g.vmid)) |s| if (std.mem.eql(u8, s.name, g.name)) {
            g.taken = true;
            l.set(i, .done, try std.fmt.allocPrint(a, "{s} — rollback: {s}", .{ g.name, try g.rollback(a) }));
            return;
        };
        l.set(i, .unknown, g.name);
        return ctx.fail(error.Partial, "the snapshot task of {s} finished, but '{s}' is not in its snapshot list; nothing else was changed", .{ g.label, g.name });
    }

    /// Appended to the workflow's success line.
    pub fn doneSuffix(g: *const Guard, arena: Allocator) []const u8 {
        if (!g.taken) return "";
        return std.fmt.allocPrint(arena, "; snapshot {s} kept ('artoo vm snap prune {s}' when no longer needed)", .{ g.name, g.label }) catch "";
    }

    /// After a later step failed or its outcome is unknown: the error
    /// message names the way back.
    pub fn annotate(g: *const Guard, ctx: *Context) void {
        if (!g.taken) return;
        const rb = g.rollback(ctx.arena) catch return;
        ctx.diag = std.fmt.allocPrint(ctx.arena, "{s} — the snapshot taken first is the way back: {s}", .{ ctx.diag orelse "the change failed", rb }) catch ctx.diag;
    }
};

const read_ = read;

/// `--snapshot`, shared by the workflows that take one.
pub const flag: @import("../cli.zig").Flag = .{ .long = "snapshot", .help = "Take an artoo-owned snapshot first (SPEC §9.16); refused at guests.snapshot_keep" };

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "snapName: artoo-<action>-UTC minute, within 40 characters" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const n = try snapName(arena.allocator(), "upgrade", 1793857500); // 2026-11-05 05:45 UTC
    try testing.expectEqualStrings("artoo-upgrade-20261105T0545Z", n);
    try testing.expect(owned(n));
    try testing.expect(n.len <= 40);
    try testing.expect((try snapName(arena.allocator(), "router", 0)).len <= 40);
    try testing.expect(!owned("pre-upgrade"));
}

fn snaps3() [4]Snap {
    return .{
        .{ .name = "pre-forgejo", .time = 100 },
        .{ .name = "artoo-upgrade-a", .time = 200 },
        .{ .name = "artoo-edge-b", .time = 300 },
        .{ .name = "artoo-upgrade-c", .time = 400 },
    };
}

test "pruneSelect: owned only, beyond keep and past the age, oldest first" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = snaps3();
    const keep1 = try pruneSelect(a, &s, 1, 10_000, 500);
    try testing.expectEqual(@as(usize, 2), keep1.len);
    try testing.expectEqualStrings("artoo-upgrade-a", keep1[0].name);
    try testing.expectEqualStrings("artoo-edge-b", keep1[1].name);
    try testing.expectEqual(@as(usize, 0), (try pruneSelect(a, &s, 3, 10_000, 500)).len);
    // Age selects within the kept ones too; the operator's snapshot never.
    const aged = try pruneSelect(a, &s, 3, 150, 500);
    try testing.expectEqual(@as(usize, 2), aged.len);
    try testing.expectEqualStrings("artoo-upgrade-a", aged[0].name);
    try testing.expectEqual(@as(usize, 2), (try stale(a, &s, 150, 500)).len);
    try testing.expectEqual(@as(usize, 3), ownedCount(&s));
}

test "blockers: snapshots newer than the target, oldest first" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = snaps3();
    const b = try blockers(a, &s, "artoo-upgrade-a");
    try testing.expectEqual(@as(usize, 2), b.len);
    try testing.expectEqualStrings("artoo-edge-b", b[0].name);
    try testing.expectEqual(@as(usize, 0), (try blockers(a, &s, "artoo-upgrade-c")).len);
    try testing.expectEqual(@as(usize, 0), (try blockers(a, &s, "missing")).len);
}

test "overHeadroom and diskStorages" {
    try testing.expect(!overHeadroom(80, 100));
    try testing.expect(overHeadroom(81, 100));
    try testing.expect(!overHeadroom(5, 0));
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cfg = try std.json.parseFromSliceLeaky(Value, a,
        \\{"scsi0":"local-zfs:vm-207-disk-0,discard=on,size=40G","scsi1":"tank:vm-207-disk-1,size=8G",
        \\ "ide2":"local-zfs:vm-207-cloudinit,media=cdrom","efidisk0":"local-zfs:vm-207-disk-2,size=4M",
        \\ "net0":"virtio=BC:24:11:00:00:01,bridge=vmbr0","sata0":"none"}
    , .{});
    const st = try diskStorages(a, cfg);
    try testing.expectEqual(@as(usize, 2), st.len);
    try testing.expectEqualStrings("local-zfs", st[0]);
    try testing.expectEqualStrings("tank", st[1]);
}
