//! `artoo vm disk grow` (SPEC §9.15): grow a VM disk on Proxmox, then the
//! guest's root filesystem on it, on the one pipeline. Proxmox cannot
//! shrink a disk, so the plan says the change is final.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const tasks = @import("../pve/task.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const storage = @import("storage.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

/// `+20G` grows by 20 GiB, `80G` grows to 80 GiB.
pub const Size = struct { grow: bool, bytes: u64 };

/// `+20G`, `80G`, `512M`, `1.5T`; no unit is GiB. Whole MiB, at most
/// 64 TiB.
pub fn parseSize(s: []const u8) ?Size {
    const by = s.len > 0 and s[0] == '+';
    const body = if (by) s[1..] else s;
    if (body.len == 0) return null;
    const last = std.ascii.toUpper(body[body.len - 1]);
    const mib_per: f64 = switch (last) {
        'M' => 1,
        'G' => 1024,
        'T' => 1024 * 1024,
        else => if (std.ascii.isDigit(last)) 1024 else return null,
    };
    const digits = if (std.ascii.isDigit(last)) body else body[0 .. body.len - 1];
    if (digits.len == 0) return null;
    for (digits) |ch| if (!std.ascii.isDigit(ch) and ch != '.') return null;
    const v = std.fmt.parseFloat(f64, digits) catch return null;
    const mib = @round(v * mib_per);
    if (!(mib >= 1) or mib > 64 * 1024 * 1024) return null;
    return .{ .grow = by, .bytes = @as(u64, @intFromFloat(mib)) << 20 };
}

/// Disk slots `PUT …/resize` takes (SPEC §17.2), CD-ROMs excluded later.
pub fn validSlot(s: []const u8) bool {
    const buses = [_]struct { []const u8, u8 }{ .{ "scsi", 30 }, .{ "virtio", 15 }, .{ "sata", 5 }, .{ "ide", 3 } };
    for (buses) |b| {
        const n = std.mem.cutPrefix(u8, s, b[0]) orelse continue;
        if (n.len == 0 or (n.len > 1 and n[0] == '0')) return false;
        const i = std.fmt.parseInt(u8, n, 10) catch return false;
        return i <= b[1];
    }
    return false;
}

/// The disk slots of a config (CD-ROMs left out), for error messages.
fn diskSlots(ctx: *Context, cfg: Value) ![]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (cfg == .object) {
        var it = cfg.object.iterator();
        while (it.next()) |e| {
            if (!validSlot(e.key_ptr.*) or e.value_ptr.* != .string) continue;
            if (std.mem.find(u8, e.value_ptr.string, "media=cdrom") != null) continue;
            try out.append(ctx.arena, e.key_ptr.*);
        }
    }
    std.mem.sort([]const u8, out.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);
    return if (out.items.len == 0) "none" else std.mem.join(ctx.arena, ", ", out.items);
}

/// Grows the partition and filesystem `/` lives on, inside the guest
/// (as root, through the agent), and prints `/`'s size before and after
/// in bytes. growpart exits 1 for "nothing to grow".
const grow_script =
    \\set -eu
    \\src=$(findmnt -nvo SOURCE /)
    \\case $src in /dev/sd*|/dev/vd*) ;; *) echo "/ is on $src, not a partition artoo grows" >&2; exit 3;; esac
    \\name=${src#/dev/}
    \\disk=$(lsblk -no PKNAME "$src" | tr -d ' ')
    \\part=$(cat "/sys/class/block/$name/partition")
    \\before=$(df -B1 --output=size / | tail -n 1 | tr -d ' ')
    \\echo 1 > "/sys/class/block/$disk/device/rescan" 2>/dev/null || true
    \\rc=0; out=$(growpart "/dev/$disk" "$part" 2>&1) || rc=$?
    \\[ "$rc" -le 1 ] || { echo "growpart: $out" >&2; exit 1; }
    \\case $(findmnt -nvo FSTYPE /) in
    \\ext4) out=$(resize2fs "$src" 2>&1) || { echo "resize2fs: $out" >&2; exit 1; } ;;
    \\xfs) out=$(xfs_growfs / 2>&1) || { echo "xfs_growfs: $out" >&2; exit 1; } ;;
    \\*) echo "/ is $(findmnt -nvo FSTYPE /), not ext4 or xfs" >&2; exit 3 ;;
    \\esac
    \\after=$(df -B1 --output=size / | tail -n 1 | tr -d ' ')
    \\echo "$before $after"
;

/// What happens to the guest's filesystem on the grown disk.
const Fs = enum {
    /// The root filesystem grows now, through the agent.
    live,
    /// The boot disk of a stopped VM, or one without an answering agent:
    /// cloud-init's growpart runs at the next boot.
    next_boot,
    /// Not the boot disk: the operator grows what is on it.
    manual,
};

const GrowOp = struct {
    c: *pve.Client,
    word: []const u8,
    slot: []const u8,
    size: Size,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: ?vms.Vm = null,
    digest: []const u8 = "",
    state: []const u8 = "",
    store: []const u8 = "",
    from: u64 = 0,
    to: u64 = 0,
    fs: Fs = .manual,
    /// `/` before and after, in bytes, when grown live.
    root: ?[2]u64 = null,
    ledger: exec.Ledger = .{},

    pub fn read(op: *GrowOp, ctx: *Context) !void {
        const v = try vms.resolve(op.c, op.word);
        op.vm = v;
        op.target = if (v.name.len > 0) try k.clean(ctx, v.name) else try std.fmt.allocPrint(ctx.arena, "{d}", .{v.vmid});
        if (v.template) return ctx.fail(error.Refused, "{s} is a template; grow the disk of a guest cloned from it ('artoo vm new --disk')", .{op.target});
        const cfg = try vms.config(op.c, v.vmid);
        op.digest = pve.str(cfg, "digest") orelse "";
        op.state = try std.fmt.allocPrint(ctx.arena, "{s}:{s}", .{ v.status, op.digest });
        const drive = pve.str(cfg, op.slot) orelse
            return ctx.fail(error.NotFound, "{s} has no disk {s} (disks: {s})", .{ op.target, op.slot, try diskSlots(ctx, cfg) });
        if (std.mem.find(u8, drive, "media=cdrom") != null) return ctx.fail(error.Refused, "{s} of {s} is a CD-ROM drive, not a disk", .{ op.slot, op.target });
        op.from = vms.driveSize(drive) orelse return ctx.fail(error.Protocol, "{s} of {s} has no size in its config", .{ op.slot, op.target });
        op.store = vms.driveStorage(drive) orelse "";
        op.to = if (op.size.grow) op.from + op.size.bytes else op.size.bytes;
        const boot = vms.bootDisk(cfg) orelse "";
        op.fs = if (!std.mem.eql(u8, boot, op.slot))
            .manual
        else if (v.running() and vms.agentEnabled(cfg))
            .live
        else
            .next_boot;
    }

    pub fn plan(op: *GrowOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const v = op.vm.?;
        if (op.to == op.from) return null;
        if (op.to < op.from) return ctx.fail(error.Refused, "Proxmox cannot shrink a disk: {s} of {s} is {s}, asked for {s}", .{ op.slot, op.target, try size(ctx, op.from), try size(ctx, op.to) });
        const more = op.to - op.from;
        const free: ?u64 = for (try storage.list(op.c)) |s| {
            if (std.mem.eql(u8, s.name, op.store)) break s.avail;
        } else null;
        if (free) |f| if (f < more)
            return ctx.fail(error.Refused, "{s} has {s} free; growing {s} by {s} needs more", .{ try k.clean(ctx, op.store), try size(ctx, f), op.slot, try size(ctx, more) });
        // The agent must answer now, else the filesystem waits for a boot.
        if (op.fs == .live and !try agent.ping(op.c, v.vmid)) op.fs = .next_boot;

        var impact: std.ArrayList([]const u8) = .empty;
        try impact.append(a, "Final: Proxmox cannot shrink a disk");
        try impact.append(a, try std.fmt.allocPrint(a, "Uses up to {s} more on {s}{s}", .{
            try size(ctx, more),
            try k.clean(ctx, op.store),
            if (free) |f| try std.fmt.allocPrint(a, " ({s} free)", .{try size(ctx, f)}) else "",
        }));
        var notes: std.ArrayList([]const u8) = .empty;
        try notes.append(a, switch (op.fs) {
            .live => "The root filesystem on it grows now, through the guest agent (growpart, then resize2fs or xfs_growfs).",
            .next_boot => if (v.running())
                "The guest agent does not answer: the root filesystem grows at the next boot (cloud-init growpart)."
            else
                "The VM is stopped: the root filesystem grows when it next boots (cloud-init growpart).",
            .manual => try std.fmt.allocPrint(a, "{s} is not the boot disk: grow its partition and filesystem in the guest.", .{op.slot}),
        });
        try notes.append(a, "Guarded by the config digest: a concurrent change makes Proxmox refuse the write.");
        return .{
            .action = try std.fmt.allocPrint(a, "Grow disk {s} of VM {s} ({d})", .{ op.slot, op.target, v.vmid }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{.{ .field = op.slot, .from = try size(ctx, op.from), .to = try size(ctx, op.to) }}),
            .impact = impact.items,
            .recovery = "none: a disk cannot be shrunk",
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *GrowOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *GrowOp, ctx: *Context) !void {
        const c = op.c;
        const a = ctx.arena;
        const id = op.vm.?.vmid;
        const l = &op.ledger;
        const s_disk = try l.add(a, try std.fmt.allocPrint(a, "grow disk {s}", .{op.slot}));
        const s_fs = if (op.fs == .live) try l.add(a, "grow root filesystem") else null;
        l.set(s_disk, .unknown, "");
        const data = try vms.resizeDisk(c, id, op.slot, try std.fmt.allocPrint(a, "{d}M", .{op.to >> 20}), op.digest);
        l.set(s_disk, .done, if (data == .null) "done" else try k.waitTask(c, try tasks.upidOf(c, data, "the resize"), 300));
        const i = s_fs orelse return;
        l.set(i, .unknown, "");
        const r = try agent.sh(c, id, grow_script, 120_000);
        const later = "grow it in the guest, or reboot (cloud-init growpart)";
        if (!r.ok()) {
            const why = try ui.text.sanitize(a, std.mem.trim(u8, r.err, " \t\r\n"), .line);
            l.set(i, .failed, why);
            return ctx.fail(error.Partial, "{s} is {s}, but the root filesystem did not grow: {s}; {s}", .{ op.slot, try size(ctx, op.to), why, later });
        }
        var it = std.mem.tokenizeAny(u8, r.out, " \t\r\n");
        const before = std.fmt.parseInt(u64, it.next() orelse "", 10) catch 0;
        const after = std.fmt.parseInt(u64, it.next() orelse "", 10) catch 0;
        if (after <= before) {
            l.set(i, .failed, "unchanged");
            return ctx.fail(error.Partial, "{s} is {s}, but the guest does not see the new space yet; {s}", .{ op.slot, try size(ctx, op.to), later });
        }
        op.root = .{ before, after };
        l.set(i, .done, try std.fmt.allocPrint(a, "/ {s} {s} {s}", .{ try size(ctx, before), ctx.ui.glyphs.arrow, try size(ctx, after) }));
    }

    pub fn verify(op: *GrowOp, ctx: *Context) !bool {
        const cfg = try vms.config(op.c, op.vm.?.vmid);
        const now = vms.driveSize(pve.str(cfg, op.slot) orelse "") orelse 0;
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        return now == op.to;
    }

    pub fn done(op: *GrowOp) []const u8 {
        const ctx = op.c.ctx;
        const disk = size(ctx, op.to) catch "?";
        return switch (op.fs) {
            .live => std.fmt.allocPrint(ctx.arena, "{s} of {s} is {s}; / is {s}", .{ op.slot, op.target, disk, size(ctx, op.root.?[1]) catch "?" }),
            .next_boot => std.fmt.allocPrint(ctx.arena, "{s} of {s} is {s}; the root filesystem grows at the next boot", .{ op.slot, op.target, disk }),
            .manual => std.fmt.allocPrint(ctx.arena, "{s} of {s} is {s}; grow its partition and filesystem in the guest", .{ op.slot, op.target, disk }),
        } catch "done";
    }
};

fn size(ctx: *Context, bytes: u64) ![]const u8 {
    return k.fmt(ctx, ui.values.bytes(bytes));
}

pub const grow = struct {
    pub const name = "grow";
    pub const summary = "Grow a VM disk and the guest's root filesystem on it";
    pub const details =
        \\SIZE is the growth (+20G) or the new size (80G): M, G or T, no unit is
        \\GiB. Proxmox cannot shrink a disk, so a smaller size is refused. On
        \\the boot disk of a running VM whose guest agent answers, the root
        \\filesystem grows at once (growpart, then resize2fs or xfs_growfs);
        \\otherwise at the next boot (cloud-init growpart). Another disk's
        \\partitions are the guest's to grow.
    ;
    pub const positionals = [_]cli.Positional{
        .{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name" },
        .{ .name = "SIZE", .help = "+GROWTH or NEW size (M, G, T; no unit = GiB)" },
    };
    pub const flags = [_]cli.Flag{.{ .long = "disk", .kind = .string, .metavar = "SLOT", .default = "scsi0", .help = "Disk slot (scsi0, virtio1, …)" }};
    pub const examples = [_][]const u8{ "artoo vm disk grow web-01 +20G", "artoo vm disk grow web-01 100G --disk scsi1" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const word = args.pos("SIZE");
        const sz = parseSize(word) orelse return ctx.fail(error.Usage, "SIZE must be +GROWTH or a new size like +20G, 80G or 512M (up to 64T), got '{s}'", .{word});
        const slot = args.string("disk") orelse "scsi0";
        if (!validSlot(slot)) return ctx.fail(error.Usage, "--disk must be a disk slot like scsi0, virtio1, sata0 or ide0, got '{s}'", .{slot});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: GrowOp = .{ .c = &c, .word = args.pos("VM"), .slot = slot, .size = sz };
        try exec.run(ctx, &op, .{});
    }
};

pub const group = cli.group("disk", "VM disks", &.{cli.leaf(grow)});

pub const commands = [_]cli.Command{group};

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "parseSize and validSlot" {
    try testing.expectEqual(Size{ .grow = true, .bytes = 20 << 30 }, parseSize("+20G").?);
    try testing.expectEqual(Size{ .grow = false, .bytes = 80 << 30 }, parseSize("80").?);
    try testing.expectEqual(Size{ .grow = false, .bytes = 512 << 20 }, parseSize("512m").?);
    try testing.expectEqual(Size{ .grow = true, .bytes = 1536 << 30 }, parseSize("+1.5T").?);
    for ([_][]const u8{ "", "+", "G", "-5G", "+0", "20X", "inf", "1e3G", "65T" }) |bad| try testing.expect(parseSize(bad) == null);
    try testing.expect(validSlot("scsi0") and validSlot("scsi30") and validSlot("virtio15") and validSlot("ide3"));
    for ([_][]const u8{ "scsi", "scsi31", "scsi01", "efidisk0", "net0", "ide4" }) |bad| try testing.expect(!validSlot(bad));
}

const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const vm_cmd = @import("vm.zig");
const root = cli.group("artoo", "t", &.{vm_cmd.group});

const disk_config =
    \\{"data":{"name":"web-01","boot":"order=scsi0;ide2;net0","agent":"1","scsi0":"local-zfs:vm-100-disk-0,discard=on,size=20G",
    \\ "scsi1":"local-zfs:vm-100-disk-1,size=8G","ide2":"local-zfs:vm-100-cloudinit,media=cdrom","digest":"abc123"}}
;
const disk_grown =
    \\{"data":{"name":"web-01","boot":"order=scsi0;ide2;net0","agent":"1","scsi0":"local-zfs:vm-100-disk-0,discard=on,size=40G","digest":"def"}}
;
const storage_body =
    \\{"data":[{"storage":"local-zfs","type":"zfspool","content":"images,rootdir","active":1,"enabled":1,"avail":107374182400,"total":214748364800,"used":21474836480}]}
;
const upid_body = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:resize:100:artoo@pve!cli:\"}";
const task_ok = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}";

test "vm disk grow: digest-guarded resize, task tracked, root filesystem grown live" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const exec_out = try std.json.Stringify.valueAlloc(arena.allocator(), .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = "20401094656 41875931136\n", .@"err-data" = "" } }, .{});
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = disk_config } },
        .{ .respond = .{ .body = storage_body } },
        .{ .respond = .{ .body = "{\"data\":{}}" } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = exec_out } },
        .{ .respond = .{ .body = disk_grown } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm disk grow web-01 +20G -y"));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/100/agent/ping HTTP/1.1", g.request(3));
    try testing.expectEqualStrings("PUT /api2/json/nodes/pve/qemu/100/resize HTTP/1.1", g.request(4));
    try testing.expectEqualStrings("disk=scsi0&size=40960M&digest=abc123", g.body(4));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/100/agent/exec HTTP/1.1", g.request(6));
    try testing.expect(std.mem.find(u8, g.body(6), "growpart") != null);
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Grow disk scsi0 of VM web-01 (100)\n",
        "Change    scsi0  20.0 GiB → 40.0 GiB\n",
        "Impact    Final: Proxmox cannot shrink a disk\n",
        "Uses up to 20.0 GiB more on local-zfs (100.0 GiB free)\n",
        "Recovery  none: a disk cannot be shrunk\n",
        "The root filesystem on it grows now, through the guest agent",
        "✓ grow root filesystem  done  / 19.0 GiB → 39.0 GiB",
        "✓ scsi0 of web-01 is 40.0 GiB; / is 39.0 GiB\n",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "vm disk grow: refusals before any write" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = disk_config } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = disk_config } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = disk_config } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = disk_config } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = disk_config } },
        .{ .respond = .{ .body = storage_body } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm disk grow web-01 -5G"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm disk grow web-01 +5G --disk efidisk0"));
    // Smaller, equal, missing slot, CD-ROM, not enough space, template.
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm disk grow web-01 10G -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "Proxmox cannot shrink a disk: scsi0 of web-01 is 20.0 GiB, asked for 10.0 GiB") != null);
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm disk grow web-01 20G -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "nothing to change") != null);
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm disk grow web-01 +5G --disk scsi2 -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "web-01 has no disk scsi2 (disks: scsi0, scsi1)") != null);
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm disk grow web-01 +5G --disk ide2 -y"));
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm disk grow web-01 +200G -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "local-zfs has 100.0 GiB free") != null);
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm disk grow ubuntu-2604 +5G -y"));
    for (0..g.sent()) |i| try testing.expect(std.mem.find(u8, g.request(i), "resize") == null);
}

test "vm disk grow: not the boot disk — no guest step" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = disk_config } },
        .{ .respond = .{ .body = storage_body } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":{\"scsi1\":\"local-zfs:vm-100-disk-1,size=16G\"}}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm disk grow web-01 16G --disk scsi1 -y"));
    try testing.expectEqualStrings("disk=scsi1&size=16384M&digest=abc123", g.body(3));
    try testing.expect(std.mem.find(u8, g.h.stdout(), "scsi1 is not the boot disk: grow its partition and filesystem in the guest.") != null);
    try testing.expect(std.mem.endsWith(u8, g.h.stdout(), "✓ scsi1 of web-01 is 16.0 GiB; grow its partition and filesystem in the guest\n"));
}

test "vm disk grow: the guest does not see the space — partial, with the next step" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const same = try std.json.Stringify.valueAlloc(arena.allocator(), .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = "20401094656 20401094656\n", .@"err-data" = "" } }, .{});
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = disk_config } },
        .{ .respond = .{ .body = storage_body } },
        .{ .respond = .{ .body = "{\"data\":{}}" } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = same } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm disk grow web-01 +20G -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "scsi0 is 40.0 GiB, but the guest does not see the new space yet; grow it in the guest, or reboot (cloud-init growpart)") != null);
}
