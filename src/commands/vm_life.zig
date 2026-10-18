//! VM mutations (SPEC §3.3, §8.2): power actions, `set`, `clone`, `rm`
//! and snapshots — all on the one pipeline: read → plan (no-ops refused)
//! → confirm (typed target for destructive ones) → send once → track the
//! returned task → verify with a fresh read.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const tasks = @import("../pve/task.zig");
const vms = @import("../pve/vm.zig");
const unifi = @import("../unifi/client.zig");
const dns = @import("../unifi/dns.zig");
const classic = @import("../unifi/classic.zig");
const k = @import("node.zig");
const known_hosts = @import("../guest/known_hosts.zig");
const ssh_config = @import("../guest/ssh_config.zig");
const vm_ssh = @import("vm_ssh.zig");
const svc = @import("svc.zig");

const watch = @import("watch.zig");

const Context = app.Context;
const Value = std.json.Value;

const vm_arg: cli.Positional = .{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name" };
const confirm_flag: cli.Flag = .{ .long = "confirm", .kind = .string, .metavar = "TARGET", .help = "Non-interactive confirmation (with --yes)" };

fn vmLabel(ctx: *Context, v: vms.Vm) ![]const u8 {
    return if (v.name.len > 0) k.clean(ctx, v.name) else std.fmt.allocPrint(ctx.arena, "{d}", .{v.vmid});
}

const nodeTarget = k.nodeTarget;
const waitTask = k.waitTask;

// ---------------------------------------------------------------- power

const Power = enum {
    start,
    shutdown,
    reboot,
    stop,

    fn expected(p: Power) []const u8 {
        return switch (p) {
            .start, .reboot => "running",
            .shutdown, .stop => "stopped",
        };
    }

    /// Task deadline (s). Shutdown asks PVE to give up after 180 s itself.
    fn deadline(p: Power) u64 {
        return switch (p) {
            .start, .stop => 120,
            .shutdown, .reboot => 240,
        };
    }
};

const PowerOp = struct {
    c: *pve.Client,
    action: Power,
    word: []const u8,
    risk: ui.blocks.Risk,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: ?vms.Vm = null,
    state: []const u8 = "",
    upid: []const u8 = "",
    result: []const u8 = "",

    pub fn read(op: *PowerOp, ctx: *Context) !void {
        const v = try vms.resolve(op.c, op.word);
        op.vm = v;
        op.target = try vmLabel(ctx, v);
        op.state = try std.fmt.allocPrint(ctx.arena, "{s}:{s}", .{ v.status, v.lock orelse "" });
    }

    pub fn plan(op: *PowerOp, ctx: *Context) !?exec.Plan {
        const v = op.vm.?;
        if (v.template) return ctx.fail(error.Refused, "{s} is a template; templates are not started or stopped", .{op.target});
        const running = v.running();
        switch (op.action) {
            .start => if (running) return null,
            .shutdown, .stop => if (std.mem.eql(u8, v.status, "stopped")) return null,
            .reboot => if (!running) return ctx.fail(error.Refused, "{s} is {s}; use 'artoo vm start {s}'", .{ op.target, v.status, op.target }),
        }
        const a = ctx.arena;
        const impact: []const u8 = switch (op.action) {
            .start => "The VM boots",
            .shutdown => "The guest OS is asked to shut down cleanly (ACPI); Proxmox gives up after 180 s",
            .reboot => "The guest restarts; its services are briefly unavailable",
            .stop => "Power is cut immediately: unsaved guest data can be lost",
        };
        return .{
            .action = try std.fmt.allocPrint(a, "{s} VM {s} ({d})", .{ switch (op.action) {
                .start => "Start",
                .shutdown => "Shut down",
                .reboot => "Reboot",
                .stop => "Force-stop",
            }, op.target, v.vmid }),
            .risk = op.risk,
            .target = try nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{.{ .field = "status", .from = try k.clean(ctx, v.status), .to = op.action.expected() }}),
            .impact = try a.dupe([]const u8, &.{impact}),
            .recovery = switch (op.action) {
                .start => try std.fmt.allocPrint(a, "artoo vm shutdown {s}", .{op.target}),
                .shutdown, .stop => try std.fmt.allocPrint(a, "artoo vm start {s}", .{op.target}),
                .reboot => null,
            },
        };
    }

    pub fn fingerprint(op: *PowerOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *PowerOp, ctx: *Context) !void {
        const c = op.c;
        const params: []const pve.Param = if (op.action == .shutdown) &.{.{ .name = "timeout", .value = "180" }} else &.{};
        const path = try c.nodePath("/qemu/{d}/status/{s}", .{ op.vm.?.vmid, @tagName(op.action) });
        op.upid = try tasks.upidOf(c, try c.send(.POST, path, params), try std.fmt.allocPrint(ctx.arena, "{s} of {s}", .{ @tagName(op.action), op.target }));
    }

    pub fn track(op: *PowerOp, _: *Context) !void {
        op.result = try waitTask(op.c, op.upid, op.action.deadline());
    }

    pub fn verify(op: *PowerOp, ctx: *Context) !bool {
        // `qmreboot` ends once the guest has shut down; Proxmox starts it
        // again right after (live 2026-10-10), so a reboot is given a
        // short grace period to show `running`.
        const tries: usize = if (op.action == .reboot) 30 else 1;
        for (0..tries) |i| {
            if (i > 0) try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 1000)), .awake);
            const st = try vms.status(op.c, op.vm.?.vmid);
            if (std.mem.eql(u8, pve.str(st, "status") orelse "", op.action.expected())) return true;
        }
        return false;
    }

    pub fn done(op: *PowerOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} is {s} ({s})", .{ op.target, op.action.expected(), op.result }) catch "done";
    }
};

fn PowerCmd(comptime action: Power) type {
    const destructive = action == .stop;
    return struct {
        pub const name = @tagName(action);
        pub const summary = switch (action) {
            .start => "Start a VM",
            .shutdown => "Shut a VM down cleanly (ACPI)",
            .reboot => "Reboot a running VM",
            .stop => "Force-stop a VM (power cut; destructive confirmation)",
        };
        pub const positionals = [_]cli.Positional{vm_arg};
        pub const flags = if (destructive) [_]cli.Flag{confirm_flag} else [_]cli.Flag{};
        pub const examples = [_][]const u8{"artoo vm " ++ @tagName(action) ++ " web-01" ++ (if (destructive) " --yes --confirm web-01" else "")};

        pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
            var c = try pve.Client.open(ctx);
            defer c.deinit();
            var op: PowerOp = .{ .c = &c, .action = action, .word = args.pos("VM"), .risk = if (destructive) .destructive else .normal };
            const confirm: ?[]const u8 = if (comptime destructive) args.string("confirm") else null;
            try exec.run(ctx, &op, .{ .confirm = confirm });
        }
    };
}

// ---------------------------------------------------------------- set

/// Config keys `vm set` accepts (SPEC §3.3: allowlisted).
const Key = enum {
    name,
    description,
    tags,
    cores,
    sockets,
    memory,
    balloon,
    onboot,

    fn hot(key: Key) bool {
        return switch (key) {
            .cores, .sockets, .memory, .balloon => true,
            else => false,
        };
    }
};

const Assignment = struct { key: Key, value: []const u8 };

/// Validate and normalize `KEY=VALUE` (sizes to MiB, booleans to 0/1).
fn parseAssignment(ctx: *Context, word: []const u8) !Assignment {
    const eq = std.mem.findScalar(u8, word, '=') orelse return ctx.fail(error.Usage, "expected KEY=VALUE, got '{s}'", .{word});
    const key = std.meta.stringToEnum(Key, word[0..eq]) orelse
        return ctx.fail(error.Usage, "'{s}' cannot be set here (allowed: name, description, tags, cores, sockets, memory, balloon, onboot)", .{word[0..eq]});
    const raw = word[eq + 1 ..];
    const a = ctx.arena;
    const value: []const u8 = switch (key) {
        .name => blk: {
            if (raw.len == 0 or raw.len > 63 or !validLabel(raw)) return ctx.fail(error.Usage, "name must be a DNS label (letters, digits, '-'), got '{s}'", .{raw});
            break :blk raw;
        },
        .description => blk: {
            if (raw.len > 8192) return ctx.fail(error.Usage, "description is longer than 8192 bytes", .{});
            break :blk raw;
        },
        .tags => blk: {
            var out: std.ArrayList(u8) = .empty;
            var it = std.mem.tokenizeAny(u8, raw, ",; ");
            while (it.next()) |t| {
                for (t) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.')
                    return ctx.fail(error.Usage, "tag '{s}' may only use letters, digits, '-', '_' and '.'", .{t});
                if (out.items.len > 0) try out.append(a, ';');
                try out.appendSlice(a, t);
            }
            break :blk out.items;
        },
        .cores, .sockets => blk: {
            const n = std.fmt.parseInt(u32, raw, 10) catch return ctx.fail(error.Usage, "{t} must be a whole number, got '{s}'", .{ key, raw });
            const max: u32 = if (key == .cores) 128 else 4;
            if (n < 1 or n > max) return ctx.fail(error.Usage, "{t} must be 1-{d}, got {d}", .{ key, max, n });
            break :blk raw;
        },
        .memory, .balloon => blk: {
            const mib = parseMiB(raw) orelse return ctx.fail(error.Usage, "{t} must be a size like 2048, 2G or 512M (MiB without a unit), got '{s}'", .{ key, raw });
            if (key == .memory and mib < 16) return ctx.fail(error.Usage, "memory must be at least 16 MiB", .{});
            break :blk try std.fmt.allocPrint(a, "{d}", .{mib});
        },
        .onboot => blk: {
            if (std.mem.eql(u8, raw, "1") or std.ascii.eqlIgnoreCase(raw, "yes") or std.ascii.eqlIgnoreCase(raw, "true")) break :blk "1";
            if (std.mem.eql(u8, raw, "0") or std.ascii.eqlIgnoreCase(raw, "no") or std.ascii.eqlIgnoreCase(raw, "false")) break :blk "0";
            return ctx.fail(error.Usage, "onboot must be yes or no, got '{s}'", .{raw});
        },
    };
    return .{ .key = key, .value = value };
}

pub fn validLabel(s: []const u8) bool {
    if (s[0] == '-' or s[s.len - 1] == '-') return false;
    for (s) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '-') return false;
    return true;
}

/// `2048` (MiB), `512M`, `2G`, `1.5G`.
pub fn parseMiB(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    const last = std.ascii.toUpper(s[s.len - 1]);
    const scale: f64 = switch (last) {
        'G' => 1024,
        'M' => 1,
        else => if (std.ascii.isDigit(last)) 1 else return null,
    };
    const digits = if (std.ascii.isDigit(last)) s else s[0 .. s.len - 1];
    const v = std.fmt.parseFloat(f64, digits) catch return null;
    if (!(v > 0) or v * scale > 4 * 1024 * 1024) return null;
    return @intFromFloat(@round(v * scale));
}

const SetOp = struct {
    c: *pve.Client,
    word: []const u8,
    wanted: []const Assignment,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: ?vms.Vm = null,
    config: Value = .null,
    digest: []const u8 = "",
    changes: []const Assignment = &.{},

    pub fn read(op: *SetOp, ctx: *Context) !void {
        op.vm = try vms.resolve(op.c, op.word);
        op.target = try vmLabel(ctx, op.vm.?);
        op.config = try vms.config(op.c, op.vm.?.vmid);
        op.digest = pve.str(op.config, "digest") orelse "";
    }

    fn current(op: *SetOp, ctx: *Context, key: Key) !?[]const u8 {
        if (op.config != .object) return null;
        const v = op.config.object.get(@tagName(key)) orelse return null;
        return switch (v) {
            .string => |s| s,
            .integer => |n| try std.fmt.allocPrint(ctx.arena, "{d}", .{n}),
            else => null,
        };
    }

    pub fn plan(op: *SetOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        var real: std.ArrayList(Assignment) = .empty;
        var hot = false;
        for (op.wanted) |w| {
            const cur = try op.current(ctx, w.key);
            if (cur != null and std.mem.eql(u8, cur.?, w.value)) continue;
            try real.append(a, w);
            hot = hot or w.key.hot();
            try changes.append(a, .{ .field = @tagName(w.key), .from = if (cur) |x| try k.clean(ctx, x) else null, .to = try k.clean(ctx, w.value) });
        }
        if (real.items.len == 0) return null;
        op.changes = real.items;
        var notes: std.ArrayList([]const u8) = .empty;
        if (hot and op.vm.?.running()) try notes.append(a, "The VM is running: CPU/memory changes may stay pending until it restarts ('artoo vm config' shows them).");
        try notes.append(a, "Guarded by the config digest: a concurrent change makes Proxmox refuse the write.");
        return .{
            .action = try std.fmt.allocPrint(a, "Configure VM {s} ({d})", .{ op.target, op.vm.?.vmid }),
            .target = try nodeTarget(ctx, op.c),
            .changes = changes.items,
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *SetOp) []const u8 {
        return op.digest;
    }

    pub fn send(op: *SetOp, ctx: *Context) !void {
        var params: std.ArrayList(pve.Param) = .empty;
        for (op.changes) |w| try params.append(ctx.arena, .{ .name = @tagName(w.key), .value = w.value });
        try params.append(ctx.arena, .{ .name = "digest", .value = op.digest });
        _ = try op.c.send(.PUT, try op.c.nodePath("/qemu/{d}/config", .{op.vm.?.vmid}), params.items);
    }

    pub fn verify(op: *SetOp, ctx: *Context) !bool {
        op.config = try vms.config(op.c, op.vm.?.vmid);
        for (op.changes) |w| {
            const cur = try op.current(ctx, w.key) orelse return false;
            if (!std.mem.eql(u8, cur, w.value)) return false;
        }
        return true;
    }

    pub fn done(_: *SetOp) []const u8 {
        return "configuration applied and verified";
    }
};

pub const set = struct {
    pub const name = "set";
    pub const summary = "Change allowlisted config keys (digest-guarded)";
    pub const details =
        \\Keys: name, description, tags (comma list), cores, sockets, memory and
        \\balloon (MiB, or 512M/2G), onboot (yes/no). Unchanged keys are left out;
        \\nothing to change exits 5.
    ;
    pub const positionals = [_]cli.Positional{ vm_arg, .{ .name = "KEY=VALUE", .help = "One or more assignments", .variadic = true, .choices = &.{
        .{ .text = "name=", .help = "Rename (a DNS label)" },
        .{ .text = "description=", .help = "Notes shown in Proxmox" },
        .{ .text = "tags=", .help = "Comma list; replaces all tags (keep artoo, role-ROLE)" },
        .{ .text = "cores=", .help = "vCPU cores per socket (1-128)" },
        .{ .text = "sockets=", .help = "CPU sockets (1-4)" },
        .{ .text = "memory=", .help = "RAM in MiB, or 512M/2G" },
        .{ .text = "balloon=", .help = "Minimum RAM in MiB, or 512M/2G" },
        .{ .text = "onboot=", .help = "Start with the host (yes/no)", .values = &.{ "yes", "no" } },
    } } };
    pub const examples = [_][]const u8{ "artoo vm set web-01 memory=4G cores=2", "artoo vm set 100 tags=artoo,web onboot=yes" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const words = args.rest("KEY=VALUE");
        if (words.len == 0) return ctx.fail(error.Usage, "give at least one KEY=VALUE", .{});
        var wanted: std.ArrayList(Assignment) = .empty;
        for (words) |w| {
            const asg = try parseAssignment(ctx, w);
            for (wanted.items) |x| if (x.key == asg.key) return ctx.fail(error.Usage, "{t} is given twice", .{asg.key});
            try wanted.append(ctx.arena, asg);
        }
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SetOp = .{ .c = &c, .word = args.pos("VM"), .wanted = wanted.items };
        try exec.run(ctx, &op, .{});
        try refreshSshBlock(ctx, &op);
    }
};

/// `ssh-jump` is a tag: a guest whose tags changed gets its block in
/// `~/.artoo/ssh_config` rewritten (SPEC §9.10), when the file has one.
fn refreshSshBlock(ctx: *Context, op: *const SetOp) !void {
    if (ctx.globals.dry_run or ctx.globals.no_wait) return;
    const v = op.vm orelse return;
    for (op.changes) |w| {
        if (w.key != .tags) continue;
        if (!try vm_ssh.present(ctx) or !try vm_ssh.hasBlock(ctx, v.name)) return;
        const block = vm_ssh.blockOf(v.name, op.config) orelse return;
        vm_ssh.put(ctx, v.name, block) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => return ctx.fail(error.Partial, "tags changed, but {s} was not updated: {s}; run 'artoo vm ssh-config'", .{ ssh_config.default_path, ctx.diag orelse @errorName(err) }),
        };
        try ctx.err.print("artoo: updated Host {s} in {s}\n", .{ v.name, ssh_config.default_path });
        return;
    }
}

// ---------------------------------------------------------------- clone

const CloneOp = struct {
    c: *pve.Client,
    word: []const u8,
    new_name: []const u8,
    want_id: ?u32,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    src: ?vms.Vm = null,
    new_id: u32 = 0,
    state: []const u8 = "",
    upid: []const u8 = "",
    result: []const u8 = "",

    pub fn read(op: *CloneOp, ctx: *Context) !void {
        const c = op.c;
        const all = try vms.list(c);
        op.src = switch (try vms.find(all, ctx.arena, op.word)) {
            .vm => |v| v,
            else => try vms.resolve(c, op.word),
        };
        for (all) |v| if (std.ascii.eqlIgnoreCase(v.name, op.new_name))
            return ctx.fail(error.Refused, "a VM named '{s}' already exists ({d})", .{ op.new_name, v.vmid });
        if (op.want_id) |id| {
            for (pve.items(try c.get("/cluster/resources?type=vm"))) |v| if (pve.uint(v, "vmid") == id)
                return ctx.fail(error.Refused, "VMID {d} is taken", .{id});
            op.new_id = id;
        } else op.new_id = try vms.freeVmid(c, 200);
        op.target = op.new_name;
        op.state = try std.fmt.allocPrint(ctx.arena, "{d}:{d}", .{ op.src.?.vmid, op.new_id });
    }

    pub fn plan(op: *CloneOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const s = op.src.?;
        return .{
            .action = try std.fmt.allocPrint(a, "Clone {s} ({d}) to {s} ({d})", .{ try vmLabel(ctx, s), s.vmid, op.new_name, op.new_id }),
            .target = try nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{
                .{ .field = "VM", .from = null, .to = try std.fmt.allocPrint(a, "{d} {s}", .{ op.new_id, op.new_name }) },
                .{ .field = "disks", .from = null, .to = try std.fmt.allocPrint(a, "full copy ({f})", .{ui.values.bytes(s.maxdisk)}) },
            }),
            .impact = try a.dupe([]const u8, &.{"Copies the source disks on Proxmox's storage; large disks take minutes"}),
            .recovery = try std.fmt.allocPrint(a, "artoo vm rm {s}", .{op.new_name}),
        };
    }

    pub fn fingerprint(op: *CloneOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *CloneOp, ctx: *Context) !void {
        const c = op.c;
        const params = [_]pve.Param{
            .{ .name = "newid", .value = try std.fmt.allocPrint(ctx.arena, "{d}", .{op.new_id}) },
            .{ .name = "name", .value = op.new_name },
            .{ .name = "full", .value = "1" },
        };
        op.upid = try tasks.upidOf(c, try c.send(.POST, try c.nodePath("/qemu/{d}/clone", .{op.src.?.vmid}), &params), "the clone");
    }

    pub fn track(op: *CloneOp, _: *Context) !void {
        op.result = try waitTask(op.c, op.upid, 1800);
    }

    pub fn verify(op: *CloneOp, ctx: *Context) !bool {
        return switch (try vms.find(try vms.list(op.c), ctx.arena, try std.fmt.allocPrint(ctx.arena, "{d}", .{op.new_id}))) {
            .vm => |v| std.mem.eql(u8, v.name, op.new_name),
            else => false,
        };
    }

    pub fn done(op: *CloneOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} ({d}) created ({s})", .{ op.new_name, op.new_id, op.result }) catch "done";
    }
};

pub const clone = struct {
    pub const name = "clone";
    pub const summary = "Full clone of a VM or template";
    pub const positionals = [_]cli.Positional{ vm_arg, .{ .name = "NEWNAME", .help = "Name of the new VM" } };
    pub const flags = [_]cli.Flag{.{ .long = "id", .kind = .int, .metavar = "VMID", .help = "VMID for the clone (default: lowest free ≥ 200)" }};
    pub const examples = [_][]const u8{ "artoo vm clone ubuntu-2604 web-01", "artoo vm clone 9000 web-02 --id 210" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const new_name = args.pos("NEWNAME");
        if (new_name.len > 63 or !validLabel(new_name)) return ctx.fail(error.Usage, "NEWNAME must be a DNS label (letters, digits, '-'), got '{s}'", .{new_name});
        const want: ?u32 = if (args.int("id")) |id| blk: {
            if (id < 100 or id > 999_999_999) return ctx.fail(error.Usage, "--id must be 100-999999999, got {d}", .{id});
            break :blk @intCast(id);
        } else null;
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: CloneOp = .{ .c = &c, .word = args.pos("VM"), .new_name = new_name, .want_id = want };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- rm

/// `ip=192.168.1.200/24,gw=…` → `192.168.1.200`.
pub fn staticAddress(cfg: Value) ?[]const u8 {
    const ipc = pve.str(cfg, "ipconfig0") orelse return null;
    var it = std.mem.tokenizeScalar(u8, ipc, ',');
    while (it.next()) |part| {
        const v = std.mem.cutPrefix(u8, part, "ip=") orelse continue;
        return v[0 .. std.mem.findScalar(u8, v, '/') orelse v.len];
    }
    return null;
}

const RmOp = struct {
    c: *pve.Client,
    word: []const u8,
    keep_dns: bool,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: ?vms.Vm = null,
    config: Value = .null,
    state: []const u8 = "",
    /// DNS record to remove (matched by name and address), or why not.
    record: ?dns.ARecord = null,
    dns_note: ?[]const u8 = null,
    /// UniFi client record to forget (the VM's MAC and name), or why not.
    client: ?classic.Record = null,
    client_note: ?[]const u8 = null,
    /// Why service routes could not be checked.
    svc_note: ?[]const u8 = null,
    secret: bool = false,
    host_key: bool = false,
    /// Its block in `~/.artoo/ssh_config` (SPEC §9.10).
    ssh_block: bool = false,
    /// The watchdog holding this VM's metrics (SPEC §9.9), or why not.
    watch_vm: ?vms.Vm = null,
    watch_series: usize = 0,
    watch_note: ?[]const u8 = null,
    ledger: exec.Ledger = .{},

    pub fn read(op: *RmOp, ctx: *Context) !void {
        const v = try vms.resolve(op.c, op.word);
        op.vm = v;
        op.target = try vmLabel(ctx, v);
        op.config = try vms.config(op.c, v.vmid);
        op.state = try std.fmt.allocPrint(ctx.arena, "{s}:{s}", .{ v.status, pve.str(op.config, "digest") orelse "" });
        if (v.template) return ctx.fail(error.Refused, "{s} is a template; use 'artoo template rm'", .{op.target});
        if (v.name.len > 0) {
            const used = try svc.pointingAt(ctx, op.c, v.name);
            if (used.names.len > 0) return ctx.fail(error.Refused, "service(s) {s} point at {s}; move them ('artoo svc set NAME VM:PORT') or remove them ('artoo svc rm NAME') first", .{ try std.mem.join(ctx.arena, ", ", used.names), op.target });
            op.svc_note = used.note;
        }
        try op.readUnifi(ctx);
        const store = try ctx.secretStore();
        if (v.name.len > 0) op.secret = store.exists(ctx.io, ctx.arena, try std.fmt.allocPrint(ctx.arena, "guest/{s}", .{v.name})) catch false;
        if (v.name.len > 0) {
            const kh = std.Io.Dir.cwd().readFileAlloc(ctx.io, try known_hosts.path(ctx), ctx.arena, .limited(1 << 20)) catch "";
            op.host_key = !std.mem.eql(u8, try known_hosts.update(ctx.arena, kh, v.name, null), kh);
            op.ssh_block = try vm_ssh.present(ctx) and try vm_ssh.hasBlock(ctx, v.name);
        }
        if (v.name.len > 0) try op.readWatch(ctx);
    }

    /// Its metrics on the watchdog: forgotten after the destroy, so alerts
    /// about a VM that no longer exists resolve instead of firing for a day.
    fn readWatch(op: *RmOp, ctx: *Context) !void {
        const v = op.vm.?;
        const w = (watch.findWatchVm(op.c) catch null) orelse return;
        if (w.vmid == v.vmid) return;
        const later = try std.fmt.allocPrint(ctx.arena, "'artoo watch forget {s}' afterwards", .{v.name});
        if (!w.running()) {
            op.watch_note = try std.fmt.allocPrint(ctx.arena, "Watchdog {s} is {s}: its metrics of {s} stay; {s}", .{ w.name, w.status, v.name, later });
            return;
        }
        op.watch_series = watch.hostSeries(op.c, w, v.name) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => {
                op.watch_note = try std.fmt.allocPrint(ctx.arena, "Watchdog not checked: {s}; {s}", .{ ctx.diag orelse @errorName(err), later });
                ctx.diag = null;
                return;
            },
        };
        if (op.watch_series > 0) op.watch_vm = w;
    }

    fn readUnifi(op: *RmOp, ctx: *Context) !void {
        const v = op.vm.?;
        if (v.name.len == 0) return;
        var u = unifi.Client.open(ctx) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => {
                op.dns_note = try std.fmt.allocPrint(ctx.arena, "UniFi not checked: {s}", .{ctx.diag orelse @errorName(err)});
                ctx.diag = null;
                return;
            },
        };
        defer u.deinit();
        try op.readClient(ctx, &u);
        try op.readDns(ctx, &u);
    }

    /// Only the record for this VM's MAC that carries the VM's name.
    fn readClient(op: *RmOp, ctx: *Context, u: *unifi.Client) !void {
        const v = op.vm.?;
        const mac = try classic.netMac(ctx.arena, pve.str(op.config, "net0") orelse "") orelse return;
        const records = classic.records(u) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => {
                op.client_note = try std.fmt.allocPrint(ctx.arena, "Client record not checked: {s}", .{ctx.diag orelse @errorName(err)});
                ctx.diag = null;
                return;
            },
        };
        const r = classic.find(records, mac) orelse return;
        if (std.mem.eql(u8, r.name, v.name)) {
            op.client = r;
        } else {
            op.client_note = try std.fmt.allocPrint(ctx.arena, "Client record {s} kept: it is named '{s}', not {s}", .{ mac, try k.clean(ctx, r.name), v.name });
        }
    }

    fn readDns(op: *RmOp, ctx: *Context, u: *unifi.Client) !void {
        if (op.keep_dns) return;
        const v = op.vm.?;
        const cfg = try ctx.config();
        const fqdn = dns.fqdn(ctx.arena, v.name, cfg.guests.domain) catch return;
        const records = dns.list(u) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => {
                op.dns_note = try std.fmt.allocPrint(ctx.arena, "DNS not checked: {s}", .{ctx.diag orelse @errorName(err)});
                ctx.diag = null;
                return;
            },
        };
        const r = dns.find(records, fqdn) orelse return;
        const addr = staticAddress(op.config);
        if (addr != null and std.mem.eql(u8, addr.?, r.ipv4)) {
            op.record = r;
        } else {
            op.dns_note = try std.fmt.allocPrint(ctx.arena, "{s} → {s} kept: it does not match this VM's address ({s})", .{ fqdn, r.ipv4, addr orelse "none configured" });
        }
    }

    pub fn plan(op: *RmOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const v = op.vm.?;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (v.running()) try changes.append(a, .{ .field = "status", .from = "running", .to = "stopped (forced)" });
        try changes.append(a, .{ .field = "VM", .from = try std.fmt.allocPrint(a, "{d} {s}", .{ v.vmid, op.target }), .to = null });
        try changes.append(a, .{ .field = "disks", .from = try std.fmt.allocPrint(a, "all ({f})", .{ui.values.bytes(v.maxdisk)}), .to = null });
        if (op.client) |r| try changes.append(a, .{ .field = "client record", .from = try std.fmt.allocPrint(a, "{s} ({s}), Fixed IP {s} on UniFi", .{ try k.clean(ctx, r.name), r.mac, r.fixed_ip orelse "off" }), .to = null });
        if (op.record) |r| try changes.append(a, .{ .field = "DNS record", .from = try std.fmt.allocPrint(a, "{s} {s} {s}", .{ try k.clean(ctx, r.domain), ctx.ui.glyphs.arrow, r.ipv4 }), .to = null });
        if (op.secret) try changes.append(a, .{ .field = "Keychain", .from = try std.fmt.allocPrint(a, "guest/{s} password", .{op.target}), .to = null });
        if (op.host_key) try changes.append(a, .{ .field = "host key", .from = try std.fmt.allocPrint(a, "{s} entry {s}", .{ known_hosts.default_path, op.target }), .to = null });
        if (op.ssh_block) try changes.append(a, .{ .field = "ssh config", .from = try std.fmt.allocPrint(a, "Host {s} in {s}", .{ op.target, ssh_config.default_path }), .to = null });
        if (op.watch_vm) |w| try changes.append(a, .{ .field = "metrics", .from = try std.fmt.allocPrint(a, "{d} series with host={s} on {s}", .{ op.watch_series, op.target, w.name }), .to = null });
        var notes: std.ArrayList([]const u8) = .empty;
        if (op.client_note) |n| try notes.append(a, n);
        if (op.dns_note) |n| try notes.append(a, n);
        if (op.svc_note) |n| try notes.append(a, n);
        if (op.watch_note) |n| try notes.append(a, n);
        if (op.keep_dns) try notes.append(a, "--keep-dns: DNS records are left alone.");
        try notes.append(a, "Steps run in order and stop at the first failure; nothing is undone automatically.");
        return .{
            .action = try std.fmt.allocPrint(a, "Destroy VM {s} ({d})", .{ op.target, v.vmid }),
            .risk = .destructive,
            .target = try nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{"The VM and its disks are gone for good (snapshots included)"}),
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *RmOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *RmOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        const v = op.vm.?;
        const l = &op.ledger;
        const stop = if (v.running()) try l.add(a, "stop VM") else null;
        const destroy = try l.add(a, "destroy VM and disks");
        const client_step = if (op.client != null) try l.add(a, "forget client record") else null;
        const dns_step = if (op.record != null) try l.add(a, "remove DNS record") else null;
        const key_step = if (op.secret) try l.add(a, "delete Keychain password") else null;
        const host_step = if (op.host_key) try l.add(a, "forget SSH host key") else null;
        const ssh_step = if (op.ssh_block) try l.add(a, "remove from ssh config") else null;
        const watch_step = if (op.watch_vm != null) try l.add(a, "forget in watch") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (stop) |i| {
            const upid = try tasks.upidOf(c, try c.send(.POST, try c.nodePath("/qemu/{d}/status/stop", .{v.vmid}), &.{}), "the stop");
            l.set(i, .unknown, "");
            l.set(i, .done, try waitTask(c, upid, 120));
        }
        l.set(destroy, .unknown, "");
        const path = try c.nodePath("/qemu/{d}?purge=1&destroy-unreferenced-disks=1", .{v.vmid});
        const upid = try tasks.upidOf(c, try c.send(.DELETE, path, &.{}), "the destroy");
        l.set(destroy, .done, try waitTask(c, upid, 600));
        if (client_step) |i| {
            var u = try unifi.Client.open(ctx);
            defer u.deinit();
            l.set(i, .unknown, "");
            try classic.forget(&u, op.client.?.mac);
            l.set(i, .done, op.client.?.mac);
        }
        if (dns_step) |i| {
            var u = try unifi.Client.open(ctx);
            defer u.deinit();
            l.set(i, .unknown, "");
            try dns.delete(&u, op.record.?.id);
            l.set(i, .done, try k.clean(ctx, op.record.?.domain));
        }
        if (key_step) |i| {
            const store = try ctx.secretStore();
            _ = store.delete(ctx.io, a, try std.fmt.allocPrint(a, "guest/{s}", .{v.name})) catch |err| {
                l.set(i, .failed, @errorName(err));
                return ctx.fail(error.Partial, "VM destroyed, but the Keychain entry guest/{s} could not be deleted", .{v.name});
            };
            l.set(i, .done, "");
        }
        if (host_step) |i| {
            known_hosts.record(ctx, v.name, null) catch |err| {
                l.set(i, .failed, @errorName(err));
                return ctx.fail(error.Partial, "VM destroyed, but its host key stays in {s}", .{known_hosts.default_path});
            };
            l.set(i, .done, "");
        }
        if (ssh_step) |i| {
            vm_ssh.put(ctx, v.name, null) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    l.set(i, .failed, ctx.diag orelse @errorName(err));
                    return ctx.fail(error.Partial, "VM destroyed, but its block stays in {s}; run 'artoo vm ssh-config'", .{ssh_config.default_path});
                },
            };
            l.set(i, .done, "");
        }
        if (watch_step) |i| {
            l.set(i, .unknown, "");
            const n = watch.forgetHost(c, op.watch_vm.?, v.name) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    l.set(i, .failed, ctx.diag orelse @errorName(err));
                    return ctx.fail(error.Partial, "VM destroyed, but its metrics stay on {s}; run 'artoo watch forget {s}'", .{ op.watch_vm.?.name, v.name });
                },
            };
            l.set(i, .done, try std.fmt.allocPrint(a, "{d} series on {s}", .{ n, op.watch_vm.?.name }));
        }
    }

    pub fn verify(op: *RmOp, ctx: *Context) !bool {
        var gone = (try vms.find(try vms.list(op.c), ctx.arena, try std.fmt.allocPrint(ctx.arena, "{d}", .{op.vm.?.vmid}))) == .missing;
        if (op.client) |r| {
            var u = try unifi.Client.open(ctx);
            defer u.deinit();
            if (classic.find(try classic.records(&u), r.mac) != null) gone = false;
        }
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        return gone;
    }

    pub fn done(op: *RmOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} destroyed", .{op.target}) catch "done";
    }
};

pub const rm = struct {
    pub const name = "rm";
    pub const summary = "Destroy a VM, its disks, its UniFi records and its stored password";
    pub const details =
        \\A running VM is force-stopped first. UniFi's client record for the
        \\VM's MAC is forgotten when it carries the VM's name; the DNS record
        \\<name>.<guests.domain> is removed only when it points at the VM's
        \\configured address; the Keychain entry guest/<name> is removed when
        \\present; its metrics on the watchdog are deleted, so alerts about it
        \\resolve. Type the VM's name to confirm, or --yes --confirm NAME.
    ;
    pub const positionals = [_]cli.Positional{vm_arg};
    pub const flags = [_]cli.Flag{ .{ .long = "keep-dns", .help = "Leave DNS records alone" }, confirm_flag };
    pub const examples = [_][]const u8{ "artoo vm rm web-01", "artoo vm rm web-01 --yes --confirm web-01" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: RmOp = .{ .c = &c, .word = args.pos("VM"), .keep_dns = args.has("keep-dns") };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

// ---------------------------------------------------------------- snapshots

fn validSnapName(s: []const u8) bool {
    if (s.len < 2 or s.len > 40 or !std.ascii.isAlphabetic(s[0])) return false;
    for (s) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_') return false;
    return std.ascii.eqlIgnoreCase(s, "current") == false;
}

const Snap = enum { add, rm, rollback };

const SnapOp = struct {
    c: *pve.Client,
    kind: Snap,
    word: []const u8,
    snap: []const u8,
    description: ?[]const u8 = null,
    ram: bool = false,
    risk: ui.blocks.Risk,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: ?vms.Vm = null,
    exists: bool = false,
    snap_has_ram: bool = false,
    state: []const u8 = "",
    upid: []const u8 = "",
    result: []const u8 = "",

    pub fn read(op: *SnapOp, ctx: *Context) !void {
        const v = try vms.resolve(op.c, op.word);
        op.vm = v;
        op.target = try std.fmt.allocPrint(ctx.arena, "{s}@{s}", .{ try vmLabel(ctx, v), op.snap });
        op.exists = false;
        for (try vms.snapshots(op.c, v.vmid)) |s| {
            if (std.mem.eql(u8, pve.str(s, "name") orelse "", op.snap)) {
                op.exists = true;
                op.snap_has_ram = pve.flag(s, "vmstate");
            }
        }
        op.state = try std.fmt.allocPrint(ctx.arena, "{s}:{}", .{ v.status, op.exists });
    }

    pub fn plan(op: *SnapOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const v = op.vm.?;
        const label = try vmLabel(ctx, v);
        switch (op.kind) {
            .add => if (op.exists) return null,
            .rm => if (!op.exists) return null,
            .rollback => if (!op.exists) return ctx.fail(error.NotFound, "{s} has no snapshot '{s}' (see 'artoo vm snap ls {s}')", .{ label, op.snap, label }),
        }
        var notes: std.ArrayList([]const u8) = .empty;
        var impact: std.ArrayList([]const u8) = .empty;
        const change: ui.blocks.Change = switch (op.kind) {
            .add => .{ .field = "snapshot", .from = null, .to = try std.fmt.allocPrint(a, "{s}{s}", .{ op.snap, if (op.ram) " (with RAM)" else "" }) },
            .rm => .{ .field = "snapshot", .from = op.snap, .to = null },
            .rollback => .{ .field = "state", .from = "current", .to = try std.fmt.allocPrint(a, "snapshot {s}", .{op.snap}) },
        };
        switch (op.kind) {
            .add => if (op.ram and !v.running()) try notes.append(a, "--ram has no effect on a stopped VM."),
            .rm => try impact.append(a, "The snapshot can no longer be rolled back to"),
            .rollback => {
                try impact.append(a, "Everything since the snapshot is lost (disks and config)");
                if (!op.snap_has_ram) try notes.append(a, "The snapshot has no RAM state: the VM is stopped afterwards.");
            },
        }
        return .{
            .action = try std.fmt.allocPrint(a, "{s} {s}", .{ switch (op.kind) {
                .add => "Snapshot",
                .rm => "Delete snapshot",
                .rollback => "Roll back",
            }, op.target }),
            .risk = op.risk,
            .target = try nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{change}),
            .impact = impact.items,
            .notes = notes.items,
            .recovery = if (op.kind == .add) try std.fmt.allocPrint(a, "artoo vm snap rm {s} {s}", .{ label, op.snap }) else null,
        };
    }

    pub fn fingerprint(op: *SnapOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *SnapOp, ctx: *Context) !void {
        const c = op.c;
        const id = op.vm.?.vmid;
        const data = switch (op.kind) {
            .add => blk: {
                var params: std.ArrayList(pve.Param) = .empty;
                try params.append(ctx.arena, .{ .name = "snapname", .value = op.snap });
                if (op.description) |d| try params.append(ctx.arena, .{ .name = "description", .value = d });
                if (op.ram) try params.append(ctx.arena, .{ .name = "vmstate", .value = "1" });
                break :blk try c.send(.POST, try c.nodePath("/qemu/{d}/snapshot", .{id}), params.items);
            },
            .rm => try c.send(.DELETE, try c.nodePath("/qemu/{d}/snapshot/{s}", .{ id, op.snap }), &.{}),
            .rollback => try c.send(.POST, try c.nodePath("/qemu/{d}/snapshot/{s}/rollback", .{ id, op.snap }), &.{}),
        };
        op.upid = try tasks.upidOf(c, data, "the snapshot request");
    }

    pub fn track(op: *SnapOp, _: *Context) !void {
        op.result = try waitTask(op.c, op.upid, 600);
    }

    pub fn verify(op: *SnapOp, _: *Context) !bool {
        var present = false;
        for (try vms.snapshots(op.c, op.vm.?.vmid)) |s| present = present or std.mem.eql(u8, pve.str(s, "name") orelse "", op.snap);
        return switch (op.kind) {
            .add, .rollback => present,
            .rm => !present,
        };
    }

    pub fn done(op: *SnapOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "{s}: {s}", .{ op.target, op.result }) catch "done";
    }
};

const snap_ls = struct {
    pub const name = "ls";
    pub const summary = "A VM's snapshots";
    pub const positionals = [_]cli.Positional{vm_arg};
    pub const examples = [_][]const u8{"artoo vm snap ls web-01"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const v = try vms.resolve(&c, args.pos("VM"));
        var list: std.ArrayList(Value) = .empty;
        for (try vms.snapshots(&c, v.vmid)) |s| if (!std.mem.eql(u8, pve.str(s, "name") orelse "", "current")) try list.append(ctx.arena, s);
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, list.items, .{ .collected_at = ctx.ui.now, .vmid = v.vmid });
        try k.header(ctx, &c);
        if (list.items.len == 0) {
            try ctx.out.print("{s}No snapshots.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
            return;
        }
        const rows = try ctx.arena.alloc([]const ui.table.Cell, list.items.len);
        for (list.items, rows) |s, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 5);
            cells[0] = .{ .text = try k.clean(ctx, pve.str(s, "name") orelse "") };
            cells[1] = .{ .text = try k.fmt(ctx, ui.values.relative(ctx.ui.now, pve.int(s, "snaptime"))) };
            cells[2] = .{ .text = try k.clean(ctx, pve.str(s, "parent") orelse "--") };
            cells[3] = .{ .text = if (pve.flag(s, "vmstate")) "yes" else "no" };
            cells[4] = .{ .text = try k.clean(ctx, pve.str(s, "description") orelse "") };
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "NAME", .truncate = false },
            .{ .title = "TAKEN" },
            .{ .title = "PARENT", .drop = 2 },
            .{ .title = "RAM", .drop = 1 },
            .{ .title = "DESCRIPTION", .drop = 3 },
        }, rows);
    }
};

fn SnapCmd(comptime kind: Snap) type {
    const destructive = kind != .add;
    return struct {
        pub const name = @tagName(kind);
        pub const summary = switch (kind) {
            .add => "Take a snapshot",
            .rm => "Delete a snapshot (destructive confirmation)",
            .rollback => "Roll a VM back to a snapshot (destructive confirmation)",
        };
        pub const details = if (destructive) "Confirm by typing VM@SNAPSHOT, or --yes --confirm VM@SNAPSHOT." else "Names: 2-40 letters, digits, '-' or '_', starting with a letter.";
        pub const positionals = [_]cli.Positional{ vm_arg, .{ .name = "NAME", .help = "Snapshot name" } };
        pub const flags = switch (kind) {
            .add => [_]cli.Flag{
                .{ .long = "description", .short = 'd', .kind = .string, .metavar = "TEXT", .help = "Snapshot description" },
                .{ .long = "ram", .help = "Include the running VM's memory" },
            },
            else => [_]cli.Flag{confirm_flag},
        };
        pub const examples = [_][]const u8{"artoo vm snap " ++ @tagName(kind) ++ " web-01 pre-upgrade" ++ (if (destructive) " --yes --confirm web-01@pre-upgrade" else "")};

        pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
            const snap = args.pos("NAME");
            if (!validSnapName(snap)) return ctx.fail(error.Usage, "invalid snapshot name '{s}' (2-40 letters, digits, '-' or '_', starting with a letter)", .{snap});
            var c = try pve.Client.open(ctx);
            defer c.deinit();
            var op: SnapOp = .{ .c = &c, .kind = kind, .word = args.pos("VM"), .snap = snap, .risk = if (destructive) .destructive else .normal };
            if (comptime kind == .add) {
                op.description = args.string("description");
                op.ram = args.has("ram");
            }
            const confirm: ?[]const u8 = if (comptime destructive) args.string("confirm") else null;
            try exec.run(ctx, &op, .{ .confirm = confirm });
        }
    };
}

pub const snap_group = cli.group("snap", "Snapshots", &.{
    cli.leaf(snap_ls),
    cli.leaf(SnapCmd(.add)),
    cli.leaf(SnapCmd(.rm)),
    cli.leaf(SnapCmd(.rollback)),
});

pub const commands = [_]cli.Command{
    cli.leaf(PowerCmd(.start)),
    cli.leaf(PowerCmd(.shutdown)),
    cli.leaf(PowerCmd(.reboot)),
    cli.leaf(PowerCmd(.stop)),
    cli.leaf(set),
    cli.leaf(clone),
    cli.leaf(rm),
    snap_group,
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "parseMiB and validSnapName" {
    try testing.expectEqual(@as(?u64, 2048), parseMiB("2048"));
    try testing.expectEqual(@as(?u64, 2048), parseMiB("2G"));
    try testing.expectEqual(@as(?u64, 1536), parseMiB("1.5g"));
    try testing.expectEqual(@as(?u64, 512), parseMiB("512M"));
    try testing.expect(parseMiB("2T") == null);
    try testing.expect(parseMiB("-1") == null);
    try testing.expect(validSnapName("pre-upgrade"));
    try testing.expect(!validSnapName("1st"));
    try testing.expect(!validSnapName("current"));
    try testing.expect(!validSnapName("a b"));
}

test "staticAddress" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const cfg = try std.json.parseFromSliceLeaky(Value, a.allocator(), "{\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\"}", .{});
    try testing.expectEqualStrings("192.168.1.200", staticAddress(cfg).?);
    try testing.expect(staticAddress(.null) == null);
}

const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const vm_cmd = @import("vm.zig");
const root = cli.group("artoo", "t", &.{vm_cmd.group});

const upid_body = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:qmstart:101:artoo@pve!cli:\"}";
const task_ok = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}";

test "vm start: one POST, task tracked, state verified" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = "{\"data\":{\"status\":\"running\"}}" } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":{\"status\":\"running\",\"vmid\":101}}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm start db-01 -y"));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/101/status/start HTTP/1.1", g.request(1));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/qemu/101/status/current HTTP/1.1", g.request(4));
    const out = g.h.stdout();
    try testing.expect(std.mem.startsWith(u8, out, "Plan · Start VM db-01 (101)\n"));
    try testing.expect(std.mem.find(u8, out, "db-01 is running (task qmstart:101@") != null);
}

test "vm power: no-ops refused, stop needs the typed name, failed task exits 6" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"VM quit/powerdown failed - got timeout\"}}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm start web-01 -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "nothing to change") != null);
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm stop web-01 -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "--confirm web-01") != null);
    try testing.expectEqual(Exit.task_failed, g.h.run(&root, "vm shutdown web-01 -y"));
    try testing.expectEqualStrings("timeout=180", g.body(3));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "got timeout") != null);
    try testing.expectEqual(@as(usize, 5), g.sent());
}

test "vm set: validated, digest-guarded PUT of changed keys only" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = vm_cmd.config_body } },
        .{ .respond = .{ .body = "{\"data\":null}" } },
        .{ .respond = .{ .body = "{\"data\":{\"cores\":2,\"memory\":\"4096\",\"tags\":\"artoo;web\",\"digest\":\"def\"}}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm set web-01 bios=ovmf"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm set web-01 memory=lots"));
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm set web-01 memory=4G cores=2 tags=artoo,web -y"));
    try testing.expectEqualStrings("PUT /api2/json/nodes/pve/qemu/100/config HTTP/1.1", g.request(2));
    try testing.expectEqualStrings("memory=4096&tags=artoo%3Bweb&digest=abc123", g.body(2));
    const out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "memory  2048 → 4096") != null);
    try testing.expect(std.mem.find(u8, out, "may stay pending until it restarts") != null);
}

test "vm clone: lowest free VMID ≥ 200, full clone, verified" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":[{\"type\":\"qemu\",\"node\":\"pve\",\"vmid\":200,\"name\":\"web-02\",\"status\":\"stopped\"}]}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm clone ubuntu-2604 web-02 -y"));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/9000/clone HTTP/1.1", g.request(2));
    try testing.expectEqualStrings("newid=200&name=web-02&full=1", g.body(2));
}

test "vm rm: stop, destroy, matching DNS record, Keychain entry, metrics on the watchdog — with a ledger" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const out_of = struct {
        fn f(ar: std.mem.Allocator, out: []const u8) ![]const u8 {
            return std.json.Stringify.valueAlloc(ar, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
        }
    }.f;
    const pid = "{\"data\":{\"pid\":42}}";
    const three = try out_of(a, "{\"status\":\"success\",\"data\":[{},{},{}]}");
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = vm_cmd.config_body } },
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = "{\"meta\":{\"rc\":\"ok\"},\"data\":[{\"_id\":\"U1\",\"mac\":\"bc:24:11:00:00:01\",\"name\":\"web-01\",\"use_fixedip\":true,\"fixed_ip\":\"192.168.1.200\"}]}" } },
        .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"S1\",\"internalReference\":\"default\",\"name\":\"Default\"}]}" } },
        .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"type\":\"A_RECORD\",\"id\":\"R7\",\"enabled\":true,\"domain\":\"web-01.lab.example.com\",\"ipv4Address\":\"192.168.1.200\",\"ttlSeconds\":300}]}" } },
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":202,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch\"}]}" } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = three } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"meta\":{\"rc\":\"ok\"},\"data\":[]}" } },
        .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":1,\"totalCount\":1,\"data\":[{\"id\":\"S1\",\"internalReference\":\"default\",\"name\":\"Default\"}]}" } },
        .{ .respond = .{ .body = "" } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = three } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try out_of(a, "") } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try out_of(a, "{\"status\":\"success\",\"data\":[]}") } },
        .{ .respond = .{ .body = "{\"data\":[]}" } },
        .{ .respond = .{ .body = "{\"meta\":{\"rc\":\"ok\"},\"data\":[]}" } },
    });
    defer g.deinit();
    try g.mem.map.put(g.h.arena.allocator(), "guest/web-01", "pw");
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    const blocks: []const ssh_config.Block = &.{ .{ .name = "web-01", .address = "192.168.1.200", .jump = false }, .{ .name = "naboo", .address = "192.168.1.230", .jump = false } };
    const s: ssh_config.Settings = .{ .domain = "lab.example.com", .user = "artoo", .identity = "/k", .known_hosts = "/kh", .proxy = "/p" };
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/ssh_config", .data = try ssh_config.render(a, s, blocks) });
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm rm web-01 -y --confirm web-01"));
    try testing.expectEqualStrings(try ssh_config.render(a, s, blocks[1..]), try g.tmp.dir.readFileAlloc(testing.io, ".artoo/ssh_config", a, .limited(1 << 16)));
    try testing.expectEqualStrings("GET /proxy/network/api/s/default/rest/user HTTP/1.1", g.request(3));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/202/agent/exec HTTP/1.1", g.request(7));
    try testing.expect(std.mem.find(u8, g.body(7), "api%2Fv1%2Fseries&command=--data-urlencode&command=match%5B%5D%3D%7Bhost%3D%22web-01%22%7D&command=--data-urlencode&command=start%3D-3d") != null);
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/100/status/stop HTTP/1.1", g.request(9));
    try testing.expectEqualStrings("DELETE /api2/json/nodes/pve/qemu/100?purge=1&destroy-unreferenced-disks=1 HTTP/1.1", g.request(11));
    try testing.expectEqualStrings("POST /proxy/network/api/s/default/cmd/stamgr HTTP/1.1", g.request(13));
    try testing.expectEqualStrings("{\"cmd\":\"forget-sta\",\"macs\":[\"bc:24:11:00:00:01\"]}", g.body(13));
    try testing.expectEqualStrings("DELETE /v1/sites/S1/dns/policies/R7 HTTP/1.1", g.request(15));
    // The delete runs after the destroy: nothing pushes for the VM any more.
    try testing.expect(std.mem.find(u8, g.body(18), "command=-X&command=POST&command=http%3A%2F%2Flocalhost%3A8428%2Fapi%2Fv1%2Fadmin%2Ftsdb%2Fdelete_series") != null);
    try testing.expect(g.mem.map.get("guest/web-01") == null);
    const out = g.h.stdout();
    for ([_][]const u8{
        "Change    status         running → stopped (forced)\n",
        "client record  web-01 (bc:24:11:00:00:01), Fixed IP 192.168.1.200 on UniFi → (removed)\n",
        "DNS record     web-01.lab.example.com → 192.168.1.200 → (removed)\n",
        "Keychain       guest/web-01 password → (removed)\n",
        "metrics        3 series with host=web-01 on scarif → (removed)\n",
        "ssh config     Host web-01 in ~/.artoo/ssh_config → (removed)\n",
        "✓ remove from ssh config    done",
        "✓ forget in watch           done  3 series on scarif",
        "✓ stop VM                   done",
        "✓ destroy VM and disks      done",
        "✓ forget client record      done  bc:24:11:00:00:01",
        "✓ remove DNS record         done",
        "✓ delete Keychain password  done",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "vm snap add: POST with name, verified in the list" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = vm_cmd.resources_body } },
        .{ .respond = .{ .body = "{\"data\":[{\"name\":\"current\"}]}" } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":[{\"name\":\"current\"},{\"name\":\"pre-upgrade\"}]}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm snap add web-01 1bad"));
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm snap add web-01 pre-upgrade -y"));
    try testing.expectEqualStrings("snapname=pre-upgrade", g.body(2));
}
