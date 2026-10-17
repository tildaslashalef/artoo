//! `artoo template ls | show T | build T | rm T | vendor` (SPEC §3.3, §9.2).
//!
//! A template is named after its image pin (`ubuntu-2604`) and built
//! entirely through the API — image fetched by Proxmox, VM created from the
//! imported disk, converted — except the shared vendor snippet, which is
//! placed over root SSH (no API accepts snippets). Templates are found by
//! name and tag at run time; their description records the image and the
//! vendor snippet they were built with.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const tasks = @import("../pve/task.zig");
const vms = @import("../pve/vm.zig");
const ssh = @import("../pve/ssh.zig");
const images = @import("../guest/image.zig");
const vendor = @import("../guest/vendor.zig");
const image_cmd = @import("image.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;
const Pin = images.Pin;

pub const tag = "artoo-template";
/// Storage for VM disks and the cloud-init drive.
pub const disk_storage = "local-zfs";
/// Templates get the lowest free VMID from here (guests start at 200).
pub const first_vmid = 9000;

const confirm_flag: cli.Flag = .{ .long = "confirm", .kind = .string, .metavar = "TARGET", .help = "Non-interactive confirmation (with --yes)" };
const template_arg: cli.Positional = .{ .name = "TEMPLATE", .complete = .template, .help = "Template name or VMID" };

// ---------------------------------------------------------------- metadata

/// What a template's description records.
pub const Meta = struct {
    image: ?[]const u8 = null,
    sha256: ?[]const u8 = null,
    vendor: ?[]const u8 = null,
};

pub fn description(arena: std.mem.Allocator, p: *const Pin, snippet: vendor.Snippet) ![]const u8 {
    return std.fmt.allocPrint(arena,
        \\Built by artoo template build (Ubuntu {s}, build {s}).
        \\image: {s}
        \\sha256: {s}
        \\vendor: {s}
        \\
    , .{ p.release, p.build, p.file, p.sha256, snippet.name });
}

pub fn parseMeta(desc: []const u8) Meta {
    var m: Meta = .{};
    var it = std.mem.tokenizeScalar(u8, desc, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r");
        if (std.mem.cutPrefix(u8, line, "image: ")) |v| m.image = v;
        if (std.mem.cutPrefix(u8, line, "sha256: ")) |v| m.sha256 = v;
        if (std.mem.cutPrefix(u8, line, "vendor: ")) |v| m.vendor = v;
    }
    return m;
}

pub fn tagged(tags: []const u8) bool {
    return taggedWith(tags, tag);
}

/// PVE tag lists are `;`-separated (`,`/space accepted too).
pub fn taggedWith(tags: []const u8, want: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, tags, ";, ");
    while (it.next()) |t| {
        if (std.mem.eql(u8, t, want)) return true;
    }
    return false;
}

/// The `cicustom` value pointing at a snippet.
fn cicustom(arena: std.mem.Allocator, s: vendor.Snippet) ![]const u8 {
    return std.fmt.allocPrint(arena, "vendor={s}", .{try s.volid(arena)});
}

/// Snippets in `local:snippets` (name → size).
pub const SnippetFile = struct { name: []const u8, size: ?u64 };

pub fn snippetFiles(c: *pve.Client) ![]SnippetFile {
    const data = try c.get(try c.nodePath("/storage/{s}/content?content=snippets", .{images.storage}));
    var out: std.ArrayList(SnippetFile) = .empty;
    for (pve.items(data)) |v| {
        const volid = pve.str(v, "volid") orelse continue;
        const name = std.mem.cutPrefix(u8, volid, images.storage ++ ":snippets/") orelse continue;
        try out.append(c.ctx.arena, .{ .name = name, .size = pve.uint(v, "size") });
    }
    return out.items;
}

pub const SnippetState = enum { present, missing, mismatch };

pub fn snippetState(all: []const SnippetFile, s: vendor.Snippet) SnippetState {
    for (all) |f| {
        if (std.mem.eql(u8, f.name, s.name)) return if (f.size == s.text.len) .present else .mismatch;
    }
    return .missing;
}

/// The release codename for the vendor snippet of a pin.
fn current(ctx: *Context, p: *const Pin) !vendor.Snippet {
    return vendor.render(ctx.arena, p.codename, (try ctx.config()).guests.user);
}

// ---------------------------------------------------------------- ls / show

const Row = struct {
    name: []const u8,
    vmid: u32,
    managed: bool,
    image: ?[]const u8,
    vendor: ?[]const u8,
    disk: ?u64,
    /// `current`: matches the pin and this artoo's vendor snippet.
    state: []const u8,
};

fn rowFor(ctx: *Context, c: *pve.Client, v: vms.Vm) !Row {
    const cfg = try vms.config(c, v.vmid);
    const managed = tagged(pve.str(cfg, "tags") orelse "");
    const meta = parseMeta(pve.str(cfg, "description") orelse "");
    var state: []const u8 = "unmanaged";
    if (managed) {
        state = "outdated";
        if (images.find(v.name)) |p| {
            const s = try current(ctx, p);
            if (meta.image != null and std.mem.eql(u8, meta.image.?, p.file) and meta.vendor != null and std.mem.eql(u8, meta.vendor.?, s.name)) state = "current";
        } else state = "unpinned";
    }
    return .{ .name = v.name, .vmid = v.vmid, .managed = managed, .image = meta.image, .vendor = meta.vendor, .disk = v.maxdisk, .state = state };
}

fn stateCell(ctx: *Context, state: []const u8) !ui.table.Cell {
    if (std.mem.eql(u8, state, "current")) return k.statusCell(ctx, .ok, state);
    if (std.mem.eql(u8, state, "unmanaged")) return k.statusCell(ctx, .not_checked, state);
    return k.statusCell(ctx, .warning, state);
}

pub const ls = struct {
    pub const name = "ls";
    pub const summary = "Templates on Proxmox and whether they match the pins";
    pub const details =
        \\STATE: current (built from the pinned image and this artoo's vendor
        \\snippet), outdated (rebuild with 'artoo template build'), unpinned (no pin
        \\of that name), unmanaged (not built by artoo).
    ;
    pub const examples = [_][]const u8{ "artoo template ls", "artoo template ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var list: std.ArrayList(Row) = .empty;
        for (try vms.list(&c)) |v| if (v.template) try list.append(ctx.arena, try rowFor(ctx, &c, v));
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, list.items, .{ .collected_at = ctx.ui.now, .node = c.node });
        try k.header(ctx, &c);
        if (list.items.len == 0) {
            try ctx.out.print("{s}No templates.{s} Build one with 'artoo template build {s}'.\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted), images.pins[0].name });
            return;
        }
        const table = try ctx.arena.alloc([]const ui.table.Cell, list.items.len);
        for (list.items, table) |r, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 6);
            cells[0] = .{ .text = try k.clean(ctx, r.name) };
            cells[1] = .{ .text = try std.fmt.allocPrint(ctx.arena, "{d}", .{r.vmid}) };
            cells[2] = .{ .text = if (r.image) |x| try k.clean(ctx, x) else "--" };
            cells[3] = .{ .text = if (r.vendor) |x| try k.clean(ctx, x) else "--" };
            cells[4] = .{ .text = try k.fmt(ctx, ui.values.bytes(r.disk)) };
            cells[5] = try stateCell(ctx, r.state);
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "NAME", .truncate = false },
            .{ .title = "VMID", .alignment = .right },
            .{ .title = "IMAGE", .drop = 2 },
            .{ .title = "VENDOR", .drop = 3 },
            .{ .title = "DISK", .alignment = .right, .drop = 1 },
            .{ .title = "STATE" },
        }, table);
    }
};

fn resolveTemplate(c: *pve.Client, word: []const u8) !vms.Vm {
    const v = try vms.resolve(c, word);
    if (!v.template) return c.ctx.fail(error.Refused, "{s} ({d}) is a VM, not a template", .{ try k.clean(c.ctx, v.name), v.vmid });
    return v;
}

/// The config's `memory` (MiB, number or numeric string) in bytes.
fn memoryBytes(cfg: std.json.Value) ?u64 {
    const mib = pve.uint(cfg, "memory") orelse return null;
    return std.math.mul(u64, mib, 1024 * 1024) catch null;
}

pub const show = struct {
    pub const name = "show";
    pub const summary = "One template: image, vendor snippet and hardware";
    pub const positionals = [_]cli.Positional{template_arg};
    pub const examples = [_][]const u8{"artoo template show ubuntu-2604"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const v = try resolveTemplate(&c, args.pos("TEMPLATE"));
        const cfg = try vms.config(&c, v.vmid);
        const r = try rowFor(ctx, &c, v);
        const meta = parseMeta(pve.str(cfg, "description") orelse "");
        const snippets = try snippetFiles(&c);
        var snippet_present: ?bool = null;
        if (meta.vendor) |want| {
            snippet_present = false;
            for (snippets) |f| snippet_present = snippet_present.? or std.mem.eql(u8, f.name, want);
        }
        if (ctx.json()) return ui.json.envelope(ctx.out, .pve, .{ .template = r, .sha256 = meta.sha256, .snippet_present = snippet_present, .config = cfg }, .{ .collected_at = ctx.ui.now, .node = c.node });
        try k.header(ctx, &c);
        const st = try stateCell(ctx, r.state);
        const snip: ui.blocks.Field = if (snippet_present) |p|
            .{ .key = "Snippet", .value = if (p) "present on Proxmox" else "missing on Proxmox (guests cannot start)", .role = if (p) .ok else .fail }
        else
            .{ .key = "Snippet", .value = "--" };
        const a = ctx.arena;
        const hw = [_]struct { []const u8, []const u8 }{
            .{ "Cores", "cores" },          .{ "Memory", "memory" }, .{ "CPU", "cpu" },     .{ "Disk", "scsi0" },
            .{ "Cloud-init", "ide2" },      .{ "Network", "net0" },  .{ "Agent", "agent" }, .{ "Serial", "serial0" },
            .{ "Vendor data", "cicustom" },
        };
        var hw_fields: std.ArrayList(ui.blocks.Field) = .empty;
        for (hw) |h| {
            const val: []const u8 = if (std.mem.eql(u8, h[1], "memory"))
                try k.fmt(ctx, ui.values.bytes(memoryBytes(cfg)))
            else if (pve.str(cfg, h[1])) |s| try k.clean(ctx, s) else if (pve.int(cfg, h[1])) |n| try std.fmt.allocPrint(a, "{d}", .{n}) else "--";
            try hw_fields.append(a, .{ .key = h[0], .value = val });
        }
        try ui.blocks.detail(ctx.out, &ctx.ui, &.{
            .{ .title = try std.fmt.allocPrint(a, "Template {s} ({d})", .{ try k.clean(ctx, v.name), v.vmid }), .fields = &.{
                .{ .key = "State", .value = st.text, .role = st.role },
                .{ .key = "Image", .value = if (meta.image) |x| try k.clean(ctx, x) else "--" },
                .{ .key = "SHA-256", .value = if (meta.sha256) |x| try k.clean(ctx, x) else "--" },
                .{ .key = "Vendor", .value = if (meta.vendor) |x| try k.clean(ctx, x) else "--" },
                snip,
                .{ .key = "Tags", .value = try k.clean(ctx, v.tags) },
            } },
            .{ .title = "Hardware", .fields = hw_fields.items },
        });
    }
};

// ---------------------------------------------------------------- build

const BuildOp = struct {
    c: *pve.Client,
    pin: *const Pin,
    want_id: ?u32,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    snippet: vendor.Snippet = undefined,
    image: image_cmd.State = .missing,
    snip: SnippetState = .missing,
    vm: ?vms.Vm = null,
    digest: []const u8 = "",
    new_id: u32 = 0,
    steps: struct { fetch: bool = false, place: bool = false, create: bool = false, update: bool = false, convert: bool = false } = .{},
    state: []const u8 = "",
    ledger: exec.Ledger = .{},

    fn vmid(op: *const BuildOp) u32 {
        return if (op.vm) |v| v.vmid else op.new_id;
    }

    pub fn read(op: *BuildOp, ctx: *Context) !void {
        const c = op.c;
        const p = op.pin;
        op.target = p.name;
        op.snippet = try current(ctx, p);
        op.image = image_cmd.lookup(try image_cmd.files(c), p).state;
        op.snip = snippetState(try snippetFiles(c), op.snippet);
        op.steps = .{};
        op.vm = null;
        const all = try vms.list(c);
        switch (try vms.find(all, ctx.arena, p.name)) {
            .ambiguous => |hits| return ctx.fail(error.Refused, "{d} VMs are named '{s}'; remove the extra ones first", .{ hits.len, p.name }),
            .missing => {
                op.steps.create = true;
                op.steps.convert = true;
                op.new_id = if (op.want_id) |id| blk: {
                    for (all) |v| if (v.vmid == id) return ctx.fail(error.Refused, "VMID {d} is taken", .{id});
                    break :blk id;
                } else try vms.freeVmid(c, first_vmid);
            },
            .vm => |v| {
                const cfg = try vms.config(c, v.vmid);
                const label = try k.clean(ctx, v.name);
                if (!tagged(pve.str(cfg, "tags") orelse ""))
                    return ctx.fail(error.Refused, "{s} ({d}) exists and was not built by artoo (no '{s}' tag); nothing was changed", .{ label, v.vmid, tag });
                const meta = parseMeta(pve.str(cfg, "description") orelse "");
                if (meta.image == null or !std.mem.eql(u8, meta.image.?, p.file))
                    return ctx.fail(error.Refused, "{s} ({d}) was built from image {s}, not the pinned {s}; remove it with 'artoo template rm {s}' and build again", .{ label, v.vmid, meta.image orelse "unknown", p.file, label });
                op.vm = v;
                op.digest = pve.str(cfg, "digest") orelse "";
                // An interrupted build leaves the VM unconverted: continue.
                op.steps.convert = !v.template;
                op.steps.update = !std.mem.eql(u8, pve.str(cfg, "cicustom") orelse "", try cicustom(ctx.arena, op.snippet)) or
                    meta.vendor == null or !std.mem.eql(u8, meta.vendor.?, op.snippet.name);
            },
        }
        op.steps.fetch = op.steps.create and op.image != .present;
        op.steps.place = op.snip == .missing;
        op.state = try std.fmt.allocPrint(ctx.arena, "{t}:{t}:{d}:{s}", .{ op.image, op.snip, op.vmid(), op.digest });
    }

    pub fn plan(op: *BuildOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const p = op.pin;
        const s = op.snippet;
        if (op.snip == .mismatch) return ctx.fail(error.Refused, "local:snippets/{s} exists with another size; inspect it over SSH before building", .{s.name});
        if (op.steps.fetch and op.image == .mismatch) return ctx.fail(error.Refused, "local:import/{s} is not the pinned build; remove it with 'artoo image rm {s}' first", .{ p.file, p.name });
        const st = op.steps;
        if (!(st.fetch or st.place or st.create or st.update or st.convert)) return null;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (st.fetch) try changes.append(a, .{ .field = "image", .from = null, .to = try std.fmt.allocPrint(a, "local:import/{s} ({f}, downloaded by Proxmox, SHA-256 checked)", .{ p.file, ui.values.bytes(p.size) }) });
        if (st.place) try changes.append(a, .{ .field = "snippet", .from = null, .to = try std.fmt.allocPrint(a, "{s}/{s} ({f}, over root SSH)", .{ vendor.snippets_dir, s.name, ui.values.bytes(s.text.len) }) });
        if (st.create) try changes.append(a, .{ .field = "VM", .from = null, .to = try std.fmt.allocPrint(a, "{d} {s} from local:import/{s} on {s}", .{ op.new_id, p.name, p.file, disk_storage }) });
        if (st.update) try changes.append(a, .{ .field = "vendor", .from = if (op.vm) |_| "previous snippet" else null, .to = s.name });
        if (st.convert) try changes.append(a, .{ .field = "template", .from = if (op.vm != null) "VM (interrupted build)" else null, .to = try std.fmt.allocPrint(a, "{s} ({d}), tag {s}", .{ p.name, op.vmid(), tag }) });
        var notes: std.ArrayList([]const u8) = .empty;
        if (st.place) try notes.append(a, "The snippet is a persistent file on Proxmox, shared by every guest built from it; it is never overwritten.");
        if (op.vm != null and st.update and !st.convert) try notes.append(a, "Existing template: only its vendor snippet reference and description change.");
        try notes.append(a, "Steps run in order and stop at the first failure; nothing is undone automatically. Re-running continues.");
        return .{
            .action = try std.fmt.allocPrint(a, "Build template {s} (Ubuntu {s}, build {s})", .{ p.name, p.release, p.build }),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{"Uses storage on Proxmox; no running guest is touched"}),
            .notes = notes.items,
            .recovery = try std.fmt.allocPrint(a, "artoo template rm {s}", .{p.name}),
        };
    }

    pub fn fingerprint(op: *BuildOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *BuildOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        const p = op.pin;
        const st = op.steps;
        const l = &op.ledger;
        const fetch = if (st.fetch) try l.add(a, "fetch image") else null;
        const place = if (st.place) try l.add(a, "place vendor snippet") else null;
        const create = if (st.create) try l.add(a, "create VM from image") else null;
        const update = if (st.update) try l.add(a, "point at vendor snippet") else null;
        const convert = if (st.convert) try l.add(a, "convert to template") else null;
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        if (fetch) |i| {
            l.set(i, .unknown, "");
            const upid = try image_cmd.download(c, p);
            l.set(i, .done, try k.waitTaskNoted(c, upid, 1800, l.noter(i)));
        }
        if (place) |i| {
            l.set(i, .unknown, "");
            const how = ssh.placeSnippet(ctx, op.snippet) catch |err| {
                if (err == error.Network or err == error.Refused) l.set(i, .failed, "");
                return err;
            };
            l.set(i, .done, @tagName(how));
        }
        if (create) |i| {
            l.set(i, .unknown, "");
            const params = try createParams(a, op.new_id, p, op.snippet);
            const upid = try tasks.upidOf(c, try c.send(.POST, try c.nodePath("/qemu", .{}), params), "the VM creation");
            l.set(i, .done, try k.waitTaskNoted(c, upid, 900, l.noter(i)));
        }
        if (update) |i| {
            l.set(i, .unknown, "");
            _ = try c.send(.PUT, try c.nodePath("/qemu/{d}/config", .{op.vmid()}), &.{
                .{ .name = "cicustom", .value = try cicustom(a, op.snippet) },
                .{ .name = "description", .value = try description(a, p, op.snippet) },
                .{ .name = "digest", .value = op.digest },
            });
            l.set(i, .done, op.snippet.name);
        }
        if (convert) |i| {
            l.set(i, .unknown, "");
            const upid = try tasks.upidOf(c, try c.send(.POST, try c.nodePath("/qemu/{d}/template", .{op.vmid()}), &.{}), "the conversion");
            l.set(i, .done, try k.waitTaskNoted(c, upid, 300, l.noter(i)));
        }
    }

    pub fn verify(op: *BuildOp, ctx: *Context) !bool {
        const c = op.c;
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const v = switch (try vms.find(try vms.list(c), ctx.arena, try std.fmt.allocPrint(ctx.arena, "{d}", .{op.vmid()}))) {
            .vm => |v| v,
            else => return false,
        };
        if (!v.template or !std.mem.eql(u8, v.name, op.pin.name)) return false;
        const cfg = try vms.config(c, v.vmid);
        const meta = parseMeta(pve.str(cfg, "description") orelse "");
        return tagged(pve.str(cfg, "tags") orelse "") and
            std.mem.eql(u8, pve.str(cfg, "cicustom") orelse "", try cicustom(ctx.arena, op.snippet)) and
            meta.vendor != null and std.mem.eql(u8, meta.vendor.?, op.snippet.name) and
            snippetState(try snippetFiles(c), op.snippet) == .present;
    }

    pub fn done(op: *BuildOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "template {s} ({d}) is ready: {s}, {s}", .{ op.pin.name, op.vmid(), op.pin.file, op.snippet.name }) catch "done";
    }
};

/// `POST /nodes/{node}/qemu` for a template from the pinned image. Size
/// `small` hardware; `vm new` sets the guest's own size, identity and
/// address.
pub fn createParams(arena: std.mem.Allocator, vmid: u32, p: *const Pin, s: vendor.Snippet) ![]const pve.Param {
    return arena.dupe(pve.Param, &.{
        .{ .name = "vmid", .value = try std.fmt.allocPrint(arena, "{d}", .{vmid}) },
        .{ .name = "name", .value = p.name },
        .{ .name = "description", .value = try description(arena, p, s) },
        .{ .name = "tags", .value = tag },
        .{ .name = "ostype", .value = "l26" },
        .{ .name = "machine", .value = "q35" },
        .{ .name = "cpu", .value = "host" },
        .{ .name = "cores", .value = "1" },
        .{ .name = "memory", .value = "1024" },
        .{ .name = "scsihw", .value = "virtio-scsi-single" },
        .{ .name = "scsi0", .value = try std.fmt.allocPrint(arena, "{s}:0,import-from={s},discard=on,iothread=1,ssd=1", .{ disk_storage, try p.volidAlloc(arena) }) },
        .{ .name = "ide2", .value = disk_storage ++ ":cloudinit" },
        .{ .name = "boot", .value = "order=scsi0" },
        .{ .name = "net0", .value = "virtio,bridge=vmbr0" },
        .{ .name = "agent", .value = "enabled=1,fstrim_cloned_disks=1" },
        .{ .name = "serial0", .value = "socket" },
        .{ .name = "vga", .value = "serial0" },
        .{ .name = "cicustom", .value = try cicustom(arena, s) },
    });
}

pub const build = struct {
    pub const name = "build";
    pub const summary = "Build (or bring up to date) the template of a pinned image";
    pub const details =
        \\Steps, each only when needed: Proxmox fetches the pinned image (SHA-256
        \\checked); the vendor snippet is placed in local:snippets over root SSH
        \\(pve.ssh_host, pve.ssh_identity); a VM is created from the imported disk
        \\with a cloud-init drive, guest agent and serial console; it is converted to
        \\a template tagged artoo-template. An existing template built from the same
        \\image only gets the current vendor snippet. Re-running continues an
        \\interrupted build; a template from another image is refused.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "TEMPLATE", .help = "Pinned image name (see 'artoo image ls')" }};
    pub const flags = [_]cli.Flag{.{ .long = "id", .kind = .int, .metavar = "VMID", .help = "VMID for a new template (default: lowest free ≥ 9000)" }};
    pub const examples = [_][]const u8{ "artoo template build ubuntu-2604 -n", "artoo template build ubuntu-2604 -y" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const word = args.pos("TEMPLATE");
        const p = images.find(word) orelse return ctx.fail(error.Usage, "'{s}' is not a pinned image; templates are named after their image (see 'artoo image ls')", .{word});
        const want: ?u32 = if (args.int("id")) |id| blk: {
            if (id < 100 or id > 999_999_999) return ctx.fail(error.Usage, "--id must be 100-999999999, got {d}", .{id});
            break :blk @intCast(id);
        } else null;
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: BuildOp = .{ .c = &c, .pin = p, .want_id = want };
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
    vm: ?vms.Vm = null,
    upid: []const u8 = "",
    result: []const u8 = "",

    pub fn read(op: *RmOp, ctx: *Context) !void {
        const v = try resolveTemplate(op.c, op.word);
        op.vm = v;
        op.target = if (v.name.len > 0) try k.clean(ctx, v.name) else try std.fmt.allocPrint(ctx.arena, "{d}", .{v.vmid});
    }

    pub fn plan(op: *RmOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const v = op.vm.?;
        return .{
            .action = try std.fmt.allocPrint(a, "Remove template {s} ({d})", .{ op.target, v.vmid }),
            .risk = .destructive,
            .target = try k.nodeTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{
                .{ .field = "template", .from = try std.fmt.allocPrint(a, "{d} {s}", .{ v.vmid, op.target }), .to = null },
                .{ .field = "disks", .from = try std.fmt.allocPrint(a, "base disk + cloud-init drive ({f})", .{ui.values.bytes(v.maxdisk)}), .to = null },
            }),
            .impact = try a.dupe([]const u8, &.{"New guests cannot be built from it; existing full clones are unaffected"}),
            .notes = try a.dupe([]const u8, &.{"The image in local:import and the vendor snippet stay (guests reference the snippet)."}),
            .recovery = if (images.find(v.name)) |p| try std.fmt.allocPrint(a, "artoo template build {s}", .{p.name}) else null,
        };
    }

    pub fn fingerprint(op: *RmOp) []const u8 {
        return op.target;
    }

    pub fn send(op: *RmOp, _: *Context) !void {
        const c = op.c;
        const path = try c.nodePath("/qemu/{d}?purge=1&destroy-unreferenced-disks=1", .{op.vm.?.vmid});
        op.upid = try tasks.upidOf(c, try c.send(.DELETE, path, &.{}), "the removal");
    }

    pub fn track(op: *RmOp, _: *Context) !void {
        op.result = try k.waitTask(op.c, op.upid, 600);
    }

    pub fn verify(op: *RmOp, ctx: *Context) !bool {
        return (try vms.find(try vms.list(op.c), ctx.arena, try std.fmt.allocPrint(ctx.arena, "{d}", .{op.vm.?.vmid}))) == .missing;
    }

    pub fn done(op: *RmOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "template {s} removed ({s})", .{ op.target, op.result }) catch "done";
    }
};

pub const rm = struct {
    pub const name = "rm";
    pub const summary = "Remove a template and its disks (destructive confirmation)";
    pub const details = "Type the template's name to confirm, or --yes --confirm NAME. Image and vendor snippet stay.";
    pub const positionals = [_]cli.Positional{template_arg};
    pub const flags = [_]cli.Flag{confirm_flag};
    pub const examples = [_][]const u8{ "artoo template rm ubuntu-2604", "artoo template rm ubuntu-2604 --yes --confirm ubuntu-2604" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: RmOp = .{ .c = &c, .word = args.pos("TEMPLATE") };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

// ---------------------------------------------------------------- vendor

pub const vendor_cmd = struct {
    pub const name = "vendor";
    pub const summary = "Print the vendor-data snippet this artoo places on Proxmox";
    pub const details = "Local and read-only: the exact cloud-config document, named by its content hash.";
    pub const positionals = [_]cli.Positional{.{ .name = "TEMPLATE", .help = "Pinned image name", .required = false }};
    pub const examples = [_][]const u8{ "artoo template vendor", "artoo template vendor -o json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const word = args.optPos("TEMPLATE") orelse images.pins[0].name;
        const p = images.find(word) orelse return ctx.fail(error.Usage, "'{s}' is not a pinned image (see 'artoo image ls')", .{word});
        const s = try current(ctx, p);
        if (ctx.json()) return ui.json.envelope(ctx.out, .local, .{ .name = s.name, .rev = s.rev, .sha256 = s.sha256, .size = s.text.len, .text = s.text }, .{});
        try ctx.err.print("# {s}  sha256 {s}  ({d} bytes)\n", .{ s.name, s.sha256, s.text.len });
        try ctx.out.writeAll(s.text);
    }
};

pub const group = cli.group("template", "Guest templates on Proxmox", &.{
    cli.leaf(ls),
    cli.leaf(show),
    cli.leaf(build),
    cli.leaf(rm),
    cli.leaf(vendor_cmd),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const root = cli.group("artoo", "t", &.{group});

test "description round-trips through parseMeta; tags" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const p = &images.pins[0];
    const s = try vendor.render(ar, p.codename, "artoo");
    const m = parseMeta(try description(ar, p, s));
    try testing.expectEqualStrings(p.file, m.image.?);
    try testing.expectEqualStrings(p.sha256, m.sha256.?);
    try testing.expectEqualStrings(s.name, m.vendor.?);
    try testing.expect(tagged("artoo;artoo-template"));
    try testing.expect(!tagged("artoo-templates"));
}

const FakeRunner = @import("../secrets/common.zig").FakeRunner;
const upid_body = "{\"data\":\"UPID:pve:0006B482:00B442ED:6ACA1C3A:qmcreate:9000:artoo@pve!cli:\"}";
const task_ok = "{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}";

test "template build: fetch, snippet over SSH, create from import, convert — with a ledger" {
    var g: testkit.Gateway = undefined;
    const ar = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(ar);
    defer arena.deinit();
    const a = arena.allocator();
    const p = &images.pins[0];
    const s = try vendor.render(a, p.codename, "artoo");
    const snippets_present = try std.fmt.allocPrint(a, "{{\"data\":[{{\"volid\":\"local:snippets/{s}\",\"size\":{d}}}]}}", .{ s.name, s.text.len });
    const cfg_body = try std.fmt.allocPrint(a, "{{\"data\":{{\"tags\":\"artoo-template\",\"cicustom\":\"vendor=local:snippets/{s}\",\"description\":\"x\\nimage: {s}\\nvendor: {s}\\n\",\"digest\":\"d1\"}}}}", .{ s.name, p.file, s.name });
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":[]}" } },
        .{ .respond = .{ .body = "{\"data\":[]}" } },
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":100,\"name\":\"web-01\",\"status\":\"running\"}]}" } },
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":100,\"type\":\"qemu\"},{\"vmid\":9000,\"type\":\"qemu\"}]}" } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = "{\"data\":{\"status\":\"running\"}}" } },
        .{ .respond = .{ .body = "{\"data\":[{\"n\":1,\"t\":\"downloading https://cloud-images.ubuntu.com/…\"},{\"n\":2,\"t\":\"512.00 MiB of 1.20 GiB (41.67%)\"},{\"n\":3,\"t\":\"\"}]}" } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":100,\"name\":\"web-01\"},{\"vmid\":9001,\"name\":\"ubuntu-2604\",\"template\":1,\"status\":\"stopped\"}]}" } },
        .{ .respond = .{ .body = cfg_body } },
        .{ .respond = .{ .body = snippets_present } },
    });
    defer g.deinit();
    var fake: FakeRunner = .{ .arena = a };
    const identity = try std.fmt.allocPrint(a, "{s}/.ssh/id_ed25519", .{g.h.env.get("HOME").?});
    try fake.expect(&.{
        "/usr/bin/ssh", "-i",                identity, "-o",                     "IdentitiesOnly=yes", "-o",                           "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o",           "ConnectTimeout=10", "-o",     "ServerAliveInterval=10", "root@192.168.1.10",  try ssh.placeScript(a, s.name),
    }, s.text, .{ .stdout = try std.fmt.allocPrint(a, "written\n{s}  {s}/{s}\n", .{ s.sha256, vendor.snippets_dir, s.name }) });
    g.h.hooks.runner = fake.runner();

    try testing.expectEqual(Exit.usage, g.h.run(&root, "template build web-01"));
    try testing.expectEqual(Exit.ok, g.h.run(&root, "template build ubuntu-2604 -y"));
    try fake.done();
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/storage/local/download-url HTTP/1.1", g.request(4));
    try testing.expectEqualStrings("GET /api2/json/nodes/pve/tasks/UPID%3Apve%3A0006B482%3A00B442ED%3A6ACA1C3A%3Aqmcreate%3A9000%3Aartoo%40pve%21cli%3A/log?start=0&limit=500 HTTP/1.1", g.request(6));
    // Not a terminal: the task log's newest line, once, while the step runs.
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, g.h.stderr(), "  · fetch image  512.00 MiB of 1.20 GiB (41.67%)\n"));
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu HTTP/1.1", g.request(8));
    const create = g.body(8);
    for ([_][]const u8{
        "vmid=9001&name=ubuntu-2604&description=Built%20by%20artoo",
        "&tags=artoo-template&ostype=l26&machine=q35&cpu=host&cores=1&memory=1024&scsihw=virtio-scsi-single",
        "&scsi0=local-zfs%3A0%2Cimport-from%3Dlocal%3Aimport%2Fubuntu-26.04-20260927-amd64.qcow2%2Cdiscard%3Don%2Ciothread%3D1%2Cssd%3D1",
        "&ide2=local-zfs%3Acloudinit&boot=order%3Dscsi0&net0=virtio%2Cbridge%3Dvmbr0",
        "&serial0=socket&vga=serial0&cicustom=vendor%3Dlocal%3Asnippets%2Fartoo-vendor-",
    }) |want| {
        if (std.mem.find(u8, create, want) == null) {
            std.debug.print("missing: {s}\n--- body:\n{s}\n", .{ want, create });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqualStrings("POST /api2/json/nodes/pve/qemu/9001/template HTTP/1.1", g.request(10));
    const out = g.h.stdout();
    for ([_][]const u8{
        "Plan · Build template ubuntu-2604 (Ubuntu 26.04, build 20260927)\n",
        "✓ fetch image           done",
        "✓ place vendor snippet  done  written",
        "✓ create VM from image  done",
        "✓ convert to template   done",
        "✓ template ubuntu-2604 (9001) is ready",
    }) |line| {
        if (std.mem.find(u8, out, line) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
            return error.TestUnexpectedResult;
        }
    }
}

test "template build: current template is a no-op; foreign VM or other image refused" {
    var g: testkit.Gateway = undefined;
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = &images.pins[0];
    const s = try vendor.render(a, p.codename, "artoo");
    const snippets_present = try std.fmt.allocPrint(a, "{{\"data\":[{{\"volid\":\"local:snippets/{s}\",\"size\":{d}}}]}}", .{ s.name, s.text.len });
    const list = "{\"data\":[{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"template\":1}]}";
    const cfg_current = try std.fmt.allocPrint(a, "{{\"data\":{{\"tags\":\"artoo-template\",\"cicustom\":\"vendor=local:snippets/{s}\",\"description\":\"image: {s}\\nvendor: {s}\\n\"}}}}", .{ s.name, p.file, s.name });
    try g.init(&.{
        .{ .respond = .{ .body = image_cmd.present_body } },
        .{ .respond = .{ .body = snippets_present } },
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = cfg_current } },
        .{ .respond = .{ .body = image_cmd.present_body } },
        .{ .respond = .{ .body = snippets_present } },
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = "{\"data\":{\"tags\":\"web\"}}" } },
        .{ .respond = .{ .body = image_cmd.present_body } },
        .{ .respond = .{ .body = snippets_present } },
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = "{\"data\":{\"tags\":\"artoo-template\",\"description\":\"image: ubuntu-26.04-20260401-amd64.qcow2\\n\"}}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.refused, g.h.run(&root, "template build ubuntu-2604 -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "nothing to change") != null);
    try testing.expectEqual(Exit.refused, g.h.run(&root, "template build ubuntu-2604 -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "was not built by artoo") != null);
    try testing.expectEqual(Exit.refused, g.h.run(&root, "template build ubuntu-2604 -y"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "was built from image ubuntu-26.04-20260401-amd64.qcow2") != null);
    try testing.expectEqual(@as(usize, 12), g.sent());
}

test "template rm: only templates, destructive, verified gone" {
    var g: testkit.Gateway = undefined;
    const list = "{\"data\":[{\"vmid\":100,\"name\":\"web-01\",\"status\":\"running\"},{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"template\":1,\"status\":\"stopped\"}]}";
    try g.init(&.{
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = upid_body } },
        .{ .respond = .{ .body = task_ok } },
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":100,\"name\":\"web-01\"}]}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.refused, g.h.run(&root, "template rm web-01 --yes --confirm web-01"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "is a VM, not a template") != null);
    try testing.expectEqual(Exit.ok, g.h.run(&root, "template rm ubuntu-2604 --yes --confirm ubuntu-2604"));
    try testing.expectEqualStrings("DELETE /api2/json/nodes/pve/qemu/9000?purge=1&destroy-unreferenced-disks=1 HTTP/1.1", g.request(2));
}

test "template show: memory with a unit" {
    var g: testkit.Gateway = undefined;
    const list = "{\"data\":[{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"template\":1,\"status\":\"stopped\"}]}";
    const cfg = "{\"data\":{\"tags\":\"artoo-template\",\"cores\":1,\"memory\":\"1024\"}}";
    try g.init(&.{
        .{ .respond = .{ .body = list } },
        .{ .respond = .{ .body = cfg } },
        .{ .respond = .{ .body = cfg } },
        .{ .respond = .{ .body = "{\"data\":[]}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "template show ubuntu-2604"));
    const out = g.h.stdout();
    const at = std.mem.find(u8, out, "  Memory ") orelse return error.TestUnexpectedResult;
    const line = out[at..][0 .. std.mem.findScalar(u8, out[at..], '\n') orelse return error.TestUnexpectedResult];
    try testing.expect(std.mem.endsWith(u8, line, " 1.0 GiB"));
}

test "template vendor: the rendered snippet, named by its hash" {
    var h = try testkit.Harness.init();
    defer h.deinit();
    try h.env.put("HOME", "/nonexistent-artoo-home");
    try testing.expectEqual(Exit.ok, h.run(&root, "template vendor"));
    try testing.expect(std.mem.startsWith(u8, h.stdout(), "#cloud-config\n"));
    try testing.expect(std.mem.startsWith(u8, h.stderr(), "# artoo-vendor-"));
    try testing.expectEqual(Exit.usage, h.run(&root, "template vendor ubuntu-2404"));
}
