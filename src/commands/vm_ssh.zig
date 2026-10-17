//! `artoo vm ssh-config` and `artoo vm cp` (SPEC §9.10): plain ssh, scp
//! and rsync as strict as `vm ssh`, and copies as the guest user to, from or
//! between guests with a SHA-256 check on the far side. Neither writes as
//! root nor reaches Proxmox or UniFi.

const std = @import("std");
const Io = std.Io;
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const files = @import("../files.zig");
const proc = @import("../proc.zig");
const exposure = @import("../exposure.zig");
const known_hosts = @import("../guest/known_hosts.zig");
const ssh_config = @import("../guest/ssh_config.zig");
const life = @import("vm_life.zig");
const template = @import("template.zig");
const k = @import("node.zig");

const Context = app.Context;
const Value = std.json.Value;

pub fn path(ctx: *Context) ![]const u8 {
    return files.expandHome(ctx.arena, ctx.env, ssh_config.default_path) catch
        ctx.fail(error.ConfigInvalid, "HOME is not set; cannot locate {s}", .{ssh_config.default_path});
}

/// The settings every block shares, from the config.
pub fn settings(ctx: *Context) !ssh_config.Settings {
    const cfg = try ctx.config();
    const public = files.expandHome(ctx.arena, ctx.env, cfg.guests.ssh_public_key) catch
        return ctx.fail(error.ConfigInvalid, "cannot expand guests.ssh_public_key: HOME is not set", .{});
    const identity = std.mem.cutSuffix(u8, public, ".pub") orelse
        return ctx.fail(error.ConfigInvalid, "guests.ssh_public_key '{s}' does not end in .pub; cannot name its private key", .{cfg.guests.ssh_public_key});
    const s: ssh_config.Settings = .{
        .domain = cfg.guests.domain,
        .user = cfg.guests.user,
        .identity = identity,
        .known_hosts = try known_hosts.path(ctx),
        .proxy = try known_hosts.proxyCommand(ctx),
    };
    for ([_][]const u8{ s.identity, s.known_hosts, s.domain }) |v| {
        if (!ssh_config.plainValue(v)) return ctx.fail(error.ConfigInvalid, "'{s}' cannot be written to {s} (no spaces or quotes)", .{ v, ssh_config.default_path });
    }
    return s;
}

/// An artoo guest: tagged `artoo`, named, not a template.
pub fn isGuest(v: vms.Vm) bool {
    return !v.template and v.name.len > 0 and template.taggedWith(v.tags, "artoo");
}

/// The guest's address: the static `ipconfig0`, else the agent's first
/// IPv4 (as `vm ssh`); null when neither is known.
fn addressOf(c: *pve.Client, v: vms.Vm, cfg: Value) !?[]const u8 {
    if (life.staticAddress(cfg)) |a| return a;
    if (!v.running()) return null;
    if (!(agent.ping(c, v.vmid) catch false)) return null;
    const list = vms.agentAddresses(c, v.vmid) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return null,
    };
    for (list) |ad| if (!ad.ipv6) return ad.address;
    return null;
}

fn readKnownHosts(ctx: *Context) ![]const u8 {
    return Io.Dir.cwd().readFileAlloc(ctx.io, try known_hosts.path(ctx), ctx.arena, .limited(1 << 20)) catch |err| switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        else => "",
    };
}

fn hasAlias(text: []const u8, alias: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        const first = line[0 .. std.mem.findScalar(u8, line, ' ') orelse line.len];
        if (std.mem.eql(u8, first, alias)) return true;
    }
    return false;
}

/// Pin the guest's host key from the guest agent (SPEC §9.3 step 7).
fn pinKey(c: *pve.Client, v: vms.Vm) !void {
    const ctx = c.ctx;
    const key = try known_hosts.keyOf(ctx.arena, try agent.readFile(c, v.vmid, known_hosts.host_key_file)) orelse
        return ctx.fail(error.Refused, "{s} has no usable {s}", .{ v.name, known_hosts.host_key_file });
    try known_hosts.record(ctx, v.name, key);
}

pub const Host = struct {
    name: []const u8,
    vmid: u32,
    hostname: ?[]const u8,
    jump: bool,
    pinned: bool,
};

const Collected = struct {
    hosts: []const Host,
    blocks: []const ssh_config.Block,
    notes: []const []const u8,
    /// Some guest is not usable over plain ssh.
    partial: bool,
};

/// Every artoo guest in `list` as a block. `pin`: running guests with no
/// pinned key are pinned through the guest agent first.
fn collect(c: *pve.Client, list: []const vms.Vm, pin: bool) !Collected {
    const ctx = c.ctx;
    const a = ctx.arena;
    const kh = try readKnownHosts(ctx);
    var hosts: std.ArrayList(Host) = .empty;
    var blocks: std.ArrayList(ssh_config.Block) = .empty;
    var notes: std.ArrayList([]const u8) = .empty;
    var partial = false;
    for (list) |v| {
        if (!isGuest(v)) continue;
        if (!ssh_config.validName(v.name)) {
            try notes.append(a, try std.fmt.allocPrint(a, "{d}: the name '{s}' cannot be an ssh Host; left out", .{ v.vmid, try k.clean(ctx, v.name) }));
            partial = true;
            continue;
        }
        const cfg = try vms.config(c, v.vmid);
        const address = try addressOf(c, v, cfg);
        const jump = known_hosts.wantsJump(pve.str(cfg, "tags") orelse v.tags);
        var pinned = hasAlias(kh, v.name);
        if (!pinned and pin and v.running()) {
            if (pinKey(c, v)) {
                pinned = true;
                try notes.append(a, try std.fmt.allocPrint(a, "{s}: host key pinned from the guest agent", .{v.name}));
            } else |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => {
                    try notes.append(a, try std.fmt.allocPrint(a, "{s}: host key not pinned: {s}", .{ v.name, ctx.diag orelse @errorName(err) }));
                    ctx.diag = null;
                },
            }
        }
        const usable = if (address) |ad| ssh_config.validAddress(ad) else false;
        try hosts.append(a, .{ .name = v.name, .vmid = v.vmid, .hostname = if (usable) address else null, .jump = jump, .pinned = pinned });
        if (!usable) {
            try notes.append(a, try std.fmt.allocPrint(a, "{s}: no address known ({s}); left out", .{ v.name, v.status }));
            partial = true;
            continue;
        }
        try blocks.append(a, .{ .name = v.name, .address = address.?, .jump = jump });
        if (!pinned) {
            try notes.append(a, try std.fmt.allocPrint(a, "{s}: host key not pinned; ssh refuses it until 'artoo vm ssh {s}' pins it", .{ v.name, v.name }));
            partial = true;
        }
    }
    return .{ .hosts = hosts.items, .blocks = blocks.items, .notes = notes.items, .partial = partial };
}

fn readFile(ctx: *Context, p: []const u8) ![]const u8 {
    return Io.Dir.cwd().readFileAlloc(ctx.io, p, ctx.arena, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => "",
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        else => ctx.fail(error.Io, "cannot read {s}", .{ctx.tilde(p)}),
    };
}

fn write(ctx: *Context, p: []const u8, text: []const u8) !void {
    const dir = std.fs.path.dirname(p).?;
    files.ensurePrivateDir(ctx.io, dir) catch |err| return switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        else => ctx.fail(error.Io, "cannot create {s}", .{ctx.tilde(dir)}),
    };
    files.atomicWrite(ctx.io, ctx.arena, p, text) catch |err| return switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        error.UnsafePath => ctx.fail(error.UnsafePath, "{s} is a symlink; refusing to write it", .{ctx.tilde(p)}),
        else => ctx.fail(error.Io, "cannot write {s}", .{ctx.tilde(p)}),
    };
}

/// Whether the operator's ssh reads the file: `ssh -G ALIAS` (opens no
/// connection) shows `hostkeyalias ALIAS`. Null when ssh could not say.
fn includeState(ctx: *Context, alias: []const u8) !?bool {
    const runner = ctx.test_hooks.runner orelse proc.Runner{};
    const r = runner.run(ctx.io, ctx.arena, &.{ "/usr/bin/ssh", "-G", alias }, null) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return null,
    };
    if (r.code == null or r.code.? != 0) return null;
    return ssh_config.includeActive(r.stdout, alias);
}

/// Whether the file exists: `vm new`, `vm rm` and `vm set` keep it current
/// only once the operator has made it (`vm ssh-config`).
pub fn present(ctx: *Context) !bool {
    return files.exists(ctx.io, try path(ctx));
}

/// Replace (or with null, remove) one guest's block; the other blocks stay.
pub fn put(ctx: *Context, name: []const u8, block: ?ssh_config.Block) !void {
    const p = try path(ctx);
    const text = try readFile(ctx, p);
    const next = try ssh_config.update(ctx.arena, text, try settings(ctx), name, block);
    if (!std.mem.eql(u8, text, next)) try write(ctx, p, next);
}

/// Whether the file has a block for `name`.
pub fn hasBlock(ctx: *Context, name: []const u8) !bool {
    return ssh_config.hasBlock(ctx.arena, try readFile(ctx, try path(ctx)), name);
}

/// The block for a guest from its config (for `vm new` and `vm set`).
pub fn blockOf(name: []const u8, cfg: Value) ?ssh_config.Block {
    const address = life.staticAddress(cfg) orelse return null;
    if (!ssh_config.validName(name) or !ssh_config.validAddress(address)) return null;
    return .{ .name = name, .address = address, .jump = known_hosts.wantsJump(pve.str(cfg, "tags") orelse "") };
}

// ---------------------------------------------------------------- ssh-config

pub const ssh_config_cmd = struct {
    pub const name = "ssh-config";
    pub const summary = "Write ~/.artoo/ssh_config so plain ssh, scp and rsync are as strict as vm ssh";
    pub const details =
        \\One Host block per artoo guest (the VM name and its machine name) with
        \\vm ssh's settings: the guest's address, guests.user, your key only, host
        \\keys from ~/.artoo/known_hosts under the VM name, strict checking, and
        \\the Proxmox jump for guests tagged ssh-jump. Running guests with no
        \\pinned key are pinned through the guest agent first. artoo never edits
        \\~/.ssh/config: add 'Include ~/.artoo/ssh_config' there once, above the
        \\first Host or Match line. vm new and vm rm keep the file current.
        \\-n prints the file and writes nothing.
    ;
    pub const examples = [_][]const u8{ "artoo vm ssh-config", "artoo vm ssh-config -n", "ssh bespin  # once the Include is in place" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const s = try settings(ctx);
        const dry = ctx.globals.dry_run;
        const got = try collect(&c, try vms.list(&c), !dry);
        const text = try ssh_config.render(ctx.arena, s, got.blocks);
        const p = try path(ctx);
        const changed = !std.mem.eql(u8, try readFile(ctx, p), text);
        if (!dry and changed) try write(ctx, p, text);
        const include: ?bool = if (got.blocks.len > 0) try includeState(ctx, got.blocks[0].name) else null;
        const state = if (dry) "dry-run" else if (changed) "written" else "unchanged";

        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .local, .{ .path = ctx.tilde(p), .state = state, .include = include, .hosts = got.hosts }, .{ .notes = got.notes });
        } else if (dry) {
            try ctx.out.writeAll(text);
            for (got.notes) |n| try ctx.err.print("artoo: {s}\n", .{n});
        } else {
            const pal = ctx.ui.palette;
            try ctx.out.print("{s}: {d} guest{s}, {s}\n", .{ ctx.tilde(p), got.blocks.len, if (got.blocks.len == 1) "" else "s", state });
            for (got.notes) |n| try ctx.out.print("  {s}{s} {s}{s}\n", .{ pal.on(.muted), ctx.ui.glyphs.dot, n, pal.off(.muted) });
            if (include) |on| {
                if (!on) try ctx.out.print("\nNot in effect for plain ssh yet: add this line to ~/.ssh/config, above the\nfirst Host or Match line:\n\n  Include {s}\n", .{ssh_config.default_path});
            } else if (got.blocks.len > 0) {
                try ctx.out.print("\nInclude not checked ('ssh -G {s}' failed).\n", .{got.blocks[0].name});
            }
        }
        if (got.partial) return ctx.fail(error.Partial, "some guests are not usable over plain ssh (see the notes)", .{});
    }
};

// ---------------------------------------------------------------- cp

/// One side of a copy (SPEC §9.10).
pub const Side = union(enum) {
    local: []const u8,
    remote: Remote,

    pub const Remote = struct {
        /// The word before `:` (VM name or VMID).
        host: []const u8,
        /// Absolute, or relative to the guest user's home ("" = home); `~/` removed.
        path: []const u8,
        /// Set once resolved.
        guest: ?Guest = null,
    };
};

/// `VM:PATH` when the word has a `:` with no `/` before it (scp's rule);
/// otherwise a local path.
pub fn parseSide(ctx: *Context, word: []const u8) !Side {
    if (word.len == 0) return ctx.fail(error.Usage, "empty path", .{});
    if (std.mem.findAny(u8, word, "\n\r\x00") != null) return ctx.fail(error.Usage, "paths with a newline cannot be copied", .{});
    if (std.ascii.startsWithIgnoreCase(word, "scp://")) return ctx.fail(error.Refused, "use VM:PATH, not an scp:// URI", .{});
    const colon = std.mem.findScalar(u8, word, ':') orelse return .{ .local = word };
    if (std.mem.findScalar(u8, word[0..colon], '/') != null) return .{ .local = word };
    const host = word[0..colon];
    var p = word[colon + 1 ..];
    if (host.len == 0) return ctx.fail(error.Usage, "'{s}' names no VM (write ./{s} for a local path)", .{ word, word });
    if (std.mem.findScalar(u8, host, '@') != null) return ctx.fail(error.Refused, "vm cp copies as the guest user (guests.user) only: write VM:PATH without user@", .{});
    if (std.mem.eql(u8, p, "~")) {
        p = "";
    } else if (std.mem.cutPrefix(u8, p, "~/")) |rest| {
        p = rest;
    } else if (p.len > 0 and p[0] == '~') {
        return ctx.fail(error.Refused, "'{s}': ~user paths are not supported; paths are absolute or relative to the guest user's home", .{word});
    }
    if (std.mem.findAny(u8, p, "*?[") != null) return ctx.fail(error.Usage, "'{s}': no wildcards — one source, one target, one checksum", .{word});
    return .{ .remote = .{ .host = host, .path = p } };
}

/// A resolved remote side.
const Guest = struct {
    vm: vms.Vm,
    address: []const u8,
    jump: bool,
};

const Kind = enum { none, file, dir };

/// Fixed remote commands: the path arrives on stdin, never in the command
/// line; `sh -c` because guests' login shell is fish.
const probe_script = "sh -c 'IFS= read -r p; if [ -d \"$p\" ]; then echo dir; elif [ -e \"$p\" ] || [ -L \"$p\" ]; then echo file; else echo none; fi'";
const hash_script = "sh -c 'IFS= read -r p; exec sha256sum -- \"$p\"'";
const tree_script = "sh -c 'IFS= read -r p; cd -- \"$p\" && exec find -L . -type f -exec sha256sum -- {} +'";

const Copy = struct {
    ctx: *Context,
    src: Side,
    dst: Side,

    fn guestOf(_: *const Copy, side: Side) ?Guest {
        return switch (side) {
            .local => null,
            .remote => |r| r.guest,
        };
    }

    fn display(cp: *const Copy, side: Side, p: []const u8) ![]const u8 {
        return switch (side) {
            .local => p,
            .remote => std.fmt.allocPrint(cp.ctx.arena, "{s}:{s}", .{ cp.guestOf(side).?.vm.name, p }),
        };
    }

    /// Run a fixed script on a guest over SSH with `p` on stdin.
    fn remote(cp: *const Copy, g: Guest, script: []const u8, p: []const u8) !proc.Result {
        const ctx = cp.ctx;
        const argv = try known_hosts.sshArgv(ctx, g.vm.name, g.address, true, g.jump, &.{script});
        const runner = ctx.test_hooks.runner orelse proc.Runner{};
        const r = runner.run(ctx.io, ctx.arena, argv, try std.fmt.allocPrint(ctx.arena, "{s}\n", .{p})) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            error.NotFound => return ctx.fail(error.Network, "/usr/bin/ssh not found", .{}),
            error.Failed => return ctx.fail(error.Network, "ssh to {s} failed to run", .{g.vm.name}),
        };
        if (r.code == null or r.code.? == 255) return ctx.fail(error.Network, "ssh to {s} failed: {s}", .{ g.vm.name, firstLine(r.stderr) });
        return r;
    }

    fn probe(cp: *const Copy, side: Side, p: []const u8) !Kind {
        const ctx = cp.ctx;
        switch (side) {
            .local => {
                const st = Io.Dir.cwd().statFile(ctx.io, p, .{}) catch |err| switch (err) {
                    error.FileNotFound => return .none,
                    error.Canceled => return error.Canceled,
                    else => return ctx.fail(error.Io, "cannot read {s}: {t}", .{ p, err }),
                };
                return if (st.kind == .directory) .dir else .file;
            },
            .remote => {
                if (p.len == 0) return .dir;
                const g = cp.guestOf(side).?;
                const r = try cp.remote(g, probe_script, p);
                const word = std.mem.trim(u8, r.stdout, " \r\n");
                if (r.code.? == 0) {
                    if (std.mem.eql(u8, word, "dir")) return .dir;
                    if (std.mem.eql(u8, word, "file")) return .file;
                    if (std.mem.eql(u8, word, "none")) return .none;
                }
                return ctx.fail(error.Protocol, "cannot check {s}:{s}: {s}", .{ g.vm.name, p, firstLine(r.stderr) });
            },
        }
    }

    fn hashOne(cp: *const Copy, side: Side, p: []const u8) ![64]u8 {
        const ctx = cp.ctx;
        switch (side) {
            .local => {
                const f = Io.Dir.cwd().openFile(ctx.io, p, .{}) catch |err| return ctx.fail(error.Io, "cannot read {s}: {t}", .{ p, err });
                defer f.close(ctx.io);
                return hashFile(ctx, f, p);
            },
            .remote => {
                const g = cp.guestOf(side).?;
                const r = try cp.remote(g, hash_script, p);
                if (r.code.? != 0) return ctx.fail(error.Protocol, "sha256sum on {s} failed: {s}", .{ g.vm.name, firstLine(r.stderr) });
                return hexOf(r.stdout) orelse ctx.fail(error.Protocol, "sha256sum on {s} printed no checksum", .{g.vm.name});
            },
        }
    }

    fn hashTree(cp: *const Copy, side: Side, p: []const u8) ![]const Sum {
        const ctx = cp.ctx;
        switch (side) {
            .local => {
                var out: std.ArrayList(Sum) = .empty;
                var dir = Io.Dir.cwd().openDir(ctx.io, p, .{ .iterate = true }) catch |err| return ctx.fail(error.Io, "cannot read {s}: {t}", .{ p, err });
                defer dir.close(ctx.io);
                try walk(ctx, dir, "", &out, 0);
                return out.items;
            },
            .remote => {
                const g = cp.guestOf(side).?;
                const r = try cp.remote(g, tree_script, p);
                if (r.code.? != 0) return ctx.fail(error.Protocol, "listing {s}:{s} failed: {s}", .{ g.vm.name, p, firstLine(r.stderr) });
                return parseSums(ctx.arena, r.stdout);
            },
        }
    }
};

pub const Sum = struct { path: []const u8, sha256: []const u8 };

fn hexOf(line: []const u8) ?[64]u8 {
    if (line.len < 64) return null;
    var out: [64]u8 = undefined;
    for (line[0..64], &out) |ch, *o| {
        if (!std.ascii.isHex(ch)) return null;
        o.* = std.ascii.toLower(ch);
    }
    if (line.len > 64 and line[64] != ' ') return null;
    return out;
}

/// `sha256sum` lines (`HEX  ./rel`) → sums by relative path.
pub fn parseSums(arena: std.mem.Allocator, text: []const u8) ![]const Sum {
    var out: std.ArrayList(Sum) = .empty;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        // An escaped name (`\HEX  ./a\nb`) never matches a plain one.
        const body = if (line.len > 0 and line[0] == '\\') line[1..] else line;
        const hex = hexOf(body) orelse continue;
        if (body.len < 66) continue;
        var rel = body[66..];
        if (std.mem.cutPrefix(u8, rel, "./")) |r| rel = r;
        try out.append(arena, .{ .path = try arena.dupe(u8, if (body.ptr == line.ptr) rel else try std.fmt.allocPrint(arena, "\\{s}", .{rel})), .sha256 = try arena.dupe(u8, &hex) });
    }
    return out.items;
}

fn hashFile(ctx: *Context, f: Io.File, display: []const u8) ![64]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [64 * 1024]u8 = undefined;
    while (true) {
        const n = f.readStreaming(ctx.io, &.{buf[0..]}) catch |err| switch (err) {
            error.EndOfStream => break,
            error.Canceled => return error.Canceled,
            else => return ctx.fail(error.Io, "cannot read {s}: {t}", .{ display, err }),
        };
        h.update(buf[0..n]);
    }
    return std.fmt.bytesToHex(h.finalResult(), .lower);
}

/// Every regular file under `dir`, following symbolic links as scp -r and
/// `find -L` do.
fn walk(ctx: *Context, dir: Io.Dir, prefix: []const u8, out: *std.ArrayList(Sum), depth: usize) !void {
    if (depth > 40) return ctx.fail(error.Usage, "{s}: directories nested too deep (a symbolic link loop?)", .{prefix});
    var it = dir.iterate();
    while (it.next(ctx.io) catch |err| return ctx.fail(error.Io, "cannot list {s}: {t}", .{ prefix, err })) |e| {
        const rel = if (prefix.len == 0) try ctx.arena.dupe(u8, e.name) else try std.fmt.allocPrint(ctx.arena, "{s}/{s}", .{ prefix, e.name });
        var kind = e.kind;
        if (kind == .sym_link or kind == .unknown) {
            const st = dir.statFile(ctx.io, e.name, .{}) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => continue, // dangling: find -L skips it too
            };
            kind = st.kind;
        }
        switch (kind) {
            .directory => {
                var sub = dir.openDir(ctx.io, e.name, .{ .iterate = true }) catch |err| return ctx.fail(error.Io, "cannot list {s}: {t}", .{ rel, err });
                defer sub.close(ctx.io);
                try walk(ctx, sub, rel, out, depth + 1);
            },
            .file => {
                const f = dir.openFile(ctx.io, e.name, .{}) catch |err| return ctx.fail(error.Io, "cannot read {s}: {t}", .{ rel, err });
                defer f.close(ctx.io);
                const hex = try hashFile(ctx, f, rel);
                try out.append(ctx.arena, .{ .path = rel, .sha256 = try ctx.arena.dupe(u8, &hex) });
            },
            else => {},
        }
    }
}

/// Source files missing or different on the target ("" when all match).
/// Extra target files (a merge with --force) are not the copy's.
pub fn compare(arena: std.mem.Allocator, src: []const Sum, dst: []const Sum) ![]const []const u8 {
    var by: std.StringHashMapUnmanaged([]const u8) = .empty;
    for (dst) |s| try by.put(arena, s.path, s.sha256);
    var bad: std.ArrayList([]const u8) = .empty;
    for (src) |s| {
        const other = by.get(s.path) orelse {
            try bad.append(arena, try std.fmt.allocPrint(arena, "{s} (missing)", .{s.path}));
            continue;
        };
        if (!std.mem.eql(u8, other, s.sha256)) try bad.append(arena, try std.fmt.allocPrint(arena, "{s} (differs)", .{s.path}));
    }
    std.mem.sort([]const u8, bad.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    return bad.items;
}

fn firstLine(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \r\n");
    return t[0 .. std.mem.findScalar(u8, t, '\n') orelse t.len];
}

/// `name` of `p` without trailing slashes; null for `.`, `..` and home.
fn baseName(p: []const u8) ?[]const u8 {
    const t = std.mem.trimEnd(u8, p, "/");
    if (t.len == 0) return null;
    const b = std.fs.path.basename(t);
    if (b.len == 0 or std.mem.eql(u8, b, ".") or std.mem.eql(u8, b, "..")) return null;
    return b;
}

fn joinPath(arena: std.mem.Allocator, dir: []const u8, name: []const u8) ![]const u8 {
    if (dir.len == 0) return arena.dupe(u8, name);
    if (dir[dir.len - 1] == '/') return std.fmt.allocPrint(arena, "{s}{s}", .{ dir, name });
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ dir, name });
}

/// Shell-quoted for display (`-n`).
fn quoted(arena: std.mem.Allocator, argv: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (argv, 0..) |w, i| {
        if (i > 0) try out.append(arena, ' ');
        const plain = w.len > 0 and for (w) |ch| {
            if (!(std.ascii.isAlphanumeric(ch) or std.mem.findScalar(u8, "/._-:~@%+=,", ch) != null)) break false;
        } else true;
        if (plain) {
            try out.appendSlice(arena, w);
            continue;
        }
        try out.append(arena, '\'');
        for (w) |ch| {
            if (ch == '\'') try out.appendSlice(arena, "'\\''") else try out.append(arena, ch);
        }
        try out.append(arena, '\'');
    }
    return out.items;
}

pub const cp_cmd = struct {
    pub const name = "cp";
    pub const summary = "Copy a file or tree as the guest user to, from or between guests (SHA-256 checked)";
    pub const details =
        \\One side or both are VM:PATH (a VM name or VMID of a running artoo guest;
        \\a word with a / before its first : is local, so ./a:b is a local path).
        \\Remote paths are absolute or relative to the guest user's home. Copies run as it
        \\only (no sudo, no root destinations) through scp with ~/.artoo/ssh_config,
        \\which is rewritten first; guest to guest is relayed through this machine
        \\(scp -3), because the fences block SSH between guests. An existing
        \\target is refused without --force. Afterwards the SHA-256 of what was
        \\copied is compared on the far side; a mismatch exits 8. -n prints the
        \\target and the scp command and copies nothing.
    ;
    pub const flags = [_]cli.Flag{
        .{ .long = "recursive", .short = 'r', .help = "Copy a directory tree" },
        .{ .long = "force", .help = "Overwrite an existing target (or copy into an existing tree)" },
    };
    pub const positionals = [_]cli.Positional{
        .{ .name = "SRC", .complete = .file, .help = "Local path or VM:PATH" },
        .{ .name = "DST", .complete = .file, .help = "Local path or VM:PATH" },
    };
    pub const examples = [_][]const u8{
        "artoo vm cp zig-out/bin/tool naboo:bin/",
        "artoo vm cp scarif:/var/log/syslog .",
        "artoo vm cp -r bespin:site naboo:site --force",
        "artoo vm cp -n ./release.tar.gz naboo:",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const a = ctx.arena;
        var copy: Copy = .{ .ctx = ctx, .src = try parseSide(ctx, args.pos("SRC")), .dst = try parseSide(ctx, args.pos("DST")) };
        if (copy.src == .local and copy.dst == .local) return ctx.fail(error.Usage, "both sides are local: use cp (one side must be VM:PATH)", .{});
        const cfg = try ctx.config();
        for ([_]Side{ copy.src, copy.dst }) |side| {
            if (side != .remote) continue;
            const h = side.remote.host;
            if (exposure.protected(cfg, h, h) != null)
                return ctx.fail(error.Refused, "'{s}' is the Proxmox host or the gateway: vm cp reaches artoo guests only (no override)", .{h});
        }
        const s = try settings(ctx);
        const p = try path(ctx);

        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const list = try vms.list(&c);
        const kh = try readKnownHosts(ctx);
        if (copy.src == .remote) copy.src.remote.guest = try resolveGuest(&c, list, copy.src.remote.host, kh);
        if (copy.dst == .remote) copy.dst.remote.guest = try resolveGuest(&c, list, copy.dst.remote.host, kh);

        const recursive = args.has("recursive");
        const src_path = switch (copy.src) {
            .local => |x| x,
            .remote => |r| r.path,
        };
        const dst_path = switch (copy.dst) {
            .local => |x| x,
            .remote => |r| r.path,
        };
        const src_kind = try copy.probe(copy.src, src_path);
        if (src_kind == .none) return ctx.fail(error.NotFound, "{s} does not exist", .{try copy.display(copy.src, src_path)});
        if (src_kind == .dir and !recursive) return ctx.fail(error.Usage, "{s} is a directory: add -r", .{try copy.display(copy.src, src_path)});
        const base = baseName(src_path) orelse return ctx.fail(error.Usage, "name a file or directory to copy, not '{s}'", .{try copy.display(copy.src, src_path)});

        const dst_kind = try copy.probe(copy.dst, dst_path);
        const target = if (dst_kind == .dir) try joinPath(a, dst_path, base) else dst_path;
        const target_kind = if (dst_kind == .dir) try copy.probe(copy.dst, target) else dst_kind;
        const shown = try copy.display(copy.dst, target);
        if (target_kind != .none) {
            if ((target_kind == .dir) != (src_kind == .dir))
                return ctx.fail(error.Refused, "{s} exists and is a {s}; the source is a {s}", .{ shown, if (target_kind == .dir) "directory" else "file", if (src_kind == .dir) "directory" else "file" });
            if (!args.has("force"))
                return ctx.fail(error.Refused, "{s} exists: add --force to {s}", .{ shown, if (target_kind == .dir) "copy into it" else "overwrite it" });
        }

        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(a, &.{ "/usr/bin/scp", "-F", p, "-p" });
        if (recursive) try argv.append(a, "-r");
        if (copy.src == .remote and copy.dst == .remote) try argv.append(a, "-3");
        try argv.append(a, "--");
        try argv.append(a, try scpWord(&copy, copy.src));
        try argv.append(a, try scpWord(&copy, copy.dst));

        const got = try collect(&c, list, false);
        const text = try ssh_config.render(a, s, got.blocks);
        const stale = !std.mem.eql(u8, try readFile(ctx, p), text);

        if (ctx.globals.dry_run) {
            if (ctx.json()) return ui.json.envelope(ctx.out, .local, .{ .source = try copy.display(copy.src, src_path), .target = shown, .scp = argv.items, .ssh_config = if (stale) "would be rewritten" else "current", .result = "dry-run" }, .{});
            try ctx.out.print("target  {s}{s}\nscp     {s}\n", .{ shown, if (target_kind != .none) " (exists; --force)" else "", try quoted(a, argv.items) });
            if (stale) try ctx.out.print("        ({s} is rewritten first)\n", .{ctx.tilde(p)});
            try ctx.out.writeAll("\nDry run: nothing was copied.\n");
            return;
        }
        if (stale) try write(ctx, p, text);

        try ctx.out.flush();
        try ctx.err.flush();
        const code: ?u8 = if (ctx.test_hooks.runner) |r|
            (r.run(ctx.io, a, argv.items, null) catch |err| return scpFailed(ctx, err)).code
        else
            proc.runInherited(ctx.io, argv.items) catch |err| return scpFailed(ctx, err);
        if (code == null) return ctx.fail(error.Interrupted, "scp was stopped; {s} may be incomplete", .{shown});
        if (code.? != 0) return ctx.fail(error.Network, "scp failed (exit {d}); {s} may be incomplete and was not verified", .{ code.?, shown });

        // Verify on the far side.
        var sums: []const Sum = &.{};
        if (src_kind == .dir) {
            const want = copy.hashTree(copy.src, src_path) catch |err| return notVerified(ctx, shown, err);
            const have = copy.hashTree(copy.dst, target) catch |err| return notVerified(ctx, shown, err);
            const bad = try compare(a, want, have);
            if (bad.len > 0) return ctx.fail(error.Partial, "copied to {s}, but {d} file(s) do not match: {s}", .{ shown, bad.len, try std.mem.join(a, ", ", bad) });
            sums = want;
        } else {
            const want = copy.hashOne(copy.src, src_path) catch |err| return notVerified(ctx, shown, err);
            const have = copy.hashOne(copy.dst, target) catch |err| return notVerified(ctx, shown, err);
            if (!std.mem.eql(u8, &want, &have)) return ctx.fail(error.Partial, "copied to {s}, but its SHA-256 {s} differs from the source's {s}", .{ shown, &have, &want });
            sums = try a.dupe(Sum, &.{.{ .path = base, .sha256 = try a.dupe(u8, &want) }});
        }
        const where = if (copy.guestOf(copy.dst)) |g| g.vm.name else "this machine";
        if (ctx.json()) return ui.json.envelope(ctx.out, .local, .{ .source = try copy.display(copy.src, src_path), .target = shown, .files = sums, .verified = true }, .{});
        const pal = ctx.ui.palette;
        if (src_kind == .dir) {
            try ctx.out.print("{d} file{s} copied to {s}\n", .{ sums.len, if (sums.len == 1) "" else "s", shown });
        } else {
            try ctx.out.print("{s}  {s}\n", .{ sums[0].sha256, shown });
        }
        try ctx.out.print("{s}{s}{s} SHA-256 matches on {s}\n", .{ pal.on(.ok), ctx.ui.glyphs.ok, pal.off(.ok), where });
    }
};

fn scpWord(copy: *const Copy, side: Side) ![]const u8 {
    return switch (side) {
        .local => |x| x,
        .remote => |r| std.fmt.allocPrint(copy.ctx.arena, "{s}:{s}", .{ copy.guestOf(side).?.vm.name, r.path }),
    };
}

fn scpFailed(ctx: *Context, err: proc.Error) anyerror {
    return switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        error.NotFound => ctx.fail(error.Network, "/usr/bin/scp not found", .{}),
        error.Failed => ctx.fail(error.Network, "scp failed to run", .{}),
    };
}

fn notVerified(ctx: *Context, shown: []const u8, err: anyerror) anyerror {
    switch (err) {
        error.OutOfMemory, error.Canceled => return err,
        else => {},
    }
    const why = ctx.diag orelse @errorName(err);
    return ctx.fail(error.Partial, "copied to {s}, but not verified: {s}", .{ shown, why });
}

/// A running artoo guest with a pinned host key (pinned now if missing,
/// except under -n).
fn resolveGuest(c: *pve.Client, list: []const vms.Vm, word: []const u8, kh: []const u8) !Guest {
    const ctx = c.ctx;
    const v = switch (try vms.find(list, ctx.arena, word)) {
        .vm => |v| v,
        .missing => return ctx.fail(error.NotFound, "no VM '{s}' on Proxmox", .{word}),
        .ambiguous => |all| {
            var names: std.ArrayList([]const u8) = .empty;
            for (all) |x| try names.append(ctx.arena, try std.fmt.allocPrint(ctx.arena, "{d}", .{x.vmid}));
            return ctx.fail(error.Usage, "'{s}' matches several VMs ({s}); use the VMID", .{ word, try std.mem.join(ctx.arena, ", ", names.items) });
        },
    };
    if (v.template) return ctx.fail(error.Refused, "{s} is a template", .{word});
    if (!isGuest(v)) return ctx.fail(error.Refused, "{s} is not an artoo guest (tag artoo)", .{word});
    if (!ssh_config.validName(v.name)) return ctx.fail(error.Refused, "the name '{s}' cannot be an ssh host", .{try k.clean(ctx, v.name)});
    if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first", .{ v.name, v.status });
    const cfg = try vms.config(c, v.vmid);
    const address = try addressOf(c, v, cfg) orelse return ctx.fail(error.Refused, "no address known for {s}", .{v.name});
    if (!ssh_config.validAddress(address)) return ctx.fail(error.Refused, "{s} has no usable IPv4 address", .{v.name});
    if (!hasAlias(kh, v.name)) {
        if (ctx.globals.dry_run) return ctx.fail(error.Refused, "the host key of {s} is not pinned yet; run without -n (it pins it through the guest agent) or 'artoo vm ssh {s}'", .{ v.name, v.name });
        try pinKey(c, v);
        try ctx.err.print("artoo: pinned the host key of {s} from the guest agent\n", .{v.name});
    }
    return .{ .vm = v, .address = address, .jump = known_hosts.wantsJump(pve.str(cfg, "tags") orelse v.tags) };
}

pub const commands = [_]cli.Command{
    cli.leaf(ssh_config_cmd),
    cli.leaf(cp_cmd),
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const FakeRunner = @import("../secrets/common.zig").FakeRunner;
const R = testkit.Gateway.FakeServer.Route;

fn route(match: []const u8, body: []const u8) R {
    return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
}

const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIGb8kQvYwZp1n0Xo3m2cJ6d0n8wY1u5wQ7q8zT3kQ2rS";
const hello_sum = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
const world_sum = "e258d248fda94c63753607f7c4494ee0fcbe92f1a76bfdac795c9d84101eb317";

const guests_list =
    \\{"data":[{"vmid":200,"name":"bespin","status":"running","tags":"artoo;role-edge;ssh-jump"},
    \\ {"vmid":201,"name":"naboo","status":"running","tags":"artoo"},
    \\ {"vmid":202,"name":"hoth","status":"stopped","tags":"artoo"},
    \\ {"vmid":150,"name":"other","status":"running","tags":"web"},
    \\ {"vmid":9000,"name":"ubuntu-2604","status":"stopped","template":1,"tags":"artoo-template"}]}
;
const bespin_cfg = "{\"data\":{\"tags\":\"artoo;role-edge;ssh-jump\",\"ipconfig0\":\"ip=192.168.1.200/24,gw=192.168.1.1\"}}";
const naboo_cfg = "{\"data\":{\"tags\":\"artoo\",\"ipconfig0\":\"ip=192.168.1.230/24,gw=192.168.1.1\"}}";
const hoth_cfg = "{\"data\":{\"tags\":\"artoo\",\"ipconfig0\":\"ip=192.168.1.231/24,gw=192.168.1.1\"}}";

fn sideOf(word: []const u8) !Side {
    var h = try testkit.Harness.init();
    defer h.deinit();
    var ctx: Context = .{ .arena = h.arena.allocator(), .gpa = testing.allocator, .io = testing.io, .out = &h.out.writer, .err = &h.err.writer, .env = &h.env };
    return parseSide(&ctx, word);
}

test "parseSide: scp's rule, home-relative paths, refusals" {
    const r = try sideOf("naboo:bin/x");
    try testing.expectEqualStrings("naboo", r.remote.host);
    try testing.expectEqualStrings("bin/x", r.remote.path);
    try testing.expectEqualStrings("", (try sideOf("naboo:")).remote.path);
    try testing.expectEqualStrings("", (try sideOf("naboo:~")).remote.path);
    try testing.expectEqualStrings("x/y", (try sideOf("naboo:~/x/y")).remote.path);
    try testing.expectEqualStrings("/opt/a", (try sideOf("201:/opt/a")).remote.path);
    try testing.expectEqualStrings("./a:b", (try sideOf("./a:b")).local);
    try testing.expectEqualStrings("dir/a:b", (try sideOf("dir/a:b")).local);
    try testing.expectEqualStrings("file", (try sideOf("file")).local);
    try testing.expectError(error.Usage, sideOf(":x"));
    try testing.expectError(error.Refused, sideOf("artoo@naboo:x"));
    try testing.expectError(error.Refused, sideOf("scp://naboo/x"));
    try testing.expectError(error.Refused, sideOf("naboo:~bob/x"));
    try testing.expectError(error.Usage, sideOf("naboo:*.log"));
    try testing.expectError(error.Usage, sideOf("a\nb"));
}

test "parseSums, compare, baseName, quoted" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sums = try parseSums(a, hello_sum ++ "  ./a\n" ++ world_sum ++ "  ./d/b c\nnoise\n");
    try testing.expectEqual(@as(usize, 2), sums.len);
    try testing.expectEqualStrings("d/b c", sums[1].path);
    try testing.expectEqualStrings(world_sum, sums[1].sha256);
    try testing.expectEqual(@as(usize, 0), (try compare(a, sums, &.{ sums[1], sums[0], .{ .path = "extra", .sha256 = hello_sum } })).len);
    const bad = try compare(a, sums, &.{.{ .path = "a", .sha256 = world_sum }});
    try testing.expectEqual(@as(usize, 2), bad.len);
    try testing.expectEqualStrings("a (differs)", bad[0]);
    try testing.expectEqualStrings("d/b c (missing)", bad[1]);
    try testing.expectEqualStrings("x", baseName("dir/x/").?);
    try testing.expect(baseName("") == null and baseName("/") == null and baseName("a/..") == null);
    try testing.expectEqualStrings("/usr/bin/scp -- 'a b' 'it'\\''s' naboo:x", try quoted(a, &.{ "/usr/bin/scp", "--", "a b", "it's", "naboo:x" }));
}

test "vm ssh-config: one block per artoo guest; pins a running guest; an unpinned stopped one is partial" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&[_]R{
        route("/nodes/pve/qemu ", guests_list),
        route("/qemu/200/config ", bespin_cfg),
        route("/qemu/201/config ", naboo_cfg),
        route("/qemu/202/config ", hoth_cfg),
        route("/qemu/201/agent/file-read", "{\"data\":{\"content\":\"ssh-ed25519 " ++ blob ++ " root@naboo\\n\"}}"),
    });
    defer g.deinit();
    const home = g.h.env.get("HOME").?;
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/known_hosts", .data = "bespin ssh-ed25519 " ++ blob ++ "\n" });
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(&.{ "/usr/bin/ssh", "-G", "bespin" }, null, .{ .stdout = "user artoo\nport 22\n" });
    g.h.hooks.runner = fake.runner();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});

    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm ssh-config"));
    try fake.done();
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const text = try g.tmp.dir.readFileAlloc(testing.io, ".artoo/ssh_config", a, .limited(1 << 16));
    const s: ssh_config.Settings = .{
        .domain = "lab.example.com",
        .user = "artoo",
        .identity = try std.fmt.allocPrint(a, "{s}/.ssh/id_ed25519", .{home}),
        .known_hosts = try std.fmt.allocPrint(a, "{s}/.artoo/known_hosts", .{home}),
        .proxy = try std.fmt.allocPrint(a, "/usr/bin/ssh -i {s}/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -W %h:%p root@192.168.1.10", .{home}),
    };
    try testing.expectEqualStrings(try ssh_config.render(a, s, &.{
        .{ .name = "bespin", .address = "192.168.1.200", .jump = true },
        .{ .name = "naboo", .address = "192.168.1.230", .jump = false },
        .{ .name = "hoth", .address = "192.168.1.231", .jump = false },
    }), text);
    const kh = try g.tmp.dir.readFileAlloc(testing.io, ".artoo/known_hosts", a, .limited(1 << 16));
    try testing.expect(std.mem.find(u8, kh, "naboo ssh-ed25519 " ++ blob) != null);
    const out = g.h.stdout();
    for ([_][]const u8{
        "~/.artoo/ssh_config: 3 guests, written\n",
        "naboo: host key pinned from the guest agent",
        "hoth: host key not pinned; ssh refuses it until 'artoo vm ssh hoth' pins it",
        "  Include ~/.artoo/ssh_config\n",
    }) |want| {
        if (std.mem.find(u8, out, want) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ want, out });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expect(std.mem.find(u8, out, "other") == null and std.mem.find(u8, out, "ubuntu-2604") == null);
}

/// `ssh` argv for a fixed script on naboo (`vm cp`'s probes and hashes).
fn nabooSsh(a: std.mem.Allocator, home: []const u8, script: []const u8) ![]const []const u8 {
    return a.dupe([]const u8, &.{
        "/usr/bin/ssh",      "-o",                        "HostKeyAlias=naboo", "-o",            try std.fmt.allocPrint(a, "UserKnownHostsFile={s}/.artoo/known_hosts", .{home}),
        "-o",                "StrictHostKeyChecking=yes", "-o",                 "BatchMode=yes", "-o",
        "ConnectTimeout=10", "artoo@192.168.1.230",       "--",                 script,
    });
}

const cp_list =
    \\{"data":[{"vmid":201,"name":"naboo","status":"running","tags":"artoo"},
    \\ {"vmid":150,"name":"other","status":"running","tags":"web"}]}
;

fn cpRoutes(lists: usize, configs: usize) ![]const R {
    var out: std.ArrayList(R) = .empty;
    for (0..lists) |_| try out.append(testing.allocator, route("/nodes/pve/qemu ", cp_list));
    for (0..configs) |_| try out.append(testing.allocator, route("/qemu/201/config ", naboo_cfg));
    return out.toOwnedSlice(testing.allocator);
}

test "vm cp: Mac to guest — probes, scp with the rendered config, checksum on the far side" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // A copy reads the list, the guest's config, then every guest's; a
    // refusal stops after the first config.
    const routes = try cpRoutes(3, 5);
    defer testing.allocator.free(routes);
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes);
    defer g.deinit();
    const home = g.h.env.get("HOME").?;
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/known_hosts", .data = "naboo ssh-ed25519 " ++ blob ++ "\n" });
    const src = try g.file("holocron", "hello\n");
    const cfg_path = try std.fmt.allocPrint(a, "{s}/.artoo/ssh_config", .{home});
    const scp = &[_][]const u8{ "/usr/bin/scp", "-F", cfg_path, "-p", "--", src, "naboo:bin/" };
    var fake: FakeRunner = .{ .arena = a };
    // 1: copied and verified.
    try fake.expect(try nabooSsh(a, home, probe_script), "bin/\n", .{ .stdout = "dir\n" });
    try fake.expect(try nabooSsh(a, home, probe_script), "bin/holocron\n", .{ .stdout = "none\n" });
    try fake.expect(scp, null, .{});
    try fake.expect(try nabooSsh(a, home, hash_script), "bin/holocron\n", .{ .stdout = hello_sum ++ "  bin/holocron\n" });
    // 2: the target exists now — refused without --force.
    try fake.expect(try nabooSsh(a, home, probe_script), "bin/\n", .{ .stdout = "dir\n" });
    try fake.expect(try nabooSsh(a, home, probe_script), "bin/holocron\n", .{ .stdout = "file\n" });
    // 3: --force, but the far side differs — exit 8.
    try fake.expect(try nabooSsh(a, home, probe_script), "bin/\n", .{ .stdout = "dir\n" });
    try fake.expect(try nabooSsh(a, home, probe_script), "bin/holocron\n", .{ .stdout = "file\n" });
    try fake.expect(scp, null, .{});
    try fake.expect(try nabooSsh(a, home, hash_script), "bin/holocron\n", .{ .stdout = world_sum ++ "  bin/holocron\n" });
    g.h.hooks.runner = fake.runner();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});

    try testing.expectEqual(Exit.ok, g.h.runArgs(&root, &.{ "vm", "cp", src, "naboo:bin/" }));
    try testing.expectEqualStrings(hello_sum ++ "  naboo:bin/holocron\n✓ SHA-256 matches on naboo\n", g.h.stdout());
    const text = try g.tmp.dir.readFileAlloc(testing.io, ".artoo/ssh_config", a, .limited(1 << 16));
    try testing.expect(std.mem.find(u8, text, "Host naboo naboo.lab.example.com\n  HostName 192.168.1.230\n") != null);

    try testing.expectEqual(Exit.refused, g.h.runArgs(&root, &.{ "vm", "cp", src, "naboo:bin/" }));
    try testing.expectEqualStrings("artoo: naboo:bin/holocron exists: add --force to overwrite it\n", g.h.stderr());

    try testing.expectEqual(Exit.partial, g.h.runArgs(&root, &.{ "vm", "cp", src, "naboo:bin/", "--force" }));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "copied to naboo:bin/holocron, but its SHA-256 " ++ world_sum ++ " differs from the source's " ++ hello_sum) != null);
    try fake.done();
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

test "vm cp: refusals before anything runs; -n prints the scp command" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const routes = try cpRoutes(1, 2);
    defer testing.allocator.free(routes);
    var g: testkit.Gateway = undefined;
    try g.initRoutes(routes);
    defer g.deinit();
    const home = g.h.env.get("HOME").?;
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/known_hosts", .data = "naboo ssh-ed25519 " ++ blob ++ "\n" });
    const out_path = try std.fmt.allocPrint(a, "{s}/out", .{home});
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(try nabooSsh(a, home, probe_script), "notes.txt\n", .{ .stdout = "file\n" });
    g.h.hooks.runner = fake.runner();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});

    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm cp pve:/etc/x ."));
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm cp ./x 192.168.1.1:/x"));
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm cp ./x root@naboo:/x"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm cp ./a ./b"));
    try testing.expectEqual(@as(usize, 0), g.sent());

    try testing.expectEqual(Exit.ok, g.h.runArgs(&root, &.{ "vm", "cp", "-n", "naboo:notes.txt", out_path }));
    try fake.done();
    try testing.expectEqualStrings(try std.fmt.allocPrint(a,
        \\target  {s}
        \\scp     /usr/bin/scp -F {s}/.artoo/ssh_config -p -- naboo:notes.txt {s}
        \\        (~/.artoo/ssh_config is rewritten first)
        \\
        \\Dry run: nothing was copied.
        \\
    , .{ out_path, home, out_path }), g.h.stdout());
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expect(!try files.exists(testing.io, try std.fmt.allocPrint(a, "{s}/.artoo/ssh_config", .{home})));
}

test "vm cp: guest to guest is relayed (-3); trees are compared file by file" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const list =
        \\{"data":[{"vmid":200,"name":"bespin","status":"running","tags":"artoo;role-edge;ssh-jump"},
        \\ {"vmid":201,"name":"naboo","status":"running","tags":"artoo"}]}
    ;
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&[_]R{
        route("/nodes/pve/qemu ", list),
        route("/qemu/200/config ", bespin_cfg),
        route("/qemu/201/config ", naboo_cfg),
        route("/qemu/200/config ", bespin_cfg),
        route("/qemu/201/config ", naboo_cfg),
    });
    defer g.deinit();
    const home = g.h.env.get("HOME").?;
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/known_hosts", .data = "bespin ssh-ed25519 " ++ blob ++ "\nnaboo ssh-ed25519 " ++ blob ++ "\n" });
    const proxy = try std.fmt.allocPrint(a, "ProxyCommand=/usr/bin/ssh -i {s}/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -W %h:%p root@192.168.1.10", .{home});
    const kh = try std.fmt.allocPrint(a, "UserKnownHostsFile={s}/.artoo/known_hosts", .{home});
    const ds = struct {
        fn argv(al: std.mem.Allocator, khv: []const u8, px: []const u8, script: []const u8) ![]const []const u8 {
            return al.dupe([]const u8, &.{ "/usr/bin/ssh", "-o", "HostKeyAlias=bespin", "-o", khv, "-o", "StrictHostKeyChecking=yes", "-o", px, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "artoo@192.168.1.200", "--", script });
        }
    };
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(try ds.argv(a, kh, proxy, probe_script), "site\n", .{ .stdout = "dir\n" });
    try fake.expect(try nabooSsh(a, home, probe_script), "site\n", .{ .stdout = "none\n" });
    try fake.expect(&.{ "/usr/bin/scp", "-F", try std.fmt.allocPrint(a, "{s}/.artoo/ssh_config", .{home}), "-p", "-r", "-3", "--", "bespin:site", "naboo:site" }, null, .{});
    try fake.expect(try ds.argv(a, kh, proxy, tree_script), "site\n", .{ .stdout = hello_sum ++ "  ./index.html\n" ++ world_sum ++ "  ./css/a.css\n" });
    try fake.expect(try nabooSsh(a, home, tree_script), "site\n", .{ .stdout = world_sum ++ "  ./css/a.css\n" ++ hello_sum ++ "  ./index.html\n" });
    g.h.hooks.runner = fake.runner();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm cp -r bespin:site naboo:site"));
    try fake.done();
    try testing.expectEqualStrings("2 files copied to naboo:site\n✓ SHA-256 matches on naboo\n", g.h.stdout());
}

test "vm cp: a local tree is hashed by artoo, following symbolic links" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "t/sub");
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "t/a", .data = "hello\n" });
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "t/sub/b", .data = "world\n" });
    try tmp.dir.symLink(testing.io, "sub", "t/link", .{ .is_directory = true });
    var h = try testkit.Harness.init();
    defer h.deinit();
    var ctx: Context = .{ .arena = a, .gpa = testing.allocator, .io = testing.io, .out = &h.out.writer, .err = &h.err.writer, .env = &h.env };
    const copy: Copy = .{ .ctx = &ctx, .src = .{ .local = "" }, .dst = .{ .local = "" } };
    const root_path = try std.fmt.allocPrint(a, "{s}/t", .{try tmp.dir.realPathFileAlloc(testing.io, ".", a)});
    const sums = try copy.hashTree(.{ .local = root_path }, root_path);
    const want = try parseSums(a, hello_sum ++ "  ./a\n" ++ world_sum ++ "  ./sub/b\n" ++ world_sum ++ "  ./link/b\n");
    try testing.expectEqual(@as(usize, 3), sums.len);
    try testing.expectEqual(@as(usize, 0), (try compare(a, want, sums)).len);
}
