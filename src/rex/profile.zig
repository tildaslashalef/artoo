//! The agent profile and the permission kind it carries
//!: a workstation directory loaded and checked, the guest's side
//! read by one agent exec, a plan of writes, the writes, and the
//! `rex status` rows "profile" and "permissions".
//!
//! Order for `rex setup` (step 9): `loadConfigured` (or `load`) before the
//! plan — it refuses; `read` and `plan` for the confirmation; after the
//! earlier steps ran, `apply`, which reads the guest again and re-plans so
//! the merges keep what `rex skill setup` and the agy bridge just wrote.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Value = std.json.Value;
const app = @import("../app.zig");
const files = @import("../files.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const agent = @import("../pve/agent.zig");
const edge = @import("../commands/edge.zig");
const edge_files = @import("../edge/files.zig");
const vm_new = @import("../commands/vm_new.zig");
const guest_mod = @import("guest.zig");
const permissions = @import("permissions.zig");

const Context = app.Context;
pub const Kind = permissions.Kind;
pub const kindOf = permissions.kindOf;
pub const Check = vm_new.Check;

/// Limits.
pub const max_file_bytes: usize = 1 << 20;
pub const max_profile_bytes: usize = 4 << 20;
pub const max_files: usize = 500;

/// The manifest of copied files on the guest, home-relative.
pub const manifest_path = ".config/artoo/agent-profile.json";

/// A JSON file merged rather than copied.
pub const Merge = enum {
    claude_settings,
    agy_settings,
    agy_hooks,

    /// Home-relative guest path.
    pub fn target(m: Merge) []const u8 {
        return switch (m) {
            .claude_settings => ".claude/settings.json",
            .agy_settings => ".gemini/antigravity-cli/settings.json",
            .agy_hooks => ".gemini/config/hooks.json",
        };
    }
};

/// One guest file from the profile.
pub const Entry = struct {
    /// Profile-relative path ("skills/demo/SKILL.md").
    source: []const u8,
    /// Home-relative guest path (".claude/skills/demo/SKILL.md").
    target: []const u8,
    content: []const u8,
    exec: bool = false,
    merge: ?Merge = null,
    /// Written only when `agy` is on the guest user's PATH.
    agy_only: bool = false,

    pub fn mode(e: Entry) []const u8 {
        return if (e.exec) "0755" else "0644";
    }
};

pub const Profile = struct {
    /// The expanded workstation directory.
    dir: []const u8,
    /// Sorted by target.
    entries: []const Entry,
    /// Profile files read (a file mapped twice counts once).
    files: usize,
    bytes: usize,
};

// ---------------------------------------------------------------- load

/// `agents.profile` from the config, loaded; null when it is empty.
pub fn loadConfigured(ctx: *Context) !?Profile {
    const cfg = try ctx.config();
    if (cfg.agents.profile.len == 0) return null;
    return try load(ctx, cfg.agents.profile);
}

/// Load the profile at `configured` (a path; `~` is the workstation's
/// home). Every refusal is `error.Refused`, naming the file
/// and never its content.
pub fn load(ctx: *Context, configured: []const u8) !Profile {
    const a = ctx.arena;
    const io = ctx.io;
    const dir_path = files.expandHome(a, ctx.env, configured) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.HomeUnknown => return ctx.fail(error.Refused, "agents.profile {s}: HOME is not set", .{configured}),
    };
    var dir = Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.NotDir => return ctx.fail(error.Refused, "agents.profile {s} is not a directory", .{dir_path}),
        error.FileNotFound => return ctx.fail(error.Refused, "agents.profile {s} does not exist", .{dir_path}),
        else => return ctx.fail(error.Refused, "agents.profile {s} cannot be opened ({s})", .{ dir_path, @errorName(err) }),
    };
    defer dir.close(io);

    var b: Builder = .{ .ctx = ctx, .dir = dir_path };
    var w = try dir.walkSelectively(a);
    defer w.deinit();
    while (true) {
        const e = (w.next(io) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            else => return ctx.fail(error.Refused, "agents.profile {s} cannot be read ({s})", .{ dir_path, @errorName(err) }),
        }) orelse break;
        switch (try b.classify(e)) {
            .skip => {},
            .enter => w.enter(io, e) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Canceled => return error.Canceled,
                else => return ctx.fail(error.Refused, "agents.profile: {s} cannot be read ({s})", .{ e.path, @errorName(err) }),
            },
            .file => |m| try b.add(e, m),
        }
    }
    std.mem.sort(Entry, b.entries.items, {}, struct {
        fn lt(_: void, x: Entry, y: Entry) bool {
            return std.mem.lessThan(u8, x.target, y.target);
        }
    }.lt);
    return .{ .dir = dir_path, .entries = b.entries.items, .files = b.files, .bytes = b.bytes };
}

/// Where a profile file goes.
const Mapping = union(enum) {
    /// rules/AGENTS.md.
    rules,
    /// skills/NAME/** (the path below skills/).
    skill: []const u8,
    /// claude/** other than settings.json (the path below claude/).
    claude: []const u8,
    /// agy/** other than the merged files (the path below agy/).
    agy: []const u8,
    merge: Merge,
};

const Class = union(enum) { skip, enter, file: Mapping };

const Builder = struct {
    ctx: *Context,
    dir: []const u8,
    entries: std.ArrayList(Entry) = .empty,
    files: usize = 0,
    bytes: usize = 0,

    fn refuse(b: *Builder, path: []const u8, comptime why: []const u8, args: anytype) anyerror {
        const a = b.ctx.arena;
        const shown = try ui.text.sanitize(a, path, .line);
        return b.ctx.fail(error.Refused, "agents.profile {s}: {s} is refused (" ++ why ++ "); remove it from the profile", .{ b.dir, shown } ++ args);
    }

    fn classify(b: *Builder, e: Io.Dir.Walker.Entry) !Class {
        const name = e.basename;
        if (std.mem.eql(u8, name, ".DS_Store") or std.mem.eql(u8, name, ".git")) return .skip;
        var parts: [3][]const u8 = undefined;
        var it = std.mem.splitScalar(u8, e.path, std.fs.path.sep);
        var n: usize = 0;
        while (it.next()) |p| : (n += 1) if (n < parts.len) {
            parts[n] = p;
        };
        const top = parts[0];
        const area = for ([_][]const u8{ "rules", "skills", "claude", "agy" }) |x| {
            if (std.mem.eql(u8, top, x)) break true;
        } else false;
        if (!area) return .skip;
        const rest = e.path[top.len + @min(1, e.path.len - top.len) ..];
        // Inside the mapped areas, only directories and regular files.
        const mapped: ?Mapping = blk: {
            if (n == 1) break :blk null; // the area itself
            if (std.mem.eql(u8, top, "rules")) {
                if (n == 2 and std.mem.eql(u8, name, "AGENTS.md")) break :blk .rules;
                return .skip;
            }
            if (std.mem.eql(u8, top, "skills")) {
                if (n == 2 and e.kind != .directory and e.kind != .sym_link) return .skip; // not a skill
                if (std.mem.eql(u8, parts[1], "rex")) return .skip; // `rex skill setup` owns it
                break :blk .{ .skill = rest };
            }
            if (std.mem.eql(u8, top, "claude")) {
                if (n == 2 and std.mem.eql(u8, name, "README.md")) return .skip;
                if (n == 2 and std.mem.eql(u8, name, "settings.json")) break :blk .{ .merge = .claude_settings };
                break :blk .{ .claude = rest };
            }
            if (n == 2 and std.mem.eql(u8, name, "settings.json")) break :blk .{ .merge = .agy_settings };
            if (n == 2 and std.mem.eql(u8, name, "hooks.json")) break :blk .{ .merge = .agy_hooks };
            break :blk .{ .agy = rest };
        };
        switch (e.kind) {
            .directory => return if (mapped == null or mapped.? != .rules) .enter else b.refuse(e.path, "not a regular file", .{}),
            .file => return if (mapped) |m| .{ .file = m } else .skip,
            .sym_link => return b.refuse(e.path, "a symbolic link", .{}),
            else => return b.refuse(e.path, "not a regular file", .{}),
        }
    }

    fn add(b: *Builder, e: Io.Dir.Walker.Entry, m: Mapping) !void {
        const ctx = b.ctx;
        const a = ctx.arena;
        const path = try a.dupe(u8, e.path);
        const name = e.basename;
        if (refusedName(name)) |why| return b.refuse(path, "{s}", .{why});
        const st = e.dir.statFile(ctx.io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return b.refuse(path, "cannot be read: {s}", .{@errorName(err)}),
        };
        if (st.kind == .sym_link) return b.refuse(path, "a symbolic link", .{});
        if (st.kind != .file) return b.refuse(path, "not a regular file", .{});
        if (st.size > max_file_bytes) return b.refuse(path, "over 1 MiB", .{});
        const content = e.dir.readFileAlloc(ctx.io, name, a, .limited(max_file_bytes + 1)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            error.StreamTooLong => return b.refuse(path, "over 1 MiB", .{}),
            else => return b.refuse(path, "cannot be read: {s}", .{@errorName(err)}),
        };
        if (std.mem.find(u8, content, "PRIVATE KEY") != null) return b.refuse(path, "it contains a private key", .{});
        b.files += 1;
        b.bytes += content.len;
        if (b.files > max_files) return ctx.fail(error.Refused, "agents.profile {s} holds over {d} files; a profile is at most {d}", .{ b.dir, max_files, max_files });
        if (b.bytes > max_profile_bytes) return ctx.fail(error.Refused, "agents.profile {s} is over 4 MiB", .{b.dir});
        const exec = blk: {
            if (!Io.File.Permissions.has_executable_bit) break :blk false;
            break :blk st.permissions.toMode() & 0o111 != 0;
        };
        const base: Entry = .{ .source = path, .target = "", .content = content, .exec = exec };
        switch (m) {
            .rules => {
                try b.put(base, ".claude/CLAUDE.md", false);
                try b.put(base, ".gemini/config/AGENTS.md", true);
            },
            .skill => |rest| {
                try b.put(base, try std.fmt.allocPrint(a, ".claude/skills/{s}", .{rest}), false);
                try b.put(base, try std.fmt.allocPrint(a, ".gemini/config/skills/{s}", .{rest}), true);
            },
            .claude => |rest| try b.put(base, try std.fmt.allocPrint(a, ".claude/{s}", .{rest}), false),
            .agy => |rest| try b.put(base, try std.fmt.allocPrint(a, ".gemini/config/{s}", .{rest}), false),
            .merge => |mg| {
                const v = std.json.parseFromSliceLeaky(Value, a, content, .{ .parse_numbers = false }) catch
                    return b.refuse(path, "not valid JSON", .{});
                if (v != .object) return b.refuse(path, "not a JSON object", .{});
                // Claude's `env` reaches every session: a secret-looking
                // name there is refused (named, never its value).
                if (v.object.get("env")) |env| if (env == .object) for (env.object.keys()) |var_name| {
                    if (secretLooking(var_name)) return b.refuse(path, "its env names {s}, which looks like a secret", .{try ui.text.sanitize(a, var_name, .line)});
                };
                var e2 = base;
                e2.merge = mg;
                e2.exec = false;
                try b.put(e2, mg.target(), false);
            },
        }
    }

    /// Two profile files that land on one guest path refuse the profile
    /// (the run would never settle: each write undoes the other).
    fn put(b: *Builder, base: Entry, target: []const u8, agy_only: bool) !void {
        for (b.entries.items) |other| if (std.mem.eql(u8, other.target, target))
            return b.ctx.fail(error.Refused, "agents.profile: {s} and {s} both become ~/{s}; keep one", .{ try ui.text.sanitize(b.ctx.arena, other.source, .line), try ui.text.sanitize(b.ctx.arena, base.source, .line), target });
        var e = base;
        e.target = target;
        e.agy_only = agy_only;
        try b.entries.append(b.ctx.arena, e);
    }
};

/// An environment variable name that looks like it holds a secret.
fn secretLooking(name: []const u8) bool {
    for ([_][]const u8{ "KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL" }) |w|
        if (std.ascii.findIgnoreCase(name, w) != null) return true;
    return false;
}

/// Why a file name is refused, or null.
pub fn refusedName(name: []const u8) ?[]const u8 {
    for ([_][]const u8{ ".credentials.json", "credentials", "credentials.json", "oauth_creds.json", ".netrc" }) |n|
        if (std.mem.eql(u8, name, n)) return "an agent credential file";
    if (std.mem.eql(u8, name, ".env") or std.mem.eql(u8, name, ".envrc") or std.mem.startsWith(u8, name, ".env.")) return "an environment file";
    for ([_][]const u8{ ".pem", ".key", ".p12", ".pfx" }) |ext|
        if (std.mem.endsWith(u8, name, ext)) return "a key file";
    if (std.mem.startsWith(u8, name, "id_") and !std.mem.endsWith(u8, name, ".pub")) return "an SSH key file";
    return null;
}

// ---------------------------------------------------------------- guest

/// The guest's side of the profile, from one read-only exec.
pub const Guest = struct {
    /// The guest user's home.
    home: []const u8,
    /// On the guest user's PATH.
    claude: bool = false,
    agy: bool = false,
    /// Home-relative target → sha256 hex, "-" absent, "?" not a regular file.
    hashes: std.StringHashMapUnmanaged([]const u8) = .empty,
    /// The manifest's files ("~/.claude/CLAUDE.md" → sha256).
    manifest: std.StringArrayHashMapUnmanaged([]const u8) = .empty,
    /// The manifest as read (null: absent).
    manifest_raw: ?[]const u8 = null,
    /// Current contents of the merged files (null: absent).
    claude_settings: ?[]const u8 = null,
    agy_settings: ?[]const u8 = null,
    agy_hooks: ?[]const u8 = null,
    /// `~/.config/fish/conf.d/artoo-agents.fish` (null: absent).
    fish: ?[]const u8 = null,
    /// Names of the private keys in `~/.ssh` (never their contents).
    ssh_keys: []const []const u8 = &.{},

    pub fn mergedContent(g: Guest, m: Merge) ?[]const u8 {
        return switch (m) {
            .claude_settings => g.claude_settings,
            .agy_settings => g.agy_settings,
            .agy_hooks => g.agy_hooks,
        };
    }
};

/// The probe: `sh -c SCRIPT sh PATH…` (home-relative paths to hash);
/// prints one JSON object. Everything runs as the guest user (`asUser`):
/// the home is the user's to arrange, so root never follows its links —
/// a link to a root-only file reads nothing more than the user could.
/// File contents and names are base64 so the JSON stays valid.
pub fn probeScript(a: Allocator, user: []const u8) ![]const u8 {
    const inner = try std.fmt.allocPrint(a,
        \\set -u
        \\h=$HOME
        \\[ -n "$h" ] || {{ echo "no home for the guest user" >&2; exit 3; }}
        \\b() {{ if [ -f "$1" ]; then printf '"'; base64 -w0 < "$1" | tr -d '\n'; printf '"'; else printf null; fi; }}
        \\hs() {{ if [ -f "$1" ]; then sha256sum < "$1" | cut -d' ' -f1 | tr -d '\n'; elif [ -e "$1" ] || [ -L "$1" ]; then printf '%s' '?'; else printf '%s' -; fi; }}
        \\found=$(for x in claude agy; do command -v "$x" >/dev/null 2>&1 && echo "$x"; done | tr '\n' ' ')
        \\printf '{{"home":"%s","agents":"%s","hashes":[' "$(printf %s "$h" | base64 -w0)" "$found"
        \\sep=
        \\for p in "$@"; do printf '%s"%s"' "$sep" "$(hs "$h/$p")"; sep=,; done
        \\printf '],"manifest":'; b "$h/{s}"
        \\printf ',"claude_settings":'; b "$h/{s}"
        \\printf ',"agy_settings":'; b "$h/{s}"
        \\printf ',"agy_hooks":'; b "$h/{s}"
        \\printf ',"fish":'; b "$h/{s}"
        \\keys=
        \\for f in "$h"/.ssh/*; do
        \\  [ -f "$f" ] || continue
        \\  if head -n 1 "$f" 2>/dev/null | grep -q 'PRIVATE KEY'; then keys="$keys$(basename "$f")
        \\"; fi
        \\done
        \\printf ',"ssh_keys":"%s"}}\n' "$(printf %s "$keys" | base64 -w0)"
        \\
    , .{ manifest_path, Merge.claude_settings.target(), Merge.agy_settings.target(), Merge.agy_hooks.target(), permissions.fish_path });
    return std.fmt.allocPrint(a, "{s} sh \"$@\"", .{try guest_mod.asUser(a, user, inner)});
}

/// Every home-relative path the probe hashes for `profile`.
pub fn probePaths(a: Allocator, profile: ?Profile) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    if (profile) |p| for (p.entries) |e| if (e.merge == null) try list.append(a, e.target);
    return list.items;
}

/// Read the guest's side through the agent: one exec, as root.
pub fn read(ctx: *Context, c: *pve.Client, vmid: u32, user: []const u8, profile: ?Profile) !Guest {
    const a = ctx.arena;
    const paths = try probePaths(a, profile);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ "sh", "-c", try probeScript(a, user), "sh" });
    try argv.appendSlice(a, paths);
    const r = try agent.exec(c, vmid, argv.items, null, 60_000);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading the agent profile of VM {d} failed (exit {?d}): {s}", .{ vmid, r.code, try ui.text.sanitize(a, edge.firstLine(r.err), .line) });
    return parseProbe(a, r.out, paths) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return ctx.fail(error.Protocol, "the agent profile probe of VM {d} returned unexpected output", .{vmid}),
    };
}

/// Parse the probe's JSON; `paths` are the ones it was given, in order.
pub fn parseProbe(a: Allocator, out: []const u8, paths: []const []const u8) !Guest {
    const v = std.json.parseFromSliceLeaky(Value, a, std.mem.trim(u8, out, " \r\n"), .{}) catch return error.BadProbe;
    if (v != .object) return error.BadProbe;
    const o = v.object;
    var g: Guest = .{ .home = try unb64(a, strField(o, "home") orelse return error.BadProbe) };
    if (g.home.len == 0 or g.home[0] != '/') return error.BadProbe;
    var words = std.mem.tokenizeScalar(u8, strField(o, "agents") orelse "", ' ');
    while (words.next()) |w| {
        if (std.mem.eql(u8, w, "claude")) g.claude = true;
        if (std.mem.eql(u8, w, "agy")) g.agy = true;
    }
    const hashes = o.get("hashes") orelse return error.BadProbe;
    if (hashes != .array or hashes.array.items.len != paths.len) return error.BadProbe;
    for (paths, hashes.array.items) |p, h| {
        if (h != .string) return error.BadProbe;
        try g.hashes.put(a, p, h.string);
    }
    g.manifest_raw = try optB64(a, o, "manifest");
    g.claude_settings = try optB64(a, o, "claude_settings");
    g.agy_settings = try optB64(a, o, "agy_settings");
    g.agy_hooks = try optB64(a, o, "agy_hooks");
    g.fish = try optB64(a, o, "fish");
    if (g.manifest_raw) |raw| g.manifest = try parseManifest(a, raw);
    var keys: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.tokenizeScalar(u8, try unb64(a, strField(o, "ssh_keys") orelse ""), '\n');
    while (lines.next()) |l| try keys.append(a, try ui.text.sanitize(a, l, .line));
    g.ssh_keys = keys.items;
    return g;
}

fn strField(o: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = o.get(name) orelse return null;
    return if (v == .string) v.string else null;
}

fn optB64(a: Allocator, o: std.json.ObjectMap, name: []const u8) !?[]const u8 {
    const v = o.get(name) orelse return null;
    return switch (v) {
        .null => null,
        .string => |s| try unb64(a, s),
        else => error.BadProbe,
    };
}

fn unb64(a: Allocator, s: []const u8) ![]const u8 {
    const d = std.base64.standard.Decoder;
    const n = d.calcSizeForSlice(s) catch return error.BadProbe;
    const out = try a.alloc(u8, n);
    d.decode(out, s) catch return error.BadProbe;
    return out;
}

/// `{"files": {PATH: SHA256}}`; anything else is an empty manifest (its
/// files then count as not written by artoo, so they are left alone).
fn parseManifest(a: Allocator, raw: []const u8) !std.StringArrayHashMapUnmanaged([]const u8) {
    var m: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    const v = std.json.parseFromSliceLeaky(Value, a, raw, .{}) catch return m;
    if (v != .object) return m;
    const f = v.object.get("files") orelse return m;
    if (f != .object) return m;
    var it = f.object.iterator();
    while (it.next()) |kv| if (kv.value_ptr.* == .string) try m.put(a, kv.key_ptr.*, kv.value_ptr.string);
    return m;
}

// ---------------------------------------------------------------- merge

/// Merge `profile` into `base`, keeping what only the guest has: objects
/// merge key by key, the profile's value winning on a leaf; arrays are
/// joined (`joinArrays`); the top-level `hooks` merge per event
/// (`mergeHooks`), so Rex's own hooks survive.
pub fn mergeObjects(a: Allocator, base: std.json.ObjectMap, profile: std.json.ObjectMap) !std.json.ObjectMap {
    var out = try copyObject(a, base);
    var it = profile.iterator();
    while (it.next()) |kv| {
        const k = kv.key_ptr.*;
        const pv = kv.value_ptr.*;
        const bv = base.get(k) orelse {
            try out.put(a, k, pv);
            continue;
        };
        if (std.mem.eql(u8, k, "hooks") and bv == .object and pv == .object) {
            try out.put(a, k, .{ .object = try mergeHooks(a, bv.object, pv.object) });
            continue;
        }
        try out.put(a, k, try mergeValues(a, bv, pv));
    }
    return out;
}

/// Below the top level: objects recursive, arrays joined, else the
/// profile's value.
fn mergeValues(a: Allocator, base: Value, profile: Value) !Value {
    if (base == .object and profile == .object) {
        var out = try copyObject(a, base.object);
        var it = profile.object.iterator();
        while (it.next()) |kv| {
            const merged = if (base.object.get(kv.key_ptr.*)) |bv| try mergeValues(a, bv, kv.value_ptr.*) else kv.value_ptr.*;
            try out.put(a, kv.key_ptr.*, merged);
        }
        return .{ .object = out };
    }
    if (base == .array and profile == .array) return .{ .array = try joinArrays(a, base.array, profile.array) };
    return profile;
}

/// The profile's entries first, then the guest's extra ones (an entry
/// added on the guest, such as an "always allow" answer, survives); each
/// value kept once.
fn joinArrays(a: Allocator, base: std.json.Array, profile: std.json.Array) !std.json.Array {
    var out = std.json.Array.init(a);
    for ([_][]const Value{ profile.items, base.items }) |items| for (items) |v| {
        const seen = for (out.items) |o| {
            if (jsonEqual(o, v)) break true;
        } else false;
        if (!seen) try out.append(v);
    };
    return out;
}

/// Equal JSON values: objects regardless of key order; numbers as written.
fn jsonEqual(x: Value, y: Value) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .null => true,
        .bool => |b| b == y.bool,
        .integer => |i| i == y.integer,
        .float => |f| f == y.float,
        .number_string => |n| std.mem.eql(u8, n, y.number_string),
        .string => |t| std.mem.eql(u8, t, y.string),
        .array => |arr| arr.items.len == y.array.items.len and for (arr.items, y.array.items) |e, f| {
            if (!jsonEqual(e, f)) break false;
        } else true,
        .object => |o| o.count() == y.object.count() and blk: {
            var it = o.iterator();
            while (it.next()) |kv| {
                const other = y.object.get(kv.key_ptr.*) orelse break :blk false;
                if (!jsonEqual(kv.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
    };
}

fn mergeHooks(a: Allocator, base: std.json.ObjectMap, profile: std.json.ObjectMap) !std.json.ObjectMap {
    var out = try copyObject(a, base);
    var it = profile.iterator();
    while (it.next()) |kv| {
        const event = kv.key_ptr.*;
        const pv = kv.value_ptr.*;
        const bv = base.get(event);
        if (bv == null or bv.? != .array or pv != .array) {
            try out.put(a, event, pv);
            continue;
        }
        var keys: std.StringHashMapUnmanaged(void) = .empty;
        for (pv.array.items) |e| try keys.put(a, try entryKey(a, e), {});
        var list = std.json.Array.init(a);
        for (bv.?.array.items) |e| if (!keys.contains(try entryKey(a, e))) try list.append(e);
        try list.appendSlice(pv.array.items);
        try out.put(a, event, .{ .array = list });
    }
    return out;
}

/// A hook entry's identity: its command(s) (`command`, and those of its
/// `hooks`); an entry without one is itself.
fn entryKey(a: Allocator, v: Value) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    try commands(a, v, &buf);
    if (buf.items.len > 0) return buf.items;
    return std.json.Stringify.valueAlloc(a, v, .{});
}

fn commands(a: Allocator, v: Value, buf: *std.ArrayList(u8)) !void {
    if (v != .object) return;
    if (v.object.get("command")) |c| if (c == .string) {
        try buf.appendSlice(a, c.string);
        try buf.append(a, '\n');
    };
    if (v.object.get("hooks")) |h| if (h == .array) for (h.array.items) |e| try commands(a, e, buf);
}

fn copyObject(a: Allocator, o: std.json.ObjectMap) !std.json.ObjectMap {
    var out: std.json.ObjectMap = .empty;
    var it = o.iterator();
    while (it.next()) |kv| try out.put(a, kv.key_ptr.*, kv.value_ptr.*);
    return out;
}

const Merged = union(enum) {
    /// The guest file already has it.
    current,
    /// New content to write.
    write: []const u8,
    /// The guest's file is not a JSON object: left alone.
    invalid,
};

/// The merged file for `guest_content` (null: absent) and the profile's
/// `profile_content` (null: none), with the permission kind on top for
/// Claude's settings.
fn mergeFile(a: Allocator, guest_content: ?[]const u8, profile_content: ?[]const u8, kind: ?Kind) !Merged {
    const base: std.json.ObjectMap = if (guest_content) |gc| blk: {
        const v = std.json.parseFromSliceLeaky(Value, a, gc, .{ .parse_numbers = false }) catch return .invalid;
        if (v != .object) return .invalid;
        break :blk v.object;
    } else .empty;
    var result = if (profile_content) |pc| blk: {
        const v = std.json.parseFromSliceLeaky(Value, a, pc, .{ .parse_numbers = false }) catch return .invalid;
        if (v != .object) return .invalid;
        break :blk try mergeObjects(a, base, v.object);
    } else try copyObject(a, base);
    if (kind) |k| try permissions.applyClaude(a, &result, k);
    const before = try std.json.Stringify.valueAlloc(a, Value{ .object = base }, .{});
    const after = try std.json.Stringify.valueAlloc(a, Value{ .object = result }, .{});
    if (guest_content != null and std.mem.eql(u8, before, after)) return .current;
    if (guest_content == null and result.count() == 0) return .current;
    const pretty = try std.json.Stringify.valueAlloc(a, Value{ .object = result }, .{ .whitespace = .indent_2 });
    return .{ .write = try std.fmt.allocPrint(a, "{s}\n", .{pretty}) };
}

// ---------------------------------------------------------------- plan

pub const Write = struct {
    /// Home-relative.
    target: []const u8,
    /// Absolute on the guest.
    path: []const u8,
    mode: []const u8,
    content: []const u8,
    why: []const u8,
    source: Source,

    pub const Source = enum {
        /// A profile file (copied or merged; a merged Claude settings file
        /// also carries the permission kind).
        profile,
        /// The permission kind only (Claude's settings, the fish file).
        permissions,
        manifest,
    };
};

pub const LeftAlone = struct {
    /// "~/.claude/CLAUDE.md".
    path: []const u8,
    why: []const u8,
};

pub const Plan = struct {
    /// The inputs, so `apply` can plan again from a fresh read.
    profile: ?Profile,
    kind: Kind,
    force: bool,
    /// In order; the manifest is last.
    writes: []const Write = &.{},
    /// Profile files the guest already has.
    current: usize = 0,
    /// Changed on the guest (or never written by artoo), or a merged file
    /// that is not JSON there: not written.
    left_alone: []const LeftAlone = &.{},
    /// In the manifest, gone from the profile: left in place.
    dropped: []const []const u8 = &.{},
    /// Rows and notes for `exec.Plan`.
    changes: []const ui.blocks.Change = &.{},
    notes: []const []const u8 = &.{},

    pub fn empty(p: Plan) bool {
        return p.writes.len == 0;
    }

    /// Profile files that would be written ("~/…").
    pub fn behind(p: Plan, a: Allocator) ![]const []const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        for (p.writes) |w| if (w.source == .profile) try list.append(a, try tilde(a, w.target));
        return list.items;
    }
};

fn tilde(a: Allocator, rel: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "~/{s}", .{rel});
}

fn sha256Hex(a: Allocator, data: []const u8) ![]const u8 {
    return edge_files.sha256Hex(a, data);
}

/// File rows shown in the plan before they are summarized.
const max_file_rows = 12;

/// The plan for `guest`. `profile` null applies the
/// permission kind only (no profile set). `force` overwrites files
/// changed on the guest (`--force-profile`).
pub fn plan(a: Allocator, profile: ?Profile, g: Guest, kind: Kind, force: bool) !Plan {
    var writes: std.ArrayList(Write) = .empty;
    var left: std.ArrayList(LeftAlone) = .empty;
    var dropped: std.ArrayList([]const u8) = .empty;
    var manifest: std.StringArrayHashMapUnmanaged([]const u8) = .empty;
    var in_profile: std.StringHashMapUnmanaged(void) = .empty;
    var current: usize = 0;
    var claude_done = false;

    if (profile) |p| for (p.entries) |e| {
        const key = try tilde(a, e.target);
        try in_profile.put(a, key, {});
        if (e.agy_only and !g.agy) {
            if (g.manifest.get(key)) |h| try manifest.put(a, key, h);
            continue;
        }
        if (e.merge) |m| {
            const k: ?Kind = if (m == .claude_settings) kind else null;
            if (m == .claude_settings) claude_done = true;
            switch (try mergeFile(a, g.mergedContent(m), e.content, k)) {
                .current => current += 1,
                .invalid => try left.append(a, .{ .path = key, .why = "not a JSON object on the guest" }),
                .write => |content| try writes.append(a, .{
                    .target = e.target,
                    .path = try abs(a, g.home, e.target),
                    .mode = "0644",
                    .content = content,
                    .why = if (g.mergedContent(m) == null) "new, from the profile" else "merged with the profile",
                    .source = .profile,
                }),
            }
            continue;
        }
        const want = try sha256Hex(a, e.content);
        const have = g.hashes.get(e.target) orelse "-";
        const recorded = g.manifest.get(key);
        if (std.mem.eql(u8, have, want)) {
            current += 1;
            try manifest.put(a, key, want);
            continue;
        }
        // A directory (or other non-file) in the file's place stays, even
        // with --force-profile.
        if (std.mem.eql(u8, have, "?")) {
            try left.append(a, .{ .path = key, .why = "not a regular file on the guest" });
            if (recorded) |h| try manifest.put(a, key, h);
            continue;
        }
        const why: []const u8 = if (std.mem.eql(u8, have, "-"))
            "new"
        else if (recorded != null and std.mem.eql(u8, have, recorded.?))
            "updated from the profile"
        else if (force)
            "overwrites a change on the guest (--force-profile)"
        else {
            try left.append(a, .{ .path = key, .why = if (recorded == null) "not written by artoo" else "changed on the guest" });
            if (recorded) |h| try manifest.put(a, key, h);
            continue;
        };
        try writes.append(a, .{ .target = e.target, .path = try abs(a, g.home, e.target), .mode = e.mode(), .content = e.content, .why = why, .source = .profile });
        try manifest.put(a, key, want);
    };

    // The permission kind, for Claude where it is (on the
    // PATH, or its settings exist), as for agy's fish file below.
    if (!claude_done and (g.claude or g.claude_settings != null)) switch (try mergeFile(a, g.claude_settings, null, kind)) {
        .current => {},
        .invalid => try left.append(a, .{ .path = try tilde(a, Merge.claude_settings.target()), .why = "not a JSON object on the guest; its permissions are not set" }),
        .write => |content| try writes.append(a, .{
            .target = Merge.claude_settings.target(),
            .path = try abs(a, g.home, Merge.claude_settings.target()),
            .mode = "0644",
            .content = content,
            .why = "permission kind",
            .source = .permissions,
        }),
    };
    const fish_want = permissions.fishFile(kind);
    if ((g.agy or g.fish != null) and !(g.fish != null and std.mem.eql(u8, g.fish.?, fish_want)))
        try writes.append(a, .{ .target = permissions.fish_path, .path = try abs(a, g.home, permissions.fish_path), .mode = "0644", .content = fish_want, .why = "permission kind", .source = .permissions });

    // Dropped files and the manifest, last.
    if (profile != null) {
        var it = g.manifest.iterator();
        while (it.next()) |kv| if (!in_profile.contains(kv.key_ptr.*)) try dropped.append(a, kv.key_ptr.*);
        const content = try manifestJson(a, manifest);
        const same = g.manifest_raw != null and std.mem.eql(u8, g.manifest_raw.?, content);
        const nothing = g.manifest_raw == null and manifest.count() == 0;
        if (!same and !nothing) try writes.append(a, .{ .target = manifest_path, .path = try abs(a, g.home, manifest_path), .mode = "0644", .content = content, .why = "records what artoo wrote", .source = .manifest });
    }

    var p: Plan = .{ .profile = profile, .kind = kind, .force = force, .writes = writes.items, .current = current, .left_alone = left.items, .dropped = dropped.items };
    try describe(a, &p, g);
    return p;
}

fn abs(a: Allocator, home: []const u8, rel: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}/{s}", .{ std.mem.trimEnd(u8, home, "/"), rel });
}

/// `{"files": {PATH: SHA256}}`, sorted by path, with a newline.
fn manifestJson(a: Allocator, m: std.StringArrayHashMapUnmanaged([]const u8)) ![]const u8 {
    const keys = try a.dupe([]const u8, m.keys());
    std.mem.sort([]const u8, keys, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);
    var obj: std.json.ObjectMap = .empty;
    for (keys) |k| try obj.put(a, k, .{ .string = m.get(k).? });
    var root: std.json.ObjectMap = .empty;
    try root.put(a, "files", .{ .object = obj });
    const s = try std.json.Stringify.valueAlloc(a, Value{ .object = root }, .{ .whitespace = .indent_2 });
    return std.fmt.allocPrint(a, "{s}\n", .{s});
}

/// Claude's and agy's permission state in words.
fn permissionState(a: Allocator, claude_settings: ?[]const u8, fish: ?[]const u8) ![]const u8 {
    var claude: []const u8 = "Claude asks (its default)";
    if (claude_settings) |s| {
        if (std.json.parseFromSliceLeaky(Value, a, s, .{})) |v| {
            const mode = permissions.defaultMode(v);
            var disabled = false;
            if (v == .object) if (v.object.get("permissions")) |pm| if (pm == .object) if (pm.object.get("disableBypassPermissionsMode")) |d| {
                disabled = d == .string and std.mem.eql(u8, d.string, "disable");
            };
            if (mode != null or disabled) claude = try std.fmt.allocPrint(a, "Claude {s}{s}", .{ mode orelse "default", if (disabled) ", bypass disabled" else "" });
        } else |_| claude = "Claude settings not JSON";
    }
    const agy: []const u8 = if (fish) |f| (if (permissions.fishUnrestricted(f)) "agy --dangerously-skip-permissions" else "agy asks") else "agy asks";
    return std.fmt.allocPrint(a, "{s}; {s}", .{ claude, agy });
}

fn describe(a: Allocator, p: *Plan, g: Guest) !void {
    var changes: std.ArrayList(ui.blocks.Change) = .empty;
    var notes: std.ArrayList([]const u8) = .empty;
    var file_rows: usize = 0;
    var perms_changed = false;
    var claude_after: ?[]const u8 = g.claude_settings;
    var fish_after: ?[]const u8 = g.fish;
    for (p.writes) |w| {
        if (std.mem.eql(u8, w.target, Merge.claude_settings.target())) claude_after = w.content;
        if (std.mem.eql(u8, w.target, permissions.fish_path)) fish_after = w.content;
        switch (w.source) {
            .profile => {
                file_rows += 1;
                if (file_rows > max_file_rows) continue;
                const shown = try ui.text.sanitize(a, try tilde(a, w.target), .line);
                const merged = mergeOf(w.target);
                const absent = if (merged) |m| g.mergedContent(m) == null else std.mem.eql(u8, g.hashes.get(w.target) orelse "-", "-");
                try changes.append(a, .{ .field = if (merged != null) "merge" else "file", .from = if (absent) null else "differs", .to = try std.fmt.allocPrint(a, "{s} ({s})", .{ shown, w.why }) });
            },
            .permissions => perms_changed = true,
            .manifest => {},
        }
    }
    if (file_rows > max_file_rows) try changes.append(a, .{ .field = "file", .from = null, .to = try std.fmt.allocPrint(a, "… and {d} more profile files", .{file_rows - max_file_rows}) });
    const before = try permissionState(a, g.claude_settings, g.fish);
    const after = try permissionState(a, claude_after, fish_after);
    if (perms_changed or !std.mem.eql(u8, before, after))
        try changes.append(a, .{ .field = "permissions", .from = before, .to = try std.fmt.allocPrint(a, "{s}: {s}", .{ p.kind.word(), after }) });
    for (p.writes) |w| if (w.source == .manifest) try changes.append(a, .{ .field = "manifest", .from = if (g.manifest_raw == null) null else "differs", .to = try tilde(a, manifest_path) });
    if (p.left_alone.len > 0) {
        var s: std.ArrayList(u8) = .empty;
        try s.appendSlice(a, "Left alone (");
        try s.appendSlice(a, if (p.force) "not JSON" else "changed on the guest; --force-profile overwrites");
        try s.appendSlice(a, "): ");
        for (p.left_alone, 0..) |l, i| {
            if (i > 0) try s.appendSlice(a, ", ");
            try s.print(a, "{s} ({s})", .{ try ui.text.sanitize(a, l.path, .line), l.why });
        }
        try notes.append(a, s.items);
    }
    if (p.dropped.len > 0) {
        var s: std.ArrayList(u8) = .empty;
        try s.appendSlice(a, "Dropped from the profile, left in place: ");
        for (p.dropped, 0..) |d, i| {
            if (i > 0) try s.appendSlice(a, ", ");
            try s.appendSlice(a, try ui.text.sanitize(a, d, .line));
        }
        try notes.append(a, s.items);
    }
    p.changes = changes.items;
    p.notes = notes.items;
}

fn mergeOf(target: []const u8) ?Merge {
    for (std.enums.values(Merge)) |m| if (std.mem.eql(u8, target, m.target())) return m;
    return null;
}

// ---------------------------------------------------------------- apply

/// Read the guest again, plan again from `p`'s inputs and write: the
/// merges keep what the earlier `rex setup` steps wrote (Rex's own hooks
/// in Claude's settings, the agy bridge in hooks.json). Returns the plan
/// that was written.
pub fn apply(ctx: *Context, c: *pve.Client, vmid: u32, user: []const u8, p: Plan) !Plan {
    const g = try read(ctx, c, vmid, user, p.profile);
    const fresh = try plan(ctx.arena, p.profile, g, p.kind, p.force);
    try write(ctx, c, vmid, user, fresh);
    return fresh;
}

/// Write `p` as planned, the manifest last. Every file is written as the
/// guest user (`asUser`), never as root: the home's directories are the
/// user's, and root following a link there would write outside it.
pub fn write(ctx: *Context, c: *pve.Client, vmid: u32, user: []const u8, p: Plan) !void {
    for (p.writes) |w| try writeAsUser(ctx, c, vmid, user, w.target, w.mode, w.content);
}

/// As the user: `$1` home-relative path, `$2` mode, `$3` phase (`only`,
/// or `first`, `next`…, `finish` for a file in parts); base64 on stdin is
/// appended to `$1.artoo-part` (0600) and moved into place at the end. A
/// directory in the file's place is refused.
const user_write =
    \\set -eu
    \\p="$HOME/$1"; t="$p.artoo-part"
    \\case "$3" in first|only) mkdir -p "$(dirname "$p")"; rm -f "$t"; (umask 077; : > "$t");; esac
    \\case "$3" in first|next|only) base64 -d >> "$t";; esac
    \\case "$3" in finish|only)
    \\  if [ -d "$p" ] && [ ! -L "$p" ]; then rm -f "$t"; echo "~/$1 is a directory" >&2; exit 4; fi
    \\  chmod "$2" "$t"; mv -f "$t" "$p";;
    \\esac
    \\
;

fn writeAsUser(ctx: *Context, c: *pve.Client, vmid: u32, user: []const u8, rel: []const u8, mode: []const u8, content: []const u8) !void {
    const a = ctx.arena;
    const script = try std.fmt.allocPrint(a, "{s} sh \"$@\"", .{try guest_mod.asUser(a, user, user_write)});
    const enc = std.base64.standard.Encoder;
    var at: usize = 0;
    while (true) {
        const end = @min(at + edge_files.part_bytes, content.len);
        const only = at == 0 and end == content.len;
        const phase: []const u8 = if (only) "only" else if (at == 0) "first" else "next";
        const part = content[at..end];
        const buf = try a.alloc(u8, enc.calcSize(part.len));
        const r = try agent.exec(c, vmid, &.{ "sh", "-c", script, "sh", rel, mode, phase }, enc.encode(buf, part), 60_000);
        if (!r.ok()) return ctx.fail(error.Partial, "writing ~/{s} failed: {s}", .{ rel, try ui.text.sanitize(a, edge.firstLine(r.err), .line) });
        if (only) return;
        at = end;
        if (at >= content.len) break;
    }
    const r = try agent.exec(c, vmid, &.{ "sh", "-c", script, "sh", rel, mode, "finish" }, null, 60_000);
    if (!r.ok()) return ctx.fail(error.Partial, "writing ~/{s} failed: {s}", .{ rel, try ui.text.sanitize(a, edge.firstLine(r.err), .line) });
}

// ---------------------------------------------------------------- checks

/// `rex status`'s rows "profile" and "permissions", from one
/// read of the guest.
pub fn checks(ctx: *Context, c: *pve.Client, vmid: u32, user: []const u8, profile: ?Profile, fenced: bool) ![]Check {
    return checksFrom(ctx.arena, profile, try read(ctx, c, vmid, user, profile), fenced);
}

/// The rows for a guest already read.
pub fn checksFrom(a: Allocator, profile: ?Profile, g: Guest, fenced: bool) ![]Check {
    const kind = kindOf(fenced, g.ssh_keys);
    var out: std.ArrayList(Check) = .empty;
    if (profile) |pr| {
        const p = try plan(a, pr, g, kind, false);
        const behind = try p.behind(a);
        if (p.left_alone.len == 0 and behind.len == 0) {
            try out.append(a, .{ .name = "profile", .status = .ok, .detail = try std.fmt.allocPrint(a, "{d} files current", .{p.current}) });
        } else {
            var s: std.ArrayList(u8) = .empty;
            try s.print(a, "{d} of {d} files current", .{ p.current, p.current + behind.len + p.left_alone.len });
            if (p.left_alone.len > 0) {
                try s.appendSlice(a, "; changed on the guest: ");
                for (p.left_alone, 0..) |l, i| {
                    if (i > 0) try s.appendSlice(a, ", ");
                    try s.appendSlice(a, try ui.text.sanitize(a, l.path, .line));
                }
            }
            if (behind.len > 0) {
                try s.appendSlice(a, "; behind the profile: ");
                for (behind, 0..) |b, i| {
                    if (i > 0) try s.appendSlice(a, ", ");
                    try s.appendSlice(a, try ui.text.sanitize(a, b, .line));
                }
                try s.appendSlice(a, " ('artoo rex setup')");
            }
            try out.append(a, .{ .name = "profile", .status = .warning, .detail = s.items });
        }
    } else try out.append(a, .{ .name = "profile", .status = .not_checked, .detail = "no profile set (agents.profile)" });

    const why = try permissions.reason(a, fenced, g.ssh_keys);
    const claude_free = if (g.claude_settings) |s| blk: {
        const v = std.json.parseFromSliceLeaky(Value, a, s, .{}) catch break :blk false;
        break :blk permissions.claudeUnrestricted(v);
    } else false;
    const agy_free = if (g.fish) |f| permissions.fishUnrestricted(f) else false;
    if (kind != .sandboxed and (claude_free or agy_free)) {
        const what: []const u8 = if (claude_free and agy_free)
            "Claude's defaultMode is bypassPermissions and agy runs with --dangerously-skip-permissions"
        else if (claude_free)
            "Claude's defaultMode is bypassPermissions"
        else
            "agy runs with --dangerously-skip-permissions";
        try out.append(a, .{ .name = "permissions", .status = .warning, .detail = try std.fmt.allocPrint(a, "{s}, but {s} ('artoo rex setup' restricts it)", .{ why, what }) });
    } else try out.append(a, .{ .name = "permissions", .status = .ok, .detail = why });
    return out.items;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn testCtx(arena: Allocator, env: *const std.process.Environ.Map) Context {
    return .{ .arena = arena, .gpa = testing.allocator, .io = testing.io, .out = undefined, .err = undefined, .env = env };
}

fn mkfile(dir: Io.Dir, path: []const u8, data: []const u8) !void {
    if (std.fs.path.dirnamePosix(path)) |d| try dir.createDirPath(testing.io, d);
    try dir.writeFile(testing.io, .{ .sub_path = path, .data = data });
}

fn tmpPath(a: Allocator, t: *testing.TmpDir) ![]const u8 {
    return t.dir.realPathFileAlloc(testing.io, ".", a);
}

fn findEntry(p: Profile, target: []const u8) ?Entry {
    for (p.entries) |e| if (std.mem.eql(u8, e.target, target)) return e;
    return null;
}

test "load: maps the layout, keeps the executable bit, ignores the rest and skips skills/rex" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    var ctx = testCtx(a, &env);
    var t = testing.tmpDir(.{});
    defer t.cleanup();
    const d = t.dir;
    try mkfile(d, "README.md", "about\n");
    try mkfile(d, "AGENTS.md", "top-level, not the profile's rules\n");
    try mkfile(d, ".DS_Store", "x");
    try mkfile(d, ".git/config", "[core]\n");
    try mkfile(d, "fish/config.fish", "set -g x 1\n");
    try mkfile(d, "rules/AGENTS.md", "# Rules\n");
    try mkfile(d, "rules/notes.md", "ignored\n");
    try mkfile(d, "skills/README.md", "not a skill\n");
    try mkfile(d, "skills/demo/SKILL.md", "---\nname: demo\n---\n");
    try mkfile(d, "skills/demo/scripts/run.sh", "#!/bin/sh\necho hi\n");
    try d.setFilePermissions(testing.io, "skills/demo/scripts/run.sh", .fromMode(0o750), .{});
    try mkfile(d, "skills/demo/.DS_Store", "x");
    try mkfile(d, "skills/rex/SKILL.md", "rex owns it\n");
    try mkfile(d, "claude/README.md", "skipped\n");
    try mkfile(d, "claude/settings.json", "{\"model\":\"opus\"}");
    try mkfile(d, "claude/agents/helper.md", "helper\n");
    try mkfile(d, "agy/settings.json", "{}");
    try mkfile(d, "agy/hooks.json", "{\"mine\":{\"Stop\":[]}}");
    try mkfile(d, "agy/extra.md", "extra\n");

    const p = try load(&ctx, try tmpPath(a, &t));
    var targets: std.ArrayList(u8) = .empty;
    for (p.entries) |e| try targets.print(a, "{s} {s}{s}{s}\n", .{ e.mode(), e.target, if (e.agy_only) " agy" else "", if (e.merge != null) " merge" else "" });
    try testing.expectEqualStrings(
        \\0644 .claude/CLAUDE.md
        \\0644 .claude/agents/helper.md
        \\0644 .claude/settings.json merge
        \\0644 .claude/skills/demo/SKILL.md
        \\0755 .claude/skills/demo/scripts/run.sh
        \\0644 .gemini/antigravity-cli/settings.json merge
        \\0644 .gemini/config/AGENTS.md agy
        \\0644 .gemini/config/extra.md
        \\0644 .gemini/config/hooks.json merge
        \\0644 .gemini/config/skills/demo/SKILL.md agy
        \\0755 .gemini/config/skills/demo/scripts/run.sh agy
        \\
    , targets.items);
    try testing.expectEqual(@as(usize, 8), p.files);
    try testing.expectEqualStrings("# Rules\n", findEntry(p, ".claude/CLAUDE.md").?.content);
    try testing.expectEqualStrings("skills/demo/scripts/run.sh", findEntry(p, ".claude/skills/demo/scripts/run.sh").?.source);
}

test "load: every refusal names the file, never its content" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    const secret = "hunter2-SECRET-VALUE";
    const cases = [_]struct { path: []const u8, data: []const u8, want: []const u8 }{
        .{ .path = "claude/.credentials.json", .data = secret, .want = "claude/.credentials.json is refused (an agent credential file)" },
        .{ .path = "skills/demo/.env", .data = secret, .want = "skills/demo/.env is refused (an environment file)" },
        .{ .path = "skills/demo/.env.local", .data = secret, .want = "skills/demo/.env.local is refused (an environment file)" },
        .{ .path = "agy/tls.pem", .data = secret, .want = "agy/tls.pem is refused (a key file)" },
        .{ .path = "claude/api.key", .data = secret, .want = "claude/api.key is refused (a key file)" },
        .{ .path = "claude/ssh/id_ed25519", .data = secret, .want = "claude/ssh/id_ed25519 is refused (an SSH key file)" },
        .{ .path = "skills/demo/notes.md", .data = "-----BEGIN OPENSSH PRIVATE KEY-----\n" ++ secret, .want = "skills/demo/notes.md is refused (it contains a private key)" },
        .{ .path = "rules/AGENTS.md", .data = "-----BEGIN RSA PRIVATE KEY-----\n" ++ secret, .want = "rules/AGENTS.md is refused (it contains a private key)" },
        .{ .path = "claude/settings.json", .data = "{\"x\": \"" ++ secret, .want = "claude/settings.json is refused (not valid JSON)" },
        .{ .path = "agy/hooks.json", .data = "[\"" ++ secret ++ "\"]", .want = "agy/hooks.json is refused (not a JSON object)" },
        .{ .path = "claude/.netrc", .data = secret, .want = "claude/.netrc is refused (an agent credential file)" },
        .{ .path = "agy/oauth_creds.json", .data = secret, .want = "agy/oauth_creds.json is refused (an agent credential file)" },
        .{ .path = "skills/demo/.envrc", .data = secret, .want = "skills/demo/.envrc is refused (an environment file)" },
        .{ .path = "claude/client.p12", .data = secret, .want = "claude/client.p12 is refused (a key file)" },
        .{ .path = "claude/settings.json", .data = "{\"env\":{\"ANTHROPIC_API_KEY\":\"" ++ secret ++ "\"}}", .want = "claude/settings.json is refused (its env names ANTHROPIC_API_KEY, which looks like a secret)" },
        .{ .path = "claude/CLAUDE.md", .data = "rules\n", .want = "both become ~/.claude/CLAUDE.md; keep one" },
    };
    for (cases) |cs| {
        var t = testing.tmpDir(.{});
        defer t.cleanup();
        try mkfile(t.dir, "skills/demo/SKILL.md", "ok\n");
        try mkfile(t.dir, "claude/ssh/id_ed25519.pub", "ssh-ed25519 AAAA public\n");
        if (std.mem.eql(u8, cs.path, "claude/CLAUDE.md")) try mkfile(t.dir, "rules/AGENTS.md", "rules\n");
        try mkfile(t.dir, cs.path, cs.data);
        var ctx = testCtx(a, &env);
        try testing.expectError(error.Refused, load(&ctx, try tmpPath(a, &t)));
        const msg = ctx.diag.?;
        if (std.mem.find(u8, msg, cs.want) == null) {
            std.debug.print("want: {s}\ngot:  {s}\n", .{ cs.want, msg });
            return error.TestUnexpectedResult;
        }
        try testing.expect(std.mem.find(u8, msg, secret) == null);
    }
}

test "load: a symbolic link, a file over 1 MiB, too many files and too many bytes are refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    {
        var t = testing.tmpDir(.{});
        defer t.cleanup();
        try mkfile(t.dir, "skills/demo/SKILL.md", "ok\n");
        try t.dir.symLink(testing.io, "SKILL.md", "skills/demo/link.md", .{});
        var ctx = testCtx(a, &env);
        try testing.expectError(error.Refused, load(&ctx, try tmpPath(a, &t)));
        try testing.expect(std.mem.find(u8, ctx.diag.?, "skills/demo/link.md is refused (a symbolic link)") != null);
    }
    {
        // A link outside the mapped areas is ignored like the rest.
        var t = testing.tmpDir(.{});
        defer t.cleanup();
        try mkfile(t.dir, "rules/AGENTS.md", "ok\n");
        try t.dir.symLink(testing.io, "rules/AGENTS.md", "CLAUDE.md", .{});
        var ctx = testCtx(a, &env);
        _ = try load(&ctx, try tmpPath(a, &t));
    }
    const big = try a.alloc(u8, max_file_bytes + 1);
    @memset(big, 'x');
    {
        var t = testing.tmpDir(.{});
        defer t.cleanup();
        try mkfile(t.dir, "claude/big.md", big);
        var ctx = testCtx(a, &env);
        try testing.expectError(error.Refused, load(&ctx, try tmpPath(a, &t)));
        try testing.expect(std.mem.find(u8, ctx.diag.?, "claude/big.md is refused (over 1 MiB)") != null);
    }
    {
        var t = testing.tmpDir(.{});
        defer t.cleanup();
        for (0..5) |i| try mkfile(t.dir, try std.fmt.allocPrint(a, "claude/part{d}.md", .{i}), big[0 .. 900 << 10]);
        var ctx = testCtx(a, &env);
        try testing.expectError(error.Refused, load(&ctx, try tmpPath(a, &t)));
        try testing.expect(std.mem.find(u8, ctx.diag.?, "is over 4 MiB") != null);
    }
    {
        var t = testing.tmpDir(.{});
        defer t.cleanup();
        for (0..max_files + 1) |i| try mkfile(t.dir, try std.fmt.allocPrint(a, "claude/f/{d}.md", .{i}), "x");
        var ctx = testCtx(a, &env);
        try testing.expectError(error.Refused, load(&ctx, try tmpPath(a, &t)));
        try testing.expect(std.mem.find(u8, ctx.diag.?, "holds over 500 files") != null);
    }
    {
        var t = testing.tmpDir(.{});
        defer t.cleanup();
        try mkfile(t.dir, "file", "x");
        var ctx = testCtx(a, &env);
        const p = try std.fmt.allocPrint(a, "{s}/file", .{try tmpPath(a, &t)});
        try testing.expectError(error.Refused, load(&ctx, p));
        try testing.expect(std.mem.find(u8, ctx.diag.?, "is not a directory") != null);
        try testing.expectError(error.Refused, load(&ctx, try std.fmt.allocPrint(a, "{s}/missing", .{try tmpPath(a, &t)})));
        try testing.expect(std.mem.find(u8, ctx.diag.?, "does not exist") != null);
    }
    {
        // `~` is the workstation's home.
        var t = testing.tmpDir(.{});
        defer t.cleanup();
        try mkfile(t.dir, "prof/rules/AGENTS.md", "r\n");
        var env2: std.process.Environ.Map = .init(testing.allocator);
        defer env2.deinit();
        try env2.put("HOME", try tmpPath(a, &t));
        var ctx = testCtx(a, &env2);
        const p = try load(&ctx, "~/prof");
        try testing.expectEqual(@as(usize, 1), p.files);
    }
}

test "mergeObjects: profile leaves win, arrays joined, hooks per event deduplicated by command" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const guest =
        \\{"model":"sonnet","theme":"dark","permissions":{"allow":["Bash(ls)"],"deny":["Read(.env)"]},
        \\ "hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"rex __internal session-start"}]}],
        \\          "Stop":[{"hooks":[{"type":"command","command":"old.sh"}]}]}}
    ;
    const prof =
        \\{"model":"opus","permissions":{"allow":["Bash(git status)"]},
        \\ "hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"rex __internal session-start","timeout":5}]},{"hooks":[{"type":"command","command":"mine.sh"}]}],
        \\          "PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"guard.sh"}]}]}}
    ;
    const g = try std.json.parseFromSliceLeaky(Value, a, guest, .{});
    const p = try std.json.parseFromSliceLeaky(Value, a, prof, .{});
    const m = try mergeObjects(a, g.object, p.object);
    try testing.expectEqualStrings(
        \\{"model":"opus","theme":"dark","permissions":{"allow":["Bash(git status)","Bash(ls)"],"deny":["Read(.env)"]},"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"rex __internal session-start","timeout":5}]},{"hooks":[{"type":"command","command":"mine.sh"}]}],"Stop":[{"hooks":[{"type":"command","command":"old.sh"}]}],"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"guard.sh"}]}]}}
    , try std.json.Stringify.valueAlloc(a, Value{ .object = m }, .{}));
    // Merging again changes nothing.
    const again = try mergeObjects(a, m, p.object);
    try testing.expectEqualStrings(try std.json.Stringify.valueAlloc(a, Value{ .object = m }, .{}), try std.json.Stringify.valueAlloc(a, Value{ .object = again }, .{}));
}

test "mergeObjects: the guest's own effort, allow answers and nested keys survive" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const guest =
        \\{"modelSettings":{"opus":{"effortLevel":"high","x":1}},
        \\ "permissions":{"allow":["Bash(make test)","Bash(git status)"],"defaultMode":"default"},
        \\ "env":{"A":"1"},"statusLine":{"type":"command","command":"old"},
        \\ "list":[{"b":2,"a":1}]}
    ;
    const prof =
        \\{"modelSettings":{"opus":{"x":2},"sonnet":{"effortLevel":"low"}},
        \\ "permissions":{"allow":["Bash(git status)","Bash(zig build)"]},
        \\ "env":{"B":"2"},"statusLine":{"command":"new"},
        \\ "list":[{"a":1,"b":2}]}
    ;
    const g = try std.json.parseFromSliceLeaky(Value, a, guest, .{});
    const p = try std.json.parseFromSliceLeaky(Value, a, prof, .{});
    const m = try mergeObjects(a, g.object, p.object);
    try testing.expectEqualStrings(
        \\{"modelSettings":{"opus":{"effortLevel":"high","x":2},"sonnet":{"effortLevel":"low"}},"permissions":{"allow":["Bash(git status)","Bash(zig build)","Bash(make test)"],"defaultMode":"default"},"env":{"A":"1","B":"2"},"statusLine":{"type":"command","command":"new"},"list":[{"a":1,"b":2}]}
    , try std.json.Stringify.valueAlloc(a, Value{ .object = m }, .{}));
    // A guest file that already holds the merge is current, so `rex status`
    // reads "current" and the plan writes nothing.
    const once = try mergeFile(a, guest, prof, null);
    try testing.expect(try mergeFile(a, once.write, prof, null) == .current);
}

test "mergeFile: agy hooks keep the bridge's key; numbers are kept as written" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const r = try mergeFile(a, "{\"artoo-rex\":{\"Stop\":[{\"type\":\"command\",\"command\":\"x\",\"timeout\":1.50}]}}", "{\"mine\":{\"enabled\":true}}", null);
    try testing.expectEqualStrings(
        \\{
        \\  "artoo-rex": {
        \\    "Stop": [
        \\      {
        \\        "type": "command",
        \\        "command": "x",
        \\        "timeout": 1.50
        \\      }
        \\    ]
        \\  },
        \\  "mine": {
        \\    "enabled": true
        \\  }
        \\}
        \\
    , r.write);
    try testing.expect(try mergeFile(a, r.write, "{\"mine\":{\"enabled\":true}}", null) == .current);
    try testing.expect(try mergeFile(a, "[1]", "{}", null) == .invalid);
    try testing.expect(try mergeFile(a, null, null, null) == .current);
}

fn testProfile(a: Allocator) !Profile {
    var list: std.ArrayList(Entry) = .empty;
    try list.appendSlice(a, &.{
        .{ .source = "rules/AGENTS.md", .target = ".claude/CLAUDE.md", .content = "rules v2\n" },
        .{ .source = "claude/settings.json", .target = ".claude/settings.json", .content = "{\"model\":\"opus\",\"permissions\":{\"defaultMode\":\"bypassPermissions\"}}", .merge = .claude_settings },
        .{ .source = "skills/demo/SKILL.md", .target = ".claude/skills/demo/SKILL.md", .content = "skill\n" },
        .{ .source = "skills/demo/run.sh", .target = ".claude/skills/demo/run.sh", .content = "#!/bin/sh\n", .exec = true },
        .{ .source = "claude/agents/a.md", .target = ".claude/agents/a.md", .content = "agent a\n" },
        .{ .source = "rules/AGENTS.md", .target = ".gemini/config/AGENTS.md", .content = "rules v2\n", .agy_only = true },
    });
    return .{ .dir = "/tmp/profile", .entries = list.items, .files = 5, .bytes = 0 };
}

fn testGuest(a: Allocator) !Guest {
    var g: Guest = .{ .home = "/home/naboo", .claude = true };
    const v1 = try sha256Hex(a, "rules v1\n");
    // CLAUDE.md: artoo wrote v1, profile now v2 → updated.
    try g.hashes.put(a, ".claude/CLAUDE.md", v1);
    try g.manifest.put(a, "~/.claude/CLAUDE.md", v1);
    // SKILL.md: current.
    try g.hashes.put(a, ".claude/skills/demo/SKILL.md", try sha256Hex(a, "skill\n"));
    try g.manifest.put(a, "~/.claude/skills/demo/SKILL.md", try sha256Hex(a, "skill\n"));
    // run.sh: absent → new.
    try g.hashes.put(a, ".claude/skills/demo/run.sh", "-");
    // a.md: changed on the guest since artoo wrote it.
    try g.hashes.put(a, ".claude/agents/a.md", try sha256Hex(a, "edited by hand\n"));
    try g.manifest.put(a, "~/.claude/agents/a.md", try sha256Hex(a, "agent a v0\n"));
    // A file gone from the profile.
    try g.manifest.put(a, "~/.claude/agents/old.md", try sha256Hex(a, "old\n"));
    try g.hashes.put(a, ".gemini/config/AGENTS.md", "-");
    g.manifest_raw = "{}";
    g.claude_settings = "{\"hooks\":{\"Stop\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"rex hook\"}]}]}}";
    return g;
}

test "plan: current, new, updated, left alone, dropped; manifest last; trusted-reach downgrades the profile's bypass" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const prof = try testProfile(a);
    const g = try testGuest(a);
    const p = try plan(a, prof, g, .trusted_reach, false);
    var got: std.ArrayList(u8) = .empty;
    for (p.writes) |w| try got.print(a, "{s} {s} {s} ({s})\n", .{ @tagName(w.source), w.mode, w.path, w.why });
    try testing.expectEqualStrings(
        \\profile 0644 /home/naboo/.claude/CLAUDE.md (updated from the profile)
        \\profile 0644 /home/naboo/.claude/settings.json (merged with the profile)
        \\profile 0755 /home/naboo/.claude/skills/demo/run.sh (new)
        \\manifest 0644 /home/naboo/.config/artoo/agent-profile.json (records what artoo wrote)
        \\
    , got.items);
    try testing.expectEqual(@as(usize, 1), p.current);
    try testing.expectEqual(@as(usize, 1), p.left_alone.len);
    try testing.expectEqualStrings("~/.claude/agents/a.md", p.left_alone[0].path);
    try testing.expectEqualStrings("changed on the guest", p.left_alone[0].why);
    try testing.expectEqual(@as(usize, 1), p.dropped.len);
    try testing.expectEqualStrings("~/.claude/agents/old.md", p.dropped[0]);
    // Settings: the profile's model, Rex's hook kept, bypass downgraded and disabled.
    const s = try std.json.parseFromSliceLeaky(Value, a, p.writes[1].content, .{});
    try testing.expectEqualStrings("opus", s.object.get("model").?.string);
    try testing.expectEqualStrings("default", permissions.defaultMode(s).?);
    try testing.expectEqualStrings("disable", s.object.get("permissions").?.object.get("disableBypassPermissionsMode").?.string);
    try testing.expectEqualStrings("rex hook", s.object.get("hooks").?.object.get("Stop").?.array.items[0].object.get("hooks").?.array.items[0].object.get("command").?.string);
    // The manifest: written and current files with the profile's hash, the
    // left-alone file keeps its old record, the dropped one is gone.
    const m = try std.json.parseFromSliceLeaky(Value, a, p.writes[3].content, .{});
    const mf = m.object.get("files").?.object;
    try testing.expectEqual(@as(usize, 4), mf.count());
    try testing.expectEqualStrings(try sha256Hex(a, "rules v2\n"), mf.get("~/.claude/CLAUDE.md").?.string);
    try testing.expectEqualStrings(try sha256Hex(a, "agent a v0\n"), mf.get("~/.claude/agents/a.md").?.string);
    try testing.expect(mf.get("~/.claude/agents/old.md") == null);
    try testing.expect(mf.get("~/.gemini/config/AGENTS.md") == null);
    // Rows and notes.
    var rows: std.ArrayList(u8) = .empty;
    for (p.changes) |ch| try rows.print(a, "{s}|{s}|{s}\n", .{ ch.field, ch.from orelse "(none)", ch.to orelse "(removed)" });
    try testing.expectEqualStrings(
        \\file|differs|~/.claude/CLAUDE.md (updated from the profile)
        \\merge|differs|~/.claude/settings.json (merged with the profile)
        \\file|(none)|~/.claude/skills/demo/run.sh (new)
        \\permissions|Claude asks (its default); agy asks|trusted-reach: Claude default, bypass disabled; agy asks
        \\manifest|differs|~/.config/artoo/agent-profile.json
        \\
    , rows.items);
    try testing.expectEqualStrings("Left alone (changed on the guest; --force-profile overwrites): ~/.claude/agents/a.md (changed on the guest)", p.notes[0]);
    try testing.expectEqualStrings("Dropped from the profile, left in place: ~/.claude/agents/old.md", p.notes[1]);

    // --force-profile overwrites it; agy present adds its copy and the fish file.
    var g2 = g;
    g2.agy = true;
    const f = try plan(a, prof, g2, .sandboxed, true);
    try testing.expectEqual(@as(usize, 0), f.left_alone.len);
    var names: std.ArrayList(u8) = .empty;
    for (f.writes) |w| try names.print(a, "{s}\n", .{w.target});
    try testing.expectEqualStrings(
        \\.claude/CLAUDE.md
        \\.claude/settings.json
        \\.claude/skills/demo/run.sh
        \\.claude/agents/a.md
        \\.gemini/config/AGENTS.md
        \\.config/fish/conf.d/artoo-agents.fish
        \\.config/artoo/agent-profile.json
        \\
    , names.items);
    try testing.expectEqualStrings(permissions.fishFile(.sandboxed), f.writes[5].content);
    const s2 = try std.json.parseFromSliceLeaky(Value, a, f.writes[1].content, .{});
    try testing.expectEqualStrings("bypassPermissions", permissions.defaultMode(s2).?);
}

test "plan: a guest that matches is empty; without a profile only the kind is applied" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const prof = try testProfile(a);
    const g = try testGuest(a);
    const p = try plan(a, prof, g, .sandboxed, true);
    // Apply the writes to a copy of the guest, as the guest would have them.
    var after = g;
    after.hashes = .empty;
    var it = g.hashes.iterator();
    while (it.next()) |kv| try after.hashes.put(a, kv.key_ptr.*, kv.value_ptr.*);
    for (p.writes) |w| {
        if (w.source == .manifest) {
            after.manifest_raw = w.content;
            after.manifest = try parseManifest(a, w.content);
        } else if (std.mem.eql(u8, w.target, Merge.claude_settings.target())) {
            after.claude_settings = w.content;
        } else try after.hashes.put(a, w.target, try sha256Hex(a, w.content));
    }
    const again = try plan(a, prof, after, .sandboxed, false);
    try testing.expect(again.empty());
    try testing.expectEqual(@as(usize, 5), again.current);
    try testing.expectEqual(@as(usize, 0), again.changes.len);
    const rows = try checksFrom(a, prof, after, true);
    try testing.expectEqualStrings("5 files current", rows[0].detail);
    try testing.expectEqual(ui.style.Status.ok, rows[0].status);
    try testing.expectEqual(ui.style.Status.ok, rows[1].status);
    try testing.expectEqualStrings("sandboxed (fenced, no private key in ~/.ssh)", rows[1].detail);

    // No profile: the kind only, the manifest untouched.
    const bare: Guest = .{ .home = "/home/naboo", .agy = true, .fish = permissions.fishFile(.sandboxed), .claude_settings = "{\"permissions\":{\"defaultMode\":\"bypassPermissions\"}}" };
    const k = try plan(a, null, bare, .trusted_reach, false);
    var names: std.ArrayList(u8) = .empty;
    for (k.writes) |w| try names.print(a, "{s} {s}\n", .{ @tagName(w.source), w.target });
    try testing.expectEqualStrings(
        \\permissions .claude/settings.json
        \\permissions .config/fish/conf.d/artoo-agents.fish
        \\
    , names.items);
    try testing.expectEqualStrings("permissions", k.changes[0].field);
    try testing.expectEqualStrings("Claude bypassPermissions; agy --dangerously-skip-permissions", k.changes[0].from.?);
    try testing.expectEqualStrings("trusted-reach: Claude default, bypass disabled; agy asks", k.changes[0].to.?);
}

test "checksFrom: no profile; drift; unrestricted on a guest not sandboxed" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const prof = try testProfile(a);
    var g = try testGuest(a);
    g.ssh_keys = &.{"id_ed25519"};
    const rows = try checksFrom(a, prof, g, true);
    try testing.expectEqual(ui.style.Status.warning, rows[0].status);
    try testing.expectEqualStrings("1 of 5 files current; changed on the guest: ~/.claude/agents/a.md; behind the profile: ~/.claude/CLAUDE.md, ~/.claude/settings.json, ~/.claude/skills/demo/run.sh ('artoo rex setup')", rows[0].detail);
    try testing.expectEqual(ui.style.Status.ok, rows[1].status);
    try testing.expectEqualStrings("trusted-reach (fenced, but holds ~/.ssh/id_ed25519)", rows[1].detail);

    g.claude_settings = "{\"permissions\":{\"defaultMode\":\"bypassPermissions\"}}";
    const bad = try checksFrom(a, null, g, true);
    try testing.expectEqual(ui.style.Status.not_checked, bad[0].status);
    try testing.expectEqualStrings("no profile set (agents.profile)", bad[0].detail);
    try testing.expectEqual(ui.style.Status.warning, bad[1].status);
    try testing.expectEqualStrings("trusted-reach (fenced, but holds ~/.ssh/id_ed25519), but Claude's defaultMode is bypassPermissions ('artoo rex setup' restricts it)", bad[1].detail);

    // Sandboxed: bypass is the point, not a warning.
    g.ssh_keys = &.{};
    try testing.expectEqual(ui.style.Status.ok, (try checksFrom(a, null, g, true))[1].status);
    // Not fenced, agy's flag.
    g.claude_settings = null;
    g.fish = permissions.fishFile(.sandboxed);
    const agy = try checksFrom(a, null, g, false);
    try testing.expectEqualStrings("trusted-reach (not fenced), but agy runs with --dangerously-skip-permissions ('artoo rex setup' restricts it)", agy[1].detail);
}

test "parseProbe: base64 fields, hashes in order, private key names" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const out = try probeOut(a, .{ .agents = "claude agy ", .hashes = &.{ "abc", "-" }, .claude_settings = "{\"model\":\"opus\"}", .keys = "id_ed25519\ndeploy\n", .manifest = "{\"files\":{\"~/.claude/CLAUDE.md\":\"abc\"}}" });
    const g = try parseProbe(a, out, &.{ ".claude/CLAUDE.md", ".claude/agents/a.md" });
    try testing.expectEqualStrings("/home/naboo", g.home);
    try testing.expect(g.claude and g.agy);
    try testing.expectEqualStrings("-", g.hashes.get(".claude/agents/a.md").?);
    try testing.expectEqualStrings("{\"model\":\"opus\"}", g.claude_settings.?);
    try testing.expect(g.agy_hooks == null and g.fish == null);
    try testing.expectEqual(@as(usize, 2), g.ssh_keys.len);
    try testing.expectEqualStrings("deploy", g.ssh_keys[1]);
    try testing.expectEqualStrings("abc", g.manifest.get("~/.claude/CLAUDE.md").?);
    try testing.expectError(error.BadProbe, parseProbe(a, out, &.{".claude/CLAUDE.md"}));
    try testing.expectError(error.BadProbe, parseProbe(a, "no json", &.{}));
}

pub const ProbeFixture = struct {
    agents: []const u8 = "claude ",
    hashes: []const []const u8 = &.{},
    manifest: ?[]const u8 = null,
    claude_settings: ?[]const u8 = null,
    fish: ?[]const u8 = null,
    keys: []const u8 = "",
};

fn b64(a: Allocator, s: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const out = try a.alloc(u8, enc.calcSize(s.len));
    return enc.encode(out, s);
}

/// The probe's output for a fixture, as the script prints it.
/// A probe answer for tests (here and in `rex status`).
pub fn probeOut(a: Allocator, f: ProbeFixture) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    try s.print(a, "{{\"home\":\"{s}\",\"agents\":\"{s}\",\"hashes\":[", .{ try b64(a, "/home/naboo"), f.agents });
    for (f.hashes, 0..) |h, i| try s.print(a, "{s}\"{s}\"", .{ if (i > 0) "," else "", h });
    try s.appendSlice(a, "],\"manifest\":");
    if (f.manifest) |m| try s.print(a, "\"{s}\"", .{try b64(a, m)}) else try s.appendSlice(a, "null");
    try s.appendSlice(a, ",\"claude_settings\":");
    if (f.claude_settings) |m| try s.print(a, "\"{s}\"", .{try b64(a, m)}) else try s.appendSlice(a, "null");
    try s.appendSlice(a, ",\"agy_settings\":null,\"agy_hooks\":null,\"fish\":");
    if (f.fish) |m| try s.print(a, "\"{s}\"", .{try b64(a, m)}) else try s.appendSlice(a, "null");
    try s.print(a, ",\"ssh_keys\":\"{s}\"}}\n", .{try b64(a, f.keys)});
    return s.items;
}

test "probeScript: runs as the user and reads only the named files" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const s = try probeScript(arena.allocator(), "naboo");
    for ([_][]const u8{ "u=naboo;", "runuser -u \"$u\"", "command -v", ".config/artoo/agent-profile.json", ".claude/settings.json", ".gemini/antigravity-cli/settings.json", ".gemini/config/hooks.json", ".config/fish/conf.d/artoo-agents.fish", "PRIVATE KEY", "basename" }) |want|
        try testing.expect(std.mem.find(u8, s, want) != null);
    for ([_][]const u8{ ".credentials.json", ".claude.json" }) |never| try testing.expect(std.mem.find(u8, s, never) == null);
}

const testkit = @import("../testkit.zig");
const cli = @import("../cli.zig");

/// Runs read → plan → apply against the fake server, printing the plan.
const apply_probe = struct {
    pub const name = "probe";
    pub const summary = "profile apply probe";
    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const a = ctx.arena;
        var list: std.ArrayList(Entry) = .empty;
        try list.appendSlice(a, &.{
            .{ .source = "rules/AGENTS.md", .target = ".claude/CLAUDE.md", .content = "rules\n" },
            .{ .source = "skills/demo/run.sh", .target = ".claude/skills/demo/run.sh", .content = "#!/bin/sh\n", .exec = true },
        });
        const prof: Profile = .{ .dir = "/p", .entries = list.items, .files = 2, .bytes = 0 };
        const g = try read(ctx, &c, 200, "naboo", prof);
        const p = try plan(a, prof, g, kindOf(false, g.ssh_keys), false);
        const done = try apply(ctx, &c, 200, "naboo", p);
        for (done.writes) |w| try ctx.out.print("{s} {s}{s}\n", .{ w.mode, w.path, if (std.mem.find(u8, w.content, "rex hook") != null) " (keeps rex hook)" else "" });
    }
};

test "read and apply through the agent: one probe each, every file written as the user, manifest last" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const pid = "{\"data\":{\"pid\":42}}";
    const st = struct {
        fn f(al: Allocator, out: []const u8) ![]const u8 {
            return std.json.Stringify.valueAlloc(al, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = out, .@"err-data" = "" } }, .{});
        }
    }.f;
    // The second read sees what `rex skill setup` wrote meanwhile.
    const first = try probeOut(a, .{ .hashes = &.{ "-", "-" } });
    const second = try probeOut(a, .{ .hashes = &.{ "-", "-" }, .claude_settings = "{\"hooks\":{\"Stop\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"rex hook\"}]}]}}" });
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try st(a, first) } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try st(a, second) } },
        // Four files.
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try st(a, "") } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try st(a, "") } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try st(a, "") } },
        .{ .respond = .{ .body = pid } },
        .{ .respond = .{ .body = try st(a, "") } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{cli.leaf(apply_probe)});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "probe"));
    try testing.expectEqualStrings(
        \\0644 /home/naboo/.claude/CLAUDE.md
        \\0755 /home/naboo/.claude/skills/demo/run.sh
        \\0644 /home/naboo/.claude/settings.json (keeps rex hook)
        \\0644 /home/naboo/.config/artoo/agent-profile.json
        \\
    , g.h.stdout());
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    // The probe passes the paths to hash and runs as the user; every file
    // is written as the user (root never follows the home's links); the
    // settings keep Rex's hook; the manifest is last.
    try testing.expect(std.mem.find(u8, g.body(0), "skills%2Fdemo%2Frun.sh") != null);
    try testing.expect(std.mem.find(u8, g.body(0), "runuser") != null);
    for ([_]usize{ 4, 6, 8, 10 }) |i| {
        try testing.expect(std.mem.find(u8, g.body(i), "runuser") != null);
        try testing.expect(std.mem.find(u8, g.body(i), "chown") == null);
    }
    try testing.expect(std.mem.find(u8, g.body(4), "command=.claude%2FCLAUDE.md") != null);
    try testing.expect(std.mem.find(u8, g.body(6), "command=.claude%2Fskills%2Fdemo%2Frun.sh&command=0755") != null);
    try testing.expect(std.mem.find(u8, g.body(8), "settings.json") != null);
    try testing.expect(std.mem.find(u8, g.body(10), "agent-profile.json") != null);
}

test {
    _ = permissions;
}

test "the profile scripts are ASCII (the guest agent wedges on anything else)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ try probeScript(arena.allocator(), "user"), user_write }) |s|
        for (s) |b| try testing.expect(b < 0x80);
}
