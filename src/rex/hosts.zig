//! The workstation's Rex hosts for guests (SPEC §20.9, §17.5): the local
//! `rex` CLI, the record of the labels artoo manages
//! (`~/.artoo/rex-hosts.json`), and the plan that brings the hosts in
//! step with the guests tagged `rex`. Shared by `rex hosts sync`, `vm rm`
//! and `vm rename`.
//!
//! The CLI runs through `proc.Runner` (argv only, never a shell) with
//! `--autostart=false`, so artoo never starts a Rex server.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const app = @import("../app.zig");
const files = @import("../files.zig");
const proc = @import("../proc.zig");
const ui = @import("../ui.zig");

const Context = app.Context;

/// The labels artoo added or adopted (SPEC §20.9).
pub const record_path = "~/.artoo/rex-hosts.json";

/// Rex for Mac's own CLI (SPEC §17.5), used when `rex` is not on the PATH.
pub const mac_bundle_cli = "/Applications/Rex.app/Contents/Helpers/Rex Server.rex/Contents/MacOS/rex";

/// Never start a missing Rex server (SPEC §17.5).
const no_autostart = "--autostart=false";

/// One host as `rex hosts list --json` lists it.
pub const Host = struct {
    label: []const u8,
    endpoints: []const []const u8,
};

/// `ssh://<user>@<fqdn>` (SPEC §20.9).
pub fn endpoint(a: Allocator, user: []const u8, fqdn: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "ssh://{s}@{s}", .{ user, fqdn });
}

// ---------------------------------------------------------------- the CLI

/// The `rex` CLI: the first `rex` on `PATH`, else `bundle` when it
/// exists (Rex for Mac; null elsewhere); null when there is none.
pub fn locate(io: Io, arena: Allocator, env: *const std.process.Environ.Map, bundle: ?[]const u8) !?[]const u8 {
    if (env.get("PATH")) |path| {
        var it = std.mem.tokenizeScalar(u8, path, ':');
        while (it.next()) |dir| {
            const candidate = try std.fs.path.join(arena, &.{ dir, "rex" });
            if (try executable(io, candidate)) return candidate;
        }
    }
    if (bundle) |b| if (try executable(io, b)) return b;
    return null;
}

fn executable(io: Io, path: []const u8) Io.Cancelable!bool {
    const st = Io.Dir.cwd().statFile(io, path, .{}) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return false,
    };
    if (st.kind != .file) return false;
    Io.Dir.cwd().access(io, path, .{ .execute = true }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return false,
    };
    return true;
}

/// The Rex for Mac bundle on macOS, nothing elsewhere.
pub fn platformBundle() ?[]const u8 {
    return if (builtin.os.tag.isDarwin()) mac_bundle_cli else null;
}

/// The local CLI with a running Rex behind it.
pub const Rex = struct {
    ctx: *Context,
    exe: []const u8,

    fn runner(r: Rex) proc.Runner {
        return r.ctx.test_hooks.runner orelse proc.Runner{};
    }

    /// `rex hosts ARGS… --autostart=false`; a failed run records the
    /// CLI's first line of error in `ctx.diag` and returns `error.Failed`.
    fn call(r: Rex, args: []const []const u8) ![]const u8 {
        const a = r.ctx.arena;
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(a, &.{ r.exe, "hosts" });
        try argv.appendSlice(a, args);
        try argv.append(a, no_autostart);
        const res = r.runner().run(r.ctx.io, a, argv.items, null) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            error.NotFound => return r.ctx.fail(error.Failed, "{s} could not be run", .{r.ctx.tilde(r.exe)}),
            error.Failed => return r.ctx.fail(error.Failed, "{s} failed to run", .{r.ctx.tilde(r.exe)}),
        };
        if (res.code != 0) {
            const why = firstLine(if (res.stderr.len > 0) res.stderr else res.stdout);
            return r.ctx.fail(error.Failed, "'rex hosts {s}' failed (exit {?d}){s}{s}", .{
                args[0],
                res.code,
                if (why.len > 0) ": " else "",
                try ui.text.sanitize(a, why, .line),
            });
        }
        return res.stdout;
    }

    pub fn list(r: Rex) ![]const Host {
        const out = try r.call(&.{ "list", "--json" });
        return parseList(r.ctx.arena, out) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            else => return r.ctx.fail(error.Protocol, "'rex hosts list --json' answered something artoo does not understand", .{}),
        };
    }

    pub fn add(r: Rex, label: []const u8, ep: []const u8) !void {
        _ = try r.call(&.{ "add", label, ep });
    }

    /// `edit LABEL [--label NEW] --endpoint E` (the endpoint replaces all).
    pub fn edit(r: Rex, label: []const u8, new_label: ?[]const u8, ep: []const u8) !void {
        if (new_label) |n|
            _ = try r.call(&.{ "edit", label, "--label", n, "--endpoint", ep })
        else
            _ = try r.call(&.{ "edit", label, "--endpoint", ep });
    }

    pub fn remove(r: Rex, label: []const u8) !void {
        _ = try r.call(&.{ "remove", label });
    }
};

/// The CLI and its hosts, or why there is none to talk to.
pub const Connection = union(enum) {
    ok: struct { rex: Rex, hosts: []const Host },
    unavailable: []const u8,
};

/// Find the CLI and list the hosts: no CLI, or no running Rex, is
/// `.unavailable` with the reason (SPEC §20.9).
pub fn connect(ctx: *Context) !Connection {
    const exe = (try locate(ctx.io, ctx.arena, ctx.env, platformBundle())) orelse
        return .{ .unavailable = if (platformBundle() != null) "no rex CLI on this machine (not on PATH, no Rex for Mac)" else "no rex CLI on this machine (not on PATH)" };
    const r: Rex = .{ .ctx = ctx, .exe = exe };
    const listed = r.list() catch |err| switch (err) {
        error.Failed => {
            defer ctx.diag = null;
            return .{ .unavailable = try std.fmt.allocPrint(ctx.arena, "no running Rex on this machine ({s})", .{ctx.diag orelse "rex hosts list failed"}) };
        },
        else => |e| return e,
    };
    return .{ .ok = .{ .rex = r, .hosts = listed } };
}

/// `{"hosts":[{"host":{"label":…,"endpoints":[…]},…}],…}` → hosts.
pub fn parseList(a: Allocator, text: []const u8) ![]const Host {
    const Listed = struct {
        hosts: []const struct {
            host: struct { label: []const u8, endpoints: []const []const u8 = &.{} },
        } = &.{},
    };
    const parsed = try std.json.parseFromSliceLeaky(Listed, a, text, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
    const out = try a.alloc(Host, parsed.hosts.len);
    for (parsed.hosts, out) |h, *o| o.* = .{ .label = h.host.label, .endpoints = h.host.endpoints };
    return out;
}

pub fn find(list: []const Host, label: []const u8) ?Host {
    for (list) |h| if (std.ascii.eqlIgnoreCase(h.label, label)) return h;
    return null;
}

/// Exactly the one endpoint `ep`.
pub fn onlyAt(h: Host, ep: []const u8) bool {
    return h.endpoints.len == 1 and std.mem.eql(u8, h.endpoints[0], ep);
}

fn firstLine(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \r\n\t");
    return std.mem.trim(u8, t[0 .. std.mem.findScalar(u8, t, '\n') orelse t.len], " \r");
}

// ---------------------------------------------------------------- record

pub fn recordPath(ctx: *Context) ![]const u8 {
    return files.expandHome(ctx.arena, ctx.env, record_path) catch
        ctx.fail(error.ConfigInvalid, "HOME is not set; cannot locate {s}", .{record_path});
}

/// The recorded labels (none when the file is absent).
pub fn loadRecord(ctx: *Context) ![]const []const u8 {
    const p = try recordPath(ctx);
    files.refuseSymlink(ctx.io, p) catch |err| return switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        else => ctx.fail(error.UnsafePath, "{s} is a symbolic link; refusing to read it", .{record_path}),
    };
    const text = Io.Dir.cwd().readFileAlloc(ctx.io, p, ctx.arena, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => return &.{},
        error.Canceled => return error.Canceled,
        error.OutOfMemory => return error.OutOfMemory,
        else => return ctx.fail(error.Io, "cannot read {s}", .{record_path}),
    };
    return parseRecord(ctx.arena, text) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        else => return ctx.fail(error.ConfigInvalid, "{s} is not artoo's record of Rex hosts ({{\"labels\": […]}}); fix or remove it", .{record_path}),
    };
}

pub fn parseRecord(a: Allocator, text: []const u8) ![]const []const u8 {
    const R = struct { labels: []const []const u8 = &.{} };
    return (try std.json.parseFromSliceLeaky(R, a, text, .{ .ignore_unknown_fields = true, .allocate = .alloc_always })).labels;
}

pub fn renderRecord(a: Allocator, labels: []const []const u8) ![]const u8 {
    var out: Io.Writer.Allocating = .init(a);
    try std.json.Stringify.value(.{ .labels = labels }, .{ .whitespace = .indent_2 }, &out.writer);
    try out.writer.writeByte('\n');
    return out.written();
}

/// Write the record atomically (0600; a symlink is refused).
pub fn saveRecord(ctx: *Context, labels: []const []const u8) !void {
    const p = try recordPath(ctx);
    const dir = std.fs.path.dirname(p).?;
    files.ensurePrivateDir(ctx.io, dir) catch |err| return switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        else => ctx.fail(error.Io, "cannot create {s}", .{ctx.tilde(dir)}),
    };
    files.atomicWrite(ctx.io, ctx.arena, p, try renderRecord(ctx.arena, labels)) catch |err| return switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        error.UnsafePath => ctx.fail(error.UnsafePath, "{s} is a symbolic link; refusing to write it", .{record_path}),
        else => ctx.fail(error.Io, "cannot write {s}", .{record_path}),
    };
}

pub fn has(labels: []const []const u8, label: []const u8) bool {
    for (labels) |l| if (std.ascii.eqlIgnoreCase(l, label)) return true;
    return false;
}

/// `labels` with `label` (once, ignoring case), sorted.
pub fn with(a: Allocator, labels: []const []const u8, label: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    try out.appendSlice(a, try without(a, labels, label));
    try out.append(a, label);
    std.mem.sort([]const u8, out.items, {}, lessIgnoreCase);
    return out.items;
}

/// `labels` without `label` (ignoring case).
pub fn without(a: Allocator, labels: []const []const u8, label: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (labels) |l| if (!std.ascii.eqlIgnoreCase(l, label)) try out.append(a, l);
    return out.items;
}

fn lessIgnoreCase(_: void, x: []const u8, y: []const u8) bool {
    return std.ascii.lessThanIgnoreCase(x, y);
}

// ---------------------------------------------------------------- vm rm, vm rename

/// The Rex host of a guest that `vm rm` or `vm rename` changes: only a
/// host artoo recorded (SPEC §20.8).
pub const Recorded = struct {
    /// The guest's label as recorded.
    label: []const u8,
    /// The CLI and the hosts, or why the step is skipped.
    conn: Connection,
    /// The host as listed now (null: not listed, or no Rex).
    listed: ?Host = null,
    record: []const []const u8,

    pub fn rex(r: Recorded) ?Rex {
        return switch (r.conn) {
            .ok => |c| c.rex,
            .unavailable => null,
        };
    }

    pub fn skipped(r: Recorded) ?[]const u8 {
        return switch (r.conn) {
            .ok => null,
            .unavailable => |why| why,
        };
    }
};

/// The recorded Rex host `label`, or null when artoo did not record it.
/// An unreadable record or no Rex makes the step `.unavailable`, never
/// an error of the command it belongs to.
pub fn recordedHost(ctx: *Context, label: []const u8) !?Recorded {
    const record = loadRecord(ctx) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            defer ctx.diag = null;
            return .{ .label = label, .record = &.{}, .conn = .{ .unavailable = ctx.diag orelse @errorName(err) } };
        },
    };
    const mine = for (record) |l| {
        if (std.ascii.eqlIgnoreCase(l, label)) break l;
    } else return null;
    const conn = connect(ctx) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => blk: {
            defer ctx.diag = null;
            break :blk Connection{ .unavailable = ctx.diag orelse @errorName(err) };
        },
    };
    return .{
        .label = mine,
        .conn = conn,
        .listed = switch (conn) {
            .ok => |c| find(c.hosts, mine),
            .unavailable => null,
        },
        .record = record,
    };
}

// ---------------------------------------------------------------- the plan

/// A guest that wants a host.
pub const Want = struct { label: []const u8, endpoint: []const u8 };

pub const Action = struct {
    kind: Kind,
    label: []const u8,
    /// The host's endpoints as listed (empty when it is not listed).
    have: []const []const u8 = &.{},
    /// The wanted endpoint (add, edit, adopt).
    want: []const u8 = "",

    pub const Kind = enum {
        /// `rex hosts add`, then recorded.
        add,
        /// `rex hosts edit --endpoint` (recorded host).
        edit,
        /// `rex hosts remove`, then dropped from the record.
        remove,
        /// Recorded only: the host already has exactly the wanted endpoint.
        adopt,
        /// Dropped from the record only: the host is gone already.
        forget,
        /// Left alone: not artoo's, other endpoints (a plan note).
        foreign,
    };

    /// Something to send or record (a foreign host is only named).
    pub fn changes(x: Action) bool {
        return x.kind != .foreign;
    }
};

/// What brings `listed` in step with `wants`, given the `recorded`
/// labels (SPEC §20.9); in the order of `wants`, then the removals.
pub fn diff(a: Allocator, wants: []const Want, listed: []const Host, recorded: []const []const u8) ![]const Action {
    var out: std.ArrayList(Action) = .empty;
    for (wants) |w| {
        const mine = has(recorded, w.label);
        const h = find(listed, w.label) orelse {
            try out.append(a, .{ .kind = .add, .label = w.label, .want = w.endpoint });
            continue;
        };
        if (onlyAt(h, w.endpoint)) {
            if (!mine) try out.append(a, .{ .kind = .adopt, .label = w.label, .have = h.endpoints, .want = w.endpoint });
            continue;
        }
        try out.append(a, .{ .kind = if (mine) .edit else .foreign, .label = w.label, .have = h.endpoints, .want = w.endpoint });
    }
    for (recorded) |r| {
        const wanted = for (wants) |w| {
            if (std.ascii.eqlIgnoreCase(w.label, r)) break true;
        } else false;
        if (wanted) continue;
        if (find(listed, r)) |h| {
            try out.append(a, .{ .kind = .remove, .label = r, .have = h.endpoints });
        } else try out.append(a, .{ .kind = .forget, .label = r });
    }
    return out.items;
}

/// The record once every action in `actions` has applied.
pub fn recordAfter(a: Allocator, recorded: []const []const u8, actions: []const Action) ![]const []const u8 {
    var labels = recorded;
    for (actions) |x| switch (x.kind) {
        .add, .edit, .adopt => labels = try with(a, labels, x.label),
        .remove, .forget => labels = try without(a, labels, x.label),
        .foreign => {},
    };
    return labels;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const sample =
    \\{"home":{"label":"pve","endpoint":"unix:///run/rex.sock","this_machine":true,"reached":true},
    \\ "hosts":[
    \\  {"host":{"endpoints":["http://naboo.example.com:7297"],"icon":"globe","id":"h1","label":"naboo","updated_at":"2026-11-25T10:00:00Z"},"from":"pve","held":false},
    \\  {"host":{"endpoints":["ssh://artoo@hoth.lab.example.com"],"id":"h2","label":"Hoth","updated_at":"2026-11-25T10:00:00Z"},"from":"pve","held":true}
    \\ ],"warnings":[]}
;

test "parseList reads labels and endpoints, ignores the rest" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const hs = try parseList(arena.allocator(), sample);
    try testing.expectEqual(@as(usize, 2), hs.len);
    try testing.expectEqualStrings("naboo", hs[0].label);
    try testing.expectEqualStrings("http://naboo.example.com:7297", hs[0].endpoints[0]);
    try testing.expect(find(hs, "hoth") != null);
    try testing.expect(onlyAt(find(hs, "HOTH").?, "ssh://artoo@hoth.lab.example.com"));
    try testing.expectEqual(@as(usize, 0), (try parseList(arena.allocator(), "{\"hosts\":[]}")).len);
    try testing.expectError(error.UnexpectedEndOfInput, parseList(arena.allocator(), "{\"hosts\":["));
}

test "diff: add, edit, remove, adopt, forget, foreign; case-insensitive" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const listed = [_]Host{
        .{ .label = "Naboo", .endpoints = &.{"ssh://artoo@naboo.lab.example.com"} }, // adopt
        .{ .label = "hoth", .endpoints = &.{"ssh://old@hoth.lab.example.com"} }, // recorded: edit
        .{ .label = "bespin", .endpoints = &.{ "ssh://artoo@bespin.lab.example.com", "http://192.168.1.200:7297" } }, // foreign
        .{ .label = "endor", .endpoints = &.{"ssh://artoo@endor.lab.example.com"} }, // recorded, gone: remove
        .{ .label = "dagobah", .endpoints = &.{"ssh://artoo@dagobah.lab.example.com"} }, // recorded, current
    };
    const wants = [_]Want{
        .{ .label = "naboo", .endpoint = "ssh://artoo@naboo.lab.example.com" },
        .{ .label = "hoth", .endpoint = "ssh://artoo@hoth.lab.example.com" },
        .{ .label = "bespin", .endpoint = "ssh://artoo@bespin.lab.example.com" },
        .{ .label = "dagobah", .endpoint = "ssh://artoo@dagobah.lab.example.com" },
        .{ .label = "tatooine", .endpoint = "ssh://artoo@tatooine.lab.example.com" },
    };
    const recorded = [_][]const u8{ "HOTH", "endor", "dagobah", "yavin" };
    const d = try diff(a, &wants, &listed, &recorded);
    const want_kinds = [_]Action.Kind{ .adopt, .edit, .foreign, .add, .remove, .forget };
    try testing.expectEqual(want_kinds.len, d.len);
    for (want_kinds, d) |k, x| try testing.expectEqual(k, x.kind);
    try testing.expectEqualStrings("tatooine", d[3].label);
    try testing.expectEqualStrings("endor", d[4].label);
    const after = try recordAfter(a, &recorded, d);
    try testing.expectEqual(@as(usize, 4), after.len);
    for ([_][]const u8{ "dagobah", "hoth", "naboo", "tatooine" }, after) |w, got| try testing.expect(std.ascii.eqlIgnoreCase(w, got));
    // Nothing to do.
    const none = try diff(a, wants[3..4], listed[4..5], &.{"dagobah"});
    try testing.expectEqual(@as(usize, 0), none.len);
}

test "record: render, parse, with, without" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try with(a, try with(a, &.{}, "naboo"), "hoth");
    try testing.expectEqualStrings("{\n  \"labels\": [\n    \"hoth\",\n    \"naboo\"\n  ]\n}\n", try renderRecord(a, l));
    const back = try parseRecord(a, try renderRecord(a, l));
    try testing.expectEqual(@as(usize, 2), back.len);
    try testing.expect(has(back, "NABOO"));
    try testing.expectEqual(@as(usize, 1), (try without(a, back, "Hoth")).len);
    try testing.expectEqual(@as(usize, 2), (try with(a, back, "Naboo")).len);
    try testing.expectError(error.UnexpectedToken, parseRecord(a, "[]"));
}

test "locate: PATH first, then the bundle, else none" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(testing.io, ".", a);
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("PATH", dir);
    try testing.expect(try locate(testing.io, a, &env, null) == null);
    // Not executable: skipped.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "rex", .data = "#!/bin/sh\n" });
    try testing.expect(try locate(testing.io, a, &env, null) == null);
    const bundle = try std.fs.path.join(a, &.{ dir, "bundle-rex" });
    const f = try Io.Dir.cwd().createFile(testing.io, bundle, .{ .permissions = .fromMode(0o755) });
    f.close(testing.io);
    try testing.expectEqualStrings(bundle, (try locate(testing.io, a, &env, bundle)).?);
    try Io.Dir.cwd().deleteFile(testing.io, try std.fs.path.join(a, &.{ dir, "rex" }));
    const on_path = try std.fs.path.join(a, &.{ dir, "rex" });
    const g = try Io.Dir.cwd().createFile(testing.io, on_path, .{ .permissions = .fromMode(0o755) });
    g.close(testing.io);
    try testing.expectEqualStrings(on_path, (try locate(testing.io, a, &env, bundle)).?);
}
