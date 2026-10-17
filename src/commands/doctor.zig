//! `artoo doctor [--connect]` (SPEC §3.3): local install, config, secret
//! store, CA bundles; `--connect` adds read-only API probes. Any failed
//! check → exit 8; warnings do not fail.

const std = @import("std");
const Io = std.Io;
const app = @import("../app.zig");
const api = @import("../api.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const files = @import("../files.zig");
const ui = @import("../ui.zig");
const unifi = @import("../unifi/client.zig");
const pve = @import("../pve/client.zig");
const cf = @import("../cloudflare/client.zig");
const version = @import("build_options").version;

const Context = app.Context;
const Status = ui.style.Status;

const Check = struct {
    name: []const u8,
    status: Status,
    detail: []const u8,
};

const Report = struct {
    ctx: *Context,
    checks: std.ArrayList(Check) = .empty,

    fn add(r: *Report, name: []const u8, status: Status, comptime fmt: []const u8, args: anytype) !void {
        const detail = try std.fmt.allocPrint(r.ctx.arena, fmt, args);
        try r.checks.append(r.ctx.arena, .{ .name = name, .status = status, .detail = try ui.text.sanitize(r.ctx.arena, detail, .line) });
    }
};

pub const doctor = struct {
    pub const name = "doctor";
    pub const summary = "Check the local installation, config, secrets and CA bundles";
    pub const details =
        \\Read-only. --connect also calls UniFi (GET /v1/info), Proxmox
        \\(GET /version) and Cloudflare (token verify, zone lookup) with the
        \\stored credentials.
    ;
    pub const flags = [_]cli.Flag{.{ .long = "connect", .short = 'c', .help = "Also probe both APIs (read-only)" }};
    pub const examples = [_][]const u8{ "artoo doctor", "artoo doctor --connect" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var r: Report = .{ .ctx = ctx };
        try binary(&r);
        const cfg_ok = try configCheck(&r);
        var have_unifi = false;
        var have_pve = false;
        var have_cf = false;
        if (cfg_ok) {
            const cfg = try ctx.config();
            if (try storeCheck(&r)) |store| {
                have_unifi = try secretCheck(&r, store, "unifi", "unifi key", .failed, "needed for every gateway command");
                have_pve = try secretCheck(&r, store, "pve", "pve token", .warning, "needed for Proxmox commands");
                have_cf = try secretCheck(&r, store, "cloudflare", "cloudflare token", .warning, "needed for 'cf' commands");
            }
            try caCheck(&r, "unifi CA", cfg.unifi.ca_bundle);
            try caCheck(&r, "pve CA", cfg.pve.ca_bundle);
            try fileCheck(&r, "ssh key", cfg.guests.ssh_public_key);
        }
        if (!args.has("connect")) {
            try r.add("unifi", .not_checked, "use --connect", .{});
            try r.add("pve", .not_checked, "use --connect", .{});
            try r.add("cloudflare", .not_checked, "use --connect", .{});
        } else {
            if (cfg_ok and have_unifi) try probeUnifi(&r) else try r.add("unifi", .not_checked, "{s}", .{if (cfg_ok) "no UniFi API key stored" else "config unusable"});
            if (cfg_ok and have_pve) try probePve(&r) else try r.add("pve", .not_checked, "{s}", .{if (cfg_ok) "no Proxmox token stored" else "config unusable"});
            if (cfg_ok and have_cf) try probeCloudflare(&r) else try r.add("cloudflare", .not_checked, "{s}", .{if (cfg_ok) "no Cloudflare token stored" else "config unusable"});
        }
        return render(ctx, r.checks.items);
    }
};

fn binary(r: *Report) !void {
    const ctx = r.ctx;
    const self = std.process.executablePathAlloc(ctx.io, ctx.arena) catch {
        return r.add("binary", .warning, "artoo {s} (own path unknown)", .{version});
    };
    const on_path = try findOnPath(ctx, "artoo");
    if (on_path) |p| {
        var a: [std.fs.max_path_bytes]u8 = undefined;
        var b: [std.fs.max_path_bytes]u8 = undefined;
        const real_self = realPath(ctx.io, self, &a);
        const real_path = realPath(ctx.io, p, &b);
        if (real_self != null and real_path != null and std.mem.eql(u8, real_self.?, real_path.?)) {
            return r.add("binary", .ok, "{s} {s}", .{ ctx.tilde(self), version });
        }
        return r.add("binary", .warning, "running {s} {s}; 'artoo' on PATH is {s} (make install)", .{ ctx.tilde(self), version, ctx.tilde(p) });
    }
    return r.add("binary", .warning, "{s} {s}; no 'artoo' on PATH (make install)", .{ ctx.tilde(self), version });
}

fn realPath(io: Io, path: []const u8, buf: []u8) ?[]const u8 {
    const n = Io.Dir.cwd().realPathFile(io, path, buf) catch return null;
    return buf[0..n];
}

fn findOnPath(ctx: *Context, exe: []const u8) !?[]const u8 {
    const path = ctx.env.get("PATH") orelse return null;
    var it = std.mem.tokenizeScalar(u8, path, ':');
    while (it.next()) |dir| {
        const candidate = try std.fs.path.join(ctx.arena, &.{ dir, exe });
        Io.Dir.cwd().access(ctx.io, candidate, .{ .execute = true }) catch continue;
        return candidate;
    }
    return null;
}

fn configCheck(r: *Report) !bool {
    const ctx = r.ctx;
    switch (ctx.loaded) {
        .failed => |f| {
            try r.add("config", .failed, "{s}", .{f.message});
            return false;
        },
        .ok => |l| {
            if (!l.exists) {
                try r.add("config", .warning, "{s} absent; using defaults (artoo config init)", .{ctx.tilde(l.path)});
                return true;
            }
            const st = Io.Dir.cwd().statFile(ctx.io, l.path, .{}) catch {
                try r.add("config", .ok, "{s} (schema 1)", .{ctx.tilde(l.path)});
                return true;
            };
            const mode = st.permissions.toMode() & 0o777;
            if (mode & 0o077 != 0) {
                try r.add("config", .warning, "{s} is mode {o}; expected 600 (chmod 600)", .{ ctx.tilde(l.path), mode });
            } else {
                try r.add("config", .ok, "{s} (schema 1, mode 600)", .{ctx.tilde(l.path)});
            }
            return true;
        },
    }
}

fn storeCheck(r: *Report) !?@import("../secrets.zig").Store {
    const ctx = r.ctx;
    const store = ctx.secretStore() catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => return err,
        else => {
            try r.add("secret store", .failed, "{s}", .{ctx.diag orelse @errorName(err)});
            ctx.diag = null;
            return null;
        },
    };
    try r.add("secret store", .ok, "{s}", .{store.describe(ctx.arena)});
    return store;
}

fn secretCheck(r: *Report, store: @import("../secrets.zig").Store, account: []const u8, label: []const u8, missing: Status, why: []const u8) !bool {
    const ctx = r.ctx;
    const present = store.exists(ctx.io, ctx.arena, account) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => return err,
        else => {
            try r.add(label, .failed, "store did not answer ({s})", .{@errorName(err)});
            return false;
        },
    };
    if (present) try r.add(label, .ok, "stored", .{}) else try r.add(label, missing, "missing: {s} (artoo auth set {s})", .{ why, account });
    return present;
}

fn caCheck(r: *Report, label: []const u8, configured: []const u8) !void {
    const ctx = r.ctx;
    const path = files.expandHome(ctx.arena, ctx.env, configured) catch return r.add(label, .failed, "cannot resolve {s}", .{configured});
    const s = api.caSummary(ctx.arena, ctx.io, path) catch |err| {
        return r.add(label, .failed, "{s}: {s}", .{ ctx.tilde(path), @errorName(err) });
    };
    if (s.certs == 0) return r.add(label, .failed, "{s}: no valid certificates (expired or not PEM)", .{ctx.tilde(path)});
    const zone = &ctx.ui.zone;
    const days = @divFloor(s.expires.? - ctx.ui.now, 86400);
    const status: Status = if (days < 30) .warning else .ok;
    try r.add(label, status, "{s} ({d} cert{s}, expires {f}, in {d} days)", .{
        ctx.tilde(path),
        s.certs,
        if (s.certs == 1) "" else "s",
        ui.values.absolute(s.expires, zone),
        days,
    });
}

fn fileCheck(r: *Report, label: []const u8, configured: []const u8) !void {
    const ctx = r.ctx;
    const path = files.expandHome(ctx.arena, ctx.env, configured) catch return r.add(label, .failed, "cannot resolve {s}", .{configured});
    Io.Dir.cwd().access(ctx.io, path, .{ .read = true }) catch {
        return r.add(label, .warning, "{s} not readable (needed for guests)", .{ctx.tilde(path)});
    };
    try r.add(label, .ok, "{s}", .{ctx.tilde(path)});
}

fn probeUnifi(r: *Report) !void {
    const ctx = r.ctx;
    var c = unifi.Client.open(ctx) catch |err| return probeFailed(r, "unifi", err);
    defer c.deinit();
    const i = unifi.info(&c) catch |err| return probeFailed(r, "unifi", err);
    try r.add("unifi", .ok, "{s}: Network Application {s}", .{ c.base, i.applicationVersion });
}

fn probePve(r: *Report) !void {
    const ctx = r.ctx;
    var c = pve.Client.open(ctx) catch |err| return probeFailed(r, "pve", err);
    defer c.deinit();
    const v = c.version() catch |err| return probeFailed(r, "pve", err);
    try r.add("pve", .ok, "{s}: Proxmox VE {s}", .{ c.base, v.version });
}

/// The zone, then the account token's status and expiry (SPEC §15).
fn probeCloudflare(r: *Report) !void {
    const ctx = r.ctx;
    var c = cf.Client.open(ctx) catch |err| return probeFailed(r, "cloudflare", err);
    defer c.deinit();
    const t = cf.verifyToken(&c) catch |err| return probeFailed(r, "cloudflare", err);
    if (!std.mem.eql(u8, t.status, "active")) return r.add("cloudflare", .failed, "token is {s}; replace it with 'artoo auth set cloudflare'", .{t.status});
    if (t.expires_on) |e| return r.add("cloudflare", .ok, "token active (expires {s}); zone {s}", .{ e, c.zone_name });
    try r.add("cloudflare", .ok, "token active (no expiry); zone {s}", .{c.zone_name});
}

fn probeFailed(r: *Report, label: []const u8, err: anyerror) !void {
    if (err == error.OutOfMemory or err == error.Canceled) return err;
    const msg = r.ctx.diag orelse @errorName(err);
    r.ctx.diag = null;
    try r.add(label, .failed, "{s}", .{msg});
}

fn render(ctx: *Context, checks: []const Check) !void {
    var failed: usize = 0;
    var warned: usize = 0;
    var ok: usize = 0;
    for (checks) |c| switch (c.status) {
        .failed => failed += 1,
        .warning => warned += 1,
        .ok => ok += 1,
        else => {},
    };
    if (ctx.json()) {
        const J = struct { name: []const u8, status: []const u8, detail: []const u8 };
        const list = try ctx.arena.alloc(J, checks.len);
        for (checks, list) |c, *j| j.* = .{ .name = c.name, .status = c.status.word(), .detail = c.detail };
        try ui.json.envelope(ctx.out, .local, list, .{ .version = version, .ok = ok, .warnings = warned, .failed = failed });
    } else {
        const u = &ctx.ui;
        try ui.blocks.header(ctx.out, u, "doctor", "artoo " ++ version);
        const rows = try ctx.arena.alloc([]const ui.table.Cell, checks.len);
        for (checks, rows) |c, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 3);
            cells[0] = .{ .text = c.name };
            cells[1] = .{ .text = try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ c.status.glyph(u.glyphs), c.status.word() }), .role = c.status.role() };
            cells[2] = .{ .text = c.detail };
            row.* = cells;
        }
        try ui.table.render(ctx.out, u, ctx.arena, &.{
            .{ .title = "CHECK", .truncate = false },
            .{ .title = "STATUS", .truncate = false },
            .{ .title = "DETAIL", .min = 20 },
        }, rows);
        try ctx.out.print("\n{d} ok, {d} warning{s}, {d} failed\n", .{ ok, warned, if (warned == 1) "" else "s", failed });
    }
    if (failed > 0) return ctx.fail(error.Partial, "{d} check{s} failed", .{ failed, if (failed == 1) "" else "s" });
}

pub const command = cli.leaf(doctor);

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Harness = @import("../testkit.zig").Harness;
const secrets = @import("../secrets.zig");
const root = cli.group("artoo", "test", &.{command});

test "doctor: local checks without --connect; missing unifi key fails" {
    var h = try Harness.init();
    defer h.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmp.dir.realPathFileAlloc(testing.io, ".", h.arena.allocator());
    try h.env.put("HOME", home);
    var mem: secrets.Memory = .{ .gpa = h.arena.allocator() };
    h.store = .{ .memory = &mem };

    try testing.expectEqual(.partial, h.run(&root, "-o json doctor"));
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, h.stdout(), .{});
    defer parsed.deinit();
    const data = parsed.value.object.get("data").?.array.items;
    var seen_unifi = false;
    for (data) |c| {
        const n = c.object.get("name").?.string;
        const st = c.object.get("status").?.string;
        if (std.mem.eql(u8, n, "unifi key")) {
            seen_unifi = true;
            try testing.expectEqualStrings("failed", st);
        }
        if (std.mem.eql(u8, n, "pve token")) try testing.expectEqualStrings("warning", st);
        if (std.mem.eql(u8, n, "config")) try testing.expectEqualStrings("warning", st);
        if (std.mem.eql(u8, n, "unifi")) try testing.expectEqualStrings("not checked", st);
        if (std.mem.eql(u8, n, "unifi CA")) try testing.expectEqualStrings("failed", st);
    }
    try testing.expect(seen_unifi);
    try testing.expectEqualStrings("{\"schema_version\":1,\"error\":{\"kind\":\"partial\",\"exit_code\":8,\"message\":\"3 checks failed\"}}\n", h.stderr());
}

test "doctor --connect: Cloudflare zone, then the account token's verify" {
    var f: @import("../testkit.zig").Gateway = undefined;
    try f.init(&.{
        .{ .respond = .{ .body = "{\"applicationVersion\":\"10.6.106\"}" } },
        .{ .respond = .{ .body = "{\"data\":{\"version\":\"9.2.21\",\"release\":\"9.2\"}}" } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":[{\"id\":\"Z1\",\"name\":\"example.com\",\"account\":{\"id\":\"A1\"}}],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":1,\"total_count\":1}}" } },
        .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"T1\",\"status\":\"active\",\"expires_on\":\"2027-10-10T00:00:00Z\"}}" } },
    });
    defer f.deinit();
    _ = f.h.run(&root, "doctor --connect");
    try testing.expectEqualStrings("GET /accounts/A1/tokens/verify HTTP/1.1", f.request(3));
    const out = f.h.stdout();
    if (std.mem.find(u8, out, "token active (expires 2027-10-10T00:00:00Z); zone example.com") == null) {
        std.debug.print("--- output:\n{s}\n", .{out});
        return error.TestUnexpectedResult;
    }
}
