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
const ts = @import("../tailscale/client.zig");
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
        \\(GET /version), Cloudflare (token verify, zone lookup) and Tailscale
        \\(the OAuth token exchange and its granted scopes) with the stored
        \\credentials.
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
        var have_ts = false;
        var have_ts_policy = false;
        if (cfg_ok) {
            const cfg = try ctx.config();
            if (try storeCheck(&r)) |store| {
                have_unifi = try secretCheck(&r, store, "unifi", "unifi key", .failed, "needed for every gateway command");
                have_pve = try secretCheck(&r, store, "pve", "pve token", .warning, "needed for Proxmox commands");
                have_cf = try secretCheck(&r, store, "cloudflare", "cloudflare token", .warning, "needed for 'cf' commands");
                have_ts = try secretCheck(&r, store, "tailscale", "tailscale client", .not_checked, "optional, for 'ts' commands and the tailnet steps (SPEC §19)");
                if (have_ts and cfg.tailscale.client_id.len == 0) {
                    try r.add("tailscale client", .warning, "secret stored, but tailscale.client_id is not set ('artoo config set tailscale.client_id ID')", .{});
                    have_ts = false;
                }
                // Created to change the policy and revoked afterwards: its
                // absence is the normal state, no warning (SPEC §19).
                have_ts_policy = store.exists(ctx.io, ctx.arena, "tailscale-policy") catch false;
                if (!have_ts_policy) {
                    try r.add("tailscale policy client", .not_checked, "not stored (created only to change the policy, SPEC §19)", .{});
                } else if (cfg.tailscale.policy_client_id.len == 0) {
                    try r.add("tailscale policy client", .warning, "secret stored, but tailscale.policy_client_id is not set", .{});
                    have_ts_policy = false;
                } else try r.add("tailscale policy client", .ok, "stored — revoke it once the policy change is done", .{});
            }
            // The policy writer is a separate, short-lived client: the same
            // ID would make the everyday client a policy writer (SPEC §19).
            if (cfg.tailscale.client_id.len > 0 and std.mem.eql(u8, cfg.tailscale.client_id, cfg.tailscale.policy_client_id))
                try r.add("tailscale clients", .failed, "tailscale.client_id and tailscale.policy_client_id name the same OAuth client; the policy client must be a separate one (SPEC §19)", .{});
            try caCheck(&r, "unifi CA", cfg.unifi.ca_bundle);
            try caCheck(&r, "pve CA", cfg.pve.ca_bundle);
            try fileCheck(&r, "ssh key", cfg.guests.ssh_public_key);
            for (try config.pathList(ctx.arena, cfg.guests.extra_ssh_keys)) |p| try fileCheck(&r, "extra ssh key", p);
        }
        if (!args.has("connect")) {
            try r.add("unifi", .not_checked, "use --connect", .{});
            try r.add("pve", .not_checked, "use --connect", .{});
            try r.add("cloudflare", .not_checked, "use --connect", .{});
            try r.add("tailscale", .not_checked, "use --connect", .{});
        } else {
            if (cfg_ok and have_unifi) {
                ctx.busy("probing UniFi", .{});
                try probeUnifi(&r);
            } else try r.add("unifi", .not_checked, "{s}", .{if (cfg_ok) "no UniFi API key stored" else "config unusable"});
            if (cfg_ok and have_pve) {
                ctx.busy("probing Proxmox", .{});
                try probePve(&r);
            } else try r.add("pve", .not_checked, "{s}", .{if (cfg_ok) "no Proxmox token stored" else "config unusable"});
            if (cfg_ok and have_cf) {
                ctx.busy("probing Cloudflare", .{});
                try probeCloudflare(&r);
            } else try r.add("cloudflare", .not_checked, "{s}", .{if (cfg_ok) "no Cloudflare token stored" else "config unusable"});
            if (cfg_ok and have_ts) {
                ctx.busy("probing Tailscale", .{});
                try probeTailscale(&r);
            } else try r.add("tailscale", .not_checked, "{s}", .{if (cfg_ok) "no Tailscale OAuth client set up" else "config unusable"});
            if (cfg_ok and have_ts_policy) {
                ctx.busy("probing the Tailscale policy client", .{});
                try probeTailscalePolicy(&r);
            }
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

/// The scopes SPEC §19 needs, and what each is for.
const ts_scopes = [_]struct { []const u8, []const u8 }{
    .{ "devices:core", "devices" },
    .{ "devices:routes", "routes" },
    .{ "auth_keys", "join keys" },
    .{ "dns", "split DNS" },
    .{ "policy_file:read", "policy" },
};

/// The token exchange, then the granted scopes against SPEC §19's table
/// (the response's `scope`; its tags are not reported there).
fn probeTailscale(r: *Report) !void {
    const ctx = r.ctx;
    var c = ts.Client.open(ctx, .main) catch |err| return probeFailed(r, "tailscale", err);
    defer c.deinit();
    const have = try ts.scopeList(ctx.arena, c.scopes);
    var missing: std.ArrayList(u8) = .empty;
    for (ts_scopes) |s| if (!ts.grants(have, s[0])) try missing.print(ctx.arena, "{s}{s} ({s})", .{ if (missing.items.len > 0) ", " else "", s[0], s[1] });
    const granted = if (c.scopes.len > 0) c.scopes else "none reported";
    // The everyday client only reads the policy; writing it is the
    // separate policy client's (SPEC §19).
    for (have) |h| if (std.mem.eql(u8, h, "policy_file") or std.mem.eql(u8, h, "all"))
        return r.add("tailscale", .failed, "token granted: {s}; the main client may write the policy ({s}) — give it policy_file:read only and keep policy writes to the policy client (SPEC §19)", .{ granted, h });
    const cfg = try ctx.config();
    // The router's tag and every guest tag `ts join` may use.
    var want: std.ArrayList([]const u8) = .empty;
    try want.append(ctx.arena, @import("../tailscale/tailnet.zig").router_tag);
    try want.appendSlice(ctx.arena, try config.tsTags(ctx.arena, cfg.tailscale.guest_tags));
    const want_text = try std.mem.join(ctx.arena, ", ", want.items);
    // The documented token response names scopes, not tags: then the
    // client's tags are checked when a key is created (an unowned tag is
    // refused there, before anything reaches a guest).
    var tags_missing: std.ArrayList(u8) = .empty;
    const tags = if (c.tags) |owned| blk: {
        for (want.items) |t| {
            var has = false;
            for (owned) |o| has = has or std.mem.eql(u8, o, t);
            if (!has) try tags_missing.print(ctx.arena, "{s}{s}", .{ if (tags_missing.items.len > 0) ", " else "", t });
        }
        break :blk if (tags_missing.items.len > 0)
            try std.fmt.allocPrint(ctx.arena, "tags missing: {s}", .{tags_missing.items})
        else
            try std.fmt.allocPrint(ctx.arena, "tags granted: {s}", .{want_text});
    } else try std.fmt.allocPrint(ctx.arena, "tags not reported by Tailscale; the client needs {s}", .{want_text});
    if (missing.items.len > 0 or tags_missing.items.len > 0) return r.add("tailscale", .warning, "token granted: {s}{s}{s} (SPEC §19); {s}", .{ granted, if (missing.items.len > 0) "; missing: " else "", missing.items, tags });
    try r.add("tailscale", .ok, "token granted: {s}; tailnet {s}; {s}", .{ granted, c.shownName(), tags });
}

/// The policy client: `policy_file` (write) and what it requires.
fn probeTailscalePolicy(r: *Report) !void {
    const ctx = r.ctx;
    var c = ts.Client.open(ctx, .policy) catch |err| return probeFailed(r, "tailscale policy", err);
    defer c.deinit();
    const have = try ts.scopeList(ctx.arena, c.scopes);
    var missing: std.ArrayList(u8) = .empty;
    for ([_][]const u8{ "policy_file", "devices:core:read", "devices:posture_attributes:read" }) |s| if (!ts.grants(have, s)) try missing.print(ctx.arena, "{s}{s}", .{ if (missing.items.len > 0) ", " else "", s });
    const granted = if (c.scopes.len > 0) c.scopes else "none reported";
    if (missing.items.len > 0) return r.add("tailscale policy", .warning, "token granted: {s}; missing: {s} (SPEC §19)", .{ granted, missing.items });
    try r.add("tailscale policy", .ok, "token granted: {s}; revoke the client once the change is done", .{granted});
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
        try ui.blocks.header(ctx.out, u, null, "artoo " ++ version);
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

test "doctor --connect: the Tailscale token exchange reports granted and missing scopes" {
    var f: @import("../testkit.zig").Gateway = undefined;
    try f.initRoutes(&.{
        .{ .match = "/v1/info", .behavior = .{ .respond = .{ .body = "{\"applicationVersion\":\"10.6.106\"}" } } },
        .{ .match = "/version", .behavior = .{ .respond = .{ .body = "{\"data\":{\"version\":\"9.2.21\"}}" } } },
        .{ .match = "/zones", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":[{\"id\":\"Z1\",\"name\":\"example.com\",\"account\":{\"id\":\"A1\"}}],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":1,\"total_count\":1}}" } } },
        .{ .match = "/tokens/verify", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"T1\",\"status\":\"active\"}}" } } },
        .{ .match = "POST /oauth/token", .behavior = .{ .respond = .{ .body = "{\"access_token\":\"tskey-access-xyz\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"devices:core devices:routes auth_keys dns\"}" } } },
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    _ = f.h.run(&root, "doctor --connect");
    const out = f.h.stdout();
    if (std.mem.find(u8, out, "token granted: devices:core devices:routes auth_keys dns; missing: policy_file:read (policy) (SPEC §19); tags not reported by Tailscale; the client needs tag:lab-router, tag:lab-guest") == null or
        std.mem.find(u8, out, "not stored (created only to change the policy, SPEC §19)") == null)
    {
        std.debug.print("--- output:\n{s}\n", .{out});
        return error.TestUnexpectedResult;
    }
    // The secret went only into the form body of the exchange.
    var exchange: []const u8 = "";
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "POST /oauth/token")) {
        exchange = q;
    };
    try testing.expect(std.mem.find(u8, exchange, "content-type: application/x-www-form-urlencoded") != null);
    try testing.expect(std.mem.endsWith(u8, exchange, "grant_type=client_credentials&client_id=kTEST1CNTRL&client_secret=tskey-client-test-secret"));
    try testing.expect(std.mem.find(u8, out, "tskey-") == null);
    try testing.expect(std.mem.find(u8, f.h.stderr(), "tskey-") == null);
}

test "doctor --connect: tags the token response names are compared with tag:lab-router and tailscale.guest_tags" {
    var f: @import("../testkit.zig").Gateway = undefined;
    try f.initRoutes(&.{
        .{ .match = "/v1/info", .behavior = .{ .respond = .{ .body = "{\"applicationVersion\":\"10.6.106\"}" } } },
        .{ .match = "/version", .behavior = .{ .respond = .{ .body = "{\"data\":{\"version\":\"9.2.21\"}}" } } },
        .{ .match = "/zones", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":[{\"id\":\"Z1\",\"name\":\"example.com\",\"account\":{\"id\":\"A1\"}}],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":1,\"total_count\":1}}" } } },
        .{ .match = "/tokens/verify", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"T1\",\"status\":\"active\"}}" } } },
        .{ .match = "POST /oauth/token", .behavior = .{ .respond = .{ .body = "{\"access_token\":\"a1\",\"scope\":\"devices:core devices:routes auth_keys dns policy_file:read\",\"tags\":\"tag:lab-router tag:lab-guest\"}" } } },
    });
    defer f.deinit();
    try f.tmp.dir.createDirPath(testing.io, ".artoo");
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = "{\"schema_version\":1,\"tailscale\":{\"client_id\":\"kMAIN\",\"guest_tags\":\"tag:lab-guest,tag:lab-app\"}}\n" });
    _ = f.h.run(&root, "doctor --connect");
    const out = f.h.stdout();
    if (std.mem.find(u8, out, "token granted: devices:core devices:routes auth_keys dns policy_file:read (SPEC §19); tags missing: tag:lab-app") == null) {
        std.debug.print("--- output:\n{s}\n", .{out});
        return error.TestUnexpectedResult;
    }
}

test "doctor --connect: a stored policy client is exchanged with its own ID and secret" {
    var f: @import("../testkit.zig").Gateway = undefined;
    try f.initRoutes(&.{
        .{ .match = "/v1/info", .behavior = .{ .respond = .{ .body = "{\"applicationVersion\":\"10.6.106\"}" } } },
        .{ .match = "/version", .behavior = .{ .respond = .{ .body = "{\"data\":{\"version\":\"9.2.21\"}}" } } },
        .{ .match = "/zones", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":[{\"id\":\"Z1\",\"name\":\"example.com\",\"account\":{\"id\":\"A1\"}}],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":1,\"total_count\":1}}" } } },
        .{ .match = "/tokens/verify", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"T1\",\"status\":\"active\"}}" } } },
        .{ .match = "POST /oauth/token", .behavior = .{ .respond = .{ .body = "{\"access_token\":\"a1\",\"scope\":\"devices:core devices:routes auth_keys dns policy_file:read\"}" } } },
        .{ .match = "POST /oauth/token", .behavior = .{ .respond = .{ .body = "{\"access_token\":\"a2\",\"scope\":\"policy_file devices:core:read\"}" } } },
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = "{\"schema_version\":1,\"tailscale\":{\"client_id\":\"kMAIN\",\"policy_client_id\":\"kPOLICY\"}}\n" });
    try f.mem.map.put(f.h.arena.allocator(), "tailscale-policy", "tskey-client-policy-secret");
    _ = f.h.run(&root, "doctor --connect");
    const out = f.h.stdout();
    if (std.mem.find(u8, out, "token granted: policy_file devices:core:read; missing: devices:posture_attributes:read") == null) {
        std.debug.print("--- output:\n{s}\n", .{out});
        return error.TestUnexpectedResult;
    }
    var bodies: usize = 0;
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "POST /oauth/token")) {
        bodies += 1;
        const main = std.mem.endsWith(u8, q, "client_id=kMAIN&client_secret=tskey-client-test-secret");
        const policy = std.mem.endsWith(u8, q, "client_id=kPOLICY&client_secret=tskey-client-policy-secret");
        try testing.expect(main or policy);
    };
    try testing.expectEqual(@as(usize, 2), bodies);
}

test "doctor --connect: a main client that may write the policy, or shares the policy client's ID, fails" {
    const T = struct {
        fn run(scope: []const u8, cfg: []const u8, want: []const u8) !void {
            var f: @import("../testkit.zig").Gateway = undefined;
            const body = try std.fmt.allocPrint(testing.allocator, "{{\"access_token\":\"a1\",\"scope\":\"{s}\"}}", .{scope});
            defer testing.allocator.free(body);
            try f.initRoutes(&.{
                .{ .match = "/v1/info", .behavior = .{ .respond = .{ .body = "{\"applicationVersion\":\"10.6.106\"}" } } },
                .{ .match = "/version", .behavior = .{ .respond = .{ .body = "{\"data\":{\"version\":\"9.2.21\"}}" } } },
                .{ .match = "/zones", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":[{\"id\":\"Z1\",\"name\":\"example.com\",\"account\":{\"id\":\"A1\"}}],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":1,\"total_count\":1}}" } } },
                .{ .match = "/tokens/verify", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"T1\",\"status\":\"active\"}}" } } },
                .{ .match = "POST /oauth/token", .behavior = .{ .respond = .{ .body = body } } },
            });
            defer f.deinit();
            try f.tailscaleConfig("");
            try f.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = cfg });
            try testing.expectEqual(@import("../testkit.zig").Exit.partial, f.h.run(&root, "doctor --connect"));
            const out = f.h.stdout();
            if (std.mem.find(u8, out, want) == null) {
                std.debug.print("--- output:\n{s}\n", .{out});
                return error.TestUnexpectedResult;
            }
        }
    };
    const main_only = "{\"schema_version\":1,\"tailscale\":{\"client_id\":\"kMAIN\"}}\n";
    try T.run("devices:core devices:routes auth_keys dns policy_file", main_only, "the main client may write the policy (policy_file)");
    try T.run("all", main_only, "the main client may write the policy (all)");
    try T.run("devices:core devices:routes auth_keys dns policy_file:read", "{\"schema_version\":1,\"tailscale\":{\"client_id\":\"kSAME\",\"policy_client_id\":\"kSAME\"}}\n", "name the same OAuth client");
}

test "doctor --connect: a rejected Tailscale client fails without echoing the secret" {
    var f: @import("../testkit.zig").Gateway = undefined;
    try f.initRoutes(&.{
        .{ .match = "/v1/info", .behavior = .{ .respond = .{ .body = "{\"applicationVersion\":\"10.6.106\"}" } } },
        .{ .match = "/version", .behavior = .{ .respond = .{ .body = "{\"data\":{\"version\":\"9.2.21\"}}" } } },
        .{ .match = "/zones", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":[{\"id\":\"Z1\",\"name\":\"example.com\",\"account\":{\"id\":\"A1\"}}],\"result_info\":{\"page\":1,\"per_page\":100,\"count\":1,\"total_count\":1}}" } } },
        .{ .match = "/tokens/verify", .behavior = .{ .respond = .{ .body = "{\"success\":true,\"errors\":[],\"messages\":[],\"result\":{\"id\":\"T1\",\"status\":\"active\"}}" } } },
        .{ .match = "POST /oauth/token", .behavior = .{ .respond = .{ .status = 401, .body = "{\"message\":\"invalid client credentials\"}" } } },
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(@import("../testkit.zig").Exit.partial, f.h.run(&root, "doctor --connect"));
    const out = f.h.stdout();
    try testing.expect(std.mem.find(u8, out, "Tailscale rejected the OAuth client (401): invalid client credentials") != null);
    try testing.expect(std.mem.find(u8, out, "tskey-") == null);
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
