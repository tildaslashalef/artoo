//! `artoo update [VERSION] [--check]` (SPEC §18): replace the running
//! binary with a GitHub release — chosen, downloaded and verified
//! (SHA256SUMS, GitHub's digest, the binary's own `--version`) before the
//! plan is shown; then a backup copy and one atomic rename. The pipeline
//! is §8.2's, run here because verification precedes the preview and the
//! staged file must go on every path that does not install it.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const ui = @import("../ui.zig");
const release = @import("../update/release.zig");
const archive = @import("../update/archive.zig");
const install = @import("../update/install.zig");
const build_version = @import("build_options").version;

const Context = app.Context;

pub const update = struct {
    pub const name = "update";
    pub const summary = "Replace this artoo with a verified GitHub release";
    pub const details =
        \\Without VERSION: the latest release (never a pre-release). The archive
        \\for this machine is downloaded from github.com/tildaslashalef/artoo and
        \\checked against SHA256SUMS and GitHub's digest, and the binary inside
        \\must report the release's version — all before the plan is shown.
        \\Then the current binary is copied to .artoo.previous beside it and
        \\the new one renamed into place. -n downloads and verifies but
        \\replaces nothing. --check reads the release only: exit 0 when an
        \\update is available, 5 when there is nothing to update.
        \\A symbolic link or an unwritable directory is refused; artoo never
        \\runs sudo. Roll back: mv <dir>/.artoo.previous <dir>/artoo.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VERSION", .required = false, .help = "A release to install, e.g. 0.4.0 (default: the latest)" }};
    pub const flags = [_]cli.Flag{.{ .long = "check", .help = "Only tell whether an update is available (exit 0) or not (exit 5)" }};
    pub const examples = [_][]const u8{
        "artoo update --check",
        "artoo update -n",
        "artoo update",
        "artoo update 0.3.0",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const hooks = ctx.test_hooks.update;
        const current_text = if (hooks) |h| h.version else build_version;
        const current = release.parseVersion(current_text) orelse
            return ctx.fail(error.Internal, "this build's version '{s}' is not SemVer", .{current_text});
        const wanted: ?[]const u8 = if (args.optPos("VERSION")) |v| blk: {
            if (release.parseVersion(v) == null) return ctx.fail(error.Usage, "'{s}' is not a version (X.Y.Z, vX.Y.Z or X.Y.Z-rc.N)", .{try clean(ctx, v)});
            break :blk std.mem.cutPrefix(u8, v, "v") orelse v;
        } else null;
        const target = (if (hooks) |h| h.target else release.hostTarget()) orelse
            return ctx.fail(error.Refused, "artoo releases are built for aarch64-macos, x86_64-macos, aarch64-linux and x86_64-linux; this build runs on {t}-{t}: build it from source", .{ builtin.cpu.arch, builtin.os.tag });
        const check = args.has("check");
        // Before any request: what would be replaced, and whether it can be.
        const inst: ?install.Install = if (check) null else try install.locate(ctx);

        var src = try release.Source.open(ctx);
        defer src.deinit();
        const rel = try src.release(ctx, wanted);
        const version = rel.version();
        const ord = release.order(current, release.parseVersion(rel.tag_name).?);
        const asset_name = try release.archiveName(ctx.arena, version, target);
        const available = ord == .lt or (wanted != null and ord == .gt);

        if (check) return reportCheck(ctx, current_text, rel, wanted, asset_name, available);
        if (ord == .eq) return ctx.fail(error.NoChange, "artoo {s} is already {s}; nothing to update", .{ current_text, rel.tag_name });
        if (!available) return ctx.fail(error.NoChange, "this build ({s}) is newer than the latest release {s}; nothing to update (to go back: artoo update {s})", .{ current_text, version, version });

        var op: Op = .{
            .ctx = ctx,
            .src = &src,
            .inst = inst.?,
            .current = current_text,
            .downgrade = ord == .gt,
            .wanted = wanted,
            .rel = rel,
            .asset_name = asset_name,
            .entry = try std.fmt.allocPrint(ctx.arena, "artoo-{s}-{s}/artoo", .{ version, target }),
            .expected = try std.fmt.allocPrint(ctx.arena, "artoo {s}", .{version}),
        };
        defer op.discard();
        try op.run();
    }
};

pub const command = cli.leaf(update);

const CheckData = struct {
    current: []const u8,
    version: []const u8,
    latest: ?[]const u8,
    update_available: bool,
    asset: []const u8,
};

fn reportCheck(ctx: *Context, current: []const u8, rel: release.Release, wanted: ?[]const u8, asset_name: []const u8, available: bool) !void {
    const version = rel.version();
    if (ctx.json()) {
        try ui.json.envelope(ctx.out, .github, CheckData{
            .current = current,
            .version = version,
            .latest = if (wanted == null) version else null,
            .update_available = available,
            .asset = asset_name,
        }, .{});
    } else if (available) {
        try ctx.out.print("Update available: artoo {s} → {s} ({s}, {s})\nRun 'artoo update{s}{s}' to install it.\n", .{
            current,
            version,
            rel.tag_name,
            try clean(ctx, rel.date()),
            if (wanted != null) " " else "",
            wanted orelse "",
        });
    }
    if (available) return;
    if (wanted != null) return ctx.fail(error.NoChange, "artoo {s} is already {s}; nothing to update", .{ current, rel.tag_name });
    return ctx.fail(error.NoChange, "artoo {s} is up to date (latest release: {s}); nothing to update", .{ current, rel.tag_name });
}

const Data = struct {
    current: []const u8,
    version: []const u8,
    latest: ?[]const u8,
    update_available: bool = true,
    asset: []const u8,
    sha256: []const u8,
    path: []const u8,
    backup: []const u8,
    result: []const u8,
};

const Op = struct {
    ctx: *Context,
    src: *release.Source,
    inst: install.Install,
    current: []const u8,
    downgrade: bool,
    wanted: ?[]const u8,
    rel: release.Release,
    asset_name: []const u8,
    /// `artoo-<ver>-<target>/artoo` inside the archive.
    entry: []const u8,
    /// What the new binary's `--version` must print.
    expected: []const u8,
    sha256: []const u8 = "",
    staged: ?[]const u8 = null,

    fn discard(op: *Op) void {
        if (op.staged) |s| Io.Dir.cwd().deleteFile(op.ctx.io, s) catch {};
        op.staged = null;
    }

    fn run(op: *Op) !void {
        const ctx = op.ctx;
        const pl = try op.prepare();

        // Preview: stdout for humans; stderr when stdout carries JSON.
        const preview_w = if (ctx.json()) ctx.err else ctx.out;
        const preview_ui = if (ctx.json()) &ctx.err_ui else &ctx.ui;
        try ui.blocks.plan(preview_w, preview_ui, pl);
        if (ctx.globals.dry_run) {
            if (ctx.json()) return ui.json.envelope(ctx.out, .github, op.jsonData("dry-run"), .{});
            return ctx.out.writeAll("\nDry run: downloaded and verified; nothing was replaced.\n");
        }

        try preview_w.flush();
        const before = try op.fingerprint(op.rel, op.inst);
        const asked_at = Io.Clock.awake.now(ctx.io);
        try ctx.confirm("Proceed?", .{});
        const waited = @divTrunc(asked_at.durationTo(Io.Clock.awake.now(ctx.io)).nanoseconds, std.time.ns_per_ms);
        if (waited >= 3000) {
            const rel = try op.src.release(ctx, op.wanted);
            const inst = try install.locate(ctx);
            if (!std.mem.eql(u8, before, try op.fingerprint(rel, inst))) {
                return ctx.fail(error.Changed, "the release or {s} changed while waiting for confirmation; nothing was replaced — run again", .{ctx.tilde(op.inst.path)});
            }
        }

        try install.backup(ctx, op.inst);
        try install.swap(ctx, op.inst, op.staged.?);
        op.staged = null;

        const got = try install.reportedVersion(ctx, op.inst.path);
        if (got == null or !std.mem.eql(u8, got.?, op.expected)) {
            return ctx.fail(error.Partial, "{s} was replaced, but it reports '{s}' instead of '{s}'; roll back with: mv {s} {s}", .{
                ctx.tilde(op.inst.path), try clean(ctx, got orelse "(nothing)"), op.expected, ctx.tilde(op.inst.backup), ctx.tilde(op.inst.path),
            });
        }
        if (ctx.json()) return ui.json.envelope(ctx.out, .github, op.jsonData("applied"), .{});
        const p = ctx.ui.palette;
        try ctx.out.print("{s}{s}{s} artoo {s} installed at {s} (the previous binary is {s})\n", .{
            p.on(.ok), ctx.ui.glyphs.ok, p.off(.ok), op.rel.version(), ctx.tilde(op.inst.path), ctx.tilde(op.inst.backup),
        });
    }

    /// Download and verify everything, stage the binary, build the plan.
    fn prepare(op: *Op) !ui.blocks.Plan {
        const ctx = op.ctx;
        const a = ctx.arena;
        const tag = op.rel.tag_name;
        const asset = op.rel.asset(op.asset_name) orelse
            return ctx.fail(error.Protocol, "release {s} has no {s} (this machine's archive)", .{ tag, op.asset_name });
        const sums_asset = op.rel.asset("SHA256SUMS") orelse
            return ctx.fail(error.Protocol, "release {s} has no SHA256SUMS", .{tag});
        for ([_]release.Asset{ asset, sums_asset }) |x| {
            if (!std.mem.eql(u8, x.state, "uploaded")) return ctx.fail(error.Protocol, "{s} of release {s} is not fully uploaded yet; try again later", .{ x.name, tag });
        }

        const sums = try op.src.asset(ctx, tag, "SHA256SUMS", release.limits.sums);
        const data = try op.src.asset(ctx, tag, op.asset_name, release.limits.archive);
        if (data.len != asset.size) {
            return ctx.fail(error.Refused, "{s} is {d} bytes, GitHub lists {d}; nothing was replaced", .{ op.asset_name, data.len, asset.size });
        }
        const want = archive.expectedSum(sums, op.asset_name) catch |err| return switch (err) {
            error.SumMissing => ctx.fail(error.Refused, "SHA256SUMS of {s} has no line for {s}; nothing was replaced", .{ tag, op.asset_name }),
            error.SumAmbiguous => ctx.fail(error.Refused, "SHA256SUMS of {s} names {s} more than once; nothing was replaced", .{ tag, op.asset_name }),
            error.SumMalformed => ctx.fail(error.Refused, "SHA256SUMS of {s} has a malformed line for {s}; nothing was replaced", .{ tag, op.asset_name }),
        };
        const got = archive.sha256(data);
        const got_hex = archive.hex(got);
        if (!std.mem.eql(u8, &got, &want)) {
            return ctx.fail(error.Refused, "SHA-256 of {s} is {s}, but SHA256SUMS says {s}; nothing was replaced", .{ op.asset_name, &got_hex, &archive.hex(want) });
        }
        var by_github = false;
        if (asset.digest) |field| if (archive.githubDigest(field)) |d| {
            if (!std.mem.eql(u8, &got, &d)) {
                return ctx.fail(error.Refused, "SHA-256 of {s} is {s}, but GitHub's digest is {s}; nothing was replaced", .{ op.asset_name, &got_hex, &archive.hex(d) });
            }
            by_github = true;
        };
        op.sha256 = try a.dupe(u8, &got_hex);

        op.staged = try install.stage(ctx, op.inst, data, op.entry);
        const reported = try install.reportedVersion(ctx, op.staged.?);
        if (reported == null or !std.mem.eql(u8, reported.?, op.expected)) {
            return ctx.fail(error.Refused, "the binary in {s} reports '{s}', expected '{s}'; nothing was replaced", .{
                op.asset_name, try clean(ctx, reported orelse "(it did not run here)"), op.expected,
            });
        }

        const version = op.rel.version();
        const verb = if (op.downgrade) "Downgrade" else "Update";
        const pre = if (op.rel.prerelease) " (pre-release)" else "";
        const changes = try a.alloc(ui.blocks.Change, 1);
        changes[0] = .{ .field = "version", .from = op.current, .to = version };
        const impact = try a.alloc([]const u8, 4);
        impact[0] = try std.fmt.allocPrint(a, "release {s}{s} of {s}: {s}, {f}", .{ tag, pre, try clean(ctx, op.rel.date()), op.asset_name, ui.values.bytes(asset.size) });
        impact[1] = try std.fmt.allocPrint(a, "SHA-256 {s} matches SHA256SUMS{s}", .{ op.sha256, if (by_github) " and GitHub's digest" else "" });
        impact[2] = try std.fmt.allocPrint(a, "the new binary reports \"{s}\"", .{op.expected});
        impact[3] = try std.fmt.allocPrint(a, "the current binary is kept as {s}", .{ctx.tilde(op.inst.backup)});
        return .{
            .action = try std.fmt.allocPrint(a, "{s} artoo {s} → {s}", .{ verb, op.current, version }),
            .target = ctx.tilde(op.inst.path),
            .changes = changes,
            .impact = impact,
            .recovery = try std.fmt.allocPrint(a, "mv {s} {s}", .{ ctx.tilde(op.inst.backup), ctx.tilde(op.inst.path) }),
        };
    }

    fn fingerprint(op: *const Op, rel: release.Release, inst: install.Install) ![]const u8 {
        const asset = rel.asset(op.asset_name);
        return std.fmt.allocPrint(op.ctx.arena, "{s}|{s}|{d}|{s}", .{
            rel.tag_name,
            if (asset) |x| x.digest orelse "" else "",
            if (asset) |x| x.size else 0,
            try inst.fingerprint(op.ctx.arena),
        });
    }

    fn jsonData(op: *const Op, result: []const u8) Data {
        return .{
            .current = op.current,
            .version = op.rel.version(),
            .latest = if (op.wanted == null) op.rel.version() else null,
            .asset = op.asset_name,
            .sha256 = op.sha256,
            .path = op.inst.path,
            .backup = op.inst.backup,
            .result = result,
        };
    }
};

fn clean(ctx: *Context, s: []const u8) ![]const u8 {
    return ui.text.sanitize(ctx.arena, s[0..@min(s.len, 200)], .line);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const Route = testkit.Gateway.FakeServer.Route;
const root = &@import("registry.zig").root;

fn script(comptime v: []const u8) []const u8 {
    return "#!/bin/sh\necho 'artoo " ++ v ++ "'\n";
}

/// A fake GitHub serving one release of `version` for aarch64-macos, and
/// an installed "artoo" (a shell script) in `$HOME/bin`.
const Fx = struct {
    g: testkit.Gateway,
    routes: [5]Route = undefined,
    archive: []u8 = &.{},
    bin: []const u8 = "",
    exe: []const u8 = "",

    const Opts = struct {
        current: []const u8 = "0.3.0",
        version: []const u8 = "0.4.0",
        /// The binary inside the archive.
        inside: []const u8 = script("0.4.0"),
        /// Its name inside the archive; null = `artoo-<ver>-<target>/artoo`.
        entry: ?[]const u8 = null,
        /// The release is asked for by tag (`artoo update VERSION`).
        by_tag: bool = false,
        bad_sum: bool = false,
        bad_digest: bool = false,
        /// Where the archive download redirects to.
        redirect: enum { cdn, evil } = .cdn,
    };

    fn init(fx: *Fx, o: Opts) !void {
        const gpa = testing.allocator;
        fx.* = .{ .g = undefined };
        const name = try std.fmt.allocPrint(gpa, "artoo-{s}-aarch64-macos.tar.gz", .{o.version});
        defer gpa.free(name);
        const entry = o.entry orelse try std.fmt.allocPrint(gpa, "artoo-{s}-aarch64-macos/artoo", .{o.version});
        defer if (o.entry == null) gpa.free(entry);
        fx.archive = try archive.testArchive(gpa, &.{
            .{ .name = "artoo-dir", .kind = .dir },
            .{ .name = entry, .data = o.inside },
            .{ .name = "artoo-dir/LICENSE", .data = "license", .mode = 0o644 },
        });
        errdefer gpa.free(fx.archive);

        // Placeholder bodies; the real ones need the arena and the port.
        fx.routes = .{
            .{ .match = "", .behavior = .{ .respond = .{} } },
            .{ .match = "/SHA256SUMS ", .behavior = .{ .respond = .{} } },
            .{ .match = "", .behavior = .{ .respond = .{} } },
            .{ .match = "/cdn/blob", .behavior = .{ .respond = .{ .body = fx.archive } } },
            .{ .match = "/never", .behavior = .{ .respond = .{} } },
        };
        try fx.g.initRoutes(&fx.routes);
        errdefer fx.g.deinit();
        const ar = fx.g.h.arena.allocator();
        const base = fx.g.h.hooks.unifi_base.?;

        const tag_match = if (o.by_tag) try std.fmt.allocPrint(ar, "/releases/tags/v{s} ", .{o.version}) else "/releases/latest ";
        const real = archive.hex(archive.sha256(fx.archive));
        const wrong: [64]u8 = @splat('0');
        const sum: []const u8 = if (o.bad_sum) &wrong else &real;
        const digest: []const u8 = if (o.bad_digest) &wrong else &real;
        const sums = try std.fmt.allocPrint(ar, "{s}  {s}\n{s}  artoo-{s}-x86_64-linux.tar.gz\n", .{ sum, name, &wrong, o.version });
        const rel = try std.fmt.allocPrint(ar,
            \\{{"tag_name":"v{s}","draft":false,"prerelease":false,"published_at":"2026-11-02T10:00:00Z","body":"notes","assets":[
            \\{{"name":"{s}","size":{d},"state":"uploaded","digest":"sha256:{s}"}},
            \\{{"name":"SHA256SUMS","size":{d},"state":"uploaded","digest":null}}]}}
        , .{ o.version, name, fx.archive.len, digest, sums.len });
        const location = switch (o.redirect) {
            .cdn => try std.fmt.allocPrint(ar, "location: {s}/cdn/blob?sig=secret\r\n", .{base}),
            .evil => "location: https://evil.example/blob\r\n",
        };
        fx.routes[0] = .{ .match = tag_match, .behavior = .{ .respond = .{ .body = rel } } };
        fx.routes[1].behavior = .{ .respond = .{ .body = sums } };
        fx.routes[2] = .{ .match = try std.fmt.allocPrint(ar, "/releases/download/v{s}/{s} ", .{ o.version, name }), .behavior = .{ .respond = .{ .status = 302, .body = "", .extra = location } } };

        try fx.g.tmp.dir.createDirPath(testing.io, "bin");
        fx.bin = try fx.g.tmp.dir.realPathFileAlloc(testing.io, "bin", ar);
        fx.exe = try fx.g.file("bin/artoo", script("0.3.0"));
        try fx.g.tmp.dir.setFilePermissions(testing.io, "bin/artoo", .fromMode(0o755), .{});
        fx.g.h.hooks.update = .{ .base = base, .exe_path = fx.exe, .version = o.current, .target = "aarch64-macos" };
    }

    fn deinit(fx: *Fx) void {
        testing.allocator.free(fx.archive);
        fx.g.deinit();
    }

    fn run(fx: *Fx, line: []const u8) Exit {
        return fx.g.h.run(root, line);
    }

    fn read(fx: *Fx, path: []const u8) ![]const u8 {
        return Io.Dir.cwd().readFileAlloc(testing.io, path, fx.g.h.arena.allocator(), .limited(1 << 20));
    }

    /// Names in bin/, sorted, joined by spaces.
    fn listing(fx: *Fx) ![]const u8 {
        const ar = fx.g.h.arena.allocator();
        var d = try fx.g.tmp.dir.openDir(testing.io, "bin", .{ .iterate = true });
        defer d.close(testing.io);
        var names: std.ArrayList([]const u8) = .empty;
        var it = d.iterate();
        while (try it.next(testing.io)) |e| try names.append(ar, try ar.dupe(u8, e.name));
        std.mem.sort([]const u8, names.items, {}, struct {
            fn lt(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lt);
        return std.mem.join(ar, " ", names.items);
    }

    fn expectUntouched(fx: *Fx) !void {
        try testing.expectEqualStrings(script("0.3.0"), try fx.read(fx.exe));
        try testing.expectEqualStrings("artoo", try fx.listing());
    }
};

test "update: a newer release is downloaded through the redirect, verified and installed" {
    var fx: Fx = undefined;
    try fx.init(.{});
    defer fx.deinit();
    try testing.expectEqual(Exit.ok, fx.run("update -y"));
    const out = fx.g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "Plan · Update artoo 0.3.0 → 0.4.0") != null);
    try testing.expect(std.mem.find(u8, out, "matches SHA256SUMS and GitHub's digest") != null);
    try testing.expect(std.mem.find(u8, out, "the new binary reports \"artoo 0.4.0\"") != null);
    try testing.expect(std.mem.find(u8, out, "artoo 0.4.0 installed at ") != null);
    try testing.expectEqualStrings(script("0.4.0"), try fx.read(fx.exe));
    try testing.expectEqualStrings(script("0.3.0"), try fx.read(try std.fmt.allocPrint(fx.g.h.arena.allocator(), "{s}/.artoo.previous", .{fx.bin})));
    try testing.expectEqualStrings(".artoo.previous artoo", try fx.listing());
    try testing.expectEqual(@as(usize, 4), fx.g.sent());
    try testing.expect(std.mem.startsWith(u8, fx.g.request(0), "GET /repos/tildaslashalef/artoo/releases/latest "));
    try testing.expect(std.mem.startsWith(u8, fx.g.request(3), "GET /cdn/blob?sig=secret "));
    const st = try Io.Dir.cwd().statFile(testing.io, fx.exe, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o755), st.permissions.toMode() & 0o777);
}

test "update: the same version is a no-op; nothing is downloaded" {
    var fx: Fx = undefined;
    try fx.init(.{ .current = "0.4.0" });
    defer fx.deinit();
    try testing.expectEqual(Exit.refused, fx.run("update -y"));
    try testing.expectEqualStrings("artoo: artoo 0.4.0 is already v0.4.0; nothing to update\n", fx.g.h.stderr());
    try testing.expectEqual(@as(usize, 1), fx.g.sent());
    try fx.expectUntouched();
}

test "update: a dev build is older than its release, newer than the one before" {
    var fx: Fx = undefined;
    try fx.init(.{ .current = "0.5.0-dev+b75b55c" });
    defer fx.deinit();
    try testing.expectEqual(Exit.refused, fx.run("update -y"));
    try testing.expect(std.mem.find(u8, fx.g.h.stderr(), "this build (0.5.0-dev+b75b55c) is newer than the latest release 0.4.0") != null);
    try fx.expectUntouched();

    var fx2: Fx = undefined;
    try fx2.init(.{ .current = "0.4.0-dev+b75b55c" });
    defer fx2.deinit();
    try testing.expectEqual(Exit.ok, fx2.run("update --check"));
    try testing.expectEqualStrings("Update available: artoo 0.4.0-dev+b75b55c → 0.4.0 (v0.4.0, 2026-11-02)\nRun 'artoo update' to install it.\n", fx2.g.h.stdout());
}

test "update: checksum mismatch refuses; nothing replaced, nothing staged" {
    var fx: Fx = undefined;
    try fx.init(.{ .bad_sum = true });
    defer fx.deinit();
    try testing.expectEqual(Exit.refused, fx.run("update -y"));
    try testing.expect(std.mem.find(u8, fx.g.h.stderr(), "but SHA256SUMS says 0000") != null);
    try fx.expectUntouched();
}

test "update: GitHub's digest must agree too" {
    var fx: Fx = undefined;
    try fx.init(.{ .bad_digest = true });
    defer fx.deinit();
    try testing.expectEqual(Exit.refused, fx.run("update -y"));
    try testing.expect(std.mem.find(u8, fx.g.h.stderr(), "but GitHub's digest is 0000") != null);
    try fx.expectUntouched();
}

test "update: the binary inside must report the release's version" {
    var fx: Fx = undefined;
    try fx.init(.{ .inside = script("0.3.9") });
    defer fx.deinit();
    try testing.expectEqual(Exit.refused, fx.run("update -y"));
    try testing.expectEqualStrings("artoo: the binary in artoo-0.4.0-aarch64-macos.tar.gz reports 'artoo 0.3.9', expected 'artoo 0.4.0'; nothing was replaced\n", fx.g.h.stderr());
    try fx.expectUntouched();
}

test "update: an archive without this target's entry is refused" {
    var fx: Fx = undefined;
    try fx.init(.{ .entry = "artoo-0.4.0-x86_64-linux/artoo" });
    defer fx.deinit();
    try testing.expectEqual(Exit.refused, fx.run("update -y"));
    try testing.expectEqualStrings("artoo: the archive has no artoo-0.4.0-aarch64-macos/artoo; nothing was replaced\n", fx.g.h.stderr());
    try fx.expectUntouched();
}

test "update: a redirect away from GitHub is refused" {
    var fx: Fx = undefined;
    try fx.init(.{ .redirect = .evil });
    defer fx.deinit();
    try testing.expectEqual(Exit.network, fx.run("update -y"));
    try testing.expectEqualStrings("artoo: downloading artoo-0.4.0-aarch64-macos.tar.gz: redirected to https://evil.example/blob, which is not GitHub's; refused\n", fx.g.h.stderr());
    try fx.expectUntouched();
}

test "update: an unsupported target is refused before any request" {
    var fx: Fx = undefined;
    try fx.init(.{});
    defer fx.deinit();
    fx.g.h.hooks.update.?.target = null;
    try testing.expectEqual(Exit.refused, fx.run("update"));
    try testing.expect(std.mem.startsWith(u8, fx.g.h.stderr(), "artoo: artoo releases are built for aarch64-macos, x86_64-macos, aarch64-linux and x86_64-linux; this build runs on "));
    try testing.expectEqual(Exit.refused, fx.run("update --check"));
    try testing.expectEqual(@as(usize, 0), fx.g.sent());
}

test "update: dry run downloads and verifies, replaces nothing" {
    var fx: Fx = undefined;
    try fx.init(.{});
    defer fx.deinit();
    try testing.expectEqual(Exit.ok, fx.run("update -n"));
    try testing.expect(std.mem.endsWith(u8, fx.g.h.stdout(), "\nDry run: downloaded and verified; nothing was replaced.\n"));
    try testing.expectEqual(@as(usize, 4), fx.g.sent());
    try fx.expectUntouched();
}

test "update: without a terminal and without --yes nothing is replaced" {
    var fx: Fx = undefined;
    try fx.init(.{});
    defer fx.deinit();
    try testing.expectEqual(Exit.refused, fx.run("update"));
    try testing.expectEqualStrings("artoo: not a terminal: re-run with --yes to confirm\n", fx.g.h.stderr());
    try fx.expectUntouched();
}

test "update: --check exits 0 for an update, 5 when up to date; JSON" {
    var fx: Fx = undefined;
    try fx.init(.{});
    defer fx.deinit();
    try testing.expectEqual(Exit.ok, fx.run("update --check"));
    try testing.expectEqualStrings("Update available: artoo 0.3.0 → 0.4.0 (v0.4.0, 2026-11-02)\nRun 'artoo update' to install it.\n", fx.g.h.stdout());
    try fx.expectUntouched();
    try testing.expectEqual(@as(usize, 1), fx.g.sent());

    fx.g.h.hooks.update.?.version = "0.4.0";
    fx.routes[4] = fx.routes[0]; // each route answers once
    try testing.expectEqual(Exit.refused, fx.run("-o json update --check"));
    try testing.expect(std.mem.find(u8, fx.g.h.stdout(), "\"target\": \"github\"") != null);
    try testing.expect(std.mem.find(u8, fx.g.h.stdout(), "\"update_available\": false") != null);
    try testing.expect(std.mem.find(u8, fx.g.h.stderr(), "artoo 0.4.0 is up to date (latest release: v0.4.0); nothing to update") != null);
}

test "update: an explicit VERSION, as given or missing" {
    var fx: Fx = undefined;
    try fx.init(.{ .by_tag = true });
    defer fx.deinit();
    try testing.expectEqual(Exit.usage, fx.run("update 0.4"));
    try testing.expectEqual(Exit.ok, fx.run("-o json update v0.4.0 -y"));
    try testing.expect(std.mem.startsWith(u8, fx.g.request(0), "GET /repos/tildaslashalef/artoo/releases/tags/v0.4.0 "));
    const out = fx.g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "\"result\": \"applied\"") != null);
    try testing.expect(std.mem.find(u8, out, "\"latest\": null") != null);
    try testing.expectEqualStrings(script("0.4.0"), try fx.read(fx.exe));
    // The fake has no route for this tag: 599 is not a release.
    try testing.expectEqual(Exit.network, fx.run("update 9.9.9 -y"));
}

test "update: a missing release is exit 2" {
    var fx: Fx = undefined;
    try fx.init(.{});
    defer fx.deinit();
    fx.routes[0] = .{ .match = "/releases/tags/v9.9.9 ", .behavior = .{ .respond = .{ .status = 404, .body = "{\"message\":\"Not Found\"}" } } };
    try testing.expectEqual(Exit.usage, fx.run("update 9.9.9 -y"));
    try testing.expectEqualStrings("artoo: no release v9.9.9 at github.com/tildaslashalef/artoo/releases\n", fx.g.h.stderr());
    try fx.expectUntouched();
}

test "update: a symbolic link to artoo is refused before any request" {
    var fx: Fx = undefined;
    try fx.init(.{});
    defer fx.deinit();
    const link = try std.fmt.allocPrint(fx.g.h.arena.allocator(), "{s}/link", .{fx.bin});
    try Io.Dir.cwd().symLink(testing.io, fx.exe, link, .{});
    fx.g.h.hooks.update.?.invoked = link;
    try testing.expectEqual(Exit.refused, fx.run("update -y"));
    try testing.expect(std.mem.find(u8, fx.g.h.stderr(), "/bin/link is a symbolic link to ") != null);
    try testing.expectEqual(@as(usize, 0), fx.g.sent());
}

test "update: an unwritable directory is a permission failure" {
    var fx: Fx = undefined;
    try fx.init(.{});
    defer fx.deinit();
    try fx.g.tmp.dir.setFilePermissions(testing.io, "bin", .fromMode(0o555), .{});
    defer fx.g.tmp.dir.setFilePermissions(testing.io, "bin", .fromMode(0o755), .{}) catch {};
    // root may write anyway; then there is nothing to test.
    if (Io.Dir.cwd().access(testing.io, fx.bin, .{ .write = true })) |_| return error.SkipZigTest else |_| {}
    try testing.expectEqual(Exit.auth, fx.run("update -y"));
    try testing.expect(std.mem.find(u8, fx.g.h.stderr(), "run artoo update as a user who can (artoo never runs sudo)") != null);
    try testing.expectEqual(@as(usize, 0), fx.g.sent());
}
