//! GitHub releases for `artoo update` (SPEC §18, §17.3): this build's
//! release target, SemVer precedence, release discovery through the API
//! and downloads that follow GitHub's own redirects, and nothing else.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const app = @import("../app.zig");
const api = @import("../api.zig");
const http = @import("../http.zig");
const ui = @import("../ui.zig");

const Context = app.Context;
const Version = std.SemanticVersion;

/// The repository releases come from (docs/RELEASING.md).
pub const repo = "tildaslashalef/artoo";
pub const api_base = "https://api.github.com";
pub const download_base = "https://github.com";

/// Hosts a download may be redirected to, `https` only (SPEC §18).
const redirect_hosts = [_][]const u8{
    "github.com",
    "api.github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
};
const max_hops = 2;

pub const limits = struct {
    pub const metadata = 1 << 20;
    pub const sums = 64 << 10;
    pub const archive = 64 << 20;
    pub const binary = 128 << 20;
};

pub const timeouts = struct {
    pub const metadata_s = 15;
    pub const archive_s = 120;
};

/// The release target this build runs on, or null when no release is
/// built for it (scripts/release-binaries.sh).
pub fn hostTarget() ?[]const u8 {
    return targetName(builtin.os.tag, builtin.cpu.arch);
}

pub fn targetName(os: std.Target.Os.Tag, arch: std.Target.Cpu.Arch) ?[]const u8 {
    return switch (os) {
        .macos => switch (arch) {
            .aarch64 => "aarch64-macos",
            .x86_64 => "x86_64-macos",
            else => null,
        },
        .linux => switch (arch) {
            .aarch64 => "aarch64-linux",
            .x86_64 => "x86_64-linux",
            else => null,
        },
        else => null,
    };
}

/// `0.4.0`, `v0.4.0`, `0.4.0-rc.1` → the version; null when not SemVer.
pub fn parseVersion(text: []const u8) ?Version {
    const t = std.mem.cutPrefix(u8, text, "v") orelse text;
    return Version.parse(t) catch null;
}

/// SemVer precedence; build metadata (`+b75b55c`) is ignored, so a `-dev`
/// build is older than its release.
pub fn order(a: Version, b: Version) std.math.Order {
    return a.order(b);
}

pub fn archiveName(arena: Allocator, version: []const u8, target: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "artoo-{s}-{s}.tar.gz", .{ version, target });
}

pub const Asset = struct {
    name: []const u8,
    size: u64 = 0,
    state: []const u8 = "uploaded",
    /// `sha256:<hex>`, GitHub's own hash of the upload (absent on old ones).
    digest: ?[]const u8 = null,
};

pub const Release = struct {
    tag_name: []const u8,
    draft: bool = false,
    prerelease: bool = false,
    published_at: ?[]const u8 = null,
    assets: []const Asset = &.{},

    /// The tag without its `v`.
    pub fn version(r: Release) []const u8 {
        return std.mem.cutPrefix(u8, r.tag_name, "v") orelse r.tag_name;
    }

    pub fn asset(r: Release, name: []const u8) ?Asset {
        for (r.assets) |a| if (std.mem.eql(u8, a.name, name)) return a;
        return null;
    }

    /// `2026-11-02` from `published_at`.
    pub fn date(r: Release) []const u8 {
        const p = r.published_at orelse return "--";
        return p[0..@min(p.len, 10)];
    }
};

/// Where releases come from: GitHub, or the fake server in tests.
pub const Source = struct {
    meta: *http.Client,
    download: *http.Client,
    api_base: []const u8,
    download_base: []const u8,
    /// Tests: the only origin a redirect may go to (plain HTTP allowed).
    test_origin: ?[]const u8 = null,

    pub fn open(ctx: *Context) !Source {
        if (ctx.test_hooks.update) |h| {
            return .{
                .meta = try testClient(ctx),
                .download = try testClient(ctx),
                .api_base = h.base,
                .download_base = h.base,
                .test_origin = h.base,
            };
        }
        return .{
            .meta = try api.httpClient(ctx, .{ .base = api_base, .ca_bundle = null, .timeout_seconds = timeouts.metadata_s }),
            .download = try api.httpClient(ctx, .{ .base = download_base, .ca_bundle = null, .timeout_seconds = timeouts.archive_s }),
            .api_base = api_base,
            .download_base = download_base,
        };
    }

    fn testClient(ctx: *Context) !*http.Client {
        const hc = try ctx.arena.create(http.Client);
        hc.init(ctx.gpa, ctx.io, .{ .ca_bundle = null, .timeout_ms = 5000, .retries = 0 }) catch return error.Tls;
        return hc;
    }

    pub fn deinit(s: *Source) void {
        s.meta.deinit();
        s.download.deinit();
    }

    /// The latest release (never a pre-release or draft), or the one
    /// tagged `v<version>`.
    pub fn release(s: *Source, ctx: *Context, version: ?[]const u8) !Release {
        const path = if (version) |v|
            try std.fmt.allocPrint(ctx.arena, "/repos/{s}/releases/tags/v{s}", .{ repo, v })
        else
            "/repos/" ++ repo ++ "/releases/latest";
        var diag: http.Diag = .{};
        const r = s.meta.send(ctx.arena, .{
            .url = try std.fmt.allocPrint(ctx.arena, "{s}{s}", .{ s.api_base, path }),
            .headers = &.{
                .{ .name = "Accept", .value = "application/vnd.github+json" },
                .{ .name = "X-GitHub-Api-Version", .value = "2022-11-28" },
            },
            .max_body = limits.metadata,
        }, &diag) catch |err| return api.transportError(ctx, err, diag, "GitHub");
        if (r.status == 404) {
            if (version) |v| return ctx.fail(error.NotFound, "no release v{s} at github.com/{s}/releases", .{ v, repo });
            return ctx.fail(error.NotFound, "github.com/{s} has no release yet", .{repo});
        }
        if (r.status != 200) return statusError(ctx, r, "the release");
        const rel = std.json.parseFromSliceLeaky(Release, ctx.arena, r.body, .{ .ignore_unknown_fields = true }) catch
            return ctx.fail(error.Protocol, "GitHub's release document could not be read", .{});
        if (rel.draft or parseVersion(rel.tag_name) == null or !std.mem.startsWith(u8, rel.tag_name, "v")) {
            return ctx.fail(error.Protocol, "GitHub answered with release '{s}', which is not a vX.Y.Z release", .{try clean(ctx, rel.tag_name)});
        }
        return rel;
    }

    /// Download one asset of `tag`, following GitHub's redirects under the
    /// policy above; the body is capped at `max`.
    pub fn asset(s: *Source, ctx: *Context, tag: []const u8, name: []const u8, max: usize) ![]const u8 {
        var url: []const u8 = try std.fmt.allocPrint(ctx.arena, "{s}/{s}/releases/download/{s}/{s}", .{ s.download_base, repo, tag, name });
        var hops: usize = 0;
        while (true) {
            var diag: http.Diag = .{};
            const r = s.download.send(ctx.arena, .{ .url = url, .redirect = .give_back, .max_body = max }, &diag) catch |err|
                return api.transportError(ctx, err, diag, name);
            if (r.status >= 300 and r.status < 400) {
                const next = r.location orelse "";
                if (hops >= max_hops) return ctx.fail(error.Protocol, "downloading {s}: more than {d} redirects", .{ name, max_hops });
                if (!s.allowed(next)) return ctx.fail(error.Protocol, "downloading {s}: redirected to {s}, which is not GitHub's; refused", .{ name, try clean(ctx, hostPart(next)) });
                url = next;
                hops += 1;
                continue;
            }
            if (r.status != 200) return statusError(ctx, r, name);
            return r.body;
        }
    }

    /// May a download be redirected to `url`?
    pub fn allowed(s: *const Source, url: []const u8) bool {
        if (s.test_origin) |o| return std.mem.startsWith(u8, url, o) and (url.len == o.len or url[o.len] == '/');
        return allowedRedirect(url);
    }
};

/// `https` to one of GitHub's download hosts, nothing else.
pub fn allowedRedirect(url: []const u8) bool {
    const uri = std.Uri.parse(url) catch return false;
    if (!std.mem.eql(u8, uri.scheme, "https")) return false;
    if (uri.user != null or uri.password != null) return false;
    if (uri.port) |p| if (p != 443) return false;
    const host = switch (uri.host orelse return false) {
        .raw, .percent_encoded => |h| h,
    };
    for (redirect_hosts) |h| if (std.ascii.eqlIgnoreCase(host, h)) return true;
    return false;
}

/// `https://host/path` of a URL, for messages (no query).
fn hostPart(url: []const u8) []const u8 {
    return url[0 .. std.mem.findScalar(u8, url, '?') orelse url.len];
}

fn clean(ctx: *Context, s: []const u8) ![]const u8 {
    return ui.text.sanitize(ctx.arena, s[0..@min(s.len, 200)], .line);
}

fn statusError(ctx: *Context, r: http.Response, what: []const u8) anyerror {
    const Msg = struct { message: []const u8 = "" };
    const m = std.json.parseFromSliceLeaky(Msg, ctx.arena, r.body, .{ .ignore_unknown_fields = true }) catch Msg{};
    const msg = try clean(ctx, m.message);
    const sep = if (msg.len > 0) ": " else "";
    if (r.status == 403 or r.status == 429) {
        return ctx.fail(error.HttpStatus, "GitHub refused {s} ({d}){s}{s} — without a token GitHub allows 60 requests an hour per address; try again later", .{ what, r.status, sep, msg });
    }
    return ctx.fail(error.HttpStatus, "GitHub answered {d} for {s}{s}{s}", .{ r.status, what, sep, msg });
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "targetName: the four release targets, nothing else" {
    try testing.expectEqualStrings("aarch64-macos", targetName(.macos, .aarch64).?);
    try testing.expectEqualStrings("x86_64-macos", targetName(.macos, .x86_64).?);
    try testing.expectEqualStrings("aarch64-linux", targetName(.linux, .aarch64).?);
    try testing.expectEqualStrings("x86_64-linux", targetName(.linux, .x86_64).?);
    try testing.expectEqual(@as(?[]const u8, null), targetName(.freebsd, .x86_64));
    try testing.expectEqual(@as(?[]const u8, null), targetName(.linux, .riscv64));
    try testing.expect(hostTarget() != null);
}

test "versions: a dev build is older than its release, build metadata ignored" {
    const cases = [_]struct { []const u8, []const u8, std.math.Order }{
        .{ "0.4.0-dev+b75b55c", "0.4.0", .lt },
        .{ "0.4.0-dev+b75b55c", "0.3.0", .gt },
        .{ "0.4.0-dev", "0.4.0-rc.1", .lt },
        .{ "0.4.0-rc.1", "0.4.0-rc.2", .lt },
        .{ "0.4.0-rc.2", "0.4.0", .lt },
        .{ "0.3.0", "v0.3.0", .eq },
        .{ "0.3.0+abc", "0.3.0", .eq },
        .{ "0.10.0", "0.9.1", .gt },
    };
    for (cases) |c| try testing.expectEqual(c[2], order(parseVersion(c[0]).?, parseVersion(c[1]).?));
    try testing.expectEqual(@as(?Version, null), parseVersion("latest"));
    try testing.expectEqual(@as(?Version, null), parseVersion("0.4"));
}

test "allowedRedirect: https to GitHub's download hosts only" {
    try testing.expect(allowedRedirect("https://release-assets.githubusercontent.com/github-production-release-asset/1/x?sig=1"));
    try testing.expect(allowedRedirect("https://objects.githubusercontent.com/x"));
    try testing.expect(allowedRedirect("https://GitHub.com/a/b"));
    try testing.expect(!allowedRedirect("http://release-assets.githubusercontent.com/x"));
    try testing.expect(!allowedRedirect("https://release-assets.githubusercontent.com.evil.example/x"));
    try testing.expect(!allowedRedirect("https://evil.example/github.com"));
    try testing.expect(!allowedRedirect("https://user@github.com/x"));
    try testing.expect(!allowedRedirect("https://github.com:8443/x"));
    try testing.expect(!allowedRedirect("/relative"));
}
