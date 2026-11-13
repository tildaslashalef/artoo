//! `artoo --version` from the Git tags (docs/RELEASING.md §1), used by
//! build.zig at configure time. Pure, so the test suite covers it.
//!
//! `git describe --match 'v[0-9]*' --long --abbrev=7` names the nearest
//! annotated release tag, the commits since it and the commit:
//!
//! - `v0.7.0-0-gabc1234`        → `0.7.0` (a release build, at its tag)
//! - `v0.6.0-5-gabc1234`        → `0.7.0-dev.5+abc1234` (the next MINOR)
//! - `v0.7.0-rc.1-3-gabc1234`   → `0.7.0-rc.1.dev.3+abc1234`
//!
//! SemVer orders every dev build after the tag it follows and before the
//! next release (`0.6.0` < `0.7.0-dev.5` < `0.7.0`; `0.7.0-rc.1` <
//! `0.7.0-rc.1.dev.3` < `0.7.0-rc.2`), and later commits after earlier
//! ones (`dev.5` < `dev.12`: numeric identifiers compare as numbers).

const std = @import("std");

/// The version for a `git describe --long` line; null when the line or
/// its tag is not what a release tag looks like.
pub fn fromDescribe(a: std.mem.Allocator, line: []const u8) !?[]const u8 {
    const d = std.mem.trim(u8, line, " \r\n");
    const g = std.mem.findScalarLast(u8, d, '-') orelse return null;
    const hash = std.mem.cutPrefix(u8, d[g + 1 ..], "g") orelse return null;
    if (hash.len == 0) return null;
    for (hash) |c| if (!std.ascii.isHex(c)) return null;
    const n_at = std.mem.findScalarLast(u8, d[0..g], '-') orelse return null;
    const n = std.fmt.parseInt(u32, d[n_at + 1 .. g], 10) catch return null;
    const tag = std.mem.cutPrefix(u8, d[0..n_at], "v") orelse return null;
    const v = std.SemanticVersion.parse(tag) catch return null;
    if (v.build != null) return null;
    if (n == 0) return try a.dupe(u8, tag);
    if (v.pre != null) return try std.fmt.allocPrint(a, "{s}.dev.{d}+{s}", .{ tag, n, hash });
    return try std.fmt.allocPrint(a, "{d}.{d}.0-dev.{d}+{s}", .{ v.major, v.minor + 1, n, hash });
}

/// A build with no reachable release tag and no `-Dversion`.
pub const unknown = "0.0.0-unknown";

test "fromDescribe" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cases = [_]struct { []const u8, ?[]const u8 }{
        .{ "v0.7.0-0-gabc1234\n", "0.7.0" },
        .{ "v0.6.0-5-gabc1234", "0.7.0-dev.5+abc1234" },
        .{ "v1.2.3-12-g0123abc", "1.3.0-dev.12+0123abc" },
        .{ "v0.7.0-rc.1-0-gabc1234", "0.7.0-rc.1" },
        .{ "v0.7.0-rc.1-3-gabc1234", "0.7.0-rc.1.dev.3+abc1234" },
        .{ "0.6.0-5-gabc1234", null }, // no v
        .{ "v0.6-5-gabc1234", null }, // not SemVer
        .{ "v0.6.0+meta-5-gabc1234", null },
        .{ "v0.6.0-x-gabc1234", null },
        .{ "v0.6.0-5-abc1234", null },
        .{ "v0.6.0-5-gxyz", null },
        .{ "abc1234", null },
        .{ "", null },
    };
    for (cases) |c| {
        const got = try fromDescribe(a, c[0]);
        if (c[1]) |want| {
            try std.testing.expectEqualStrings(want, got orelse return error.TestExpectedEqual);
        } else try std.testing.expect(got == null);
    }
}

test "dev builds order between the releases around them" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const P = std.SemanticVersion.parse;
    const order = [_][]const u8{
        "0.6.0",
        (try fromDescribe(a, "v0.6.0-5-gabc1234")).?,
        (try fromDescribe(a, "v0.6.0-12-gabc1234")).?,
        "0.7.0-rc.1",
        (try fromDescribe(a, "v0.7.0-rc.1-3-gabc1234")).?,
        "0.7.0-rc.2",
        "0.7.0",
    };
    for (order[0 .. order.len - 1], order[1..]) |lo, hi|
        try std.testing.expectEqual(std.math.Order.lt, (try P(lo)).order(try P(hi)));
}
