//! Closest-match suggestions for mistyped commands and flags.

const std = @import("std");

/// Optimal-string-alignment distance (Levenshtein + adjacent transposition),
/// capped: words longer than 32 bytes are never close.
pub fn distance(a: []const u8, b: []const u8) usize {
    const max = 32;
    if (a.len > max or b.len > max) return std.math.maxInt(usize);
    var rows: [3][max + 1]usize = undefined;
    var prev2 = &rows[0];
    var prev = &rows[1];
    var cur = &rows[2];
    for (0..b.len + 1) |j| prev[j] = j;
    for (a, 1..) |ca, i| {
        cur[0] = i;
        for (b, 1..) |cb, j| {
            const cost: usize = if (ca == cb) 0 else 1;
            var d = @min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
            if (i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb) d = @min(d, prev2[j - 2] + 1);
            cur[j] = d;
        }
        const t = prev2;
        prev2 = prev;
        prev = cur;
        cur = t;
    }
    return prev[b.len];
}

/// A unique prefix match, else the nearest candidate within a
/// length-scaled distance.
pub fn closest(word: []const u8, candidates: []const []const u8) ?[]const u8 {
    if (word.len >= 2) {
        var prefix: ?[]const u8 = null;
        var count: usize = 0;
        for (candidates) |c| {
            if (std.mem.startsWith(u8, c, word)) {
                prefix = c;
                count += 1;
            }
        }
        if (count == 1) return prefix;
    }
    var best: ?[]const u8 = null;
    var best_d: usize = std.math.maxInt(usize);
    const limit: usize = if (word.len <= 3) 1 else 2;
    for (candidates) |c| {
        const d = distance(word, c);
        if (d <= limit and d < best_d) {
            best = c;
            best_d = d;
        }
    }
    return best;
}

const testing = std.testing;

test "distance" {
    const cases = [_]struct { []const u8, []const u8, usize }{
        .{ "", "", 0 },
        .{ "ls", "ls", 0 },
        .{ "sl", "ls", 1 },
        .{ "lss", "ls", 1 },
        .{ "shwo", "show", 1 },
        .{ "stauts", "status", 1 },
        .{ "kitten", "sitting", 3 },
        .{ "", "abc", 3 },
    };
    for (cases) |c| try testing.expectEqual(c[2], distance(c[0], c[1]));
}

test "closest" {
    const verbs = [_][]const u8{ "ls", "show", "start", "stop", "shutdown", "snap" };
    try testing.expectEqualStrings("ls", closest("sl", &verbs).?);
    try testing.expectEqualStrings("show", closest("shwo", &verbs).?);
    try testing.expectEqualStrings("shutdown", closest("shut", &verbs).?);
    try testing.expect(closest("xyzzy", &verbs) == null);
    // Ambiguous prefix gives nothing rather than a guess.
    try testing.expect(closest("sta", &[_][]const u8{ "start", "status" }) == null);
}
