//! Line diffs for plans: what a file replacement changes, as a unified
//! diff (`@@ -a,b +c,d @@`, three lines of context). Lines common to both
//! ends are set aside first; the middle is diffed by longest common
//! subsequence while it stays small, else shown as removed then added
//! (still a correct diff, only not minimal).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Kind = enum { same, del, add };

pub const Line = struct {
    kind: Kind,
    text: []const u8,
};

/// The middle part diffed by LCS: at most this many cells.
const lcs_cells = 4_000_000;

fn lines(a: Allocator, s: []const u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (s.len == 0) return out.items;
    var it = std.mem.splitScalar(u8, if (s[s.len - 1] == '\n') s[0 .. s.len - 1] else s, '\n');
    while (it.next()) |l| try out.append(a, std.mem.trimEnd(u8, l, "\r"));
    return out.items;
}

/// Every line of `old` and `new`, marked same, removed or added.
pub fn diff(a: Allocator, old: []const u8, new: []const u8) ![]const Line {
    const x = try lines(a, old);
    const y = try lines(a, new);
    var pre: usize = 0;
    while (pre < x.len and pre < y.len and std.mem.eql(u8, x[pre], y[pre])) pre += 1;
    var suf: usize = 0;
    while (suf < x.len - pre and suf < y.len - pre and std.mem.eql(u8, x[x.len - 1 - suf], y[y.len - 1 - suf])) suf += 1;
    const xm = x[pre .. x.len - suf];
    const ym = y[pre .. y.len - suf];

    var out: std.ArrayList(Line) = .empty;
    for (x[0..pre]) |l| try out.append(a, .{ .kind = .same, .text = l });
    if ((xm.len + 1) * (ym.len + 1) <= lcs_cells) {
        // table[i][j]: LCS length of xm[i..] and ym[j..].
        const w = ym.len + 1;
        const table = try a.alloc(u32, (xm.len + 1) * w);
        defer a.free(table);
        @memset(table, 0);
        var i = xm.len;
        while (i > 0) {
            i -= 1;
            var j = ym.len;
            while (j > 0) {
                j -= 1;
                table[i * w + j] = if (std.mem.eql(u8, xm[i], ym[j])) table[(i + 1) * w + j + 1] + 1 else @max(table[(i + 1) * w + j], table[i * w + j + 1]);
            }
        }
        var p: usize = 0;
        var q: usize = 0;
        while (p < xm.len or q < ym.len) {
            if (p < xm.len and q < ym.len and std.mem.eql(u8, xm[p], ym[q])) {
                try out.append(a, .{ .kind = .same, .text = xm[p] });
                p += 1;
                q += 1;
            } else if (p < xm.len and (q == ym.len or table[(p + 1) * w + q] >= table[p * w + q + 1])) {
                // Removals before additions, as `diff -u` shows them.
                try out.append(a, .{ .kind = .del, .text = xm[p] });
                p += 1;
            } else {
                try out.append(a, .{ .kind = .add, .text = ym[q] });
                q += 1;
            }
        }
    } else {
        for (xm) |l| try out.append(a, .{ .kind = .del, .text = l });
        for (ym) |l| try out.append(a, .{ .kind = .add, .text = l });
    }
    for (x[x.len - suf ..]) |l| try out.append(a, .{ .kind = .same, .text = l });
    return out.items;
}

pub const Hunk = struct {
    old_start: usize,
    old_len: usize,
    new_start: usize,
    new_len: usize,
    lines: []const Line,
};

/// The changed regions with `context` lines around each; adjacent
/// regions merge. Empty when nothing changed.
pub fn hunks(a: Allocator, all: []const Line, context: usize) ![]const Hunk {
    var out: std.ArrayList(Hunk) = .empty;
    var i: usize = 0;
    // Line numbers (1-based) of all[i] in old and new.
    var old_no: usize = 1;
    var new_no: usize = 1;
    while (i < all.len) {
        if (all[i].kind == .same) {
            old_no += 1;
            new_no += 1;
            i += 1;
            continue;
        }
        // Start: up to `context` same lines back.
        var start = i;
        var back: usize = 0;
        while (start > 0 and back < context and all[start - 1].kind == .same) : (back += 1) start -= 1;
        // End: past changes until `2 * context` same lines in a row (or the end).
        var end = i;
        // Same lines in a row just before `end`.
        var run: usize = 0;
        while (end < all.len and run <= 2 * context) : (end += 1) {
            if (all[end].kind == .same) run += 1 else run = 0;
        }
        // Keep only `context` trailing same lines.
        if (run > context) end -= run - context;
        var h: Hunk = .{ .old_start = old_no - back, .old_len = 0, .new_start = new_no - back, .new_len = 0, .lines = all[start..end] };
        for (h.lines) |l| switch (l.kind) {
            .same => {
                h.old_len += 1;
                h.new_len += 1;
            },
            .del => h.old_len += 1,
            .add => h.new_len += 1,
        };
        try out.append(a, h);
        old_no = h.old_start + h.old_len;
        new_no = h.new_start + h.new_len;
        i = end;
    }
    return out.items;
}

pub const Stats = struct { added: usize = 0, removed: usize = 0 };

pub fn stats(all: []const Line) Stats {
    var s: Stats = .{};
    for (all) |l| switch (l.kind) {
        .same => {},
        .del => s.removed += 1,
        .add => s.added += 1,
    };
    return s;
}

const testing = std.testing;

test "diff and hunks: one changed line in the middle, three lines of context" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
    const new = "1\n2\n3\n4\n5\nsix\n7\n8\n9\n10\n";
    const d = try diff(a, old, new);
    try testing.expectEqual(Stats{ .added = 1, .removed = 1 }, stats(d));
    const hs = try hunks(a, d, 3);
    try testing.expectEqual(@as(usize, 1), hs.len);
    try testing.expectEqual(@as(usize, 3), hs[0].old_start);
    try testing.expectEqual(@as(usize, 7), hs[0].old_len);
    try testing.expectEqual(@as(usize, 7), hs[0].new_len);
    try testing.expectEqualStrings("6", hs[0].lines[3].text);
    try testing.expectEqual(Kind.del, hs[0].lines[3].kind);
    try testing.expectEqualStrings("six", hs[0].lines[4].text);
}

test "diff: insertions and deletions far apart make two hunks; identical text none" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const old = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\nl\n";
    const new = "a\nb2\nb\nc\nd\ne\nf\ng\nh\ni\nj\nl\n";
    const hs = try hunks(a, try diff(a, old, new), 3);
    try testing.expectEqual(@as(usize, 2), hs.len);
    try testing.expectEqual(@as(usize, 1), hs[0].old_start);
    try testing.expectEqual(@as(usize, 4), hs[0].old_len);
    try testing.expectEqual(@as(usize, 5), hs[0].new_len);
    try testing.expectEqual(@as(usize, 8), hs[1].old_start);
    try testing.expectEqual(@as(usize, 5), hs[1].old_len);
    try testing.expectEqual(@as(usize, 4), hs[1].new_len);
    try testing.expectEqual(@as(usize, 0), (try hunks(a, try diff(a, old, old), 3)).len);
}
