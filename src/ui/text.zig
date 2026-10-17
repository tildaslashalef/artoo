//! Terminal-safe text: sanitizing, display width, fitting to a column.
//!
//! Every server- or user-supplied string passes through `sanitize` before it
//! reaches a renderer (SPEC §4.1): C0 controls, DEL, C1 controls (raw and
//! UTF-8 encoded), bidi overrides and invalid UTF-8 become `?`.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Mode = enum {
    /// Table cells, one-line values: newlines and tabs become spaces.
    line,
    /// Logs, multi-line details: newlines and tabs are kept.
    block,
};

const replacement = '?';

fn isUnsafe(cp: u21) bool {
    return cp < 0x20 or cp == 0x7f or (cp >= 0x80 and cp <= 0x9f) or
        (cp >= 0x202a and cp <= 0x202e) or (cp >= 0x2066 and cp <= 0x2069);
}

/// Returns `s` unchanged when it is already safe (no allocation).
pub fn sanitize(arena: Allocator, s: []const u8, mode: Mode) Allocator.Error![]const u8 {
    if (isClean(s)) return s;
    var out: std.ArrayList(u8) = try .initCapacity(arena, s.len);
    var i: usize = 0;
    while (i < s.len) {
        const len = std.unicode.utf8ByteSequenceLength(s[i]) catch {
            try out.append(arena, replacement);
            i += 1;
            continue;
        };
        if (i + len > s.len) {
            try out.append(arena, replacement);
            i += 1;
            continue;
        }
        const cp = std.unicode.utf8Decode(s[i .. i + len]) catch {
            try out.append(arena, replacement);
            i += 1;
            continue;
        };
        if (cp == '\n' or cp == '\t') {
            try out.append(arena, if (mode == .block) @intCast(cp) else ' ');
        } else if (cp == '\r') {
            if (mode == .line) try out.append(arena, ' ');
        } else if (isUnsafe(cp)) {
            try out.append(arena, replacement);
        } else {
            try out.appendSlice(arena, s[i .. i + len]);
        }
        i += len;
    }
    return out.items;
}

fn isClean(s: []const u8) bool {
    for (s) |c| {
        if (c < 0x20 or c >= 0x7f) return false;
    }
    return true;
}

/// Columns a sanitized string occupies. Combining marks are 0, East Asian
/// wide/fullwidth and emoji ranges are 2, everything else 1.
pub fn width(s: []const u8) usize {
    var w: usize = 0;
    var it = Utf8Iter{ .s = s };
    while (it.next()) |cp| w += cpWidth(cp.cp);
    return w;
}

const Utf8Iter = struct {
    s: []const u8,
    i: usize = 0,

    const Item = struct { cp: u21, start: usize, end: usize };

    fn next(it: *Utf8Iter) ?Item {
        if (it.i >= it.s.len) return null;
        const start = it.i;
        const len = std.unicode.utf8ByteSequenceLength(it.s[start]) catch 1;
        const end = @min(start + len, it.s.len);
        const cp = std.unicode.utf8Decode(it.s[start..end]) catch replacement;
        it.i = if (end > start) end else start + 1;
        return .{ .cp = cp, .start = start, .end = it.i };
    }
};

fn cpWidth(cp: u21) usize {
    if ((cp >= 0x0300 and cp <= 0x036f) or (cp >= 0x200b and cp <= 0x200f) or (cp >= 0xfe00 and cp <= 0xfe0f)) return 0;
    if ((cp >= 0x1100 and cp <= 0x115f) or (cp >= 0x2e80 and cp <= 0xa4cf) or
        (cp >= 0xac00 and cp <= 0xd7a3) or (cp >= 0xf900 and cp <= 0xfaff) or
        (cp >= 0xfe30 and cp <= 0xfe4f) or (cp >= 0xff00 and cp <= 0xff60) or
        (cp >= 0xffe0 and cp <= 0xffe6) or (cp >= 0x1f300 and cp <= 0x1f64f) or
        (cp >= 0x1f900 and cp <= 0x1f9ff) or (cp >= 0x20000 and cp <= 0x3fffd)) return 2;
    return 1;
}

pub const Align = enum { left, right };

/// Write `s` into exactly `cols` columns: truncated at a codepoint boundary
/// with `ellipsis` when too wide, padded with spaces otherwise. With
/// `pad == false` no trailing padding is written (last column).
pub fn writeFit(w: *Io.Writer, s: []const u8, cols: usize, alignment: Align, ellipsis: []const u8, pad: bool) Io.Writer.Error!void {
    const sw = width(s);
    if (sw <= cols) {
        const fill = cols - sw;
        if (alignment == .right) try w.splatByteAll(' ', fill);
        try w.writeAll(s);
        if (alignment == .left and pad) try w.splatByteAll(' ', fill);
        return;
    }
    const ew = width(ellipsis);
    if (cols <= ew) {
        // Not even room for the ellipsis: hard cut.
        _ = try writePrefix(w, s, cols);
        return;
    }
    const used = try writePrefix(w, s, cols - ew);
    try w.writeAll(ellipsis);
    if (pad) try w.splatByteAll(' ', cols - ew - used);
}

/// Writes the longest prefix of at most `cols` columns; returns its width.
fn writePrefix(w: *Io.Writer, s: []const u8, cols: usize) Io.Writer.Error!usize {
    var used: usize = 0;
    var end: usize = 0;
    var it = Utf8Iter{ .s = s };
    while (it.next()) |item| {
        const cw = cpWidth(item.cp);
        if (used + cw > cols) break;
        used += cw;
        end = item.end;
    }
    try w.writeAll(s[0..end]);
    return used;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "sanitize: controls, C1 raw and UTF-8, bidi, invalid UTF-8" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const cases = [_]struct { []const u8, Mode, []const u8 }{
        .{ "plain text", .line, "plain text" },
        .{ "a\x1b[31mred", .line, "a?[31mred" },
        .{ "bell\x07 del\x7f", .line, "bell? del?" },
        .{ "csi\xc2\x9b2J", .line, "csi?2J" }, // UTF-8 encoded C1 (U+009B)
        .{ "raw\x9bc1", .line, "raw?c1" }, // lone C1 byte = invalid UTF-8
        .{ "bidi\u{202e}x", .line, "bidi?x" },
        .{ "two\nlines\tand\r\n", .line, "two lines and  " },
        .{ "two\nlines\tand\r\n", .block, "two\nlines\tand\n" },
        .{ "Zürich ✓ 日本", .line, "Zürich ✓ 日本" },
        .{ "cut\xe2\x9c", .line, "cut??" }, // truncated sequence
    };
    for (cases) |c| try testing.expectEqualStrings(c[2], try sanitize(ar, c[0], c[1]));
    // Clean input is returned as-is.
    const s: []const u8 = "no-alloc";
    try testing.expectEqual(s.ptr, (try sanitize(ar, s, .line)).ptr);
}

test "width" {
    try testing.expectEqual(@as(usize, 5), width("hello"));
    try testing.expectEqual(@as(usize, 9), width("● running"));
    try testing.expectEqual(@as(usize, 4), width("日本"));
    try testing.expectEqual(@as(usize, 1), width("e\u{301}"));
}

test "writeFit: pad, align, UTF-8-safe truncation" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const w = &buf.writer;
    try writeFit(w, "web", 6, .left, "…", true);
    try w.writeByte('|');
    try writeFit(w, "42", 5, .right, "…", true);
    try w.writeByte('|');
    try writeFit(w, "ubuntu-template", 8, .left, "…", true);
    try w.writeByte('|');
    try writeFit(w, "日本語テキスト", 6, .left, "…", true);
    try w.writeByte('|');
    try writeFit(w, "abcdef", 4, .left, "...", false);
    try w.writeByte('|');
    try writeFit(w, "abc", 6, .left, "…", false);
    try w.writeByte('|');
    try testing.expectEqualStrings("web   |   42|ubuntu-…|日本… |a...|abc|", buf.written());
}
