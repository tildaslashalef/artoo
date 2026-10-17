//! Width-aware tables (SPEC §4.1).
//!
//! Layout: natural column widths; on a narrow terminal drop columns by
//! descending `drop` priority, then truncate truncatable columns (widest
//! first, never below `min` or the title). Identifier columns
//! (`truncate = false`) are never cut. No width (piped output) = no limit.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const text = @import("text.zig");
const style = @import("style.zig");
const Ui = @import("Ui.zig");

pub const Column = struct {
    title: []const u8,
    alignment: text.Align = .left,
    /// 0 = always shown; higher numbers are dropped first.
    drop: u8 = 0,
    truncate: bool = true,
    min: usize = 4,
};

pub const Cell = struct {
    text: []const u8,
    role: style.Role = .text,
};

const gutter = 2;

/// Cells must already be sanitized (`text.sanitize`, `.line`).
pub fn render(w: *Io.Writer, ui: *const Ui, arena: Allocator, columns: []const Column, rows: []const []const Cell) !void {
    const n = columns.len;
    const widths = try arena.alloc(usize, n);
    const shown = try arena.alloc(bool, n);
    for (columns, 0..) |c, i| {
        widths[i] = text.width(c.title);
        shown[i] = true;
    }
    for (rows) |row| {
        for (row[0..n], 0..) |cell, i| widths[i] = @max(widths[i], text.width(cell.text));
    }

    if (ui.width) |limit| {
        // Drop optional columns, highest `drop` first (rightmost on ties).
        while (total(widths, shown) > limit) {
            var victim: ?usize = null;
            for (columns, 0..) |c, i| {
                if (!shown[i] or c.drop == 0) continue;
                if (victim == null or c.drop >= columns[victim.?].drop) victim = i;
            }
            shown[victim orelse break] = false;
        }
        // Then shrink truncatable columns, widest first.
        while (total(widths, shown) > limit) {
            var victim: ?usize = null;
            for (columns, 0..) |c, i| {
                if (!shown[i] or !c.truncate) continue;
                if (widths[i] <= floor(c)) continue;
                if (victim == null or widths[i] > widths[victim.?]) victim = i;
            }
            const v = victim orelse break;
            widths[v] -= @min(widths[v] - floor(columns[v]), total(widths, shown) - limit);
        }
    }

    const last = lastShown(shown);
    // Header.
    for (columns, 0..) |c, i| {
        if (!shown[i]) continue;
        try w.writeAll(ui.palette.on(.title));
        try text.writeFit(w, c.title, widths[i], c.alignment, ui.glyphs.ellipsis, i != last);
        try w.writeAll(ui.palette.off(.title));
        if (i != last) try w.splatByteAll(' ', gutter);
    }
    try w.writeByte('\n');
    for (rows) |row| {
        for (columns, 0..) |c, i| {
            if (!shown[i]) continue;
            const cell = row[i];
            const role: style.Role = if (cell.text.len == 0 or std.mem.eql(u8, cell.text, "--")) .muted else cell.role;
            try w.writeAll(ui.palette.on(role));
            try text.writeFit(w, cell.text, widths[i], c.alignment, ui.glyphs.ellipsis, i != last);
            try w.writeAll(ui.palette.off(role));
            if (i != last) try w.splatByteAll(' ', gutter);
        }
        try w.writeByte('\n');
    }
}

fn floor(c: Column) usize {
    return @max(c.min, text.width(c.title));
}

fn total(widths: []const usize, shown: []const bool) usize {
    var sum: usize = 0;
    var count: usize = 0;
    for (widths, shown) |wd, s| {
        if (!s) continue;
        sum += wd;
        count += 1;
    }
    return sum + gutter * (if (count > 0) count - 1 else 0);
}

fn lastShown(shown: []const bool) usize {
    var last: usize = 0;
    for (shown, 0..) |s, i| {
        if (s) last = i;
    }
    return last;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const test_cols = [_]Column{
    .{ .title = "VMID", .alignment = .right, .truncate = false },
    .{ .title = "NAME", .truncate = false },
    .{ .title = "STATUS" },
    .{ .title = "MEMORY", .alignment = .right, .drop = 1 },
    .{ .title = "DESCRIPTION", .drop = 2, .min = 8 },
};

const test_rows = [_][]const Cell{
    &.{ .{ .text = "101" }, .{ .text = "web-01" }, .{ .text = "● running", .role = .ok }, .{ .text = "1.2 GiB" }, .{ .text = "nginx front end for the lab" } },
    &.{ .{ .text = "9000" }, .{ .text = "ubuntu-2604" }, .{ .text = "○ stopped" }, .{ .text = "--" }, .{ .text = "template" } },
};

fn renderAt(width: ?usize) ![]u8 {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    errdefer buf.deinit();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ui: Ui = .{ .width = width };
    try render(&buf.writer, &ui, a.allocator(), &test_cols, &test_rows);
    return buf.toOwnedSlice();
}

test "table: natural width, no trailing spaces" {
    const out = try renderAt(null);
    defer testing.allocator.free(out);
    try testing.expectEqualStrings(
        \\VMID  NAME         STATUS      MEMORY  DESCRIPTION
        \\ 101  web-01       ● running  1.2 GiB  nginx front end for the lab
        \\9000  ubuntu-2604  ○ stopped       --  template
        \\
    , out);
}

test "table: narrow terminal drops by priority, then truncates; ids intact" {
    const out48 = try renderAt(48);
    defer testing.allocator.free(out48);
    try testing.expectEqualStrings(
        \\VMID  NAME         STATUS      MEMORY
        \\ 101  web-01       ● running  1.2 GiB
        \\9000  ubuntu-2604  ○ stopped       --
        \\
    , out48);
    const out30 = try renderAt(30);
    defer testing.allocator.free(out30);
    try testing.expectEqualStrings(
        \\VMID  NAME         STATUS
        \\ 101  web-01       ● running
        \\9000  ubuntu-2604  ○ stopped
        \\
    , out30);
    // Narrower than the identifiers: they overflow rather than being cut.
    const out10 = try renderAt(10);
    defer testing.allocator.free(out10);
    try testing.expectEqualStrings(
        \\VMID  NAME         STATUS
        \\ 101  web-01       ● run…
        \\9000  ubuntu-2604  ○ sto…
        \\
    , out10);
}

test "table: colored output wraps cells in role sequences" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ui: Ui = .{ .palette = .{ .depth = .ansi256 } };
    try render(&buf.writer, &ui, a.allocator(), test_cols[0..3], test_rows[0..1]);
    try testing.expect(std.mem.find(u8, buf.written(), "\x1b[38;5;142m● running\x1b[0m") != null);
}
