//! Header line, detail views and plan blocks (SPEC §4.1). All strings must
//! already be sanitized.

const std = @import("std");
const Io = std.Io;
const text = @import("text.zig");
const style = @import("style.zig");
const Ui = @import("Ui.zig");

/// `ARTOO · <context>` left, `<right>` (target · time) right-aligned when the
/// terminal width is known.
pub fn header(w: *Io.Writer, ui: *const Ui, context: []const u8, right: []const u8) Io.Writer.Error!void {
    const p = ui.palette;
    try w.print("{s}ARTOO {s} {s}{s}", .{ p.on(.title), ui.glyphs.dot, context, p.off(.title) });
    const left_w = "ARTOO ".len + text.width(ui.glyphs.dot) + 1 + text.width(context);
    const right_w = text.width(right);
    const gap = if (ui.width) |cols| (if (cols > left_w + right_w + 2) cols - left_w - right_w else 2) else 2;
    try w.splatByteAll(' ', gap);
    try w.print("{s}{s}{s}\n\n", .{ p.on(.muted), right, p.off(.muted) });
}

pub const Field = struct {
    key: []const u8,
    value: []const u8,
    role: style.Role = .text,

    pub fn toCell(f: Field) @import("table.zig").Cell {
        return .{ .text = f.value, .role = f.role };
    }
};

pub const Section = struct {
    title: ?[]const u8 = null,
    fields: []const Field,
};

/// Aligned key/value sections; multi-line values continue under the value
/// column.
pub fn detail(w: *Io.Writer, ui: *const Ui, sections: []const Section) Io.Writer.Error!void {
    const p = ui.palette;
    var key_w: usize = 0;
    for (sections) |s| {
        for (s.fields) |f| key_w = @max(key_w, text.width(f.key));
    }
    for (sections, 0..) |s, si| {
        if (si > 0) try w.writeByte('\n');
        const indent: usize = if (s.title != null) 2 else 0;
        if (s.title) |t| try w.print("{s}{s}{s}\n", .{ p.on(.title), t, p.off(.title) });
        for (s.fields) |f| {
            try w.splatByteAll(' ', indent);
            try w.writeAll(p.on(.muted));
            try text.writeFit(w, f.key, key_w, .left, "", true);
            try w.writeAll(p.off(.muted));
            try w.writeAll("  ");
            const role: style.Role = if (std.mem.eql(u8, f.value, "--")) .muted else f.role;
            var lines = std.mem.splitScalar(u8, f.value, '\n');
            var first = true;
            while (lines.next()) |line| {
                if (!first) {
                    try w.writeByte('\n');
                    try w.splatByteAll(' ', indent + key_w + 2);
                }
                first = false;
                try w.print("{s}{s}{s}", .{ p.on(role), line, p.off(role) });
            }
            try w.writeByte('\n');
        }
    }
}

pub const Risk = enum { normal, destructive };

pub const Change = struct {
    field: []const u8,
    /// null = currently absent.
    from: ?[]const u8,
    /// null = removed.
    to: ?[]const u8,
};

pub const Plan = struct {
    /// "Stop VM web-01 (101)".
    action: []const u8,
    risk: Risk = .normal,
    target: []const u8,
    changes: []const Change = &.{},
    impact: []const []const u8 = &.{},
    recovery: ?[]const u8 = null,
    notes: []const []const u8 = &.{},
};

/// The preview shown before every confirmation.
pub fn plan(w: *Io.Writer, ui: *const Ui, pl: Plan) Io.Writer.Error!void {
    const p = ui.palette;
    const g = ui.glyphs;
    const title_role: style.Role = if (pl.risk == .destructive) .high else .title;
    try w.print("{s}Plan {s} {s}{s}", .{ p.on(title_role), g.dot, pl.action, p.off(title_role) });
    if (pl.risk == .destructive) try w.print("  {s}{s} destructive{s}", .{ p.on(.high), g.warn, p.off(.high) });
    try w.writeByte('\n');

    try label(w, ui, "Target");
    try w.print("{s}\n", .{pl.target});
    var field_w: usize = 0;
    for (pl.changes) |c| field_w = @max(field_w, text.width(c.field));
    for (pl.changes, 0..) |c, i| {
        try label(w, ui, if (i == 0) "Change" else "");
        try text.writeFit(w, c.field, field_w, .left, "", true);
        try w.writeAll("  ");
        try w.print("{s}{s}{s} {s} ", .{ p.on(.muted), c.from orelse "(none)", p.off(.muted), g.arrow });
        const to_role: style.Role = if (c.to == null) .fail else .changed;
        try w.print("{s}{s}{s}\n", .{ p.on(to_role), c.to orelse "(removed)", p.off(to_role) });
    }
    for (pl.impact, 0..) |line, i| {
        try label(w, ui, if (i == 0) "Impact" else "");
        try w.print("{s}\n", .{line});
    }
    if (pl.recovery) |r| {
        try label(w, ui, "Recovery");
        try w.print("{s}\n", .{r});
    }
    for (pl.notes, 0..) |line, i| {
        try label(w, ui, if (i == 0) "Note" else "");
        try w.print("{s}{s}{s}\n", .{ p.on(.muted), line, p.off(.muted) });
    }
}

fn label(w: *Io.Writer, ui: *const Ui, name: []const u8) Io.Writer.Error!void {
    try w.print("  {s}", .{ui.palette.on(.muted)});
    try text.writeFit(w, name, "Recovery".len, .left, "", true);
    try w.print("{s}  ", .{ui.palette.off(.muted)});
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "header: padded to terminal width, two spaces otherwise" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const ui: Ui = .{ .width = 40 };
    try header(&buf.writer, &ui, "devices", "unifi · 14:32");
    try testing.expectEqualStrings("ARTOO · devices            unifi · 14:32\n\n", buf.written());
    buf.clearRetainingCapacity();
    const piped: Ui = .{ .glyphs = &style.ascii };
    try header(&buf.writer, &piped, "devices", "unifi");
    try testing.expectEqualStrings("ARTOO - devices  unifi\n\n", buf.written());
}

test "detail: aligned keys across sections, multi-line values" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const ui: Ui = .{};
    try detail(&buf.writer, &ui, &.{
        .{ .title = "General", .fields = &.{
            .{ .key = "Name", .value = "web-01" },
            .{ .key = "Status", .value = "● running", .role = .ok },
        } },
        .{ .title = "Network", .fields = &.{
            .{ .key = "Addresses", .value = "192.168.1.201\nfe80::1" },
            .{ .key = "DNS", .value = "--" },
        } },
    });
    try testing.expectEqualStrings(
        \\General
        \\  Name       web-01
        \\  Status     ● running
        \\
        \\Network
        \\  Addresses  192.168.1.201
        \\             fe80::1
        \\  DNS        --
        \\
    , buf.written());
}

test "plan: destructive block with changes, impact, recovery, notes" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const ui: Ui = .{};
    try plan(&buf.writer, &ui, .{
        .action = "Delete DNS record web-01.home.arpa",
        .risk = .destructive,
        .target = "unifi (site default)",
        .changes = &.{
            .{ .field = "A record", .from = "web-01.home.arpa → 192.168.1.201", .to = null },
            .{ .field = "TTL", .from = null, .to = "300" },
        },
        .impact = &.{ "Name stops resolving for LAN clients", "Cached answers expire within the TTL" },
        .recovery = "artoo dns add web-01 192.168.1.201",
        .notes = &.{"The UniFi API has no ETags; concurrent edits cannot be detected."},
    });
    try testing.expectEqualStrings(
        \\Plan · Delete DNS record web-01.home.arpa  ▲ destructive
        \\  Target    unifi (site default)
        \\  Change    A record  web-01.home.arpa → 192.168.1.201 → (removed)
        \\            TTL       (none) → 300
        \\  Impact    Name stops resolving for LAN clients
        \\            Cached answers expire within the TTL
        \\  Recovery  artoo dns add web-01 192.168.1.201
        \\  Note      The UniFi API has no ETags; concurrent edits cannot be detected.
        \\
    , buf.written());
}
