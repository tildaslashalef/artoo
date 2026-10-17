//! Gruvbox-dark palette, glyph sets and status words (SPEC §4.1).

const std = @import("std");
const Color = @import("../cli/command.zig").Color;

pub const Depth = enum { none, ansi256, truecolor };

pub const Role = enum { text, muted, border, title, id, ok, warn, fail, changed, emphasis, high };

const Rgb = struct { r: u8, g: u8, b: u8, ansi: u8 };

fn rgb(comptime hex: u24, comptime ansi: u8) Rgb {
    return .{ .r = hex >> 16, .g = (hex >> 8) & 0xff, .b = hex & 0xff, .ansi = ansi };
}

fn color(role: Role) ?Rgb {
    return switch (role) {
        // Plain text keeps the terminal's own foreground.
        .text => null,
        .muted => rgb(0xa89984, 246),
        .border => rgb(0x504945, 239),
        .title, .id => rgb(0x83a598, 109),
        .ok => rgb(0xb8bb26, 142),
        .warn => rgb(0xfabd2f, 214),
        .fail => rgb(0xfb4934, 167),
        .changed => rgb(0x8ec07c, 108),
        .emphasis => rgb(0xd3869b, 175),
        .high => rgb(0xfe8019, 208),
    };
}

fn sequence(comptime depth: Depth, comptime role: Role) []const u8 {
    const c = color(role) orelse return "";
    const bold = if (role == .title or role == .high) "1;" else "";
    return switch (depth) {
        .none => "",
        .ansi256 => std.fmt.comptimePrint("\x1b[{s}38;5;{d}m", .{ bold, c.ansi }),
        .truecolor => std.fmt.comptimePrint("\x1b[{s}38;2;{d};{d};{d}m", .{ bold, c.r, c.g, c.b }),
    };
}

const roles = std.meta.tags(Role);

fn table(comptime depth: Depth) [roles.len][]const u8 {
    var t: [roles.len][]const u8 = undefined;
    for (roles) |r| t[@backingInt(r)] = sequence(depth, r);
    return t;
}

const tables = .{ table(.none), table(.ansi256), table(.truecolor) };

pub const Palette = struct {
    depth: Depth = .none,

    pub fn on(p: Palette, role: Role) []const u8 {
        return switch (p.depth) {
            .none => "",
            .ansi256 => tables[1][@backingInt(role)],
            .truecolor => tables[2][@backingInt(role)],
        };
    }

    pub fn off(p: Palette, role: Role) []const u8 {
        if (p.depth == .none or role == .text) return "";
        return "\x1b[0m";
    }
};

pub const Glyphs = struct {
    running: []const u8,
    stopped: []const u8,
    paused: []const u8,
    ok: []const u8,
    warn: []const u8,
    fail: []const u8,
    not_checked: []const u8,
    unknown: []const u8,
    ellipsis: []const u8,
    bar_full: []const u8,
    bar_empty: []const u8,
    arrow: []const u8,
    dot: []const u8,
    rule: []const u8,
};

pub const unicode: Glyphs = .{
    .running = "●",
    .stopped = "○",
    .paused = "◐",
    .ok = "✓",
    .warn = "▲",
    .fail = "✗",
    .not_checked = "–",
    .unknown = "?",
    .ellipsis = "…",
    .bar_full = "█",
    .bar_empty = "░",
    .arrow = "→",
    .dot = "·",
    .rule = "─",
};

pub const ascii: Glyphs = .{
    .running = "*",
    .stopped = "o",
    .paused = "~",
    .ok = "+",
    .warn = "!",
    .fail = "x",
    .not_checked = "-",
    .unknown = "?",
    .ellipsis = "...",
    .bar_full = "#",
    .bar_empty = ".",
    .arrow = "->",
    .dot = "-",
    .rule = "-",
};

pub const Status = enum {
    running,
    stopped,
    paused,
    ok,
    warning,
    failed,
    not_checked,
    unknown,

    pub fn word(s: Status) []const u8 {
        return switch (s) {
            .not_checked => "not checked",
            else => @tagName(s),
        };
    }

    pub fn glyph(s: Status, g: *const Glyphs) []const u8 {
        return switch (s) {
            .running => g.running,
            .stopped => g.stopped,
            .paused => g.paused,
            .ok => g.ok,
            .warning => g.warn,
            .failed => g.fail,
            .not_checked => g.not_checked,
            .unknown => g.unknown,
        };
    }

    pub fn role(s: Status) Role {
        return switch (s) {
            .running, .ok => .ok,
            .warning, .paused => .warn,
            .failed => .fail,
            .stopped, .not_checked, .unknown => .muted,
        };
    }
};

/// Color decision (SPEC §3.1): `never` → none; `always` overrides
/// NO_COLOR; `auto` needs a TTY, no NO_COLOR and a non-dumb TERM.
pub fn decideDepth(policy: Color, is_tty: bool, no_color: ?[]const u8, term: ?[]const u8, colorterm: ?[]const u8) Depth {
    switch (policy) {
        .never => return .none,
        .always => {},
        .auto => {
            if (!is_tty) return .none;
            if (no_color) |v| if (v.len > 0) return .none;
            if (term) |t| if (std.mem.eql(u8, t, "dumb")) return .none;
        },
    }
    if (colorterm) |c| {
        if (std.mem.eql(u8, c, "truecolor") or std.mem.eql(u8, c, "24bit")) return .truecolor;
    }
    return .ansi256;
}

const testing = std.testing;

test "palette sequences" {
    const p: Palette = .{ .depth = .truecolor };
    try testing.expectEqualStrings("\x1b[38;2;184;187;38m", p.on(.ok));
    try testing.expectEqualStrings("\x1b[1;38;2;131;165;152m", p.on(.title));
    try testing.expectEqualStrings("", p.on(.text));
    try testing.expectEqualStrings("", p.off(.text));
    const q: Palette = .{ .depth = .ansi256 };
    try testing.expectEqualStrings("\x1b[38;5;167m", q.on(.fail));
    try testing.expectEqualStrings("\x1b[0m", q.off(.fail));
    const n: Palette = .{};
    try testing.expectEqualStrings("", n.on(.fail));
    try testing.expectEqualStrings("", n.off(.fail));
}

test "decideDepth" {
    try testing.expectEqual(Depth.none, decideDepth(.never, true, null, "xterm-ghostty", "truecolor"));
    try testing.expectEqual(Depth.truecolor, decideDepth(.auto, true, null, "xterm-ghostty", "truecolor"));
    try testing.expectEqual(Depth.ansi256, decideDepth(.auto, true, null, "xterm-256color", null));
    try testing.expectEqual(Depth.none, decideDepth(.auto, false, null, "xterm", null));
    try testing.expectEqual(Depth.none, decideDepth(.auto, true, "1", "xterm", null));
    try testing.expectEqual(Depth.ansi256, decideDepth(.auto, true, "", "xterm", null));
    try testing.expectEqual(Depth.none, decideDepth(.auto, true, null, "dumb", null));
    try testing.expectEqual(Depth.ansi256, decideDepth(.always, false, "1", "dumb", null));
}

test "status words and glyphs" {
    try testing.expectEqualStrings("not checked", Status.not_checked.word());
    try testing.expectEqualStrings("●", Status.running.glyph(&unicode));
    try testing.expectEqualStrings("x", Status.failed.glyph(&ascii));
    try testing.expectEqual(Role.warn, Status.warning.role());
}
