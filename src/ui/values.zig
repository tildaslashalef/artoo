//! Human value formatting (SPEC §4.1): IEC sizes, percentages, bars,
//! durations, relative and absolute times. Missing values render `--`.
//!
//! Each formatter is a small value usable with `{f}`; `alloc` turns one
//! into an arena string for table cells.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const style = @import("style.zig");

pub const missing = "--";

pub fn alloc(arena: Allocator, v: anytype) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "{f}", .{v});
}

/// IEC size with one decimal (`1.8 TiB`); bytes below 1 KiB are exact.
pub const Bytes = struct {
    n: ?u64,

    pub fn format(b: Bytes, w: *Io.Writer) Io.Writer.Error!void {
        const n = b.n orelse return w.writeAll(missing);
        if (n < 1024) return w.print("{d} B", .{n});
        const units = [_][]const u8{ "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
        var x: f64 = @floatFromInt(n);
        var u: usize = 0;
        x /= 1024;
        // Round first so 1023.96 KiB prints as 1.0 MiB, not 1024.0 KiB.
        while (@round(x * 10) >= 10240 and u + 1 < units.len) : (u += 1) x /= 1024;
        return w.print("{d:.1} {s}", .{ x, units[u] });
    }
};

pub fn bytes(n: ?u64) Bytes {
    return .{ .n = n };
}

/// A fraction (0.425) as `42.5%`.
pub const Percent = struct {
    frac: ?f64,

    pub fn format(p: Percent, w: *Io.Writer) Io.Writer.Error!void {
        const f = p.frac orelse return w.writeAll(missing);
        if (!std.math.isFinite(f)) return w.writeAll(missing);
        return w.print("{d:.1}%", .{f * 100});
    }
};

pub fn percent(frac: ?f64) Percent {
    return .{ .frac = frac };
}

pub fn ratio(part: ?u64, whole: ?u64) ?f64 {
    const p = part orelse return null;
    const t = whole orelse return null;
    if (t == 0) return null;
    return @as(f64, @floatFromInt(p)) / @as(f64, @floatFromInt(t));
}

/// `1.2 GiB / 4.0 GiB (30.0%)`.
pub const UsedTotal = struct {
    used: ?u64,
    total: ?u64,

    pub fn format(u: UsedTotal, w: *Io.Writer) Io.Writer.Error!void {
        if (u.used == null and u.total == null) return w.writeAll(missing);
        try w.print("{f} / {f}", .{ bytes(u.used), bytes(u.total) });
        if (ratio(u.used, u.total)) |r| try w.print(" ({f})", .{percent(r)});
    }
};

pub fn usedTotal(used: ?u64, total: ?u64) UsedTotal {
    return .{ .used = used, .total = total };
}

/// Ten-cell bar.
pub const Bar = struct {
    frac: ?f64,
    glyphs: *const style.Glyphs,

    pub fn format(b: Bar, w: *Io.Writer) Io.Writer.Error!void {
        const f = b.frac orelse return w.writeAll(missing);
        const clamped = std.math.clamp(f, 0, 1);
        const full: usize = @intFromFloat(@round(clamped * 10));
        try w.splatBytesAll(b.glyphs.bar_full, full);
        try w.splatBytesAll(b.glyphs.bar_empty, 10 - full);
    }
};

pub fn bar(frac: ?f64, glyphs: *const style.Glyphs) Bar {
    return .{ .frac = frac, .glyphs = glyphs };
}

/// Two largest units: `3d 4h`, `3h 12m`, `5m 3s`, `42s`.
pub const Duration = struct {
    seconds: ?u64,

    pub fn format(d: Duration, w: *Io.Writer) Io.Writer.Error!void {
        const s = d.seconds orelse return w.writeAll(missing);
        const day = 86400;
        if (s >= day) return pair(w, s / day, "d", (s % day) / 3600, "h");
        if (s >= 3600) return pair(w, s / 3600, "h", (s % 3600) / 60, "m");
        if (s >= 60) return pair(w, s / 60, "m", s % 60, "s");
        return w.print("{d}s", .{s});
    }

    fn pair(w: *Io.Writer, a: u64, ua: []const u8, b: u64, ub: []const u8) Io.Writer.Error!void {
        if (b == 0) return w.print("{d}{s}", .{ a, ua });
        return w.print("{d}{s} {d}{s}", .{ a, ua, b, ub });
    }
};

pub fn duration(seconds: ?u64) Duration {
    return .{ .seconds = seconds };
}

/// `2m ago`, `in 3d`, `just now`; one unit.
pub const Relative = struct {
    now: i64,
    t: ?i64,

    pub fn format(r: Relative, w: *Io.Writer) Io.Writer.Error!void {
        const t = r.t orelse return w.writeAll(missing);
        const delta = r.now - t;
        const abs: u64 = @abs(delta);
        if (abs < 5) return w.writeAll("just now");
        const n: u64, const unit: []const u8 = if (abs < 60)
            .{ abs, "s" }
        else if (abs < 3600)
            .{ abs / 60, "m" }
        else if (abs < 86400)
            .{ abs / 3600, "h" }
        else if (abs < 365 * 86400)
            .{ abs / 86400, "d" }
        else
            .{ abs / (365 * 86400), "y" };
        if (delta >= 0) return w.print("{d}{s} ago", .{ n, unit });
        return w.print("in {d}{s}", .{ n, unit });
    }
};

pub fn relative(now: i64, t: ?i64) Relative {
    return .{ .now = now, .t = t };
}

/// `2026-10-10 14:32:05` in the given zone.
pub const Absolute = struct {
    t: ?i64,
    zone: *const Zone,

    pub fn format(a: Absolute, w: *Io.Writer) Io.Writer.Error!void {
        const t = a.t orelse return w.writeAll(missing);
        const local = t + a.zone.offsetAt(t);
        if (local < 0) return w.writeAll(missing);
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(local) };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        try w.print("{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
            yd.year,              md.month.numeric(),      md.day_index + 1,
            ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        });
    }
};

pub fn absolute(t: ?i64, zone: *const Zone) Absolute {
    return .{ .t = t, .zone = zone };
}

/// `14:32` in the given zone.
pub const Clock = struct {
    t: i64,
    zone: *const Zone,

    pub fn format(c: Clock, w: *Io.Writer) Io.Writer.Error!void {
        const local = c.t + c.zone.offsetAt(c.t);
        const ds: std.time.epoch.DaySeconds = .{ .secs = @intCast(@mod(local, 86400)) };
        try w.print("{d:0>2}:{d:0>2}", .{ ds.getHoursIntoDay(), ds.getMinutesIntoHour() });
    }
};

pub fn clock(t: i64, zone: *const Zone) Clock {
    return .{ .t = t, .zone = zone };
}

/// UTC offsets from the system zone file (`/etc/localtime`, TZif). Times
/// beyond the file's last transition use that transition's offset.
pub const Zone = struct {
    transitions: []const Transition = &.{},
    /// Offset before the first transition (or the only one).
    base: i32 = 0,

    pub const utc: Zone = .{};

    const Transition = struct { at: i64, offset: i32 };

    pub fn offsetAt(z: *const Zone, t: i64) i32 {
        var off = z.base;
        for (z.transitions) |tr| {
            if (tr.at > t) break;
            off = tr.offset;
        }
        return off;
    }

    /// Never fails: an unreadable or malformed zone file means UTC.
    pub fn loadLocal(io: Io, arena: Allocator) Zone {
        const data = Io.Dir.cwd().readFileAlloc(io, "/etc/localtime", arena, .limited(256 * 1024)) catch return utc;
        return parse(arena, data) catch utc;
    }

    pub fn parse(arena: Allocator, data: []const u8) !Zone {
        var r: Io.Reader = .fixed(data);
        const tz = try std.tz.Tz.parse(arena, &r);
        const list = try arena.alloc(Transition, tz.transitions.len);
        for (tz.transitions, list) |src, *dst| dst.* = .{ .at = src.ts, .offset = src.timetype.offset };
        const base = if (tz.timetypes.len > 0) tz.timetypes[0].offset else 0;
        return .{ .transitions = list, .base = base };
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn expectFmt(expected: []const u8, v: anytype) !void {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings(expected, try std.fmt.bufPrint(&buf, "{f}", .{v}));
}

test "bytes" {
    try expectFmt("--", bytes(null));
    try expectFmt("0 B", bytes(0));
    try expectFmt("1023 B", bytes(1023));
    try expectFmt("1.0 KiB", bytes(1024));
    try expectFmt("1.5 KiB", bytes(1536));
    try expectFmt("1.0 MiB", bytes(1024 * 1024 - 1));
    try expectFmt("1.8 TiB", bytes(2_000_000_000_000));
    try expectFmt("16.0 EiB", bytes(std.math.maxInt(u64)));
}

test "percent, usedTotal, bar" {
    try expectFmt("42.5%", percent(0.425));
    try expectFmt("--", percent(null));
    try expectFmt("0.0%", percent(0));
    try expectFmt("1.0 GiB / 4.0 GiB (25.0%)", usedTotal(1 << 30, 4 << 30));
    try expectFmt("1.0 GiB / --", usedTotal(1 << 30, null));
    try expectFmt("--", usedTotal(null, null));
    try expectFmt("███░░░░░░░", bar(0.3, &style.unicode));
    try expectFmt("##########", bar(1.7, &style.ascii));
    try expectFmt("--", bar(null, &style.ascii));
}

test "duration and relative" {
    try expectFmt("0s", duration(0));
    try expectFmt("42s", duration(42));
    try expectFmt("5m 3s", duration(303));
    try expectFmt("3h 12m", duration(3 * 3600 + 12 * 60 + 9));
    try expectFmt("2h", duration(7200));
    try expectFmt("3d 4h", duration(3 * 86400 + 4 * 3600 + 59));
    try expectFmt("--", duration(null));
    const now: i64 = 1_800_000_000;
    try expectFmt("just now", relative(now, now - 2));
    try expectFmt("30s ago", relative(now, now - 30));
    try expectFmt("2m ago", relative(now, now - 150));
    try expectFmt("5h ago", relative(now, now - 5 * 3600));
    try expectFmt("in 3d", relative(now, now + 3 * 86400 + 10));
    try expectFmt("2y ago", relative(now, now - 800 * 86400));
    try expectFmt("--", relative(now, null));
}

test "absolute time with zone transitions" {
    // Europe/Berlin-like: CET +1h, CEST +2h from 2026-03-29 01:00 UTC.
    const zone: Zone = .{ .base = 3600, .transitions = &.{
        .{ .at = 1774746000, .offset = 7200 },
        .{ .at = 1792890000, .offset = 3600 },
    } };
    try expectFmt("2026-10-10 14:32:05", absolute(1791635525, &zone)); // 12:32:05Z, CEST
    try expectFmt("2026-01-01 01:00:00", absolute(1767225600, &zone)); // CET
    try expectFmt("2026-10-10 12:32:05", absolute(1791635525, &Zone.utc));
    try expectFmt("--", absolute(null, &zone));
    try expectFmt("14:32", clock(1791635525, &zone));
}

test "zone file parses (system zone when present)" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const z = Zone.loadLocal(testing.io, a.allocator());
    // Any offset is valid; it must be within ±14h.
    try testing.expect(@abs(z.offsetAt(1791635525)) <= 14 * 3600);
}
