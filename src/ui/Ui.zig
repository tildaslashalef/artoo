//! Rendering settings for one invocation.

const std = @import("std");
const Io = std.Io;
const style = @import("style.zig");
const values = @import("values.zig");
const Color = @import("../cli/command.zig").Color;

const Ui = @This();

palette: style.Palette = .{},
glyphs: *const style.Glyphs = &style.unicode,
/// Terminal columns; null = not a terminal (no width limit).
width: ?usize = null,
zone: values.Zone = .utc,
/// Collection time, epoch seconds.
now: i64 = 0,

pub const Options = struct {
    color: Color = .auto,
    ascii: bool = false,
};

/// Settings for output written to `file` (stdout or stderr).
pub fn detect(io: Io, file: Io.File, env: *const std.process.Environ.Map, opts: Options) Io.Cancelable!Ui {
    const tty = try file.isTty(io);
    const depth = style.decideDepth(opts.color, tty, env.get("NO_COLOR"), env.get("TERM"), env.get("COLORTERM"));
    return .{
        .palette = .{ .depth = depth },
        .glyphs = if (opts.ascii) &style.ascii else &style.unicode,
        .width = if (tty) try terminalWidth(io, file, env) else null,
        .now = @intCast(@divFloor(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s)),
    };
}

/// `COLUMNS` wins (lets users and tests pin a width); else the ioctl.
fn terminalWidth(io: Io, file: Io.File, env: *const std.process.Environ.Map) Io.Cancelable!?usize {
    if (env.get("COLUMNS")) |c| {
        if (std.fmt.parseInt(usize, c, 10)) |n| {
            if (n >= 20) return n;
        } else |_| {}
    }
    if (@import("builtin").os.tag == .windows) return null;
    var ws: std.posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    const rc = (try io.operate(.{ .device_io_control = .{
        .file = file,
        .code = std.posix.T.IOCGWINSZ,
        .arg = &ws,
    } })).device_io_control;
    if (rc < 0 or ws.col == 0) return null;
    return ws.col;
}

/// Times in the system zone (loaded once; UTC when unavailable).
pub fn withLocalZone(ui: Ui, io: Io, arena: std.mem.Allocator) Ui {
    var copy = ui;
    copy.zone = values.Zone.loadLocal(io, arena);
    return copy;
}

test "detect: non-TTY output has no color and no width limit" {
    const io = std.testing.io;
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    try env.put("COLORTERM", "truecolor");
    try env.put("COLUMNS", "120");
    const devnull = try Io.Dir.cwd().openFile(io, "/dev/null", .{ .mode = .write_only });
    defer devnull.close(io);
    const auto = try detect(io, devnull, &env, .{});
    try std.testing.expectEqual(style.Depth.none, auto.palette.depth);
    try std.testing.expectEqual(@as(?usize, null), auto.width);
    const forced = try detect(io, devnull, &env, .{ .color = .always, .ascii = true });
    try std.testing.expectEqual(style.Depth.truecolor, forced.palette.depth);
    try std.testing.expectEqualStrings("...", forced.glyphs.ellipsis);
}
