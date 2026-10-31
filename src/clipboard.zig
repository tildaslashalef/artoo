//! Copy text to the desktop clipboard through the platform's helper:
//! `pbcopy` on macOS; `wl-copy`, `xclip` or `xsel` on Linux. The text
//! travels only through the helper's stdin (SPEC §6).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const proc = @import("proc.zig");

pub const Error = error{ClipboardUnavailable} || Io.Cancelable;

const Os = enum { mac, linux, other };

/// Helpers to try, in order, for this session: Wayland before X11; none
/// without a display (an SSH login).
fn candidates(os: Os, env: *const std.process.Environ.Map) []const []const []const u8 {
    const pbcopy: []const []const u8 = &.{"/usr/bin/pbcopy"};
    const wl_copy: []const []const u8 = &.{"wl-copy"};
    const xclip: []const []const u8 = &.{ "xclip", "-selection", "clipboard" };
    const xsel: []const []const u8 = &.{ "xsel", "--clipboard", "--input" };
    return switch (os) {
        .mac => &.{pbcopy},
        .linux => if (env.get("WAYLAND_DISPLAY") != null)
            &.{ wl_copy, xclip, xsel }
        else if (env.get("DISPLAY") != null)
            &.{ xclip, xsel }
        else
            &.{},
        .other => &.{},
    };
}

fn currentOs() Os {
    if (builtin.os.tag.isDarwin()) return .mac;
    if (builtin.os.tag == .linux) return .linux;
    return .other;
}

/// Copy `text`; `runner` stands in for the helper in tests.
pub fn copy(io: Io, arena: std.mem.Allocator, env: *const std.process.Environ.Map, text: []const u8, runner: ?proc.Runner) Error!void {
    for (candidates(currentOs(), env)) |argv| {
        const code = if (runner) |r|
            ((r.run(io, arena, argv, text) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => continue,
            }).code)
        else
            proc.feed(io, argv, text) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => continue,
            };
        if (code == 0) return;
    }
    return error.ClipboardUnavailable;
}

const testing = std.testing;

test "candidates per platform and session" {
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try testing.expectEqualStrings("/usr/bin/pbcopy", candidates(.mac, &env)[0][0]);
    try testing.expectEqual(@as(usize, 0), candidates(.linux, &env).len);
    try testing.expectEqual(@as(usize, 0), candidates(.other, &env).len);
    try env.put("DISPLAY", ":0");
    try testing.expectEqualStrings("xclip", candidates(.linux, &env)[0][0]);
    try env.put("WAYLAND_DISPLAY", "wayland-0");
    try testing.expectEqualStrings("wl-copy", candidates(.linux, &env)[0][0]);
    try testing.expectEqual(@as(usize, 3), candidates(.linux, &env).len);
}
