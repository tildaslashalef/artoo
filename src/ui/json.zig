//! JSON output (SPEC §4.2): exactly one document on stdout,
//! `{"schema_version":1,"target":…,"data":…,"meta":…}`; errors as one JSON
//! object on stderr. Non-ASCII is \u-escaped so no control sequence (incl.
//! UTF-8 C1) can reach a terminal that displays the output.

const std = @import("std");
const Io = std.Io;

pub const schema_version = 1;

pub const Target = enum { pve, unifi, cloudflare, github, local };

pub const options: std.json.Stringify.Options = .{
    .whitespace = .indent_2,
    .escape_unicode = true,
};

pub fn envelope(w: *Io.Writer, target: Target, data: anytype, meta: anytype) Io.Writer.Error!void {
    try std.json.Stringify.value(.{
        .schema_version = schema_version,
        .target = target,
        .data = data,
        .meta = meta,
    }, options, w);
    try w.writeByte('\n');
}

pub fn writeError(w: *Io.Writer, kind: []const u8, exit_code: u8, message: []const u8) Io.Writer.Error!void {
    return writeErrorSteps(w, kind, exit_code, message, &[_]u8{});
}

/// `writeError` with a workflow's step ledger (SPEC §4.2), when it ran any.
pub fn writeErrorSteps(w: *Io.Writer, kind: []const u8, exit_code: u8, message: []const u8, steps: anytype) Io.Writer.Error!void {
    const e = .{ .kind = kind, .exit_code = exit_code, .message = message };
    if (steps.len == 0) {
        try std.json.Stringify.value(.{ .schema_version = schema_version, .@"error" = e }, .{ .escape_unicode = true }, w);
    } else {
        try std.json.Stringify.value(.{ .schema_version = schema_version, .@"error" = e, .steps = steps }, .{ .escape_unicode = true }, w);
    }
    try w.writeByte('\n');
}

const testing = std.testing;

test "envelope: shape, nulls, escaping" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const Row = struct { name: []const u8, memory: ?u64 };
    try envelope(&buf.writer, .unifi, [_]Row{
        .{ .name = "web\x1b[2J", .memory = null },
        .{ .name = "z\u{9b}ü", .memory = 1024 },
    }, .{ .collected_at = 1791635525 });
    try testing.expectEqualStrings(
        \\{
        \\  "schema_version": 1,
        \\  "target": "unifi",
        \\  "data": [
        \\    {
        \\      "name": "web\u001b[2J",
        \\      "memory": null
        \\    },
        \\    {
        \\      "name": "z\u009b\u00fc",
        \\      "memory": 1024
        \\    }
        \\  ],
        \\  "meta": {
        \\    "collected_at": 1791635525
        \\  }
        \\}
        \\
    , buf.written());
}

test "writeError" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try writeError(&buf.writer, "usage", 2, "missing VM");
    try testing.expectEqualStrings(
        \\{"schema_version":1,"error":{"kind":"usage","exit_code":2,"message":"missing VM"}}
        \\
    , buf.written());
}
