//! Rendering helpers shared by the Proxmox commands (host, storage, task,
//! vm, status): the header line, status cells and value text.

const std = @import("std");
const app = @import("../app.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const tasks = @import("../pve/task.zig");

const Context = app.Context;
const Status = ui.style.Status;

/// `ARTOO · <path>` left, `pve · <clock>` right (`pve/<node>` when
/// the configured node has another name).
pub fn header(ctx: *Context, c: *const pve.Client) !void {
    const target = if (std.mem.eql(u8, c.node, "pve")) "pve" else try std.fmt.allocPrint(ctx.arena, "pve/{s}", .{try clean(ctx, c.node)});
    const right = try std.fmt.allocPrint(ctx.arena, "{s} {s} {f}", .{ target, ctx.ui.glyphs.dot, ui.values.clock(ctx.ui.now, &ctx.ui.zone) });
    try ui.blocks.header(ctx.out, &ctx.ui, ctx.path, right);
}

pub fn clean(ctx: *Context, s: []const u8) ![]const u8 {
    return ui.text.sanitize(ctx.arena, s, .line);
}

/// PVE VM status word → glyph + word cell.
pub fn vmStatus(ctx: *Context, status: []const u8, template: bool) !ui.table.Cell {
    if (template) return statusCell(ctx, .stopped, "template");
    const s: Status = if (std.mem.eql(u8, status, "running"))
        .running
    else if (std.mem.eql(u8, status, "stopped"))
        .stopped
    else if (std.mem.eql(u8, status, "paused") or std.mem.eql(u8, status, "suspended"))
        .paused
    else
        .unknown;
    return statusCell(ctx, s, try clean(ctx, status));
}

pub fn statusCell(ctx: *Context, s: Status, word: []const u8) !ui.table.Cell {
    return .{ .text = try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ s.glyph(ctx.ui.glyphs), word }), .role = s.role() };
}

pub fn fmt(ctx: *Context, v: anytype) ![]const u8 {
    return ui.values.alloc(ctx.arena, v);
}

/// `used / total (pct)` + bar, or `--`.
pub fn usage(ctx: *Context, used: ?u64, total: ?u64) ![]const u8 {
    if (used == null or total == null or total.? == 0) return "--";
    return std.fmt.allocPrint(ctx.arena, "{f}  {f}", .{ ui.values.usedTotal(used, total), ui.values.bar(ui.values.ratio(used, total), ctx.ui.glyphs) });
}

/// Plan target line: `Proxmox (node pve)`.
pub fn nodeTarget(ctx: *Context, c: *pve.Client) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "Proxmox (node {s})", .{try clean(ctx, c.node)});
}

/// The task a write returned, tracked to completion: `task <handle>: OK`.
pub fn waitTask(c: *pve.Client, upid: []const u8, timeout_s: u64) ![]const u8 {
    return waitTaskNoted(c, upid, timeout_s, null);
}

/// `waitTask`, with the task log's newest line as the step's detail.
pub fn waitTaskNoted(c: *pve.Client, upid: []const u8, timeout_s: u64, note: ?@import("../exec.zig").Note) ![]const u8 {
    const done = try tasks.waitNoted(c, upid, timeout_s * 1000, note);
    const h = try tasks.handle(c.ctx.arena, upid, &c.ctx.ui.zone);
    return std.fmt.allocPrint(c.ctx.arena, "task {s}: {s}", .{ h, done.exitstatus });
}
