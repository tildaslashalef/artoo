//! QEMU guest agent through the Proxmox API (SPEC §9.3, §9.4): ping,
//! command execution with bounded polling, and file reads. Commands run
//! as root inside the guest; the token needs `VM.GuestAgent.Unrestricted`
//! (in `PVEVMAdmin`, verified on 9.2).

const std = @import("std");
const Io = std.Io;
const Value = std.json.Value;
const pve = @import("client.zig");
const ui = @import("../ui.zig");
const exec_mod = @import("../exec.zig");

/// True when the agent answers. An error answer (agent not running yet)
/// is false; its message is not kept.
pub fn ping(c: *pve.Client, vmid: u32) !bool {
    _ = c.send(.POST, try c.nodePath("/qemu/{d}/agent/ping", .{vmid}), &.{}) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            c.ctx.diag = null;
            return false;
        },
    };
    return true;
}

/// Poll `ping` until it answers or `timeout_ms` passes (WaitTimeout).
pub fn waitReady(c: *pve.Client, vmid: u32, timeout_ms: u64) !void {
    const ctx = c.ctx;
    const started = Io.Clock.awake.now(ctx.io);
    while (!try ping(c, vmid)) {
        if (elapsed(ctx.io, started) >= timeout_ms)
            return ctx.fail(error.WaitTimeout, "the guest agent of VM {d} did not answer within {d} s", .{ vmid, timeout_ms / 1000 });
        try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 2000)), .awake);
    }
}

pub const Result = struct {
    /// Null when the process did not exit normally.
    code: ?i64,
    out: []const u8,
    err: []const u8,

    pub fn ok(r: Result) bool {
        return r.code != null and r.code.? == 0;
    }
};

/// Run `argv` in the guest and wait for it (WaitTimeout after
/// `timeout_ms`; the process keeps running in the guest).
pub fn exec(c: *pve.Client, vmid: u32, argv: []const []const u8, input: ?[]const u8, timeout_ms: u64) !Result {
    return execWatched(c, vmid, argv, input, timeout_ms, null);
}

/// A guest file a long script writes its current stage to, reported to a
/// ledger step while the script runs (SPEC §4.4).
pub const Watch = struct {
    file: []const u8,
    note: exec_mod.Note,
};

/// Polls between reads of `Watch.file` (500 ms each: about every 2 s).
const watch_every = 4;

pub fn execWatched(c: *pve.Client, vmid: u32, argv: []const []const u8, input: ?[]const u8, timeout_ms: u64, watch: ?Watch) !Result {
    const ctx = c.ctx;
    var params: std.ArrayList(pve.Param) = .empty;
    for (argv) |a| try params.append(ctx.arena, .{ .name = "command", .value = a });
    if (input) |i| try params.append(ctx.arena, .{ .name = "input-data", .value = i });
    const started_data = try c.send(.POST, try c.nodePath("/qemu/{d}/agent/exec", .{vmid}), params.items);
    const pid = pve.int(started_data, "pid") orelse return ctx.fail(error.Protocol, "the guest agent of VM {d} returned no pid", .{vmid});
    const path = try c.nodePath("/qemu/{d}/agent/exec-status?pid={d}", .{ vmid, pid });
    const started = Io.Clock.awake.now(ctx.io);
    var polls: usize = 0;
    while (true) : (polls += 1) {
        const st = try c.get(path);
        if (truthy(pve.obj(st, "exited"))) {
            return .{
                .code = pve.int(st, "exitcode"),
                .out = pve.str(st, "out-data") orelse "",
                .err = pve.str(st, "err-data") orelse "",
            };
        }
        if (watch) |w| if (polls % watch_every == 0) try readStage(c, vmid, w);
        if (elapsed(ctx.io, started) >= timeout_ms)
            return ctx.fail(error.WaitTimeout, "'{s}' in VM {d} still running after {d} s", .{ argv[0], vmid, timeout_ms / 1000 });
        try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 500)), .awake);
    }
}

/// `sh -c script` in the guest.
pub fn sh(c: *pve.Client, vmid: u32, script: []const u8, timeout_ms: u64) !Result {
    return exec(c, vmid, &.{ "sh", "-c", script }, null, timeout_ms);
}

/// The stage file's last line as the step's detail. A missing file (not
/// written yet) or a failed read reports nothing.
fn readStage(c: *pve.Client, vmid: u32, w: Watch) !void {
    const ctx = c.ctx;
    const text = readFile(c, vmid, w.file) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            ctx.diag = null;
            return;
        },
    };
    const t = std.mem.trim(u8, text, " \t\r\n");
    if (t.len == 0) return;
    const last = t[if (std.mem.findScalarLast(u8, t, '\n')) |i| i + 1 else 0..];
    w.note.say(try ui.text.sanitize(ctx.arena, last, .line));
}

/// `sh -c script` with a stage file (`Watch`).
pub fn shWatched(c: *pve.Client, vmid: u32, script: []const u8, timeout_ms: u64, watch: ?Watch) !Result {
    return execWatched(c, vmid, &.{ "sh", "-c", script }, null, timeout_ms, watch);
}

/// A (small) file from the guest, decoded.
pub fn readFile(c: *pve.Client, vmid: u32, path: []const u8) ![]const u8 {
    const ctx = c.ctx;
    var q: std.ArrayList(u8) = .empty;
    try q.print(ctx.arena, "/qemu/{d}/agent/file-read?", .{vmid});
    try q.appendSlice(ctx.arena, try pve.form(ctx.arena, &.{ .{ .name = "file", .value = path }, .{ .name = "decode", .value = "1" } }));
    const data = try c.get(try c.nodePath("{s}", .{q.items}));
    return pve.str(data, "content") orelse ctx.fail(error.Protocol, "the guest agent of VM {d} returned no content for {s}", .{ vmid, path });
}

fn truthy(v: Value) bool {
    return switch (v) {
        .bool => |b| b,
        .integer => |n| n != 0,
        .string => |s| std.mem.eql(u8, s, "1") or std.mem.eql(u8, s, "true"),
        else => false,
    };
}

fn elapsed(io: Io, since: Io.Timestamp) u64 {
    return @intCast(@max(0, @divTrunc(since.durationTo(Io.Clock.awake.now(io)).nanoseconds, std.time.ns_per_ms)));
}

test "truthy" {
    try std.testing.expect(truthy(.{ .integer = 1 }));
    try std.testing.expect(truthy(.{ .bool = true }));
    try std.testing.expect(!truthy(.{ .integer = 0 }));
    try std.testing.expect(!truthy(.null));
}

const watch_probe = struct {
    pub const name = "probe";
    pub const summary = "execWatched probe";
    pub fn run(ctx: *@import("../app.zig").Context, _: @import("../cli.zig").Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var l: exec_mod.Ledger = .{};
        const i = try l.add(ctx.arena, "build caddy");
        const r = try execWatched(&c, 200, &.{ "sh", "-c", "build" }, null, 60_000, .{ .file = "/run/x.stage", .note = l.noter(i) });
        try ctx.out.print("{s}|{s}\n", .{ l.steps.items[i].detail, r.out });
    }
};

test "execWatched: the stage file's last line becomes the step's detail" {
    const testkit = @import("../testkit.zig");
    const cli = @import("../cli.zig");
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"exited\":0}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"content\":\"installing Go\\nbuilding Caddy v2.11.7\\n\"}}" } },
        .{ .respond = .{ .body = "{\"data\":{\"exited\":1,\"exitcode\":0,\"out-data\":\"built\"}}" } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{cli.leaf(watch_probe)});
    try std.testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "probe"));
    try std.testing.expectEqualStrings("building Caddy v2.11.7|built\n", g.h.stdout());
    try std.testing.expectEqualStrings("GET /api2/json/nodes/pve/qemu/200/agent/file-read?file=%2Frun%2Fx.stage&decode=1 HTTP/1.1", g.request(2));
}
