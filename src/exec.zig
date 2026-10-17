//! The one mutation pipeline (SPEC §8.2), used by every write:
//!
//!   read target → plan (no-op refused) → preview → `--dry-run` stops →
//!   confirm → re-read if the prompt took long (abort on drift) → send once
//!   → track → verify with a fresh read.
//!
//! An operation is any struct pointer with these declarations:
//!
//!   target: []const u8                  name/ID shown and typed to confirm
//!   risk: ui.blocks.Risk
//!   api: ui.json.Target
//!   fn read(op, *Context) !void         load current state into op
//!   fn plan(op, *Context) !?Plan        null = nothing to do; slices in
//!                                       the plan must live in ctx.arena
//!   fn fingerprint(op) []const u8       identity + version of the read state
//!   fn send(op, *Context) !void         the single write
//!   fn track(op, *Context) !void        optional: wait for async completion
//!   fn verify(op, *Context) !bool       fresh read shows the intended state
//!   fn done(op) []const u8              success line
//!
//! Errors from `send` keep their meaning (`OutcomeUnknown` → exit 7,
//! `Network` → 4); nothing here retries or reports an unverified write as
//! success.

const std = @import("std");
const Io = std.Io;
const app = @import("app.zig");
const prompt = @import("prompt.zig");
const ui = @import("ui.zig");

const Context = app.Context;

pub const Plan = ui.blocks.Plan;

pub const Options = struct {
    /// `--confirm TARGET` (destructive, non-interactive).
    confirm: ?[]const u8 = null,
    /// Re-read the target when the confirmation took longer than this.
    reread_after_ms: i64 = 3000,
};

pub fn run(ctx: *Context, op: anytype, opts: Options) !void {
    const Op = @TypeOf(op.*);
    try op.read(ctx);
    const pl = (try op.plan(ctx)) orelse return ctx.fail(error.NoChange, "nothing to change: {s} already has the requested state", .{op.target});

    // Preview: stdout for humans; stderr when stdout carries JSON.
    const preview_w = if (ctx.json()) ctx.err else ctx.out;
    const preview_ui = if (ctx.json()) &ctx.err_ui else &ctx.ui;
    try ui.blocks.plan(preview_w, preview_ui, pl);
    if (ctx.globals.dry_run) {
        if (ctx.json()) return ui.json.envelope(ctx.out, op.api, .{ .plan = pl, .result = "dry-run" }, .{});
        try ctx.out.writeAll("\nDry run: nothing was sent.\n");
        return;
    }

    // The plan must be on screen before the question (the prompt goes to
    // stderr, the plan to buffered stdout).
    try preview_w.flush();
    const before = try ctx.arena.dupe(u8, op.fingerprint());
    const asked_at = Io.Clock.awake.now(ctx.io);
    try confirm(ctx, op.target, op.risk, opts.confirm);
    const waited = @divTrunc(asked_at.durationTo(Io.Clock.awake.now(ctx.io)).nanoseconds, std.time.ns_per_ms);
    if (waited >= opts.reread_after_ms) {
        try op.read(ctx);
        if (!std.mem.eql(u8, before, op.fingerprint())) {
            return ctx.fail(error.Changed, "{s} changed while waiting for confirmation; nothing was sent — review and run again", .{op.target});
        }
    }

    var progress = Progress.init(ctx);
    if (@hasField(Op, "ledger")) progress.attach(&op.ledger);
    op.send(ctx) catch |err| {
        progress.end(false);
        if (@hasField(Op, "ledger")) ctx.steps = op.ledger.steps.items;
        return err;
    };
    progress.end(true);
    if (@hasField(Op, "ledger")) ctx.steps = op.ledger.steps.items;
    if (ctx.globals.no_wait) {
        if (ctx.json()) return ui.json.envelope(ctx.out, op.api, .{ .plan = pl, .result = "accepted", .steps = ctx.steps }, .{});
        try ctx.out.print("Accepted (not waited for): {s}\n", .{op.target});
        return;
    }
    if (@hasDecl(Op, "track")) try op.track(ctx);
    if (!try op.verify(ctx)) {
        return ctx.fail(error.Partial, "the write was accepted, but a fresh read does not show the intended state of {s}", .{op.target});
    }
    if (ctx.json()) return ui.json.envelope(ctx.out, op.api, .{ .plan = pl, .result = "applied", .steps = ctx.steps }, .{});
    const p = ctx.ui.palette;
    try ctx.out.print("{s}{s}{s} {s}\n", .{ p.on(.ok), ctx.ui.glyphs.ok, p.off(.ok), op.done() });
}

/// SPEC §3.4: normal → `[y/N]` (or `--yes`); destructive → typed target
/// interactively, `--yes --confirm TARGET` otherwise.
fn confirm(ctx: *Context, target: []const u8, risk: ui.blocks.Risk, confirm_flag: ?[]const u8) !void {
    if (risk == .normal) return ctx.confirm("Proceed?", .{});
    if (ctx.globals.yes) {
        const given = confirm_flag orelse
            return ctx.fail(error.TargetMismatch, "destructive change: add --confirm {s} to proceed with --yes", .{target});
        if (!std.mem.eql(u8, given, target)) {
            return ctx.fail(error.TargetMismatch, "--confirm '{s}' does not match the target '{s}'; nothing was sent", .{ given, target });
        }
        return;
    }
    const answer = prompt.askTyped(ctx.input, ctx.io, ctx.arena, ctx.err, target) catch |err| switch (err) {
        error.NonInteractive => return ctx.fail(error.NonInteractive, "destructive change without a terminal: use --yes --confirm {s}", .{target}),
        else => |e| return e,
    };
    if (answer == .no) return ctx.fail(error.Declined, "confirmation did not match; nothing was sent", .{});
}

/// Step ledger for multi-step workflows (SPEC §8.2): every step ends as
/// done, failed, not run or unknown, and the ledger is printed whatever
/// happened — workflows never auto-destroy to compensate. With a
/// `Progress` attached (by `run`), steps are also shown live (SPEC §4.4):
/// steps run in the order they were added, so the first added step and
/// the step after each finished one start automatically; nothing may
/// prompt once steps are added.
pub const Ledger = struct {
    steps: std.ArrayList(Step) = .empty,
    progress: ?*Progress = null,

    pub const State = enum { done, failed, not_run, unknown, skipped };

    pub const Step = struct {
        name: []const u8,
        state: State = .not_run,
        detail: []const u8 = "",
        /// How long the step ran, when it was shown running (SPEC §4.2).
        seconds: ?u64 = null,
    };

    pub fn add(l: *Ledger, arena: std.mem.Allocator, name: []const u8) !usize {
        try l.steps.append(arena, .{ .name = name });
        if (l.progress) |p| p.added(l);
        return l.steps.items.len - 1;
    }

    pub fn set(l: *Ledger, i: usize, state: State, detail: []const u8) void {
        const before = l.steps.items[i].state;
        l.steps.items[i].state = state;
        l.steps.items[i].detail = detail;
        if (l.progress) |p| p.update(l, i, before);
    }

    /// New detail for a running step (e.g. a wait's latest status).
    /// Never starts or finishes a step.
    pub fn note(l: *Ledger, i: usize, detail: []const u8) void {
        if (std.mem.eql(u8, l.steps.items[i].detail, detail)) return;
        l.steps.items[i].detail = detail;
        if (l.progress) |p| p.noted(l, i);
    }

    /// A handle for waits to report into step `i` (`Note.say`).
    pub fn noter(l: *Ledger, i: usize) Note {
        return .{ .ledger = l, .step = i };
    }

    pub fn complete(l: *const Ledger) bool {
        for (l.steps.items) |s| {
            if (s.state != .done and s.state != .skipped) return false;
        }
        return true;
    }

    fn nameWidth(l: *const Ledger) usize {
        var width: usize = 0;
        for (l.steps.items) |s| width = @max(width, ui.text.width(s.name));
        return width;
    }

    /// The end-of-run summary on stdout — unless the live lines already
    /// were the ledger on this terminal (SPEC §4.4).
    pub fn render(l: *const Ledger, w: *Io.Writer, u: *const ui.Ui) !void {
        if (l.progress) |p| if (p.replaces) return;
        const width = l.nameWidth();
        for (l.steps.items) |s| try finalLine(w, u, s, width, null);
    }
};

/// Where a long wait reports its latest status: the running step's
/// detail (SPEC §4.4). Waits take `?Note`; null reports nothing.
pub const Note = struct {
    ledger: *Ledger,
    step: usize,

    pub fn say(n: Note, detail: []const u8) void {
        n.ledger.note(n.step, detail);
    }
};

fn finalLine(w: *Io.Writer, u: *const ui.Ui, s: Ledger.Step, width: usize, seconds: ?u64) !void {
    const status: ui.style.Status = switch (s.state) {
        .done => .ok,
        .failed => .failed,
        .not_run => .not_checked,
        .unknown => .unknown,
        .skipped => .not_checked,
    };
    const word = switch (s.state) {
        .not_run => "not run",
        else => @tagName(s.state),
    };
    try w.print("  {s}{s} ", .{ u.palette.on(status.role()), status.glyph(u.glyphs) });
    try ui.text.writeFit(w, s.name, width, .left, "", true);
    try w.print("  {s}{s}", .{ word, u.palette.off(status.role()) });
    if (seconds) |t| try w.print("  {f}", .{ui.values.duration(t)});
    if (s.detail.len > 0) try w.print("  {s}{s}{s}", .{ u.palette.on(.muted), s.detail, u.palette.off(.muted) });
    try w.writeByte('\n');
}

const frames_unicode = [_][]const u8{ "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏" };
const frames_ascii = [_][]const u8{ "|", "/", "-", "\\" };

/// The running step's line (no newline): spinner, name, elapsed, detail,
/// cut to `cols` so it never wraps (a wrapped line cannot be redrawn).
pub fn liveLine(w: *Io.Writer, u: *const ui.Ui, s: Ledger.Step, width: usize, seconds: u64, frame: usize, cols: ?usize) !void {
    const ascii = u.glyphs == &ui.style.ascii;
    const spin = if (ascii) frames_ascii[frame % frames_ascii.len] else frames_unicode[frame % frames_unicode.len];
    var buf: [512]u8 = undefined;
    var rest: Io.Writer = .fixed(&buf);
    ui.text.writeFit(&rest, s.name, width, .left, "", true) catch {};
    rest.print("  {f}", .{ui.values.duration(seconds)}) catch {};
    if (s.detail.len > 0) rest.print("  {s}", .{s.detail}) catch {};
    try w.print("  {s}{s}{s} ", .{ u.palette.on(.title), spin, u.palette.off(.title) });
    const room = if (cols) |c| (if (c > 6) c - 5 else 1) else rest.buffered().len;
    try ui.text.writeFit(w, rest.buffered(), room, .left, u.glyphs.ellipsis, false);
}

/// `HH:MM:SS` local time for plain progress lines.
fn timeOfDay(w: *Io.Writer, epoch: i64, zone: *const ui.values.Zone) !void {
    const t = epoch + zone.offsetAt(epoch);
    const day: u64 = @intCast(@mod(t, 86400));
    try w.print("{d:0>2}:{d:0>2}:{d:0>2}", .{ day / 3600, day % 3600 / 60, day % 60 });
}

/// Live step progress on stderr (SPEC §4.4). On a terminal the running
/// step is redrawn by a concurrent ticker; otherwise one timestamped line
/// per step start and end. All drawing happens under `mutex`.
pub const Progress = struct {
    io: Io,
    w: *Io.Writer,
    u: *const ui.Ui,
    zone: *const ui.values.Zone,
    /// Redrawn spinner line (stderr is a terminal, no `-v`).
    live: bool,
    /// The live lines are the ledger, or stdout carries JSON: stdout's
    /// text summary is skipped.
    replaces: bool,
    mutex: Io.Mutex = .init,
    ledger: ?*Ledger = null,
    current: ?usize = null,
    started_any: bool = false,
    step_started: Io.Timestamp = .zero,
    run_started: Io.Timestamp = .zero,
    frame: usize = 0,
    /// The detail last printed by `plainNote`.
    last_note: []const u8 = "",
    ticker: ?Io.Future(Io.Cancelable!void) = null,

    pub fn init(ctx: *Context) Progress {
        const live = ctx.err_ui.width != null and !ctx.globals.verbose;
        return .{
            .io = ctx.io,
            .w = ctx.err,
            .u = &ctx.err_ui,
            .zone = &ctx.ui.zone,
            .live = live,
            .replaces = ctx.json() or (live and ctx.ui.width != null),
        };
    }

    pub fn attach(p: *Progress, l: *Ledger) void {
        p.ledger = l;
        l.progress = p;
        p.run_started = Io.Clock.awake.now(p.io);
        if (p.live) p.ticker = p.io.concurrent(tick, .{p}) catch null;
    }

    fn tick(p: *Progress) Io.Cancelable!void {
        while (true) {
            try p.io.sleep(.fromMilliseconds(100), .awake);
            try p.mutex.lock(p.io);
            defer p.mutex.unlock(p.io);
            p.frame +%= 1;
            p.drawCurrent() catch {};
        }
    }

    fn secondsSince(p: *const Progress, t: Io.Timestamp) u64 {
        const ns = t.durationTo(Io.Clock.awake.now(p.io)).nanoseconds;
        return if (ns <= 0) 0 else @intCast(@divTrunc(ns, std.time.ns_per_s));
    }

    fn added(p: *Progress, l: *Ledger) void {
        if (p.started_any) return;
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.start(l, 0) catch {};
    }

    fn update(p: *Progress, l: *Ledger, i: usize, before: Ledger.State) void {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.updateLocked(l, i, before) catch {};
    }

    /// A new detail: redrawn (terminal) or one line (plain), only while
    /// that step is the running one.
    fn noted(p: *Progress, l: *Ledger, i: usize) void {
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        if (p.current != i) return;
        if (p.live) p.drawCurrent() catch {} else p.plainNote(l.steps.items[i]) catch {};
    }

    fn updateLocked(p: *Progress, l: *Ledger, i: usize, before: Ledger.State) !void {
        const state = l.steps.items[i].state;
        if (p.current != i and (before == .not_run or state != .not_run)) {
            if (p.current) |c| try p.finish(l, c);
            try p.start(l, i);
        }
        switch (state) {
            .unknown, .not_run => try p.drawCurrent(),
            .done, .failed, .skipped => {
                try p.finish(l, i);
                if (i + 1 < l.steps.items.len and l.steps.items[i + 1].state == .not_run) try p.start(l, i + 1);
            },
        }
    }

    fn start(p: *Progress, l: *Ledger, i: usize) !void {
        if (!p.started_any) try p.w.writeByte('\n'); // apart from the plan
        p.current = i;
        p.last_note = "";
        p.started_any = true;
        p.step_started = Io.Clock.awake.now(p.io);
        if (p.live) return p.drawCurrent();
        const now = @divFloor(Io.Clock.real.now(p.io).nanoseconds, std.time.ns_per_s);
        try timeOfDay(p.w, @intCast(now), p.zone);
        try p.w.print("  ▸ {s}\n", .{l.steps.items[i].name});
        try p.w.flush();
    }

    /// Not a terminal: a changed detail of the running step is one dated
    /// line, so logs show what a long wait is doing.
    fn plainNote(p: *Progress, s: Ledger.Step) !void {
        if (s.detail.len == 0 or std.mem.eql(u8, s.detail, p.last_note)) return;
        p.last_note = s.detail;
        try timeOfDay(p.w, @intCast(@divFloor(Io.Clock.real.now(p.io).nanoseconds, std.time.ns_per_s)), p.zone);
        try p.w.print("  · {s}  {s}\n", .{ s.name, s.detail });
        try p.w.flush();
    }

    fn finish(p: *Progress, l: *Ledger, i: usize) !void {
        const secs: ?u64 = if (p.current == i) p.secondsSince(p.step_started) else null;
        if (secs) |t| l.steps.items[i].seconds = t;
        if (p.current == i) p.current = null;
        const s = l.steps.items[i];
        if (p.live) {
            try p.w.writeAll("\r\x1b[2K");
            try finalLine(p.w, p.u, s, l.nameWidth(), secs);
        } else {
            const now = @divFloor(Io.Clock.real.now(p.io).nanoseconds, std.time.ns_per_s);
            try timeOfDay(p.w, @intCast(now), p.zone);
            try finalLine(p.w, &.{ .glyphs = p.u.glyphs }, s, ui.text.width(s.name), secs);
        }
        try p.w.flush();
    }

    fn drawCurrent(p: *Progress) !void {
        if (!p.live) return;
        const l = p.ledger orelse return;
        const i = p.current orelse return;
        try p.w.writeAll("\r\x1b[2K");
        try liveLine(p.w, p.u, l.steps.items[i], l.nameWidth(), p.secondsSince(p.step_started), p.frame, p.u.width);
        try p.w.flush();
    }

    /// Stops the ticker and closes the open line. After a failure, the
    /// steps never started are listed too when the live lines are the
    /// ledger; after success the total time follows.
    pub fn end(p: *Progress, ok: bool) void {
        if (p.ticker) |*t| {
            t.cancel(p.io) catch {};
            p.ticker = null;
        }
        p.mutex.lockUncancelable(p.io);
        defer p.mutex.unlock(p.io);
        p.endLocked(ok) catch {};
    }

    fn endLocked(p: *Progress, ok: bool) !void {
        const l = p.ledger orelse return;
        if (l.steps.items.len == 0) return;
        if (p.current) |c| try p.finish(l, c);
        if (!ok and p.replaces and p.live) {
            for (l.steps.items) |s| if (s.state == .not_run) try finalLine(p.w, p.u, s, l.nameWidth(), null);
        }
        if (ok) {
            if (!p.live) try timeOfDay(p.w, @intCast(@divFloor(Io.Clock.real.now(p.io).nanoseconds, std.time.ns_per_s)), p.zone);
            try p.w.print("{s}  total {f}{s}\n", .{ p.u.palette.on(.muted), ui.values.duration(p.secondsSince(p.run_started)), p.u.palette.off(.muted) });
        }
        try p.w.flush();
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const cli = @import("cli.zig");
const Harness = @import("testkit.zig").Harness;

/// Fake DNS-record edit: state is a value; `send` records calls.
const FakeOp = struct {
    target: []const u8 = "web-01",
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .unifi,
    current: []const u8 = "192.168.1.10",
    wanted: []const u8 = "192.168.1.20",
    /// Value seen by the second read (simulates a concurrent edit).
    drift: ?[]const u8 = null,
    reads: usize = 0,
    sends: usize = 0,
    send_error: ?anyerror = null,
    verify_ok: bool = true,
    ledger: Ledger = .{},

    fn read(op: *FakeOp, _: *Context) !void {
        op.reads += 1;
        if (op.reads > 1) if (op.drift) |d| {
            op.current = d;
        };
    }
    fn plan(op: *FakeOp, ctx: *Context) !?Plan {
        if (std.mem.eql(u8, op.current, op.wanted)) return null;
        const changes = try ctx.arena.dupe(ui.blocks.Change, &.{.{ .field = "ipv4", .from = op.current, .to = op.wanted }});
        return .{
            .action = "Update DNS record web-01",
            .risk = op.risk,
            .target = "unifi (site default)",
            .changes = changes,
        };
    }
    fn fingerprint(op: *FakeOp) []const u8 {
        return op.current;
    }
    fn send(op: *FakeOp, ctx: *Context) !void {
        op.sends += 1;
        const i = try op.ledger.add(ctx.arena, "write record");
        if (op.send_error) |e| {
            op.ledger.set(i, .failed, "simulated");
            return ctx.fail(e, "simulated", .{});
        }
        op.current = op.wanted;
        op.ledger.set(i, .done, "ok");
    }
    fn verify(op: *FakeOp, _: *Context) !bool {
        return op.verify_ok;
    }
    fn done(_: *FakeOp) []const u8 {
        return "updated web-01";
    }
};

var fake_op: FakeOp = .{};
var fake_reread_ms: i64 = 3000;

const probe = struct {
    pub const name = "probe";
    pub const summary = "exec probe";
    pub const flags = [_]cli.Flag{.{ .long = "confirm", .kind = .string, .metavar = "TARGET", .help = "" }};
    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        return exec(ctx, &fake_op, .{ .confirm = args.string("confirm"), .reread_after_ms = fake_reread_ms });
    }
};
const exec = run;
const root = cli.group("artoo", "t", &.{cli.leaf(probe)});

fn scenario(h: *Harness, op: FakeOp, script: prompt.Script, line: []const u8) !@import("testkit.zig").Exit {
    fake_op = op;
    fake_reread_ms = 3000;
    const s = try h.arena.allocator().create(prompt.Script);
    s.* = script;
    h.input = .{ .script = s };
    return h.run(&root, line);
}

test "exec: dry-run, declined and non-interactive send nothing" {
    var h = try Harness.init();
    defer h.deinit();
    try testing.expectEqual(.ok, try scenario(&h, .{}, .{}, "probe -n"));
    try testing.expectEqual(@as(usize, 0), fake_op.sends);
    try testing.expect(std.mem.endsWith(u8, h.stdout(), "\nDry run: nothing was sent.\n"));
    try testing.expect(std.mem.startsWith(u8, h.stdout(), "Plan · Update DNS record web-01\n"));

    try testing.expectEqual(.refused, try scenario(&h, .{}, .{ .lines = &.{"n"} }, "probe"));
    try testing.expectEqual(@as(usize, 0), fake_op.sends);
    try testing.expectEqual(.refused, try scenario(&h, .{}, .{ .interactive = false }, "probe"));
    try testing.expectEqual(@as(usize, 0), fake_op.sends);
    try testing.expectEqualStrings("artoo: not a terminal: re-run with --yes to confirm\n", h.stderr());
}

test "exec: confirmed write is sent once, verified, reported" {
    var h = try Harness.init();
    defer h.deinit();
    try testing.expectEqual(.ok, try scenario(&h, .{}, .{ .lines = &.{"y"} }, "probe"));
    try testing.expectEqual(@as(usize, 1), fake_op.sends);
    try testing.expect(std.mem.endsWith(u8, h.stdout(), "✓ updated web-01\n"));
    try testing.expectEqual(.ok, try scenario(&h, .{}, .{ .interactive = false }, "probe --yes"));
    try testing.expectEqual(@as(usize, 1), fake_op.sends);
}

test "exec: no-op refused, verify failure partial, unknown never success" {
    var h = try Harness.init();
    defer h.deinit();
    try testing.expectEqual(.refused, try scenario(&h, .{ .current = "192.168.1.20" }, .{}, "probe -y"));
    try testing.expectEqual(@as(usize, 0), fake_op.sends);
    try testing.expectEqual(.partial, try scenario(&h, .{ .verify_ok = false }, .{}, "probe -y"));
    try testing.expectEqual(@as(usize, 1), fake_op.sends);
    try testing.expectEqual(.unknown, try scenario(&h, .{ .send_error = error.OutcomeUnknown }, .{}, "probe -y"));
    try testing.expectEqual(@as(usize, 1), fake_op.sends);
    try testing.expect(std.mem.find(u8, h.stdout(), "✓") == null);
    try testing.expectEqual(.network, try scenario(&h, .{ .send_error = error.Network }, .{}, "probe -y"));
}

test "exec: destructive needs the typed target or --yes --confirm TARGET" {
    var h = try Harness.init();
    defer h.deinit();
    const d: FakeOp = .{ .risk = .destructive };
    try testing.expectEqual(.refused, try scenario(&h, d, .{ .lines = &.{"y"} }, "probe"));
    try testing.expectEqual(@as(usize, 0), fake_op.sends);
    try testing.expectEqual(.ok, try scenario(&h, d, .{ .lines = &.{"web-01"} }, "probe"));
    try testing.expectEqual(@as(usize, 1), fake_op.sends);
    try testing.expectEqual(.refused, try scenario(&h, d, .{ .interactive = false }, "probe"));
    try testing.expect(std.mem.find(u8, h.stderr(), "use --yes --confirm web-01") != null);
    try testing.expectEqual(.refused, try scenario(&h, d, .{ .interactive = false }, "probe -y"));
    try testing.expectEqual(.refused, try scenario(&h, d, .{ .interactive = false }, "probe -y --confirm web-02"));
    try testing.expectEqual(@as(usize, 0), fake_op.sends);
    try testing.expectEqual(.ok, try scenario(&h, d, .{ .interactive = false }, "probe -y --confirm web-01"));
    try testing.expectEqual(@as(usize, 1), fake_op.sends);
    try testing.expect(std.mem.find(u8, h.stdout(), "▲ destructive") != null);
}

test "exec: drift during a slow confirmation aborts" {
    var h = try Harness.init();
    defer h.deinit();
    fake_op = .{ .drift = "192.168.1.99" };
    fake_reread_ms = 0;
    var s: prompt.Script = .{ .lines = &.{"y"} };
    h.input = .{ .script = &s };
    try testing.expectEqual(.refused, h.run(&root, "probe"));
    try testing.expectEqual(@as(usize, 0), fake_op.sends);
    try testing.expect(std.mem.find(u8, h.stderr(), "changed while waiting for confirmation") != null);
}

test "exec: JSON mode keeps stdout a single document" {
    var h = try Harness.init();
    defer h.deinit();
    try testing.expectEqual(.ok, try scenario(&h, .{}, .{}, "-o json probe -y"));
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, h.stdout(), .{});
    defer parsed.deinit();
    try testing.expectEqualStrings("applied", parsed.value.object.get("data").?.object.get("result").?.string);
    try testing.expect(std.mem.startsWith(u8, h.stderr(), "Plan · "));
}

test "exec: JSON results and errors carry the step ledger" {
    var h = try Harness.init();
    defer h.deinit();
    try testing.expectEqual(.ok, try scenario(&h, .{}, .{}, "-o json probe -y"));
    {
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, h.stdout(), .{});
        defer parsed.deinit();
        const steps = parsed.value.object.get("data").?.object.get("steps").?.array.items;
        try testing.expectEqual(@as(usize, 1), steps.len);
        const s0 = steps[0].object;
        try testing.expectEqualStrings("write record", s0.get("name").?.string);
        try testing.expectEqualStrings("done", s0.get("state").?.string);
        try testing.expectEqualStrings("ok", s0.get("detail").?.string);
        try testing.expectEqual(@as(i64, 0), s0.get("seconds").?.integer);
    }
    try testing.expectEqual(.network, try scenario(&h, .{ .send_error = error.Network }, .{}, "-o json probe -y"));
    {
        const err = h.stderr();
        const line = err[(std.mem.findLast(u8, std.mem.trimEnd(u8, err, "\n"), "\n") orelse 0)..];
        const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, line, .{});
        defer parsed.deinit();
        try testing.expectEqualStrings("network", parsed.value.object.get("error").?.object.get("kind").?.string);
        const steps = parsed.value.object.get("steps").?.array.items;
        try testing.expectEqualStrings("failed", steps[0].object.get("state").?.string);
    }
    // A failure before any step: no ledger in the error object.
    try testing.expectEqual(.refused, try scenario(&h, .{ .current = "192.168.1.20" }, .{}, "-o json probe -y"));
    try testing.expect(std.mem.find(u8, h.stderr(), "\"steps\"") == null);
}

test "progress, plain: a line per step start and end, auto-start in order, total" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: Io.Writer.Allocating = .init(a);
    const u: ui.Ui = .{};
    var p: Progress = .{ .io = testing.io, .w = &buf.writer, .u = &u, .zone = &ui.values.Zone.utc, .live = false, .replaces = false };
    var l: Ledger = .{};
    p.attach(&l);
    const s1 = try l.add(a, "clone template");
    const s2 = try l.add(a, "wait for agent");
    l.set(s1, .unknown, "");
    l.set(s1, .done, "task OK");
    l.set(s2, .done, "");
    p.end(true);
    const out = buf.written();
    for ([_][]const u8{ "  ▸ clone template\n", "  ✓ clone template  done  0s  task OK\n", "  ▸ wait for agent\n", "  ✓ wait for agent  done  0s\n", "  total 0s\n" }) |want| {
        if (std.mem.find(u8, out, want) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ want, out });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "▸ clone template"));
    // Plain progress does not replace the stdout summary.
    var sum: Io.Writer.Allocating = .init(a);
    try l.render(&sum.writer, &u);
    try testing.expect(std.mem.find(u8, sum.written(), "clone template") != null);
}

test "progress, plain: a changed detail of the running step is one dated line; durations kept" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: Io.Writer.Allocating = .init(a);
    const u: ui.Ui = .{};
    var p: Progress = .{ .io = testing.io, .w = &buf.writer, .u = &u, .zone = &ui.values.Zone.utc, .live = false, .replaces = false };
    var l: Ledger = .{};
    p.attach(&l);
    const s1 = try l.add(a, "wait for cloud-init");
    l.set(s1, .unknown, "");
    const n = l.noter(s1);
    n.say("stage modules-config");
    n.say("stage modules-config");
    n.say("stage modules-final");
    l.set(s1, .done, "done");
    n.say("late"); // after the step ended: kept as detail, not printed
    p.end(true);
    const out = buf.written();
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "  · wait for cloud-init  stage modules-config\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, "  · wait for cloud-init  stage modules-final\n"));
    try testing.expect(std.mem.find(u8, out, "late") == null);
    try testing.expectEqual(@as(?u64, 0), l.steps.items[s1].seconds);
}

test "progress, failure: the open step closes as unknown; live-as-ledger lists steps never run" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: Io.Writer.Allocating = .init(a);
    const u: ui.Ui = .{};
    var p: Progress = .{ .io = testing.io, .w = &buf.writer, .u = &u, .zone = &ui.values.Zone.utc, .live = true, .replaces = true };
    var l: Ledger = .{};
    p.ledger = &l; // attach without the ticker: deterministic output
    l.progress = &p;
    _ = try l.add(a, "stop VM");
    _ = try l.add(a, "destroy VM");
    l.set(0, .unknown, "");
    p.end(false);
    const out = buf.written();
    try testing.expect(std.mem.find(u8, out, "? stop VM     unknown") != null);
    try testing.expect(std.mem.find(u8, out, "– destroy VM  not run") != null);
    try testing.expect(std.mem.find(u8, out, "total") == null);
    var sum: Io.Writer.Allocating = .init(a);
    try l.render(&sum.writer, &u);
    try testing.expectEqualStrings("", sum.written());
}

test "liveLine: spinner, elapsed, detail; cut to the terminal width" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const u: ui.Ui = .{};
    var buf: Io.Writer.Allocating = .init(a);
    try liveLine(&buf.writer, &u, .{ .name = "wait for cloud-init", .state = .unknown, .detail = "modules-final" }, 20, 102, 2, null);
    try testing.expectEqualStrings("  ⠹ wait for cloud-init   1m 42s  modules-final", buf.written());
    buf.clearRetainingCapacity();
    try liveLine(&buf.writer, &u, .{ .name = "wait for cloud-init", .state = .unknown, .detail = "modules-final" }, 20, 102, 2, 30);
    try testing.expect(ui.text.width(buf.written()) <= 30);
    try testing.expect(std.mem.endsWith(u8, buf.written(), "…"));
    buf.clearRetainingCapacity();
    const ascii: ui.Ui = .{ .glyphs = &ui.style.ascii };
    try liveLine(&buf.writer, &ascii, .{ .name = "x" }, 1, 0, 1, null);
    try testing.expectEqualStrings("  / x  0s", buf.written());
}
