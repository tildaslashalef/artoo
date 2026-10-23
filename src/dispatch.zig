//! Parse → load config → run the command → map its error to the exit code.
//! The error → exit-code table lives here and nowhere else (SPEC §4.3).

const std = @import("std");
const Io = std.Io;
const build_options = @import("build_options");

const app = @import("app.zig");
const cli = @import("cli.zig");
const ui = @import("ui.zig");
const config = @import("config.zig");
const prompt = @import("prompt.zig");
const secrets = @import("secrets.zig");

pub const version = build_options.version;

pub const Exit = enum(u8) {
    ok = 0,
    internal = 1,
    usage = 2,
    auth = 3,
    network = 4,
    refused = 5,
    task_failed = 6,
    unknown = 7,
    partial = 8,
    interrupted = 130,

    pub fn kind(e: Exit) []const u8 {
        return @tagName(e);
    }
};

/// The one error → exit-code table (SPEC §4.3). Modules return their own
/// error sets; anything unlisted is an internal error.
pub fn exitFor(err: anyerror) Exit {
    return switch (err) {
        // A named target that does not exist is the caller's mistake, not the network's.
        error.Usage, error.ConfigInvalid, error.ConfigMissing, error.ConfigExists, error.UnsafePath, error.NotFound => .usage,
        error.SecretMissing, error.SecretStoreUnavailable, error.AuthFailed, error.PermissionDenied => .auth,
        error.Network, error.Tls, error.Protocol, error.Timeout, error.HttpStatus => .network,
        error.Refused, error.Declined, error.NonInteractive, error.TargetMismatch, error.NoChange, error.Changed => .refused,
        error.TaskFailed => .task_failed,
        error.OutcomeUnknown, error.WaitTimeout => .unknown,
        error.Partial => .partial,
        error.Canceled, error.Interrupted => .interrupted,
        else => .internal,
    };
}

pub const Process = struct {
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: Io,
    env: *const std.process.Environ.Map,
    out: *Io.Writer,
    err: *Io.Writer,
    out_file: Io.File,
    err_file: Io.File,
    argv0: []const u8 = "",
    input: prompt.Input = .stdin,
    store: ?secrets.Store = null,
    test_hooks: app.Context.TestHooks = .{},
};

pub fn run(p: Process, root: *const cli.Command, words: []const []const u8) Exit {
    return dispatchInner(p, root, words) catch |e| {
        // Only writer/allocation failures reach here.
        p.err.print("artoo: {s}\n", .{@errorName(e)}) catch {};
        return exitFor(e);
    };
}

fn dispatchInner(p: Process, root: *const cli.Command, words: []const []const u8) !Exit {
    const parsed = try cli.parse.parse(p.arena, root, words);
    var globals: cli.Globals = switch (parsed) {
        .run => |inv| inv.globals,
        .help => |h| h.globals,
        .version => |g| g,
        .usage => |u| u.globals,
    };
    // Commands load config here once; its output settings become defaults.
    var loaded: app.Context.LoadedConfig = undefined;
    if (parsed == .run) {
        loaded = try loadConfig(p, globals.config);
        if (loaded == .ok) {
            globals.output = globals.output orelse loaded.ok.config.output.format;
            globals.color = globals.color orelse loaded.ok.config.output.color;
        }
    }
    const ui_opts: ui.Ui.Options = .{ .color = globals.color orelse .auto, .ascii = globals.ascii };
    const out_ui = try ui.Ui.detect(p.io, p.out_file, p.env, ui_opts);
    const err_ui = try ui.Ui.detect(p.io, p.err_file, p.env, ui_opts);
    const json = globals.output == .json;

    switch (parsed) {
        .version => {
            try p.out.print("artoo {s}\n", .{version});
            return .ok;
        },
        .help => |h| {
            try cli.help.write(p.out, h.path, .{
                .title_on = out_ui.palette.on(.title),
                .title_off = out_ui.palette.off(.title),
            });
            return .ok;
        },
        .usage => |u| {
            const hint = try pathTail(p.arena, u.path);
            try report(p.err, &err_ui, json, .usage, u.message, hint);
            return .usage;
        },
        .run => |inv| {
            var ctx: app.Context = .{
                .arena = p.arena,
                .gpa = p.gpa,
                .io = p.io,
                .out = p.out,
                .err = p.err,
                .env = p.env,
                .argv0 = p.argv0,
                .globals = globals,
                .ui = out_ui.withLocalZone(p.io, p.arena),
                .loaded = loaded,
                .input = p.input,
                .store_override = p.store,
                .test_hooks = p.test_hooks,
                .err_ui = err_ui,
                .path = try pathTail(p.arena, inv.path),
            };
            inv.command().run.?(&ctx, &inv) catch |e| {
                const code = exitFor(e);
                const message = ctx.diag orelse try defaultMessage(p.arena, e, code);
                if (json) {
                    try ui.json.writeErrorSteps(p.err, code.kind(), @backingInt(code), message, ctx.steps);
                } else try report(p.err, &err_ui, json, code, message, if (e == error.Usage) ctx.path else null);
                return code;
            };
            return .ok;
        },
    }
}

fn loadConfig(p: Process, override: ?[]const u8) !app.Context.LoadedConfig {
    const path = config.resolvePath(p.arena, p.env, override) catch |err| switch (err) {
        error.HomeUnknown => return .{ .failed = .{ .err = error.ConfigInvalid, .message = "HOME is not set; pass --config PATH" } },
        error.OutOfMemory => return error.OutOfMemory,
    };
    var msg: []const u8 = "";
    const l = config.load(p.io, p.arena, path, &msg) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => |e| return .{ .failed = .{ .err = e, .message = if (msg.len > 0) msg else @errorName(e) } },
    };
    return .{ .ok = l };
}

/// "vm ls" for a path rooted at "artoo".
fn pathTail(arena: std.mem.Allocator, path: []const *const cli.Command) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (path[1..], 0..) |c, i| {
        if (i > 0) try out.append(arena, ' ');
        try out.appendSlice(arena, c.name);
    }
    return out.items;
}

fn defaultMessage(arena: std.mem.Allocator, e: anyerror, code: Exit) ![]const u8 {
    return switch (code) {
        .partial => "some results are missing or unverified (see above)",
        .interrupted => "interrupted",
        else => std.fmt.allocPrint(arena, "failed: {s}", .{@errorName(e)}),
    };
}

/// One error report on stderr: a JSON object under `-o json`, else
/// `artoo: message` (+ a help hint for usage errors).
fn report(w: *Io.Writer, err_ui: *const ui.Ui, json: bool, code: Exit, message: []const u8, help_path: ?[]const u8) !void {
    if (json) return ui.json.writeError(w, code.kind(), @backingInt(code), message);
    const role: ui.style.Role = if (code == .partial or code == .refused) .warn else .fail;
    try w.print("{s}artoo:{s} {s}\n", .{ err_ui.palette.on(role), err_ui.palette.off(role), message });
    if (help_path) |hp| {
        try w.print("Run 'artoo help{s}{s}' for usage.\n", .{ if (hp.len > 0) " " else "", hp });
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const Harness = @import("testkit.zig").Harness;

const probe = struct {
    pub const name = "probe";
    pub const summary = "Fails on request";
    pub const positionals = [_]cli.Positional{.{ .name = "WHAT" }};
    pub fn run(ctx: *app.Context, args: cli.Args(@This())) !void {
        const what = args.pos("WHAT");
        if (std.mem.eql(u8, what, "ok")) return ctx.out.writeAll("fine\n");
        if (std.mem.eql(u8, what, "usage")) return ctx.fail(error.Usage, "bad KEY=VALUE '{s}'", .{"x"});
        if (std.mem.eql(u8, what, "unknown")) return ctx.fail(error.OutcomeUnknown, "write sent; outcome unknown", .{});
        if (std.mem.eql(u8, what, "partial")) return error.Partial;
        return error.SomethingUnexpected;
    }
};
const test_root = cli.group("artoo", "test", &.{cli.leaf(probe)});

test "exitFor covers the SPEC table" {
    try testing.expectEqual(Exit.usage, exitFor(error.Usage));
    try testing.expectEqual(Exit.usage, exitFor(error.NotFound));
    try testing.expectEqual(Exit.auth, exitFor(error.SecretMissing));
    try testing.expectEqual(Exit.network, exitFor(error.Tls));
    try testing.expectEqual(Exit.refused, exitFor(error.NonInteractive));
    try testing.expectEqual(Exit.task_failed, exitFor(error.TaskFailed));
    try testing.expectEqual(Exit.unknown, exitFor(error.OutcomeUnknown));
    try testing.expectEqual(Exit.partial, exitFor(error.Partial));
    try testing.expectEqual(Exit.interrupted, exitFor(error.Canceled));
    try testing.expectEqual(Exit.internal, exitFor(error.OutOfMemory));
}

test "dispatch: success, usage, handler failures, JSON errors" {
    var h = try Harness.init();
    defer h.deinit();

    try testing.expectEqual(Exit.ok, h.run(&test_root, "probe ok"));
    try testing.expectEqualStrings("fine\n", h.out.written());

    try testing.expectEqual(Exit.usage, h.run(&test_root, "probe"));
    try testing.expectEqualStrings("artoo: missing WHAT\nRun 'artoo help probe' for usage.\n", h.err.written());

    try testing.expectEqual(Exit.usage, h.run(&test_root, "probe usage"));
    try testing.expectEqualStrings("artoo: bad KEY=VALUE 'x'\nRun 'artoo help probe' for usage.\n", h.err.written());

    try testing.expectEqual(Exit.unknown, h.run(&test_root, "probe unknown"));
    try testing.expectEqualStrings("artoo: write sent; outcome unknown\n", h.err.written());

    try testing.expectEqual(Exit.partial, h.run(&test_root, "probe partial"));
    try testing.expectEqual(Exit.internal, h.run(&test_root, "probe boom"));
    try testing.expectEqualStrings("artoo: failed: SomethingUnexpected\n", h.err.written());

    try testing.expectEqual(Exit.unknown, h.run(&test_root, "-o json probe unknown"));
    try testing.expectEqualStrings(
        \\{"schema_version":1,"error":{"kind":"unknown","exit_code":7,"message":"write sent; outcome unknown"}}
        \\
    , h.err.written());
    try testing.expectEqual(Exit.usage, h.run(&test_root, "nope -o json"));
    try testing.expect(std.mem.startsWith(u8, h.err.written(), "{\"schema_version\":1,\"error\":{\"kind\":\"usage\""));
}

test "dispatch: help and version go to stdout with exit 0" {
    var h = try Harness.init();
    defer h.deinit();
    try testing.expectEqual(Exit.ok, h.run(&test_root, "--version"));
    try testing.expectEqualStrings("artoo " ++ version ++ "\n", h.out.written());
    try testing.expectEqual(Exit.ok, h.run(&test_root, "help probe"));
    try testing.expect(std.mem.startsWith(u8, h.out.written(), "Usage: artoo probe WHAT\n"));
    try testing.expectEqual(@as(usize, 0), h.err.written().len);
}
