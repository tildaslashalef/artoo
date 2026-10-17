//! Per-invocation context handed to every command handler.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const cli = @import("cli.zig");
const cfg = @import("config.zig");
const Ui = @import("ui/Ui.zig");
const prompt = @import("prompt.zig");
const secrets = @import("secrets.zig");
const proc = @import("proc.zig");

pub const Context = struct {
    /// One arena per invocation; everything parsed lives here.
    arena: Allocator,
    /// For long-lived helpers that manage their own memory (HTTP client).
    gpa: Allocator,
    io: Io,
    out: *Io.Writer,
    err: *Io.Writer,
    env: *const std.process.Environ.Map,
    /// Command-line globals with config defaults applied.
    globals: cli.Globals = .{},
    /// Rendering settings for stdout / stderr.
    ui: Ui = .{},
    err_ui: Ui = .{},
    /// Command path for hints, e.g. "vm ls".
    path: []const u8 = "",
    /// Message for the error a handler returns (rendered by main).
    diag: ?[]const u8 = null,
    /// The step ledger of the workflow that ran (`exec.run`), for the JSON
    /// error object (SPEC §4.2).
    steps: []const @import("exec.zig").Ledger.Step = &.{},
    /// The config file as loaded by main (defaults when absent).
    loaded: LoadedConfig = .{ .failed = .{ .err = error.ConfigMissing, .message = "config not loaded" } },
    /// Answers to prompts (stdin, or a script in tests).
    input: prompt.Input = .stdin,
    /// Tests inject a store; otherwise `credentials.store` decides.
    store_override: ?secrets.Store = null,
    /// Tests point API clients at an in-process plain-HTTP server.
    test_hooks: TestHooks = .{},

    pub const TestHooks = struct {
        unifi_base: ?[]const u8 = null,
        pve_base: ?[]const u8 = null,
        cloudflare_base: ?[]const u8 = null,
        /// Task polling interval override (ms).
        poll_ms: ?u64 = null,
        /// Stands in for helper processes (ssh).
        runner: ?proc.Runner = null,
    };

    pub const LoadedConfig = union(enum) {
        ok: cfg.Loaded,
        failed: struct { err: anyerror, message: []const u8 },
    };

    /// Record a message and return `err` for main to map to an exit code.
    pub fn fail(ctx: *Context, err: anyerror, comptime fmt: []const u8, args: anytype) anyerror {
        ctx.diag = std.fmt.allocPrint(ctx.arena, fmt, args) catch null;
        return err;
    }

    pub fn json(ctx: *const Context) bool {
        return ctx.globals.output == .json;
    }

    /// The effective configuration, or the load error.
    pub fn config(ctx: *Context) !*const cfg.Config {
        return switch (ctx.loaded) {
            .ok => |*l| &l.config,
            .failed => |f| ctx.fail(f.err, "{s}", .{f.message}),
        };
    }

    /// The configured secret store.
    pub fn secretStore(ctx: *Context) !secrets.Store {
        if (ctx.store_override) |s| return s;
        const c = try ctx.config();
        return secrets.open(ctx.io, ctx.arena, ctx.env, c.credentials.store, .{}) catch |err| switch (err) {
            error.SecretStoreUnavailable => ctx.fail(error.SecretStoreUnavailable, "secret store '{s}' is not available on this system (credentials.store)", .{@tagName(c.credentials.store)}),
            error.HomeUnknown => ctx.fail(error.SecretStoreUnavailable, "HOME is not set; cannot locate the secrets file", .{}),
            else => |e| e,
        };
    }

    /// Normal confirmation (SPEC §3.4): `--yes` skips it; without a TTY and
    /// without `--yes` the action is refused.
    pub fn confirm(ctx: *Context, comptime fmt: []const u8, args: anytype) !void {
        if (ctx.globals.yes) return;
        const q = try std.fmt.allocPrint(ctx.arena, fmt, args);
        const answer = prompt.ask(ctx.input, ctx.io, ctx.arena, ctx.err, q) catch |err| switch (err) {
            error.NonInteractive => return ctx.fail(error.NonInteractive, "not a terminal: re-run with --yes to confirm", .{}),
            else => |e| return e,
        };
        if (answer == .no) return ctx.fail(error.Declined, "declined; nothing changed", .{});
    }

    /// `/Users/x/.artoo/config.json` → `~/.artoo/config.json` for display.
    pub fn tilde(ctx: *const Context, path: []const u8) []const u8 {
        const home = ctx.env.get("HOME") orelse return path;
        const rest = std.mem.cutPrefix(u8, path, home) orelse return path;
        if (rest.len == 0 or rest[0] != '/') return path;
        return std.fmt.allocPrint(ctx.arena, "~{s}", .{rest}) catch path;
    }
};
