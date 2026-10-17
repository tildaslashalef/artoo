//! Shared plumbing for the Proxmox and UniFi clients: building the HTTP
//! client from config, mapping statuses to errors, CA bundle facts.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const app = @import("app.zig");
const files = @import("files.zig");
const http = @import("http.zig");
const version = @import("build_options").version;

const Context = app.Context;

pub const Endpoint = struct {
    /// Base URL without trailing slash.
    base: []const u8,
    /// PEM bundle from config; null trusts the system root store (§15).
    ca_bundle: ?[]const u8,
    timeout_seconds: u32,
};

/// An HTTP client for one API, CA bundle from config (or the system
/// roots), `--timeout` honored.
pub fn httpClient(ctx: *Context, ep: Endpoint) !*http.Client {
    const ca: ?[]const u8 = if (ep.ca_bundle) |b| files.expandHome(ctx.arena, ctx.env, b) catch
        return ctx.fail(error.ConfigInvalid, "cannot resolve {s}: HOME is not set", .{b}) else null;
    const c = try ctx.arena.create(http.Client);
    const seconds = ctx.globals.timeout orelse ep.timeout_seconds;
    c.init(ctx.gpa, ctx.io, .{
        .ca_bundle = ca,
        .system_roots = ca == null,
        .timeout_ms = @as(u64, seconds) * 1000,
        .user_agent = "artoo/" ++ version,
        .trace = if (ctx.globals.verbose) ctx.err else null,
    }) catch |err| return switch (err) {
        error.CaUnreadable => if (ca) |path|
            ctx.fail(error.Tls, "cannot read CA bundle {s} (config ca_bundle)", .{ctx.tilde(path)})
        else
            ctx.fail(error.Tls, "cannot load the system's root certificates", .{}),
        error.OutOfMemory => error.OutOfMemory,
    };
    return c;
}

/// Map a transport error to the caller's message.
pub fn transportError(ctx: *Context, err: http.Error, diag: http.Diag, what: []const u8) anyerror {
    return switch (err) {
        error.OutOfMemory, error.Canceled => err,
        else => ctx.fail(err, "{s}: {s}", .{ what, if (diag.message.len > 0) diag.message else @errorName(err) }),
    };
}

pub fn trimSlash(s: []const u8) []const u8 {
    return std.mem.trimEnd(u8, s, "/");
}

pub const CaSummary = struct {
    certs: usize,
    /// Earliest expiry (epoch seconds) among the certificates.
    expires: ?i64,
};

/// Parse a PEM bundle (expired certificates are dropped by the stdlib).
pub fn caSummary(arena: Allocator, io: Io, path: []const u8) !CaSummary {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    const now = Io.Clock.real.now(io);
    try bundle.addCertsFromFilePathAbsolute(arena, io, now, path);
    var earliest: ?i64 = null;
    var it = bundle.map.valueIterator();
    while (it.next()) |index| {
        const cert: std.crypto.Certificate = .{ .buffer = bundle.bytes.items, .index = index.* };
        const parsed = cert.parse() catch continue;
        const na: i64 = @intCast(parsed.validity.not_after);
        earliest = if (earliest) |e| @min(e, na) else na;
    }
    return .{ .certs = bundle.map.count(), .expires = earliest };
}
