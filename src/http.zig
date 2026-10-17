//! HTTP transport for both APIs (SPEC §8.1).
//!
//! - CA bundle from config only; `now` is pinned so the stdlib never
//!   replaces the bundle with system roots. Hostnames verified.
//! - No connection reuse: the pool is disabled and every request sends
//!   `Connection: close` (pveproxy closes idle sockets after 5 s; the prototype lost
//!   writes on reused dead sockets).
//! - Redirects refused; `accept-encoding: identity`; bodies capped while
//!   streaming.
//! - Every request has a deadline: the attempt runs as a concurrent task
//!   raced against a sleep in an `Io.Select`; on expiry the attempt is
//!   canceled (Io.Threaded interrupts the blocked syscall with SIG.IO).
//!   Timed `connect` is not implemented in 0.17's Io.Threaded, so this is
//!   the only deadline mechanism.
//! - GETs retry transport failures and 5xx with backoff. Writes are sent
//!   once: failure before any byte is sent → `Network`/`Tls`/`Timeout`;
//!   anything after → `OutcomeUnknown`.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Method = enum { GET, POST, PUT, PATCH, DELETE };

pub const Request = struct {
    method: Method = .GET,
    url: []const u8,
    /// Extra headers (e.g. X-API-KEY). Never logged.
    headers: []const std.http.Header = &.{},
    /// Full Authorization header value. Never logged.
    authorization: ?[]const u8 = null,
    body: ?[]const u8 = null,
    content_type: []const u8 = "application/json",
};

pub const Response = struct {
    status: u16,
    body: []const u8,
    /// Status-line reason phrase (pveproxy puts its error message here).
    reason: []const u8 = "",
};

pub const Error = error{
    /// Nothing was sent: DNS, TCP or protocol failure before the request.
    Network,
    Tls,
    /// Deadline hit before anything was sent (or on a GET).
    Timeout,
    /// Redirect, oversized or unreadable response on a GET.
    Protocol,
    /// A write was (possibly) sent; its result was not observed.
    OutcomeUnknown,
} || Allocator.Error || Io.Cancelable;

pub const Options = struct {
    /// Absolute path of the PEM bundle; null only for plain-HTTP tests
    /// and with `system_roots`.
    ca_bundle: ?[]const u8,
    /// Trust the operating system's root store instead (the one public
    /// API, Cloudflare — SPEC §15).
    system_roots: bool = false,
    timeout_ms: u64,
    max_body: usize = 16 << 20,
    /// GET retries after the first attempt.
    retries: u8 = 2,
    backoff_ms: u64 = 300,
    user_agent: []const u8 = "artoo",
    /// `-v`: one line per attempt on this writer (no headers, no bodies).
    trace: ?*Io.Writer = null,
};

pub const Diag = struct {
    /// Human explanation of the last failure.
    message: []const u8 = "",
    attempts: u8 = 0,
};

pub const Client = struct {
    io: Io,
    opts: Options,
    inner: std.http.Client,

    pub const InitError = error{CaUnreadable} || Allocator.Error;

    pub fn init(c: *Client, gpa: Allocator, io: Io, opts: Options) InitError!void {
        c.* = .{ .io = io, .opts = opts, .inner = .{ .allocator = gpa, .io = io } };
        errdefer c.inner.deinit();
        c.inner.connection_pool.free_size = 0;
        const now = Io.Clock.real.now(io);
        c.inner.now = now;
        if (opts.ca_bundle) |path| {
            c.inner.ca_bundle.addCertsFromFilePathAbsolute(gpa, io, now, path) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.CaUnreadable,
            };
        }
        if (opts.system_roots) {
            c.inner.ca_bundle.rescan(gpa, io, now) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.CaUnreadable,
            };
        }
    }

    pub fn deinit(c: *Client) void {
        c.inner.deinit();
    }

    pub fn send(c: *Client, arena: Allocator, req: Request, diag: *Diag) Error!Response {
        diag.* = .{};
        if (req.method != .GET) return c.once(arena, req, diag);
        var attempt: u8 = 0;
        while (true) : (attempt += 1) {
            const result = c.once(arena, req, diag);
            const retry = if (result) |r| r.status >= 500 else |err| switch (err) {
                error.Network, error.Timeout => true,
                else => false,
            };
            if (!retry or attempt >= c.opts.retries) return result;
            try c.io.sleep(.fromMilliseconds(@intCast(c.opts.backoff_ms << @intCast(attempt))), .awake);
        }
    }

    /// One attempt under the deadline.
    fn once(c: *Client, arena: Allocator, req: Request, diag: *Diag) Error!Response {
        diag.attempts += 1;
        const started = Io.Clock.awake.now(c.io);
        var a: Attempt = .{ .client = c, .arena = arena, .req = req };
        const result = c.race(&a);
        if (c.opts.trace) |w| {
            const ms = @divTrunc(started.durationTo(Io.Clock.awake.now(c.io)).nanoseconds, std.time.ns_per_ms);
            if (result) |r| {
                w.print("http: {s} {s} → {d} ({d} ms, {d} bytes)\n", .{ @tagName(req.method), req.url, r.status, ms, r.body.len }) catch {};
            } else |err| {
                w.print("http: {s} {s} → {s} ({d} ms)\n", .{ @tagName(req.method), req.url, @errorName(err), ms }) catch {};
            }
        }
        const sent = @backingInt(a.phase.load(.acquire)) >= @backingInt(Phase.sending);
        if (result) |r| return r else |err| {
            diag.message = a.message;
            if (err == error.Canceled) return err;
            if (req.method != .GET and sent) {
                diag.message = std.fmt.allocPrint(arena, "{s}; the request was sent but its result was not received", .{a.message}) catch a.message;
                return error.OutcomeUnknown;
            }
            return err;
        }
    }

    const Outcome = union(enum) {
        done: Error!Response,
        deadline: Io.Cancelable!void,
    };

    fn race(c: *Client, a: *Attempt) Error!Response {
        var buf: [2]Outcome = undefined;
        var sel: Io.Select(Outcome) = .init(c.io, &buf);
        sel.concurrent(.done, Attempt.run, .{a}) catch {
            // No unit of concurrency available: run inline, unbounded.
            return a.run();
        };
        // `concurrent`, not `async`: with no async slot left (few CPU
        // cores) `async` runs the sleep inline and blocks for the whole
        // deadline. Without a thread for it, wait for the attempt alone.
        sel.concurrent(.deadline, sleepMs, .{ c.io, c.opts.timeout_ms }) catch {};
        const first = sel.await() catch |err| {
            sel.cancelDiscard();
            return err;
        };
        switch (first) {
            .done => |r| {
                sel.cancelDiscard();
                return r;
            },
            .deadline => {
                // Cancel the attempt; it may still have finished meanwhile.
                var late: ?(Error!Response) = null;
                while (sel.cancel()) |o| switch (o) {
                    .done => |r| late = r,
                    .deadline => {},
                };
                if (late) |r| {
                    if (r) |ok| return ok else |_| {}
                }
                const ms = c.opts.timeout_ms;
                a.message = (if (ms % 1000 == 0)
                    std.fmt.allocPrint(a.arena, "no response within {d} s ({s})", .{ ms / 1000, a.phase.load(.acquire).describe() })
                else
                    std.fmt.allocPrint(a.arena, "no response within {d} ms ({s})", .{ ms, a.phase.load(.acquire).describe() })) catch "deadline exceeded";
                return error.Timeout;
            },
        }
    }
};

fn sleepMs(io: Io, ms: u64) Io.Cancelable!void {
    return io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
}

const Phase = enum(u8) {
    connecting,
    sending,
    waiting,
    receiving,

    fn describe(p: Phase) []const u8 {
        return switch (p) {
            .connecting => "while connecting",
            .sending => "while sending",
            .waiting => "waiting for the response",
            .receiving => "while reading the response",
        };
    }
};

const Attempt = struct {
    client: *Client,
    arena: Allocator,
    req: Request,
    phase: std.atomic.Value(Phase) = .init(.connecting),
    message: []const u8 = "",

    fn fail(a: *Attempt, err: Error, comptime fmt: []const u8, args: anytype) Error {
        a.message = std.fmt.allocPrint(a.arena, fmt, args) catch "request failed";
        return err;
    }

    fn run(a: *Attempt) Error!Response {
        const c = a.client;
        const uri = std.Uri.parse(a.req.url) catch return a.fail(error.Protocol, "invalid URL {s}", .{a.req.url});
        const host = hostOf(a.arena, uri);
        const method: std.http.Method = switch (a.req.method) {
            inline else => |m| @field(std.http.Method, @tagName(m)),
        };
        // The stdlib asserts on a body for GET/DELETE; refuse instead.
        if (a.req.body != null and !method.requestHasBody()) {
            return a.fail(error.Protocol, "internal: {t} request with a body", .{a.req.method});
        }
        var req = c.inner.request(method, uri, .{
            .keep_alive = false,
            .redirect_behavior = .unhandled,
            .headers = .{
                .user_agent = .{ .override = c.opts.user_agent },
                .accept_encoding = .{ .override = "identity" },
                .authorization = if (a.req.authorization) |v| .{ .override = v } else .omit,
                .content_type = if (a.req.body != null) .{ .override = a.req.content_type } else .default,
            },
            .extra_headers = a.req.headers,
        }) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            error.OutOfMemory => error.OutOfMemory,
            error.TlsInitializationFailed => a.fail(error.Tls, "TLS handshake with {s} failed (certificate not trusted by the configured CA bundle, or wrong hostname)", .{host}),
            else => a.fail(error.Network, "cannot connect to {s} ({s})", .{ host, @errorName(err) }),
        };
        defer req.deinit();

        a.phase.store(.sending, .release);
        if (a.req.body) |body| {
            req.transfer_encoding = .{ .content_length = body.len };
            const copy = a.arena.dupe(u8, body) catch return error.OutOfMemory;
            req.sendBodyComplete(copy) catch |err| return a.sendFailed(err, host);
        } else {
            req.sendBodiless() catch |err| return a.sendFailed(err, host);
        }
        a.phase.store(.waiting, .release);

        var redirect_buf: [0]u8 = .{};
        var response = req.receiveHead(&redirect_buf) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            else => a.fail(error.Network, "no response from {s} ({s})", .{ host, @errorName(err) }),
        };
        a.phase.store(.receiving, .release);
        const status: u16 = @backingInt(response.head.status);
        if (status >= 300 and status < 400) {
            return a.fail(error.Protocol, "{s} answered with a redirect ({d}); redirects are refused", .{ host, status });
        }
        // The head buffer is reused while the body streams: copy first.
        const reason = a.arena.dupe(u8, response.head.reason) catch return error.OutOfMemory;
        var transfer_buf: [64]u8 = undefined;
        const body_reader = response.reader(&transfer_buf);
        const body = body_reader.allocRemaining(a.arena, .limited(c.opts.max_body)) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.StreamTooLong => a.fail(error.Protocol, "response from {s} exceeds {d} bytes", .{ host, c.opts.max_body }),
            error.ReadFailed => if (response.request.reader.body_err) |e| switch (e) {
                else => a.fail(error.Network, "reading the response from {s} failed ({s})", .{ host, @errorName(e) }),
            } else a.fail(error.Network, "reading the response from {s} failed", .{host}),
        };
        return .{ .status = status, .body = body, .reason = reason };
    }

    fn sendFailed(a: *Attempt, err: anyerror, host: []const u8) Error {
        if (err == error.Canceled) return error.Canceled;
        return a.fail(error.Network, "sending to {s} failed ({s})", .{ host, @errorName(err) });
    }
};

fn hostOf(arena: Allocator, uri: std.Uri) []const u8 {
    const h = uri.host orelse return "?";
    const name = switch (h) {
        .raw, .percent_encoded => |s| s,
    };
    return if (uri.port) |p| std.fmt.allocPrint(arena, "{s}:{d}", .{ name, p }) catch name else name;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

/// In-process HTTP/1.1 server on 127.0.0.1 with one scripted behavior per
/// connection; it always closes the connection after each exchange (like
/// pveproxy's idle close), so any client-side reuse would fail.
pub const FakeServer = struct {
    io: Io,
    server: Io.net.Server,
    port: u16,
    script: []const Behavior,
    /// Route mode: each connection is answered by the first unused route
    /// whose `match` occurs in its request line, so concurrent clients may
    /// arrive in any order.
    routes: []const Route = &.{},
    used: [64]bool = @splat(false),
    accepted: std.atomic.Value(usize) = .init(0),
    /// Requests fully read (method line + body), per connection.
    received: [64]?[]const u8 = @splat(null),
    arena: std.heap.ArenaAllocator,
    future: ?Io.Future(void) = null,

    pub const Behavior = union(enum) {
        respond: struct { status: u16 = 200, body: []const u8 = "{}", delay_ms: u64 = 0, extra: []const u8 = "", reason: []const u8 = "X" },
        /// Read the request, then close without answering.
        drop_after_request,
        /// Close as soon as the connection is accepted.
        drop_immediately,
    };

    pub const Route = struct { match: []const u8, behavior: Behavior };

    pub fn startRoutes(s: *FakeServer, io: Io, routes: []const Route) !void {
        try s.start(io, &.{});
        s.routes = routes;
        if (s.future) |*f| _ = f.cancel(io);
        s.future = try io.concurrent(serveRoutes, .{s});
    }

    pub fn start(s: *FakeServer, io: Io, script: []const Behavior) !void {
        const addr: Io.net.IpAddress = try .parse("127.0.0.1", 0);
        s.* = .{
            .io = io,
            .server = try addr.listen(io, .{ .reuse_address = true }),
            .port = 0,
            .script = script,
            .arena = .init(testing.allocator),
        };
        s.port = s.server.socket.address.getPort();
        s.future = try io.concurrent(serve, .{s});
    }

    pub fn stop(s: *FakeServer) void {
        if (s.future) |*f| f.cancel(s.io);
        s.server.deinit(s.io);
        s.arena.deinit();
    }

    pub fn url(s: *FakeServer, arena: Allocator, path: []const u8) ![]const u8 {
        return std.fmt.allocPrint(arena, "http://127.0.0.1:{d}{s}", .{ s.port, path });
    }

    fn serve(s: *FakeServer) void {
        for (s.script, 0..) |b, i| {
            const stream = s.server.accept(s.io) catch return;
            _ = s.accepted.fetchAdd(1, .release);
            defer stream.close(s.io);
            if (b == .drop_immediately) continue;
            var rbuf: [8192]u8 = undefined;
            var r = stream.reader(s.io, &rbuf);
            const req = readRequest(s.arena.allocator(), &r.interface) catch continue;
            if (i < s.received.len) s.received[i] = req;
            switch (b) {
                .respond => |resp| {
                    if (resp.delay_ms > 0) s.io.sleep(.fromMilliseconds(@intCast(resp.delay_ms)), .awake) catch return;
                    var wbuf: [1024]u8 = undefined;
                    var w = stream.writer(s.io, &wbuf);
                    w.interface.print("HTTP/1.1 {d} {s}\r\ncontent-length: {d}\r\ncontent-type: application/json\r\n{s}\r\n{s}", .{ resp.status, resp.reason, resp.body.len, resp.extra, resp.body }) catch continue;
                    w.interface.flush() catch continue;
                },
                else => {},
            }
        }
    }

    fn serveRoutes(s: *FakeServer) void {
        for (0..s.routes.len) |i| {
            const stream = s.server.accept(s.io) catch return;
            _ = s.accepted.fetchAdd(1, .release);
            defer stream.close(s.io);
            var rbuf: [8192]u8 = undefined;
            var r = stream.reader(s.io, &rbuf);
            const req = readRequest(s.arena.allocator(), &r.interface) catch continue;
            if (i < s.received.len) s.received[i] = req;
            const line = req[0 .. std.mem.findScalar(u8, req, '\r') orelse req.len];
            const b: Behavior = for (s.routes, 0..) |rt, j| {
                if (j < s.used.len and !s.used[j] and std.mem.find(u8, line, rt.match) != null) {
                    s.used[j] = true;
                    break rt.behavior;
                }
            } else .{ .respond = .{ .status = 599, .body = "{\"unmatched\":true}", .reason = "Unmatched" } };
            switch (b) {
                .respond => |resp| {
                    if (resp.delay_ms > 0) s.io.sleep(.fromMilliseconds(@intCast(resp.delay_ms)), .awake) catch return;
                    var wbuf: [1024]u8 = undefined;
                    var w = stream.writer(s.io, &wbuf);
                    w.interface.print("HTTP/1.1 {d} {s}\r\ncontent-length: {d}\r\ncontent-type: application/json\r\n{s}\r\n{s}", .{ resp.status, resp.reason, resp.body.len, resp.extra, resp.body }) catch continue;
                    w.interface.flush() catch continue;
                },
                else => {},
            }
        }
    }

    /// Routes not answered yet (route mode).
    pub fn unused(s: *const FakeServer) usize {
        var n: usize = 0;
        for (s.routes, 0..) |_, j| n += @intFromBool(j >= s.used.len or !s.used[j]);
        return n;
    }

    fn readRequest(arena: Allocator, r: *Io.Reader) ![]const u8 {
        var head: std.ArrayList(u8) = .empty;
        var len: usize = 0;
        while (true) {
            const line = try r.takeDelimiterInclusive('\n');
            try head.appendSlice(arena, line);
            if (std.ascii.startsWithIgnoreCase(line, "content-length:")) {
                len = try std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " \r\n"), 10);
            }
            if (std.mem.eql(u8, line, "\r\n")) break;
        }
        try head.appendSlice(arena, try r.take(len));
        return head.items;
    }
};

fn testClient(c: *Client, timeout_ms: u64) !void {
    try c.init(testing.allocator, testing.io, .{ .ca_bundle = null, .timeout_ms = timeout_ms, .backoff_ms = 10 });
}

test "GET: success, headers sent, fresh connection per request" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var srv: FakeServer = undefined;
    try srv.start(testing.io, &.{ .{ .respond = .{ .body = "{\"a\":1}" } }, .{ .respond = .{ .body = "{\"b\":2}" } } });
    defer srv.stop();
    var c: Client = undefined;
    try testClient(&c, 2000);
    defer c.deinit();
    var d: Diag = .{};
    const r1 = try c.send(ar, .{ .url = try srv.url(ar, "/v1/info"), .headers = &.{.{ .name = "X-API-KEY", .value = "k" }} }, &d);
    try testing.expectEqual(@as(u16, 200), r1.status);
    try testing.expectEqualStrings("{\"a\":1}", r1.body);
    // The server closed the first connection; a reused socket would fail.
    const r2 = try c.send(ar, .{ .url = try srv.url(ar, "/v1/sites") }, &d);
    try testing.expectEqualStrings("{\"b\":2}", r2.body);
    try testing.expectEqual(@as(usize, 2), srv.accepted.load(.acquire));
    const req = srv.received[0].?;
    try testing.expect(std.mem.startsWith(u8, req, "GET /v1/info HTTP/1.1\r\n"));
    try testing.expect(std.ascii.findIgnoreCase(req, "x-api-key: k\r\n") != null);
    try testing.expect(std.ascii.findIgnoreCase(req, "accept-encoding: identity\r\n") != null);
    try testing.expect(std.ascii.findIgnoreCase(req, "connection: close\r\n") != null);
}

test "GET: retries 5xx and dropped connections, then succeeds" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var srv: FakeServer = undefined;
    try srv.start(testing.io, &.{ .{ .respond = .{ .status = 503 } }, .drop_immediately, .{ .respond = .{ .body = "ok" } } });
    defer srv.stop();
    var c: Client = undefined;
    try testClient(&c, 2000);
    defer c.deinit();
    var d: Diag = .{};
    const r = try c.send(ar, .{ .url = try srv.url(ar, "/") }, &d);
    try testing.expectEqualStrings("ok", r.body);
    try testing.expectEqual(@as(u8, 3), d.attempts);
}

test "GET: no async slot left (few CPU cores) still answers at once" {
    // On a small machine the runtime's async slots run out and `async`
    // runs inline; the deadline must not block the request (a CI hang).
    var threaded: Io.Threaded = .init(testing.allocator, .{ .async_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var srv: FakeServer = undefined;
    try srv.start(io, &.{.{ .respond = .{ .body = "ok" } }});
    defer srv.stop();
    var c: Client = undefined;
    try c.init(testing.allocator, io, .{ .ca_bundle = null, .timeout_ms = 5000, .retries = 0 });
    defer c.deinit();
    var d: Diag = .{};
    const t0 = Io.Clock.awake.now(io);
    const r = try c.send(ar, .{ .url = try srv.url(ar, "/") }, &d);
    try testing.expectEqualStrings("ok", r.body);
    const ms = @divTrunc(t0.durationTo(Io.Clock.awake.now(io)).nanoseconds, std.time.ns_per_ms);
    try testing.expect(ms < 1000);
}

test "GET: deadline cancels a hung request" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var srv: FakeServer = undefined;
    try srv.start(testing.io, &.{.{ .respond = .{ .delay_ms = 3000 } }});
    defer srv.stop();
    var c: Client = undefined;
    try c.init(testing.allocator, testing.io, .{ .ca_bundle = null, .timeout_ms = 200, .retries = 0 });
    defer c.deinit();
    var d: Diag = .{};
    const t0 = Io.Clock.awake.now(testing.io);
    try testing.expectError(error.Timeout, c.send(ar, .{ .url = try srv.url(ar, "/") }, &d));
    const ms = @divTrunc(t0.durationTo(Io.Clock.awake.now(testing.io)).nanoseconds, std.time.ns_per_ms);
    try testing.expect(ms < 2000);
    try testing.expectEqualStrings("no response within 200 ms (waiting for the response)", d.message);
}

test "GET: redirect refused, oversized body refused" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var srv: FakeServer = undefined;
    try srv.start(testing.io, &.{ .{ .respond = .{ .status = 302, .extra = "location: http://evil/\r\n" } }, .{ .respond = .{ .body = "0123456789abcdef" } } });
    defer srv.stop();
    var c: Client = undefined;
    try c.init(testing.allocator, testing.io, .{ .ca_bundle = null, .timeout_ms = 2000, .max_body = 8 });
    defer c.deinit();
    var d: Diag = .{};
    try testing.expectError(error.Protocol, c.send(ar, .{ .url = try srv.url(ar, "/") }, &d));
    try testing.expect(std.mem.find(u8, d.message, "redirects are refused") != null);
    try testing.expectError(error.Protocol, c.send(ar, .{ .url = try srv.url(ar, "/") }, &d));
    try testing.expect(std.mem.find(u8, d.message, "exceeds 8 bytes") != null);
}

test "writes: sent once; lost response or deadline after sending is unknown" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var srv: FakeServer = undefined;
    try srv.start(testing.io, &.{
        .{ .respond = .{ .status = 201, .body = "{\"id\":\"x\"}" } },
        .drop_after_request,
        .{ .respond = .{ .status = 500 } },
        .{ .respond = .{ .delay_ms = 3000 } },
    });
    defer srv.stop();
    var c: Client = undefined;
    try c.init(testing.allocator, testing.io, .{ .ca_bundle = null, .timeout_ms = 300 });
    defer c.deinit();
    var d: Diag = .{};
    const body = "{\"domain\":\"web-01.home.arpa\"}";
    const ok = try c.send(ar, .{ .method = .POST, .url = try srv.url(ar, "/v1/x"), .body = body }, &d);
    try testing.expectEqual(@as(u16, 201), ok.status);
    try testing.expect(std.mem.endsWith(u8, srv.received[0].?, "\r\n\r\n" ++ body));

    try testing.expectError(error.OutcomeUnknown, c.send(ar, .{ .method = .POST, .url = try srv.url(ar, "/v1/x"), .body = body }, &d));
    try testing.expectEqual(@as(u8, 1), d.attempts);
    // A 5xx answer is an answer: returned, not retried.
    const r500 = try c.send(ar, .{ .method = .PUT, .url = try srv.url(ar, "/v1/x"), .body = "{}" }, &d);
    try testing.expectEqual(@as(u16, 500), r500.status);
    try testing.expectError(error.OutcomeUnknown, c.send(ar, .{ .method = .DELETE, .url = try srv.url(ar, "/v1/x") }, &d));
    try testing.expect(std.mem.find(u8, d.message, "was sent but its result was not received") != null);
    try testing.expectEqual(@as(usize, 4), srv.accepted.load(.acquire));
}

test "writes: connection refused means nothing was sent" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    // Grab a free port, then close it so connecting is refused.
    const addr: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    var srv = try addr.listen(testing.io, .{});
    const port = srv.socket.address.getPort();
    srv.deinit(testing.io);
    var c: Client = undefined;
    try testClient(&c, 2000);
    defer c.deinit();
    var d: Diag = .{};
    const u = try std.fmt.allocPrint(ar, "http://127.0.0.1:{d}/", .{port});
    try testing.expectError(error.Network, c.send(ar, .{ .method = .POST, .url = u, .body = "{}" }, &d));
    try testing.expect(std.mem.startsWith(u8, d.message, "cannot connect to 127.0.0.1:"));
}

test "TLS: unreadable CA bundle is reported" {
    var c: Client = undefined;
    try testing.expectError(error.CaUnreadable, c.init(testing.allocator, testing.io, .{ .ca_bundle = "/nonexistent/rootCA.pem", .timeout_ms = 1000 }));
}
