//! Test harness: runs a command line through `dispatch.run` with captured
//! stdout/stderr and a private environment.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const cli = @import("cli.zig");
const dispatch = @import("dispatch.zig");
const prompt = @import("prompt.zig");
const secrets = @import("secrets.zig");

pub const Exit = dispatch.Exit;

var no_input: prompt.Script = .{ .interactive = false };

pub const Harness = struct {
    arena: std.heap.ArenaAllocator,
    env: std.process.Environ.Map,
    out: Io.Writer.Allocating,
    err: Io.Writer.Allocating,
    devnull: Io.File,
    input: prompt.Input = .{ .script = &no_input },
    store: ?secrets.Store = null,
    hooks: @import("app.zig").Context.TestHooks = .{},

    pub fn init() !Harness {
        return .{
            .arena = .init(testing.allocator),
            .env = .init(testing.allocator),
            .out = .init(testing.allocator),
            .err = .init(testing.allocator),
            .devnull = try Io.Dir.cwd().openFile(testing.io, "/dev/null", .{ .mode = .write_only }),
        };
    }

    pub fn deinit(h: *Harness) void {
        h.devnull.close(testing.io);
        h.out.deinit();
        h.err.deinit();
        h.env.deinit();
        h.arena.deinit();
    }

    /// Run space-separated words (no quoting).
    pub fn run(h: *Harness, root: *const cli.Command, line: []const u8) Exit {
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        while (it.next()) |w| list.append(h.arena.allocator(), w) catch return .internal;
        return h.runArgs(root, list.items);
    }

    pub fn runArgs(h: *Harness, root: *const cli.Command, args: []const []const u8) Exit {
        h.out.clearRetainingCapacity();
        h.err.clearRetainingCapacity();
        return dispatch.run(.{
            .arena = h.arena.allocator(),
            .gpa = testing.allocator,
            .io = testing.io,
            .env = &h.env,
            .out = &h.out.writer,
            .err = &h.err.writer,
            .out_file = h.devnull,
            .err_file = h.devnull,
            .input = h.input,
            .store = h.store,
            .test_hooks = h.hooks,
        }, root, args);
    }

    pub fn stdout(h: *Harness) []const u8 {
        return h.out.written();
    }

    pub fn stderr(h: *Harness) []const u8 {
        return h.err.written();
    }
};

/// A harness wired to an in-process fake server standing in for UniFi
/// and Proxmox: `HOME` in a temp dir (config defaults), a memory secret
/// store holding both API secrets, no TTY, both clients pointed at the
/// scripted server, fast task polling.
pub const Gateway = struct {
    h: Harness,
    srv: FakeServer,
    tmp: testing.TmpDir,
    mem: secrets.Memory,
    script: prompt.Script = .{ .interactive = false },

    pub const FakeServer = @import("http.zig").FakeServer;

    pub fn init(g: *Gateway, behaviors: []const FakeServer.Behavior) !void {
        g.h = try Harness.init();
        g.tmp = testing.tmpDir(.{});
        g.script = .{ .interactive = false };
        const ar = g.h.arena.allocator();
        try g.h.env.put("HOME", try g.tmp.dir.realPathFileAlloc(testing.io, ".", ar));
        g.mem = .{ .gpa = ar };
        try g.mem.map.put(ar, "unifi", "test-key");
        try g.mem.map.put(ar, "pve", "test-secret");
        try g.mem.map.put(ar, "cloudflare", "test-token");
        g.h.store = .{ .memory = &g.mem };
        g.h.input = .{ .script = &g.script };
        try g.srv.start(testing.io, behaviors);
        g.h.hooks.unifi_base = try g.srv.url(ar, "");
        g.h.hooks.pve_base = g.h.hooks.unifi_base;
        g.h.hooks.cloudflare_base = g.h.hooks.unifi_base;
        g.h.hooks.poll_ms = 5;
    }

    /// Like `init`, but requests are matched by route, in any order.
    pub fn initRoutes(g: *Gateway, routes: []const FakeServer.Route) !void {
        try g.init(&.{});
        g.srv.stop();
        try g.srv.startRoutes(testing.io, routes);
        const ar = g.h.arena.allocator();
        g.h.hooks.unifi_base = try g.srv.url(ar, "");
        g.h.hooks.pve_base = g.h.hooks.unifi_base;
        g.h.hooks.cloudflare_base = g.h.hooks.unifi_base;
    }

    pub fn deinit(g: *Gateway) void {
        g.srv.stop();
        g.tmp.cleanup();
        g.h.deinit();
    }

    /// Request line of the i-th connection.
    pub fn request(g: *Gateway, i: usize) []const u8 {
        const req = g.srv.received[i] orelse return "";
        return req[0 .. std.mem.findScalar(u8, req, '\r') orelse req.len];
    }

    /// Body of the i-th request.
    pub fn body(g: *Gateway, i: usize) []const u8 {
        const req = g.srv.received[i] orelse return "";
        return req[(std.mem.find(u8, req, "\r\n\r\n") orelse return "") + 4 ..];
    }

    /// Connections accepted so far.
    pub fn sent(g: *Gateway) usize {
        return g.srv.accepted.load(.acquire);
    }

    /// Write `data` into the temp dir; returns its absolute path.
    pub fn file(g: *Gateway, name: []const u8, data: []const u8) ![]const u8 {
        try g.tmp.dir.writeFile(testing.io, .{ .sub_path = name, .data = data });
        const dir = try g.tmp.dir.realPathFileAlloc(testing.io, ".", g.h.arena.allocator());
        return std.fmt.allocPrint(g.h.arena.allocator(), "{s}/{s}", .{ dir, name });
    }
};
