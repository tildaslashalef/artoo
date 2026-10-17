//! `artoo auth set|status|rm` (SPEC §6). Secrets are read from a hidden
//! prompt or `--stdin` and never echoed.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const prompt = @import("../prompt.zig");
const secrets = @import("../secrets.zig");
const ui = @import("../ui.zig");

const Context = app.Context;

const Kind = enum {
    pve,
    unifi,
    cloudflare,

    fn label(k: Kind) []const u8 {
        return switch (k) {
            .pve => "Proxmox API token secret (artoo@pve!cli)",
            .unifi => "UniFi API key",
            .cloudflare => "Cloudflare API token (DNS records, tunnels)",
        };
    }
};

const kinds = std.meta.tags(Kind);

fn kindArg(ctx: *Context, word: []const u8) !Kind {
    return std.meta.stringToEnum(Kind, word) orelse ctx.fail(error.Usage, "unknown secret '{s}' (expected pve, unifi or cloudflare)", .{word});
}

const secret_arg = [_]cli.Positional{.{ .name = "SECRET", .help = "pve, unifi or cloudflare" }};

pub const set = struct {
    pub const name = "set";
    pub const summary = "Store a secret (hidden prompt or --stdin)";
    pub const details = "Replacing an existing secret asks first. The value is never echoed.";
    pub const positionals = secret_arg;
    pub const flags = [_]cli.Flag{.{ .long = "stdin", .help = "Read the secret from standard input" }};
    pub const examples = [_][]const u8{
        "artoo auth set unifi",
        "ssh root@pve 'pveum user token add …' | artoo auth set pve --stdin --yes",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const kind = try kindArg(ctx, args.pos("SECRET"));
        const store = try ctx.secretStore();
        const where = store.describe(ctx.arena);
        const present = store.exists(ctx.io, ctx.arena, @tagName(kind)) catch |err| return storeError(ctx, err, where);

        const secret = if (args.has("stdin"))
            try prompt.readAll(ctx.input, ctx.io, ctx.arena, 4096)
        else blk: {
            if (!try prompt.interactive(ctx.input, ctx.io)) {
                return ctx.fail(error.NonInteractive, "not a terminal: pipe the secret with --stdin", .{});
            }
            break :blk try prompt.askHidden(ctx.input, ctx.io, ctx.arena, ctx.err, kind.label());
        };
        if (!secrets.validSecret(secret)) {
            return ctx.fail(error.Usage, "the secret must be one line of 1-4096 printable characters", .{});
        }
        if (present) try ctx.confirm("Replace the existing {s} secret in {s}?", .{ @tagName(kind), where });
        if (ctx.globals.dry_run) {
            try ctx.out.print("Dry run: would store {s} in {s}.\n", .{ @tagName(kind), where });
            return;
        }
        store.set(ctx.io, ctx.arena, @tagName(kind), secret) catch |err| return storeError(ctx, err, where);
        try ctx.out.print("Stored {s} in {s}.\n", .{ @tagName(kind), where });
    }
};

pub const status = struct {
    pub const name = "status";
    pub const summary = "Show the secret store and which secrets are present";
    pub const details = "Checks presence only; secrets are not read.";
    pub const examples = [_][]const u8{"artoo auth status"};

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        const store = try ctx.secretStore();
        const where = store.describe(ctx.arena);
        var present: [kinds.len]bool = undefined;
        for (kinds, 0..) |k, i| {
            present[i] = store.exists(ctx.io, ctx.arena, @tagName(k)) catch |err| return storeError(ctx, err, where);
        }
        if (ctx.json()) {
            return ui.json.envelope(ctx.out, .local, .{
                .store = store.kind(),
                .location = where,
                .secrets = .{ .pve = present[0], .unifi = present[1], .cloudflare = present[2] },
            }, .{});
        }
        const u = &ctx.ui;
        try ui.blocks.header(ctx.out, u, "auth", where);
        var rows: [kinds.len][]const ui.table.Cell = undefined;
        for (kinds, 0..) |k, i| {
            const st: ui.style.Status = if (present[i]) .ok else .failed;
            const cells = try ctx.arena.alloc(ui.table.Cell, 3);
            cells[0] = .{ .text = @tagName(k), .role = .id };
            cells[1] = .{ .text = k.label() };
            cells[2] = .{
                .text = try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ st.glyph(u.glyphs), if (present[i]) "stored" else "missing" }),
                .role = st.role(),
            };
            rows[i] = cells;
        }
        try ui.table.render(ctx.out, u, ctx.arena, &.{
            .{ .title = "SECRET", .truncate = false },
            .{ .title = "PURPOSE", .drop = 1 },
            .{ .title = "STATUS" },
        }, &rows);
        if (std.mem.findScalar(bool, &present, false) != null) {
            try ctx.out.print("\n{s}Add a missing secret with 'artoo auth set pve|unifi|cloudflare'.{s}\n", .{ u.palette.on(.muted), u.palette.off(.muted) });
        }
    }
};

pub const rm = struct {
    pub const name = "rm";
    pub const summary = "Delete a stored secret (asks first)";
    pub const positionals = secret_arg;
    pub const examples = [_][]const u8{"artoo auth rm pve"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const kind = try kindArg(ctx, args.pos("SECRET"));
        const store = try ctx.secretStore();
        const where = store.describe(ctx.arena);
        const present = store.exists(ctx.io, ctx.arena, @tagName(kind)) catch |err| return storeError(ctx, err, where);
        if (!present) return ctx.fail(error.NoChange, "{s} is not stored in {s}; nothing to remove", .{ @tagName(kind), where });
        try ctx.confirm("Delete the {s} secret from {s}?", .{ @tagName(kind), where });
        if (ctx.globals.dry_run) {
            try ctx.out.print("Dry run: would delete {s} from {s}.\n", .{ @tagName(kind), where });
            return;
        }
        _ = store.delete(ctx.io, ctx.arena, @tagName(kind)) catch |err| return storeError(ctx, err, where);
        try ctx.out.print("Deleted {s} from {s}.\n", .{ @tagName(kind), where });
    }
};

fn storeError(ctx: *Context, err: anyerror, where: []const u8) anyerror {
    return switch (err) {
        error.UnsafePath => ctx.fail(error.UnsafePath, "refusing {s}: it must be a regular file owned by you with mode 0600 (not a symlink)", .{where}),
        error.SecretStoreUnavailable => ctx.fail(error.SecretStoreUnavailable, "{s} did not answer as expected", .{where}),
        else => err,
    };
}

pub const group = cli.group("auth", "Credentials for Proxmox and UniFi", &.{
    cli.leaf(set),
    cli.leaf(status),
    cli.leaf(rm),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Harness = @import("../testkit.zig").Harness;
const root = cli.group("artoo", "test", &.{group});

test "auth: set via prompt and --stdin, status, rm with confirmations" {
    var h = try Harness.init();
    defer h.deinit();
    var mem: secrets.Memory = .{ .gpa = h.arena.allocator() };
    var script: prompt.Script = .{};
    h.store = .{ .memory = &mem };
    h.input = .{ .script = &script };

    script.lines = &.{"key-123"};
    try testing.expectEqual(.ok, h.run(&root, "auth set unifi"));
    try testing.expectEqualStrings("Stored unifi in memory (test).\n", h.stdout());
    try testing.expectEqualStrings("UniFi API key (input hidden): \n", h.stderr());
    try testing.expectEqualStrings("key-123", mem.map.get("unifi").?);

    // Replacing asks; "n" declines (exit 5) and keeps the old value.
    script = .{ .lines = &.{ "key-456", "n" } };
    try testing.expectEqual(.refused, h.run(&root, "auth set unifi"));
    try testing.expectEqualStrings("key-123", mem.map.get("unifi").?);

    // Non-interactive replace needs --yes.
    script = .{ .interactive = false, .piped = "key-789\n" };
    try testing.expectEqual(.refused, h.run(&root, "auth set unifi --stdin"));
    try testing.expectEqual(.ok, h.run(&root, "auth set unifi --stdin -y"));
    try testing.expectEqualStrings("key-789", mem.map.get("unifi").?);
    // No TTY and no --stdin.
    try testing.expectEqual(.refused, h.run(&root, "auth set pve"));
    // Control characters are rejected.
    script = .{ .interactive = false, .piped = "a\x1bb" };
    try testing.expectEqual(.usage, h.run(&root, "auth set pve --stdin"));
    try testing.expectEqual(.usage, h.run(&root, "auth set guest"));

    try testing.expectEqual(.ok, h.run(&root, "auth status"));
    try testing.expectEqualStrings(
        \\ARTOO · auth  memory (test)
        \\
        \\SECRET      PURPOSE                                      STATUS
        \\pve         Proxmox API token secret (artoo@pve!cli)     ✗ missing
        \\unifi       UniFi API key                                ✓ stored
        \\cloudflare  Cloudflare API token (DNS records, tunnels)  ✗ missing
        \\
        \\Add a missing secret with 'artoo auth set pve|unifi|cloudflare'.
        \\
    , h.stdout());
    try testing.expectEqual(.ok, h.run(&root, "-o json auth status"));
    try testing.expect(std.mem.find(u8, h.stdout(), "\"unifi\": true") != null);

    try testing.expectEqual(.refused, h.run(&root, "auth rm pve"));
    try testing.expect(std.mem.find(u8, h.stderr(), "nothing to remove") != null);
    script = .{ .lines = &.{"y"} };
    try testing.expectEqual(.ok, h.run(&root, "auth rm unifi"));
    try testing.expect(!mem.map.contains("unifi"));
    // The secret never appears in any output.
    try testing.expect(std.mem.find(u8, h.stdout(), "key-") == null);
}
