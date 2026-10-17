//! `artoo config show|get|set|unset|edit|init` (SPEC §5).

const std = @import("std");
const Io = std.Io;
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const files = @import("../files.zig");
const ui = @import("../ui.zig");

const Context = app.Context;

fn loaded(ctx: *Context) !*config.Loaded {
    return switch (ctx.loaded) {
        .ok => |*l| l,
        .failed => |f| ctx.fail(f.err, "{s}", .{f.message}),
    };
}

fn usageKey(ctx: *Context, name: []const u8) anyerror {
    return ctx.fail(error.Usage, "{s}", .{config.unknownKeyMessage(ctx.arena, name) catch "unknown config key"});
}

const section_titles = [_]struct { []const u8, []const u8 }{
    .{ "output", "Output" },
    .{ "credentials", "Credentials" },
    .{ "pve", "Proxmox (pve)" },
    .{ "unifi", "UniFi (unifi)" },
    .{ "guests", "Guests" },
};

pub const show = struct {
    pub const name = "show";
    pub const summary = "Show the effective configuration";
    pub const details = "Keys not set in the file show their default, marked (default).";
    pub const examples = [_][]const u8{ "artoo config show", "artoo config show -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        const l = try loaded(ctx);
        if (ctx.json()) {
            var defaults: std.ArrayList([]const u8) = .empty;
            for (config.keys) |k| {
                if (!l.explicit(k.name)) try defaults.append(ctx.arena, k.name);
            }
            return ui.json.envelope(ctx.out, .local, l.config, .{
                .path = l.path,
                .exists = l.exists,
                .defaults = defaults.items,
            });
        }
        const u = &ctx.ui;
        try ui.blocks.header(ctx.out, u, "config", ctx.tilde(l.path));
        if (!l.exists) {
            try ctx.out.print("{s}No config file; showing defaults. Create one with 'artoo config init'.{s}\n\n", .{ u.palette.on(.muted), u.palette.off(.muted) });
        }
        var sections: std.ArrayList(ui.blocks.Section) = .empty;
        for (section_titles) |st| {
            var fields: std.ArrayList(ui.blocks.Field) = .empty;
            for (config.keys) |k| {
                if (!std.mem.startsWith(u8, k.name, st[0]) or k.name[st[0].len] != '.') continue;
                const raw = (try config.get(&l.config, ctx.arena, k.name)).?;
                const value = if (raw.len == 0) "--" else try ui.text.sanitize(ctx.arena, raw, .line);
                const explicit = l.explicit(k.name);
                try fields.append(ctx.arena, .{
                    .key = k.name[st[0].len + 1 ..],
                    .value = if (explicit) value else try std.fmt.allocPrint(ctx.arena, "{s}  (default)", .{value}),
                    .role = if (explicit) .text else .muted,
                });
            }
            try sections.append(ctx.arena, .{ .title = st[1], .fields = fields.items });
        }
        try ui.blocks.detail(ctx.out, u, sections.items);
    }
};

pub const get = struct {
    pub const name = "get";
    pub const summary = "Print one value";
    pub const positionals = [_]cli.Positional{.{ .name = "KEY", .help = "Dotted key, e.g. unifi.endpoint" }};
    pub const examples = [_][]const u8{"artoo config get unifi.endpoint"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const l = try loaded(ctx);
        const key = args.pos("KEY");
        const value = (try config.get(&l.config, ctx.arena, key)) orelse return usageKey(ctx, key);
        if (ctx.json()) {
            return ui.json.envelope(ctx.out, .local, .{ .key = key, .value = value, .default = !l.explicit(key) }, .{ .path = l.path });
        }
        try ctx.out.print("{s}\n", .{try ui.text.sanitize(ctx.arena, value, .line)});
    }
};

pub const set = struct {
    pub const name = "set";
    pub const summary = "Set one value (validated, written atomically)";
    pub const details = config.key_help;
    pub const positionals = [_]cli.Positional{
        .{ .name = "KEY", .help = "Dotted key (see 'artoo config show')" },
        .{ .name = "VALUE", .help = "New value" },
    };
    pub const examples = [_][]const u8{
        "artoo config set unifi.timeout_seconds 20",
        "artoo config set credentials.store file",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const l = try loaded(ctx);
        const key = args.pos("KEY");
        if (config.find(key) == null) return usageKey(ctx, key);
        const before = (try config.get(&l.config, ctx.arena, key)).?;
        var msg: []const u8 = "";
        const value = (try config.assign(&l.config, ctx.arena, key, .{ .string = args.pos("VALUE") }, &msg)) orelse
            return ctx.fail(error.Usage, "{s}", .{msg});
        const after = (try config.get(&l.config, ctx.arena, key)).?;
        if (l.explicit(key) and std.mem.eql(u8, before, after)) {
            try ctx.out.print("{s} is already {s}\n", .{ key, try ui.text.sanitize(ctx.arena, after, .line) });
            return;
        }
        const text = try config.edit(ctx.arena, &l.tree, key, value);
        try save(ctx, l.path, text);
        const p = ctx.ui.palette;
        try ctx.out.print("Set {s}: {s}{s}{s} {s} {s}{s}{s}\n", .{
            key,
            p.on(.muted),
            try ui.text.sanitize(ctx.arena, before, .line),
            p.off(.muted),
            ctx.ui.glyphs.arrow,
            p.on(.changed),
            try ui.text.sanitize(ctx.arena, after, .line),
            p.off(.changed),
        });
    }
};

pub const unset = struct {
    pub const name = "unset";
    pub const summary = "Remove a key from the file (its default applies)";
    pub const positionals = [_]cli.Positional{.{ .name = "KEY", .help = "Dotted key" }};
    pub const examples = [_][]const u8{"artoo config unset unifi.timeout_seconds"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const l = try loaded(ctx);
        const key = args.pos("KEY");
        if (config.find(key) == null) return usageKey(ctx, key);
        const default = (try config.get(&config.Config{}, ctx.arena, key)).?;
        if (!l.explicit(key)) {
            try ctx.out.print("{s} is not set in the file (default: {s})\n", .{ key, default });
            return;
        }
        const text = try config.edit(ctx.arena, &l.tree, key, null);
        try save(ctx, l.path, text);
        try ctx.out.print("Unset {s} (default applies: {s})\n", .{ key, default });
    }
};

pub const init = struct {
    pub const name = "init";
    pub const summary = "Write a fresh config with all defaults";
    pub const details = "Refuses to overwrite an existing file (there is no migration).";
    pub const examples = [_][]const u8{"artoo config init"};

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        const path = switch (ctx.loaded) {
            .ok => |l| l.path,
            .failed => try config.resolvePath(ctx.arena, ctx.env, ctx.globals.config),
        };
        if (try files.exists(ctx.io, path)) {
            return ctx.fail(error.ConfigExists, "{s} already exists; change it with 'artoo config set' or 'artoo config edit', or move it aside first", .{ctx.tilde(path)});
        }
        try save(ctx, path, try config.defaultFile(ctx.arena));
        try ctx.out.print("Wrote {s} with defaults.\nNext: 'artoo auth set unifi' and 'artoo doctor'.\n", .{ctx.tilde(path)});
    }
};

pub const edit = struct {
    pub const name = "edit";
    pub const summary = "Edit the file in $EDITOR, validated before saving";
    pub const details =
        \\Opens a private copy in $VISUAL or $EDITOR (default vi). The file is
        \\replaced only if the edited copy is a valid config; otherwise the
        \\copy is kept and its path is printed.
    ;
    pub const examples = [_][]const u8{"EDITOR=vim artoo config edit"};

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        const l = try loaded(ctx);
        const original = if (l.exists)
            try Io.Dir.cwd().readFileAlloc(ctx.io, l.path, ctx.arena, .limited(1 << 20))
        else
            try config.defaultFile(ctx.arena);

        const dir = std.fs.path.dirname(l.path) orelse ".";
        try files.ensurePrivateDir(ctx.io, dir);
        var rnd: [6]u8 = undefined;
        ctx.io.random(&rnd);
        const draft = try std.fmt.allocPrint(ctx.arena, "{s}/.config.edit-{x}.json", .{ dir, rnd });
        try files.atomicWrite(ctx.io, ctx.arena, draft, original);

        const editor = ctx.env.get("VISUAL") orelse ctx.env.get("EDITOR") orelse "vi";
        var argv: std.ArrayList([]const u8) = .empty;
        var words = std.mem.tokenizeScalar(u8, editor, ' ');
        while (words.next()) |w| try argv.append(ctx.arena, w);
        try argv.append(ctx.arena, draft);
        var child = std.process.spawn(ctx.io, .{ .argv = argv.items }) catch |err|
            return ctx.fail(error.Usage, "cannot start editor '{s}' ({s}); your copy is {s}", .{ editor, @errorName(err), draft });
        const term = child.wait(ctx.io) catch |err|
            return ctx.fail(error.Usage, "editor failed ({s}); your copy is {s}", .{ @errorName(err), draft });
        if (!term.success()) {
            return ctx.fail(error.Usage, "editor exited unsuccessfully; nothing saved, your copy is {s}", .{draft});
        }

        const edited = try Io.Dir.cwd().readFileAlloc(ctx.io, draft, ctx.arena, .limited(1 << 20));
        if (std.mem.eql(u8, edited, original)) {
            Io.Dir.cwd().deleteFile(ctx.io, draft) catch {};
            try ctx.out.writeAll("No changes.\n");
            return;
        }
        var msg: []const u8 = "";
        _ = config.parse(ctx.arena, edited, &msg) catch |err| switch (err) {
            error.ConfigInvalid => return ctx.fail(error.ConfigInvalid, "{s}; nothing saved, your edits are in {s}", .{ msg, draft }),
            else => |e| return e,
        };
        try save(ctx, l.path, edited);
        Io.Dir.cwd().deleteFile(ctx.io, draft) catch {};
        try ctx.out.print("Saved {s}.\n", .{ctx.tilde(l.path)});
    }
};

/// Atomic, locked save into a private directory; symlinks refused.
fn save(ctx: *Context, path: []const u8, text: []const u8) !void {
    const dir = std.fs.path.dirname(path) orelse ".";
    files.ensurePrivateDir(ctx.io, dir) catch |err| switch (err) {
        error.UnsafePath => return ctx.fail(error.UnsafePath, "{s} is not a directory", .{ctx.tilde(dir)}),
        else => |e| return ctx.fail(e, "cannot create {s}", .{ctx.tilde(dir)}),
    };
    files.atomicWrite(ctx.io, ctx.arena, path, text) catch |err| switch (err) {
        error.UnsafePath => return ctx.fail(error.UnsafePath, "refusing to write {s}: it is a symlink", .{ctx.tilde(path)}),
        else => |e| return ctx.fail(e, "cannot write {s} ({s})", .{ ctx.tilde(path), @errorName(e) }),
    };
}

pub const group = cli.group("config", "Local configuration (~/.artoo/config.json)", &.{
    cli.leaf(show),
    cli.leaf(get),
    cli.leaf(set),
    cli.leaf(unset),
    cli.leaf(edit),
    cli.leaf(init),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Harness = @import("../testkit.zig").Harness;
const root = cli.group("artoo", "test", &.{group});

fn setup(h: *Harness, tmp: *testing.TmpDir) ![]const u8 {
    const ar = h.arena.allocator();
    const dir = try tmp.dir.realPathFileAlloc(testing.io, ".", ar);
    try h.env.put("HOME", dir);
    return std.fs.path.join(ar, &.{ dir, ".artoo", "config.json" });
}

test "config: show defaults without a file, init, refuse re-init" {
    var h = try Harness.init();
    defer h.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try setup(&h, &tmp);

    try testing.expectEqual(.ok, h.run(&root, "config get pve.node"));
    try testing.expectEqualStrings("pve\n", h.stdout());

    try testing.expectEqual(.ok, h.run(&root, "config show"));
    try testing.expect(std.mem.find(u8, h.stdout(), "No config file; showing defaults.") != null);

    try testing.expectEqual(.ok, h.run(&root, "config init"));
    try testing.expectEqualStrings("Wrote ~/.artoo/config.json with defaults.\nNext: 'artoo auth set unifi' and 'artoo doctor'.\n", h.stdout());
    const st = try Io.Dir.cwd().statFile(testing.io, path, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);
    const dst = try Io.Dir.cwd().statFile(testing.io, std.fs.path.dirname(path).?, .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o700), dst.permissions.toMode() & 0o777);

    try testing.expectEqual(.usage, h.run(&root, "config init"));
    try testing.expect(std.mem.startsWith(u8, h.stderr(), "artoo: ~/.artoo/config.json already exists"));
}

test "config: show renders sections, marks defaults" {
    var h = try Harness.init();
    defer h.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    _ = try setup(&h, &tmp);
    try testing.expectEqual(.ok, h.run(&root, "config set unifi.timeout_seconds 20"));
    try testing.expectEqualStrings("Set unifi.timeout_seconds: 10 → 20\n", h.stdout());
    try testing.expectEqual(.ok, h.run(&root, "config show"));
    try testing.expectEqualStrings(
        \\ARTOO · config  ~/.artoo/config.json
        \\
        \\Output
        \\  format           table  (default)
        \\  color            auto  (default)
        \\
        \\Credentials
        \\  store            auto  (default)
        \\
        \\Proxmox (pve)
        \\  endpoint         https://pve.home.arpa:8006  (default)
        \\  node             pve  (default)
        \\  token_id         artoo@pve!cli  (default)
        \\  ca_bundle        ~/.artoo/tls/rootCA.pem  (default)
        \\  timeout_seconds  15  (default)
        \\  ssh_host         192.168.1.10  (default)
        \\  ssh_identity     ~/.ssh/id_ed25519  (default)
        \\
        \\UniFi (unifi)
        \\  endpoint         https://unifi.home.arpa/proxy/network/integration  (default)
        \\  site             default  (default)
        \\  ca_bundle        ~/.artoo/tls/rootCA.pem  (default)
        \\  timeout_seconds  20
        \\
        \\Guests
        \\  domain           lab.example.com  (default)
        \\  template         ubuntu-2604  (default)
        \\  ssh_public_key   ~/.ssh/id_ed25519.pub  (default)
        \\  address_pool     192.168.1.200-192.168.1.254  (default)
        \\  gateway          192.168.1.1/24  (default)
        \\  user             artoo  (default)
        \\  reserved_names   --  (default)
        \\
    , h.stdout());
}

test "config: set/unset/get validation and JSON" {
    var h = try Harness.init();
    defer h.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    _ = try setup(&h, &tmp);

    try testing.expectEqual(.usage, h.run(&root, "config set pve.timeout_seconds 0"));
    try testing.expectEqualStrings("artoo: pve.timeout_seconds: expected 1..3600 seconds, got 0\nRun 'artoo help config set' for usage.\n", h.stderr());
    try testing.expectEqual(.usage, h.run(&root, "config set pve.tokenid x"));
    try testing.expect(std.mem.find(u8, h.stderr(), "did you mean 'pve.token_id'?") != null);
    try testing.expectEqual(.usage, h.run(&root, "config get nope"));

    try testing.expectEqual(.ok, h.run(&root, "config set output.format json"));
    // Config default now applies to every command.
    try testing.expectEqual(.ok, h.run(&root, "config get output.format"));
    try testing.expect(std.mem.find(u8, h.stdout(), "\"value\": \"json\"") != null);
    try testing.expectEqual(.ok, h.run(&root, "-o table config get output.format"));
    try testing.expectEqualStrings("json\n", h.stdout());

    try testing.expectEqual(.ok, h.run(&root, "-o table config set output.format json"));
    try testing.expectEqualStrings("output.format is already json\n", h.stdout());
    try testing.expectEqual(.ok, h.run(&root, "-o table config unset output.format"));
    try testing.expectEqualStrings("Unset output.format (default applies: table)\n", h.stdout());
    try testing.expectEqual(.ok, h.run(&root, "config unset output.format"));
    try testing.expectEqualStrings("output.format is not set in the file (default: table)\n", h.stdout());
}

test "config: another schema and a symlinked file are refused" {
    var h = try Harness.init();
    defer h.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try setup(&h, &tmp);
    const ar = h.arena.allocator();
    try files.ensurePrivateDir(testing.io, std.fs.path.dirname(path).?);
    try files.atomicWrite(testing.io, ar, path, "{\"schema_version\":2,\"default_profile\":\"mutation\"}");
    try testing.expectEqual(.usage, h.run(&root, "config show"));
    try testing.expect(std.mem.find(u8, h.stderr(), "unsupported config") != null);

    const real = try std.fmt.allocPrint(ar, "{s}.real", .{path});
    try Io.Dir.cwd().deleteFile(testing.io, path);
    try files.atomicWrite(testing.io, ar, real, try config.defaultFile(ar));
    try Io.Dir.cwd().symLink(testing.io, real, path, .{});
    try testing.expectEqual(.ok, h.run(&root, "config get pve.node"));
    try testing.expectEqual(.usage, h.run(&root, "config set pve.node other"));
    try testing.expect(std.mem.find(u8, h.stderr(), "it is a symlink") != null);
}

test "config edit: no change, failed editor, invalid edit kept, valid edit saved" {
    var h = try Harness.init();
    defer h.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try setup(&h, &tmp);
    try testing.expectEqual(.ok, h.run(&root, "config init"));

    try h.env.put("EDITOR", "true");
    try testing.expectEqual(.ok, h.run(&root, "config edit"));
    try testing.expectEqualStrings("No changes.\n", h.stdout());

    try h.env.put("EDITOR", "false");
    try testing.expectEqual(.usage, h.run(&root, "config edit"));
    try testing.expect(std.mem.find(u8, h.stderr(), "editor exited unsuccessfully") != null);

    try h.env.put("EDITOR", "perl -pi -e s/15/0/");
    try testing.expectEqual(.usage, h.run(&root, "config edit"));
    try testing.expect(std.mem.find(u8, h.stderr(), "pve.timeout_seconds: expected 1..3600 seconds, got 0; nothing saved") != null);

    try h.env.put("EDITOR", "perl -pi -e s/15/25/");
    try testing.expectEqual(.ok, h.run(&root, "config edit"));
    try testing.expectEqual(.ok, h.run(&root, "config get pve.timeout_seconds"));
    try testing.expectEqualStrings("25\n", h.stdout());
    _ = path;
}
