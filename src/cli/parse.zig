//! Argument parser over the declarative command tree.
//!
//! Words descend the tree until a leaf; the leaf's remaining words are
//! positionals. Global flags are accepted anywhere, command flags after the
//! command. `--flag=v`, `--flag v`, `-f v`, `-fv` and bool clusters (`-yn`)
//! are accepted; `--` ends flag parsing (words after it go to `trailing`
//! when the leaf declares it, else they are positionals).

const std = @import("std");
const Allocator = std.mem.Allocator;
const command = @import("command.zig");
const suggest = @import("suggest.zig");

const Command = command.Command;
const Flag = command.Flag;
const Globals = command.Globals;
const Invocation = command.Invocation;
const Value = command.Value;

pub const Result = union(enum) {
    run: Invocation,
    /// Help for the last node of `path`.
    help: Help,
    version: Globals,
    usage: Usage,
};

pub const Help = struct {
    path: []const *const Command,
    globals: Globals,
};

pub const Usage = struct {
    message: []const u8,
    /// Deepest node resolved before the error (for the help hint).
    path: []const *const Command,
    globals: Globals,
};

pub fn parse(arena: Allocator, root: *const Command, argv: []const []const u8) Allocator.Error!Result {
    var p: Parser = .{ .arena = arena, .argv = argv };
    try p.path.append(arena, root);
    return p.run(argv);
}

const Parser = struct {
    arena: Allocator,
    argv: []const []const u8,
    path: std.ArrayList(*const Command) = .empty,
    globals: Globals = .{},
    seen_globals: [command.global_flags.len]bool = @splat(false),
    flags: []Value = &.{},
    positionals: std.ArrayList([]const u8) = .empty,
    trailing: std.ArrayList([]const u8) = .empty,
    help_mode: bool = false,
    /// Set by `flag` when it fails, so `run` can return the usage result.
    pending: ?Result = null,

    fn node(p: *const Parser) *const Command {
        return p.path.items[p.path.items.len - 1];
    }

    fn usage(p: *Parser, comptime fmt: []const u8, args: anytype) Allocator.Error!Result {
        return .{ .usage = .{
            .message = try std.fmt.allocPrint(p.arena, fmt, args),
            .path = p.path.items,
            .globals = renderGlobals(p.globals, p.argv),
        } };
    }

    fn run(p: *Parser, argv: []const []const u8) Allocator.Error!Result {
        var i: usize = 0;
        var flags_done = false;
        while (i < argv.len) : (i += 1) {
            const w = argv[i];
            if (!flags_done and std.mem.eql(u8, w, "--")) {
                flags_done = true;
                continue;
            }
            if (!flags_done and w.len > 1 and w[0] == '-') {
                const consumed = (try p.flag(argv, i)) orelse return p.pending.?;
                i += consumed;
                continue;
            }
            if (try p.word(w, flags_done)) |r| return r;
        }

        if (p.globals.version) return .{ .version = p.globals };
        if (p.help_mode or p.globals.help or p.node().isGroup()) {
            return .{ .help = .{ .path = p.path.items, .globals = p.globals } };
        }
        return p.finish();
    }

    /// A non-flag word: a command name, `help`, or a positional.
    fn word(p: *Parser, w: []const u8, after_dashdash: bool) Allocator.Error!?Result {
        const n = p.node();
        if (n.isGroup()) {
            if (n.child(w)) |c| {
                try p.path.append(p.arena, c);
                if (!c.isGroup()) {
                    p.flags = try p.arena.alloc(Value, c.flags.len);
                    @memset(p.flags, .unset);
                }
                return null;
            }
            if (p.path.items.len == 1 and !p.help_mode and std.mem.eql(u8, w, "help")) {
                p.help_mode = true;
                return null;
            }
            return try p.unknownCommand(w);
        }
        if (after_dashdash and n.trailing != null) {
            try p.trailing.append(p.arena, w);
        } else if (p.help_mode) {
            return try p.usage("'{s}' has no subcommand '{s}'", .{ try p.pathString(), w });
        } else {
            try p.positionals.append(p.arena, w);
        }
        return null;
    }

    fn unknownCommand(p: *Parser, w: []const u8) Allocator.Error!Result {
        const n = p.node();
        var names: std.ArrayList([]const u8) = .empty;
        for (n.children) |c| if (!c.hidden) try names.append(p.arena, c.name);
        if (p.path.items.len == 1) try names.append(p.arena, "help");
        const where = try p.pathString();
        if (suggest.closest(w, names.items)) |s| {
            return p.usage("unknown command '{s}' for '{s}' — did you mean '{s}'?", .{ w, where, s });
        }
        return p.usage("unknown command '{s}' for '{s}'", .{ w, where });
    }

    fn pathString(p: *const Parser) Allocator.Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        for (p.path.items, 0..) |c, k| {
            if (k > 0) try out.append(p.arena, ' ');
            try out.appendSlice(p.arena, c.name);
        }
        return out.items;
    }

    /// Parse the flag at argv[i]; returns extra words consumed, or null on a
    /// usage error (stored in `pending`).
    fn flag(p: *Parser, argv: []const []const u8, i: usize) Allocator.Error!?usize {
        const w = argv[i];
        const next: ?[]const u8 = if (i + 1 < argv.len) argv[i + 1] else null;
        if (std.mem.startsWith(u8, w, "--")) {
            const body = w[2..];
            const name, const inline_value = if (std.mem.findScalar(u8, body, '=')) |eq|
                .{ body[0..eq], @as(?[]const u8, body[eq + 1 ..]) }
            else
                .{ body, @as(?[]const u8, null) };
            const target = p.resolveLong(name) orelse {
                p.pending = try p.unknownFlag(w, name);
                return null;
            };
            const f = target.spec();
            if (!f.takesValue()) {
                if (inline_value != null) {
                    p.pending = try p.usage("--{s} takes no value", .{name});
                    return null;
                }
                return if (try p.set(target, null)) 0 else null;
            }
            if (inline_value) |v| return if (try p.set(target, v)) 0 else null;
            const v = next orelse {
                p.pending = try p.usage("--{s} needs a value ({s})", .{ name, metavar(f) });
                return null;
            };
            return if (try p.set(target, v)) 1 else null;
        }
        // Short flags: a cluster of bools, the last may take a value.
        var k: usize = 1;
        while (k < w.len) : (k += 1) {
            const target = p.resolveShort(w[k]) orelse {
                p.pending = try p.unknownFlag(w, w[k .. k + 1]);
                return null;
            };
            const f = target.spec();
            if (!f.takesValue()) {
                if (!try p.set(target, null)) return null;
                continue;
            }
            if (k + 1 < w.len) return if (try p.set(target, w[k + 1 ..])) 0 else null;
            const v = next orelse {
                p.pending = try p.usage("-{c} needs a value ({s})", .{ w[k], metavar(f) });
                return null;
            };
            return if (try p.set(target, v)) 1 else null;
        }
        return 0;
    }

    const Target = union(enum) {
        global: usize,
        local: struct { cmd: *const Command, index: usize },

        fn spec(t: Target) Flag {
            return switch (t) {
                .global => |g| command.global_flags[g],
                .local => |l| l.cmd.flags[l.index],
            };
        }
    };

    fn resolveLong(p: *const Parser, name: []const u8) ?Target {
        for (command.global_flags, 0..) |g, k| {
            if (std.mem.eql(u8, g.long, name)) return .{ .global = k };
        }
        const n = p.node();
        if (n.findFlag(name)) |k| return .{ .local = .{ .cmd = n, .index = k } };
        return null;
    }

    fn resolveShort(p: *const Parser, c: u8) ?Target {
        for (command.global_flags, 0..) |g, k| {
            if (g.short == c) return .{ .global = k };
        }
        const n = p.node();
        if (n.findShort(c)) |k| return .{ .local = .{ .cmd = n, .index = k } };
        return null;
    }

    fn unknownFlag(p: *Parser, w: []const u8, name: []const u8) Allocator.Error!Result {
        var names: std.ArrayList([]const u8) = .empty;
        for (command.global_flags) |g| try names.append(p.arena, g.long);
        for (p.node().flags) |f| try names.append(p.arena, f.long);
        const where = try p.pathString();
        if (name.len > 1) {
            if (suggest.closest(name, names.items)) |s| {
                return p.usage("unknown flag '{s}' for '{s}' — did you mean '--{s}'?", .{ w, where, s });
            }
        }
        return p.usage("unknown flag '{s}' for '{s}'", .{ w, where });
    }

    /// Validate and store; false = usage error stored in `pending`.
    fn set(p: *Parser, target: Target, raw: ?[]const u8) Allocator.Error!bool {
        const f = target.spec();
        const value: Value = switch (f.kind) {
            .bool => .on,
            .string => .{ .str = raw.? },
            .int => .{ .int = std.fmt.parseInt(i64, raw.?, 10) catch {
                p.pending = try p.usage("invalid value '{s}' for --{s}: expected an integer", .{ raw.?, f.long });
                return false;
            } },
            .choice => blk: {
                for (f.choices) |c| {
                    if (std.mem.eql(u8, c, raw.?)) break :blk .{ .str = c };
                }
                p.pending = try p.usage("invalid value '{s}' for --{s} (expected {s})", .{ raw.?, f.long, metavar(f) });
                return false;
            },
        };
        switch (target) {
            .local => |l| {
                if (p.flags[l.index] != .unset) {
                    p.pending = try p.usage("--{s} given more than once", .{f.long});
                    return false;
                }
                p.flags[l.index] = value;
            },
            .global => |g| {
                if (p.seen_globals[g]) {
                    p.pending = try p.usage("--{s} given more than once", .{f.long});
                    return false;
                }
                p.seen_globals[g] = true;
                if (!try p.setGlobal(f.long, value)) return false;
            },
        }
        return true;
    }

    fn setGlobal(p: *Parser, long: []const u8, v: Value) Allocator.Error!bool {
        const g = &p.globals;
        const eql = std.mem.eql;
        if (eql(u8, long, "output")) {
            g.output = std.meta.stringToEnum(command.Output, v.str);
        } else if (eql(u8, long, "color")) {
            g.color = std.meta.stringToEnum(command.Color, v.str);
        } else if (eql(u8, long, "ascii")) {
            g.ascii = true;
        } else if (eql(u8, long, "yes")) {
            g.yes = true;
        } else if (eql(u8, long, "dry-run")) {
            g.dry_run = true;
        } else if (eql(u8, long, "no-wait")) {
            g.no_wait = true;
        } else if (eql(u8, long, "timeout")) {
            if (v.int < 1 or v.int > 3600) {
                p.pending = try p.usage("--timeout must be 1..3600 seconds", .{});
                return false;
            }
            g.timeout = @intCast(v.int);
        } else if (eql(u8, long, "verbose")) {
            g.verbose = true;
        } else if (eql(u8, long, "config")) {
            g.config = v.str;
        } else if (eql(u8, long, "help")) {
            g.help = true;
        } else if (eql(u8, long, "version")) {
            g.version = true;
        }
        return true;
    }

    fn finish(p: *Parser) Allocator.Error!Result {
        const c = p.node();
        const given = p.positionals.items;
        var required: usize = 0;
        var variadic = false;
        for (c.positionals) |pos| {
            if (pos.required) required += 1;
            if (pos.variadic) variadic = true;
        }
        if (given.len < required) {
            return p.usage("missing {s}", .{c.positionals[given.len].name});
        }
        if (!variadic and given.len > c.positionals.len) {
            return p.usage("unexpected argument '{s}'", .{given[c.positionals.len]});
        }
        return .{ .run = .{
            .path = p.path.items,
            .globals = p.globals,
            .flags = p.flags,
            .positionals = given,
            .trailing = p.trailing.items,
        } };
    }
};

/// Parsing stopped early: still honor output/color/ascii given anywhere so
/// the error itself renders as requested.
fn renderGlobals(parsed: Globals, argv: []const []const u8) Globals {
    var g = parsed;
    const eql = std.mem.eql;
    for (argv, 0..) |w, i| {
        if (eql(u8, w, "--")) break;
        const next: []const u8 = if (i + 1 < argv.len) argv[i + 1] else "";
        if (eql(u8, w, "--ascii")) g.ascii = true;
        const out: ?[]const u8 = if (eql(u8, w, "-o") or eql(u8, w, "--output")) next else std.mem.cutPrefix(u8, w, "--output=") orelse std.mem.cutPrefix(u8, w, "-o");
        if (out) |v| g.output = std.meta.stringToEnum(command.Output, v) orelse g.output;
        const col: ?[]const u8 = if (eql(u8, w, "--color")) next else std.mem.cutPrefix(u8, w, "--color=");
        if (col) |v| g.color = std.meta.stringToEnum(command.Color, v) orelse g.color;
    }
    return g;
}

pub fn metavar(f: Flag) []const u8 {
    if (f.metavar) |m| return m;
    return switch (f.kind) {
        .bool => "",
        .int => "N",
        .string => "VALUE",
        .choice => "CHOICE", // unreachable for normalized tables
    };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const app = @import("../app.zig");

const T = struct {
    const ls = struct {
        pub const name = "ls";
        pub const summary = "List things";
        pub const flags = [_]Flag{
            .{ .long = "all", .short = 'a', .help = "Everything" },
            .{ .long = "limit", .short = 'l', .kind = .int, .help = "Max" },
            .{ .long = "status", .short = 's', .kind = .choice, .choices = &.{ "running", "stopped" }, .help = "State" },
            .{ .long = "name", .kind = .string, .help = "Glob" },
        };
        pub fn run(_: *app.Context, _: command.Args(@This())) !void {}
    };
    const show = struct {
        pub const name = "show";
        pub const summary = "Show a thing";
        pub const positionals = [_]command.Positional{.{ .name = "VM" }};
        pub fn run(_: *app.Context, _: command.Args(@This())) !void {}
    };
    const health = struct {
        pub const name = "health";
        pub const summary = "Checks";
        pub const positionals = [_]command.Positional{.{ .name = "CHECK", .required = false, .variadic = true }};
        pub fn run(_: *app.Context, _: command.Args(@This())) !void {}
    };
    const ssh = struct {
        pub const name = "ssh";
        pub const summary = "SSH";
        pub const positionals = [_]command.Positional{.{ .name = "VM" }};
        pub const trailing = "CMD";
        pub fn run(_: *app.Context, _: command.Args(@This())) !void {}
    };
    const root = command.group("artoo", "root", &.{
        command.group("vm", "VMs", &.{ command.leaf(ls), command.leaf(show), command.leaf(ssh) }),
        command.group("host", "Host", &.{command.leaf(health)}),
    });
};

fn splitWords(comptime s: []const u8) []const []const u8 {
    comptime {
        var out: []const []const u8 = &.{};
        var it = std.mem.tokenizeScalar(u8, s, ' ');
        while (it.next()) |w| out = out ++ .{w};
        return out;
    }
}

fn parseT(arena: Allocator, comptime line: []const u8) !Result {
    return parse(arena, &T.root, comptime splitWords(line));
}

test "parse: leaf with flags in every form, globals anywhere" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const r = try parseT(a.allocator(), "-o json vm ls -a --limit=5 -s running --name web* -yn --timeout 30");
    const inv = r.run;
    try testing.expectEqualStrings("ls", inv.command().name);
    try testing.expectEqual(command.Output.json, inv.globals.output.?);
    try testing.expect(inv.globals.yes and inv.globals.dry_run);
    try testing.expectEqual(@as(u32, 30), inv.globals.timeout.?);
    try testing.expectEqual(Value.on, inv.flags[0]);
    try testing.expectEqual(@as(i64, 5), inv.flags[1].int);
    try testing.expectEqualStrings("running", inv.flags[2].str);
    try testing.expectEqualStrings("web*", inv.flags[3].str);
}

test "parse: attached short value and cluster ending in a valued flag" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const r1 = try parseT(a.allocator(), "vm ls -l7");
    try testing.expectEqual(@as(i64, 7), r1.run.flags[1].int);
    const r2 = try parseT(a.allocator(), "vm ls -al 9");
    try testing.expectEqual(Value.on, r2.run.flags[0]);
    try testing.expectEqual(@as(i64, 9), r2.run.flags[1].int);
}

test "parse: positionals, variadic, trailing" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const r1 = try parseT(a.allocator(), "vm show web-01 -v");
    try testing.expectEqualStrings("web-01", r1.run.positionals[0]);
    try testing.expect(r1.run.globals.verbose);
    const r2 = try parseT(a.allocator(), "host health");
    try testing.expectEqual(@as(usize, 0), r2.run.positionals.len);
    const r3 = try parseT(a.allocator(), "host health zfs api");
    try testing.expectEqual(@as(usize, 2), r3.run.positionals.len);
    const r4 = try parseT(a.allocator(), "vm ssh web-01 -- ls -la");
    try testing.expectEqualStrings("web-01", r4.run.positionals[0]);
    try testing.expectEqual(@as(usize, 2), r4.run.trailing.len);
    try testing.expectEqualStrings("-la", r4.run.trailing[1]);
    // `--` without `trailing` makes dash-words positionals.
    const r5 = try parseT(a.allocator(), "vm show -- -odd-name");
    try testing.expectEqualStrings("-odd-name", r5.run.positionals[0]);
}

test "parse: help and version requests" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "", "artoo" },
        .{ "vm", "vm" },
        .{ "help", "artoo" },
        .{ "help vm", "vm" },
        .{ "help vm ls", "ls" },
        .{ "vm ls -h", "ls" },
        .{ "--help vm", "vm" },
        .{ "vm show --help", "show" }, // missing VM is not an error under --help
    };
    inline for (cases) |c| {
        const r = try parseT(a.allocator(), c[0]);
        const path = r.help.path;
        try testing.expectEqualStrings(c[1], path[path.len - 1].name);
    }
    try testing.expect((try parseT(a.allocator(), "vm ls --version")) == .version);
}

test "parse: usage errors keep rendering globals given anywhere" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const r = try parseT(a.allocator(), "frob -o json --color=never --ascii");
    try testing.expectEqual(command.Output.json, r.usage.globals.output.?);
    try testing.expectEqual(command.Color.never, r.usage.globals.color.?);
    try testing.expect(r.usage.globals.ascii);
    const r2 = try parseT(a.allocator(), "frob --output=json");
    try testing.expectEqual(command.Output.json, r2.usage.globals.output.?);
}

test "parse: usage errors" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "vm lss", "unknown command 'lss' for 'artoo vm' — did you mean 'ls'?" },
        .{ "hots", "unknown command 'hots' for 'artoo' — did you mean 'host'?" },
        .{ "frob", "unknown command 'frob' for 'artoo'" },
        .{ "vm ls --limt 3", "unknown flag '--limt' for 'artoo vm ls' — did you mean '--limit'?" },
        .{ "vm ls -x", "unknown flag '-x' for 'artoo vm ls'" },
        .{ "--limit 3 vm ls", "unknown flag '--limit' for 'artoo'" },
        .{ "vm ls --limit x", "invalid value 'x' for --limit: expected an integer" },
        .{ "vm ls --limit", "--limit needs a value (N)" },
        .{ "vm ls -s paused", "invalid value 'paused' for --status (expected running|stopped)" },
        .{ "vm ls -a -a", "--all given more than once" },
        .{ "vm ls --all=yes", "--all takes no value" },
        .{ "vm show", "missing VM" },
        .{ "vm show a b", "unexpected argument 'b'" },
        .{ "-o yaml vm ls", "invalid value 'yaml' for --output (expected table|json)" },
        .{ "--timeout 0 vm ls", "--timeout must be 1..3600 seconds" },
        .{ "help vm ls extra", "'artoo vm ls' has no subcommand 'extra'" },
    };
    inline for (cases) |c| {
        const r = try parseT(a.allocator(), c[0]);
        testing.expectEqualStrings(c[1], r.usage.message) catch |err| {
            std.debug.print("case: {s}\n", .{c[0]});
            return err;
        };
    }
}
