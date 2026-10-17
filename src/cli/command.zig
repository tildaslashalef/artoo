//! Declarative command table (SPEC §3). One tree of `Command` nodes drives
//! parsing, help and suggestions, so help cannot drift from behavior.
//!
//! A leaf command is declared as a struct and converted with `leaf`:
//!
//!     pub const ls = struct {
//!         pub const name = "ls";
//!         pub const summary = "List virtual machines";
//!         pub const flags = [_]cli.Flag{ .{ .long = "all", .short = 'a', .help = "Include templates" } };
//!         pub fn run(ctx: *app.Context, args: cli.Args(@This())) !void { … }
//!     };
//!
//! `Args(D)` checks every flag/positional name at compile time.

const std = @import("std");
const app = @import("../app.zig");

pub const Kind = enum { bool, string, int, choice };

pub const Flag = struct {
    long: []const u8,
    short: ?u8 = null,
    kind: Kind = .bool,
    /// Placeholder in help (`N`, `PATH`); defaults by kind.
    metavar: ?[]const u8 = null,
    choices: []const []const u8 = &.{},
    /// Shown as "(default: …)"; documentation only, the command applies it.
    default: ?[]const u8 = null,
    help: []const u8,

    pub fn takesValue(f: Flag) bool {
        return f.kind != .bool;
    }
};

/// Where shell completion finds a positional's candidates (SPEC §3.5).
pub const Complete = enum { none, vm, template, file };

pub const Positional = struct {
    name: []const u8,
    help: []const u8 = "",
    complete: Complete = .none,
    required: bool = true,
    /// Collects all remaining words (must be last).
    variadic: bool = false,
};

pub const Handler = *const fn (*app.Context, *const Invocation) anyerror!void;

pub const Command = struct {
    name: []const u8,
    summary: []const u8,
    /// Longer help text, pre-wrapped.
    details: []const u8 = "",
    flags: []const Flag = &.{},
    positionals: []const Positional = &.{},
    /// Metavar for words after `--` (e.g. `CMD`); null = `--` only ends flags.
    trailing: ?[]const u8 = null,
    examples: []const []const u8 = &.{},
    children: []const Command = &.{},
    run: ?Handler = null,
    /// Left out of help and suggestions (`__complete`).
    hidden: bool = false,

    pub fn isGroup(c: *const Command) bool {
        return c.run == null;
    }

    pub fn child(c: *const Command, word: []const u8) ?*const Command {
        for (c.children) |*ch| {
            if (std.mem.eql(u8, ch.name, word)) return ch;
        }
        return null;
    }

    pub fn findFlag(c: *const Command, long: []const u8) ?usize {
        for (c.flags, 0..) |f, i| {
            if (std.mem.eql(u8, f.long, long)) return i;
        }
        return null;
    }

    pub fn findShort(c: *const Command, short: u8) ?usize {
        for (c.flags, 0..) |f, i| {
            if (f.short == short) return i;
        }
        return null;
    }
};

pub const Value = union(enum) {
    unset,
    on,
    str: []const u8,
    int: i64,
};

pub const Output = enum { table, json };
pub const Color = enum { auto, always, never };

/// Global flags (SPEC §3.1), accepted anywhere after the program name.
pub const Globals = struct {
    output: ?Output = null,
    color: ?Color = null,
    ascii: bool = false,
    yes: bool = false,
    dry_run: bool = false,
    no_wait: bool = false,
    timeout: ?u32 = null,
    verbose: bool = false,
    config: ?[]const u8 = null,
    help: bool = false,
    version: bool = false,
};

pub const global_flags = normalize(&[_]Flag{
    .{ .long = "output", .short = 'o', .kind = .choice, .choices = &.{ "table", "json" }, .default = "table", .help = "Output format" },
    .{ .long = "color", .kind = .choice, .choices = &.{ "auto", "always", "never" }, .default = "auto", .help = "Color policy; NO_COLOR is honored" },
    .{ .long = "ascii", .help = "ASCII-only glyphs and borders" },
    .{ .long = "yes", .short = 'y', .help = "Skip the confirmation prompt (never validation)" },
    .{ .long = "dry-run", .short = 'n', .help = "Plan and preview only; send no write" },
    .{ .long = "no-wait", .help = "Return once a write is accepted" },
    .{ .long = "timeout", .kind = .int, .metavar = "SECONDS", .help = "Per-request deadline" },
    .{ .long = "verbose", .short = 'v', .help = "Request/step diagnostics on stderr" },
    .{ .long = "config", .kind = .string, .metavar = "PATH", .default = "~/.artoo/config.json", .help = "Alternate config file" },
    .{ .long = "help", .short = 'h', .help = "Show help" },
    .{ .long = "version", .help = "Show the version" },
});

pub const Invocation = struct {
    /// Root first, the leaf last.
    path: []const *const Command,
    globals: Globals = .{},
    /// Aligned with `command().flags`.
    flags: []const Value = &.{},
    positionals: []const []const u8 = &.{},
    trailing: []const []const u8 = &.{},

    pub fn command(inv: *const Invocation) *const Command {
        return inv.path[inv.path.len - 1];
    }
};

/// Build a group node.
pub fn group(comptime name: []const u8, comptime summary: []const u8, comptime children: []const Command) Command {
    comptime {
        for (children, 0..) |a, i| {
            for (children[i + 1 ..]) |b| {
                if (std.mem.eql(u8, a.name, b.name)) @compileError("duplicate command '" ++ a.name ++ "' in '" ++ name ++ "'");
            }
        }
    }
    return .{ .name = name, .summary = summary, .children = children };
}

/// Build a leaf node from a declaration struct (see file comment).
pub fn leaf(comptime D: type) Command {
    return comptime blk: {
        const flags: []const Flag = if (@hasDecl(D, "flags")) normalize(&D.flags) else &.{};
        const positionals: []const Positional = if (@hasDecl(D, "positionals")) &D.positionals else &.{};
        validate(D.name, flags, positionals);
        break :blk .{
            .name = D.name,
            .summary = D.summary,
            .details = if (@hasDecl(D, "details")) D.details else "",
            .flags = flags,
            .positionals = positionals,
            .trailing = if (@hasDecl(D, "trailing")) D.trailing else null,
            .examples = if (@hasDecl(D, "examples")) &D.examples else &.{},
            .hidden = @hasDecl(D, "hidden") and D.hidden,
            .run = &struct {
                fn call(ctx: *app.Context, inv: *const Invocation) anyerror!void {
                    return D.run(ctx, .{ .inv = inv });
                }
            }.call,
        };
    };
}

/// Fill choice metavars with `a|b|c` at compile time.
fn normalize(comptime flags: []const Flag) []const Flag {
    comptime {
        var out: [flags.len]Flag = flags[0..flags.len].*;
        for (&out) |*f| {
            if (f.kind != .choice or f.metavar != null) continue;
            var m: []const u8 = "";
            for (f.choices, 0..) |c, i| m = m ++ (if (i > 0) "|" else "") ++ c;
            f.metavar = m;
        }
        const final = out;
        return &final;
    }
}

fn validate(comptime name: []const u8, comptime flags: []const Flag, comptime positionals: []const Positional) void {
    for (flags, 0..) |f, i| {
        if (f.kind == .choice and f.choices.len == 0) @compileError(name ++ ": --" ++ f.long ++ " has no choices");
        for (global_flags) |g| {
            if (std.mem.eql(u8, f.long, g.long)) @compileError(name ++ ": --" ++ f.long ++ " shadows a global flag");
            if (f.short != null and f.short == g.short) @compileError(name ++ ": -" ++ .{f.short.?} ++ " shadows a global flag");
        }
        for (flags[i + 1 ..]) |o| {
            if (std.mem.eql(u8, f.long, o.long)) @compileError(name ++ ": duplicate --" ++ f.long);
            if (f.short != null and f.short == o.short) @compileError(name ++ ": duplicate -" ++ .{f.short.?});
        }
    }
    var optional_seen = false;
    for (positionals, 0..) |p, i| {
        if (p.variadic and i != positionals.len - 1) @compileError(name ++ ": variadic " ++ p.name ++ " must be last");
        if (p.required and optional_seen) @compileError(name ++ ": required " ++ p.name ++ " after an optional one");
        if (!p.required) optional_seen = true;
    }
}

/// Typed, compile-time-checked access to a parsed invocation of leaf `D`.
pub fn Args(comptime D: type) type {
    return struct {
        inv: *const Invocation,

        const Self = @This();

        pub fn globals(self: Self) Globals {
            return self.inv.globals;
        }

        /// Bool flag.
        pub fn has(self: Self, comptime long: []const u8) bool {
            return self.inv.flags[comptime flagIndex(D, long, .bool)] == .on;
        }

        pub fn string(self: Self, comptime long: []const u8) ?[]const u8 {
            return switch (self.inv.flags[comptime flagIndex(D, long, .string)]) {
                .str => |s| s,
                else => null,
            };
        }

        pub fn int(self: Self, comptime long: []const u8) ?i64 {
            return switch (self.inv.flags[comptime flagIndex(D, long, .int)]) {
                .int => |n| n,
                else => null,
            };
        }

        /// Choice flag as enum `E` (choices must be `E`'s tag names).
        pub fn choice(self: Self, comptime long: []const u8, comptime E: type) ?E {
            const i = comptime flagIndex(D, long, .choice);
            comptime for (D.flags[i].choices) |c| {
                if (!@hasField(E, c)) @compileError(@typeName(E) ++ " lacks choice '" ++ c ++ "'");
            };
            return switch (self.inv.flags[i]) {
                .str => |s| std.meta.stringToEnum(E, s),
                else => null,
            };
        }

        /// Required positional.
        pub fn pos(self: Self, comptime name: []const u8) []const u8 {
            const i = comptime posIndex(D, name);
            comptime if (!D.positionals[i].required or D.positionals[i].variadic)
                @compileError(name ++ " is optional or variadic; use optPos/rest");
            return self.inv.positionals[i];
        }

        pub fn optPos(self: Self, comptime name: []const u8) ?[]const u8 {
            const i = comptime posIndex(D, name);
            comptime if (D.positionals[i].variadic) @compileError(name ++ " is variadic; use rest");
            return if (i < self.inv.positionals.len) self.inv.positionals[i] else null;
        }

        /// Variadic positional: every remaining word.
        pub fn rest(self: Self, comptime name: []const u8) []const []const u8 {
            const i = comptime posIndex(D, name);
            comptime if (!D.positionals[i].variadic) @compileError(name ++ " is not variadic");
            return if (i < self.inv.positionals.len) self.inv.positionals[i..] else &.{};
        }

        /// Words after `--` (requires `trailing`).
        pub fn trailing(self: Self) []const []const u8 {
            comptime if (!@hasDecl(D, "trailing")) @compileError(D.name ++ " declares no trailing words");
            return self.inv.trailing;
        }
    };
}

fn flagIndex(comptime D: type, comptime long: []const u8, comptime kind: Kind) usize {
    if (!@hasDecl(D, "flags")) @compileError(D.name ++ " has no flags");
    for (D.flags, 0..) |f, i| {
        if (std.mem.eql(u8, f.long, long)) {
            if (f.kind != kind) @compileError("--" ++ long ++ " is not a " ++ @tagName(kind) ++ " flag");
            return i;
        }
    }
    @compileError(D.name ++ " has no flag --" ++ long);
}

fn posIndex(comptime D: type, comptime name: []const u8) usize {
    if (!@hasDecl(D, "positionals")) @compileError(D.name ++ " has no positionals");
    for (D.positionals, 0..) |p, i| {
        if (std.mem.eql(u8, p.name, name)) return i;
    }
    @compileError(D.name ++ " has no positional " ++ name);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const probe = struct {
    pub const name = "probe";
    pub const summary = "Accessor probe";
    pub const flags = [_]Flag{
        .{ .long = "all", .short = 'a', .help = "" },
        .{ .long = "limit", .kind = .int, .help = "" },
        .{ .long = "name", .kind = .string, .help = "" },
        .{ .long = "output-mode", .kind = .choice, .choices = &.{ "table", "json" }, .help = "" },
    };
    pub const positionals = [_]Positional{
        .{ .name = "VM" },
        .{ .name = "SNAP", .required = false },
        .{ .name = "KEY", .required = false, .variadic = true },
    };
    pub const trailing = "CMD";
    pub fn run(_: *app.Context, _: Args(@This())) !void {}
};

test "Args: typed accessors over a parsed invocation" {
    const node = leaf(probe);
    try testing.expectEqualStrings("table|json", node.flags[3].metavar.?);
    const path = [_]*const Command{&node};
    const inv: Invocation = .{
        .path = &path,
        .flags = &.{ .on, .{ .int = 3 }, .unset, .{ .str = "json" } },
        .positionals = &.{ "web-01", "pre", "a=1", "b=2" },
        .trailing = &.{"uptime"},
    };
    const args: Args(probe) = .{ .inv = &inv };
    try testing.expect(args.has("all"));
    try testing.expectEqual(@as(?i64, 3), args.int("limit"));
    try testing.expectEqual(@as(?[]const u8, null), args.string("name"));
    try testing.expectEqual(Output.json, args.choice("output-mode", Output).?);
    try testing.expectEqualStrings("web-01", args.pos("VM"));
    try testing.expectEqualStrings("pre", args.optPos("SNAP").?);
    try testing.expectEqual(@as(usize, 2), args.rest("KEY").len);
    try testing.expectEqualStrings("uptime", args.trailing()[0]);

    const short: Invocation = .{ .path = &path, .flags = &.{ .unset, .unset, .unset, .unset }, .positionals = &.{"web-01"} };
    const args2: Args(probe) = .{ .inv = &short };
    try testing.expect(!args2.has("all"));
    try testing.expectEqual(@as(?[]const u8, null), args2.optPos("SNAP"));
    try testing.expectEqual(@as(usize, 0), args2.rest("KEY").len);
}
