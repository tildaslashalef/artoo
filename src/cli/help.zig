//! Help text generated from the command table.

const std = @import("std");
const Io = std.Io;
const command = @import("command.zig");
const parse = @import("parse.zig");

const Command = command.Command;
const Flag = command.Flag;

pub const Style = struct {
    /// Wraps section titles and command names; empty = plain.
    title_on: []const u8 = "",
    title_off: []const u8 = "",
};

pub fn write(w: *Io.Writer, path: []const *const Command, style: Style) Io.Writer.Error!void {
    const c = path[path.len - 1];
    try w.writeAll("Usage: ");
    try writePath(w, path);
    if (c.isGroup()) {
        try w.writeAll(" <command> [flags]\n");
    } else {
        if (c.flags.len > 0) try w.writeAll(" [flags]");
        for (c.positionals) |p| {
            try w.writeByte(' ');
            if (!p.required) try w.writeByte('[');
            try w.writeAll(p.name);
            if (p.variadic) try w.writeAll("...");
            if (!p.required) try w.writeByte(']');
        }
        if (c.trailing) |t| try w.print(" [-- {s}...]", .{t});
        try w.writeByte('\n');
    }
    try w.print("\n{s}\n", .{c.summary});
    if (c.details.len > 0) try w.print("\n{s}\n", .{std.mem.trimEnd(u8, c.details, "\n")});

    if (c.isGroup()) {
        try title(w, style, "Commands");
        var width: usize = 0;
        for (c.children) |ch| if (!ch.hidden) {
            width = @max(width, ch.name.len);
        };
        if (path.len == 1) width = @max(width, "help".len);
        for (c.children) |ch| if (!ch.hidden) try row(w, ch.name, width, ch.summary);
        if (path.len == 1) try row(w, "help", width, "Show help for a command");
    } else {
        var has_pos_help = false;
        for (c.positionals) |p| has_pos_help = has_pos_help or p.help.len > 0;
        if (has_pos_help) {
            try title(w, style, "Arguments");
            var width: usize = 0;
            for (c.positionals) |p| width = @max(width, p.name.len);
            for (c.positionals) |p| try row(w, p.name, width, p.help);
        }
        if (c.flags.len > 0) {
            try title(w, style, "Flags");
            try flagRows(w, c.flags);
        }
    }

    if (path.len == 1 or !c.isGroup()) {
        try title(w, style, "Global flags");
        try flagRows(w, command.global_flags);
    }

    if (c.examples.len > 0) {
        try title(w, style, "Examples");
        for (c.examples) |e| try w.print("  {s}\n", .{e});
    }
    if (c.isGroup()) {
        try w.writeAll("\nRun 'artoo help ");
        if (path.len > 1) {
            try writePathTail(w, path);
            try w.writeByte(' ');
        }
        try w.writeAll("<command>' for its flags and examples.\n");
    }
}

pub fn writePath(w: *Io.Writer, path: []const *const Command) Io.Writer.Error!void {
    for (path, 0..) |c, i| {
        if (i > 0) try w.writeByte(' ');
        try w.writeAll(c.name);
    }
}

/// Path without the program name ("vm ls").
fn writePathTail(w: *Io.Writer, path: []const *const Command) Io.Writer.Error!void {
    try writePath(w, path[1..]);
}

fn title(w: *Io.Writer, style: Style, text: []const u8) Io.Writer.Error!void {
    try w.print("\n{s}{s}:{s}\n", .{ style.title_on, text, style.title_off });
}

fn row(w: *Io.Writer, name: []const u8, width: usize, text: []const u8) Io.Writer.Error!void {
    try w.print("  {s}", .{name});
    if (text.len > 0) {
        try w.splatByteAll(' ', width - name.len + 3);
        try w.writeAll(text);
    }
    try w.writeByte('\n');
}

fn flagLeftLen(f: Flag) usize {
    var n: usize = "-x, --".len + f.long.len;
    if (f.takesValue()) n += 1 + parse.metavar(f).len;
    return n;
}

fn flagRows(w: *Io.Writer, flags: []const Flag) Io.Writer.Error!void {
    var width: usize = 0;
    for (flags) |f| width = @max(width, flagLeftLen(f));
    for (flags) |f| {
        if (f.short) |s| try w.print("  -{c}, --{s}", .{ s, f.long }) else try w.print("      --{s}", .{f.long});
        if (f.takesValue()) try w.print(" {s}", .{parse.metavar(f)});
        try w.splatByteAll(' ', width - flagLeftLen(f) + 3);
        try w.writeAll(f.help);
        if (f.default) |d| try w.print(" (default: {s})", .{d});
        try w.writeByte('\n');
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const app = @import("../app.zig");

const demo = struct {
    pub const name = "ls";
    pub const summary = "List virtual machines";
    pub const details = "Stopped VMs show -- for live values.";
    pub const flags = [_]Flag{
        .{ .long = "all", .short = 'a', .help = "Include templates" },
        .{ .long = "status", .kind = .choice, .choices = &.{ "running", "stopped" }, .help = "Only VMs in this state" },
        .{ .long = "limit", .short = 'l', .kind = .int, .default = "25", .help = "Max rows" },
    };
    pub const positionals = [_]command.Positional{.{ .name = "NAME", .required = false, .help = "Glob over VM names" }};
    pub const examples = [_][]const u8{"artoo vm ls --status running"};
    pub fn run(_: *app.Context, _: command.Args(@This())) !void {}
};
const demo_root = command.group("artoo", "Home-lab CLI", &.{command.group("vm", "Virtual machines", &.{command.leaf(demo)})});

test "help: leaf lists arguments, flags with types/defaults, globals, examples" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    const vm = &demo_root.children[0];
    try write(&buf.writer, &.{ &demo_root, vm, &vm.children[0] }, .{});
    const expected =
        \\Usage: artoo vm ls [flags] [NAME]
        \\
        \\List virtual machines
        \\
        \\Stopped VMs show -- for live values.
        \\
        \\Arguments:
        \\  NAME   Glob over VM names
        \\
        \\Flags:
        \\  -a, --all                      Include templates
        \\      --status running|stopped   Only VMs in this state
        \\  -l, --limit N                  Max rows (default: 25)
        \\
        \\Global flags:
        \\
    ;
    try testing.expectStringStartsWith(buf.written(), expected);
    try testing.expect(std.mem.find(u8, buf.written(), "  -o, --output table|json") != null);
    try testing.expect(std.mem.endsWith(u8, buf.written(), "Examples:\n  artoo vm ls --status running\n"));
}

test "help: group lists children and the drill-down hint" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try write(&buf.writer, &.{ &demo_root, &demo_root.children[0] }, .{});
    try testing.expectEqualStrings(
        \\Usage: artoo vm <command> [flags]
        \\
        \\Virtual machines
        \\
        \\Commands:
        \\  ls   List virtual machines
        \\
        \\Run 'artoo help vm <command>' for its flags and examples.
        \\
    , buf.written());
}
