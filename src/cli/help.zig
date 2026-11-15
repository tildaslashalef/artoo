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
    /// Terminal columns; null (piped) wraps at `default_width`.
    width: ?usize = null,

    fn cols(s: Style) usize {
        return std.math.clamp(s.width orelse default_width, min_width, max_width);
    }
};

const default_width = 80;
const min_width = 60;
const max_width = 100;

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
    if (c.details.len > 0) {
        try w.writeByte('\n');
        try paragraphs(w, c.details, style.cols());
    }

    if (c.isGroup()) {
        try title(w, style, "Commands");
        var width: usize = 0;
        for (c.children) |ch| if (!ch.hidden) {
            width = @max(width, ch.name.len);
        };
        if (path.len == 1) width = @max(width, "help".len);
        for (c.children) |ch| if (!ch.hidden) try row(w, style, ch.name, width, ch.summary);
        if (path.len == 1) try row(w, style, "help", width, "Show help for a command");
    } else {
        var has_pos_help = false;
        for (c.positionals) |p| has_pos_help = has_pos_help or p.help.len > 0;
        if (has_pos_help) {
            try title(w, style, "Arguments");
            var width: usize = 0;
            for (c.positionals) |p| width = @max(width, p.name.len);
            for (c.positionals) |p| try row(w, style, p.name, width, p.help);
        }
        if (c.flags.len > 0) {
            try title(w, style, "Flags");
            try flagRows(w, style, c.flags);
        }
    }

    if (path.len == 1) {
        try title(w, style, "Global flags");
        try flagRows(w, style, command.global_flags);
    } else if (!c.isGroup()) {
        // Every command takes them; the root help explains each.
        try title(w, style, "Global flags");
        try w.writeAll("  -o json, -y, -n, -v, --timeout SECONDS, --config PATH, … ('artoo --help')\n");
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

fn row(w: *Io.Writer, style: Style, name: []const u8, width: usize, text: []const u8) Io.Writer.Error!void {
    try w.print("  {s}", .{name});
    if (text.len > 0) {
        try w.splatByteAll(' ', width - name.len + 3);
        try wrapped(w, text, 2 + width + 3, style.cols());
    } else try w.writeByte('\n');
}

fn cells(s: []const u8) usize {
    return std.unicode.utf8CountCodepoints(s) catch s.len;
}

/// Writes `text` from the current column `indent`, wrapping at `cols`
/// with continuation lines indented to `indent`; ends with a newline. A
/// word longer than the room left stays whole.
fn wrapped(w: *Io.Writer, text: []const u8, indent: usize, cols: usize) Io.Writer.Error!void {
    const room = if (cols > indent + 20) cols - indent else 20;
    var col: usize = 0;
    var words = std.mem.tokenizeScalar(u8, text, ' ');
    while (words.next()) |word| {
        const n = cells(word);
        if (col > 0 and col + 1 + n > room) {
            try w.writeByte('\n');
            try w.splatByteAll(' ', indent);
            col = 0;
        }
        if (col > 0) {
            try w.writeByte(' ');
            col += 1;
        }
        try w.writeAll(word);
        col += n;
    }
    try w.writeByte('\n');
}

/// The details text, reflowed: blank lines separate paragraphs, and the
/// lines of a paragraph are joined and wrapped at `cols`. Indented lines
/// (tables, lists) and the line ending with ':' that introduces them
/// are kept as written.
fn paragraphs(w: *Io.Writer, details: []const u8, cols: usize) Io.Writer.Error!void {
    var flow: [4096]u8 = undefined;
    var len: usize = 0;
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, details, "\n"), '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, " ");
        const verbatim = line.len == 0 or line[0] == ' ';
        if (verbatim or len + 1 + line.len > flow.len) {
            if (len > 0) try wrapped(w, flow[0..len], 0, cols);
            len = 0;
        }
        if (verbatim) {
            try w.print("{s}\n", .{line});
            continue;
        }
        if (len > 0) {
            flow[len] = ' ';
            len += 1;
        }
        @memcpy(flow[len..][0..line.len], line);
        len += line.len;
        if (line[line.len - 1] == ':') {
            try wrapped(w, flow[0..len], 0, cols);
            len = 0;
        }
    }
    if (len > 0) try wrapped(w, flow[0..len], 0, cols);
}

fn flagLeftLen(f: Flag) usize {
    var n: usize = "-x, --".len + f.long.len;
    if (f.takesValue()) n += 1 + parse.metavar(f).len;
    return n;
}

fn flagRows(w: *Io.Writer, style: Style, flags: []const Flag) Io.Writer.Error!void {
    // A flag much wider than the others (a long choice list) puts its help
    // on the next line instead of widening the column for every flag.
    const wide = 34;
    var width: usize = 0;
    for (flags) |f| if (flagLeftLen(f) <= wide) {
        width = @max(width, flagLeftLen(f));
    };
    for (flags) |f| {
        const below = flagLeftLen(f) > wide;
        if (f.short) |s| try w.print("  -{c}, --{s}", .{ s, f.long }) else try w.print("      --{s}", .{f.long});
        if (f.takesValue()) try w.print(" {s}", .{parse.metavar(f)});
        var buf: [512]u8 = undefined;
        const text = if (f.default) |d|
            std.fmt.bufPrint(&buf, "{s} (default: {s})", .{ f.help, d }) catch f.help
        else
            f.help;
        if (below) {
            try w.writeByte('\n');
            try w.splatByteAll(' ', 2 + width + 3);
            try wrapped(w, text, 2 + width + 3, style.cols());
        } else {
            try w.splatByteAll(' ', width - flagLeftLen(f) + 3);
            try wrapped(w, text, 2 + width + 3, style.cols());
        }
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
    try testing.expect(std.mem.find(u8, buf.written(), "  -o json, -y, -n, -v") != null);
    try testing.expect(std.mem.find(u8, buf.written(), "--output table|json") == null);
    try testing.expect(std.mem.endsWith(u8, buf.written(), "Examples:\n  artoo vm ls --status running\n"));
}

test "help: details reflow to the width; indented lines and their lead-in stay" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try paragraphs(&buf.writer,
        \\One two three four five six seven eight nine ten eleven twelve thirteen
        \\fourteen.
        \\
        \\Kinds:
        \\  a   first
        \\  b   second
        \\Tail text.
    , 60);
    try testing.expectEqualStrings(
        \\One two three four five six seven eight nine ten eleven
        \\twelve thirteen fourteen.
        \\
        \\Kinds:
        \\  a   first
        \\  b   second
        \\Tail text.
        \\
    , buf.written());
}

test "help: long flag help wraps under its column" {
    var buf: Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try flagRows(&buf.writer, .{ .width = 60 }, &.{
        .{ .long = "all", .short = 'a', .help = "Include templates and every other kind of guest that the host knows about" },
    });
    try testing.expectEqualStrings(
        \\  -a, --all   Include templates and every other kind of
        \\              guest that the host knows about
        \\
    , buf.written());
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
