//! Shell completion over the command table (SPEC §3.5).
//!
//! The scripts `artoo completion <shell>` prints are thin: on every Tab they
//! run `artoo __complete -- <words…>` (the words after `artoo`, the last
//! one being completed, maybe empty) and show what it prints:
//! `candidate<TAB>description` lines, or the one directive `:file`, handing
//! the word to the shell's path completion. `resolve` (words → what is
//! being completed) and `candidates` are pure; live names (VMs, templates)
//! are fetched by the caller only when `resolve` asks for them.

const std = @import("std");
const Allocator = std.mem.Allocator;
const command = @import("command.zig");

const Command = command.Command;
const Flag = command.Flag;
const Positional = command.Positional;

pub const Target = union(enum) {
    none,
    /// Subcommands of the group (and `help` at the root).
    commands: struct { node: *const Command, root: bool },
    /// Flags of the node plus the global ones.
    flags: *const Command,
    /// The value of a flag.
    value: Flag,
    positional: Positional,
};

pub const Candidate = struct {
    text: []const u8,
    help: []const u8 = "",
};

pub const Answer = union(enum) {
    file,
    list: []const Candidate,
};

/// What the last word of `words` is.
pub fn resolve(root: *const Command, words: []const []const u8) Target {
    if (words.len == 0) return .{ .commands = .{ .node = root, .root = true } };
    const current = words[words.len - 1];
    var node = root;
    var help_mode = false;
    var positional: usize = 0;
    var pending: ?Flag = null;
    var dashdash = false;
    for (words[0 .. words.len - 1]) |w| {
        if (pending != null) {
            pending = null;
            continue;
        }
        if (!dashdash and std.mem.eql(u8, w, "--")) {
            dashdash = true;
            if (node.trailing != null) return .none;
            continue;
        }
        if (!dashdash and w.len > 1 and w[0] == '-') {
            pending = valueFlag(node, w);
            continue;
        }
        if (node == root and !help_mode and std.mem.eql(u8, w, "help")) {
            help_mode = true;
            continue;
        }
        if (node.isGroup()) {
            node = node.child(w) orelse return .none;
            if (node.hidden) return .none;
            continue;
        }
        positional += 1;
    }
    if (pending) |f| return .{ .value = f };
    if (!dashdash and current.len > 0 and current[0] == '-') return .{ .flags = node };
    if (node.isGroup()) return .{ .commands = .{ .node = node, .root = node == root and !help_mode } };
    if (help_mode) return .none;
    if (node.positionals.len == 0) return .none;
    const last = node.positionals[node.positionals.len - 1];
    if (positional >= node.positionals.len) return if (last.variadic) .{ .positional = last } else .none;
    return .{ .positional = node.positionals[positional] };
}

/// The flag `w` (`--long`, `-s`, a cluster `-yn`) leaves waiting for a
/// value in the next word, if any.
fn valueFlag(node: *const Command, w: []const u8) ?Flag {
    if (std.mem.startsWith(u8, w, "--")) {
        if (std.mem.findScalar(u8, w, '=') != null) return null;
        const f = findLong(node, w[2..]) orelse return null;
        return if (f.takesValue()) f else null;
    }
    for (w[1..], 1..) |ch, i| {
        const f = findShort(node, ch) orelse return null;
        if (f.takesValue()) return if (i == w.len - 1) f else null;
    }
    return null;
}

fn findLong(node: *const Command, name: []const u8) ?Flag {
    for (node.flags) |f| if (std.mem.eql(u8, f.long, name)) return f;
    for (command.global_flags) |f| if (std.mem.eql(u8, f.long, name)) return f;
    return null;
}

fn findShort(node: *const Command, ch: u8) ?Flag {
    for (node.flags) |f| if (f.short == ch) return f;
    for (command.global_flags) |f| if (f.short == ch) return f;
    return null;
}

fn isPath(f: Flag) bool {
    const m = f.metavar orelse return false;
    return std.mem.eql(u8, m, "PATH") or std.mem.eql(u8, m, "FILE");
}

/// Candidates for `target`, filtered by the prefix `current`; `live` holds
/// the names fetched for a `.vm`/`.template` positional.
pub fn candidates(arena: Allocator, target: Target, current: []const u8, live: []const Candidate) !Answer {
    var out: std.ArrayList(Candidate) = .empty;
    switch (target) {
        .none => {},
        .commands => |c| {
            for (c.node.children) |ch| if (!ch.hidden) try out.append(arena, .{ .text = ch.name, .help = ch.summary });
            if (c.root) try out.append(arena, .{ .text = "help", .help = "Show help for a command" });
        },
        .flags => |node| {
            if (std.mem.startsWith(u8, current, "--")) {
                if (std.mem.findScalar(u8, current, '=')) |eq| {
                    const f = findLong(node, current[2..eq]) orelse return .{ .list = &.{} };
                    for (f.choices) |ch| try out.append(arena, .{ .text = try std.fmt.allocPrint(arena, "{s}{s}", .{ current[0 .. eq + 1], ch }) });
                    return .{ .list = try filter(arena, out.items, current) };
                }
            }
            for (node.flags) |f| try out.append(arena, .{ .text = try std.fmt.allocPrint(arena, "--{s}", .{f.long}), .help = f.help });
            for (command.global_flags) |f| try out.append(arena, .{ .text = try std.fmt.allocPrint(arena, "--{s}", .{f.long}), .help = f.help });
        },
        .value => |f| {
            if (isPath(f)) return .file;
            for (f.choices) |ch| try out.append(arena, .{ .text = ch });
        },
        .positional => |p| switch (p.complete) {
            .none => {},
            .file => return .file,
            .vm, .template => try out.appendSlice(arena, live),
        },
    }
    return .{ .list = try filter(arena, out.items, current) };
}

fn filter(arena: Allocator, all: []const Candidate, prefix: []const u8) ![]const Candidate {
    var out: std.ArrayList(Candidate) = .empty;
    for (all) |c| if (std.mem.startsWith(u8, c.text, prefix)) try out.append(arena, c);
    return out.items;
}

/// One line per candidate; descriptions keep to one line, no tabs.
pub fn write(w: *std.Io.Writer, answer: Answer) !void {
    switch (answer) {
        .file => try w.writeAll(":file\n"),
        .list => |list| for (list) |c| {
            try w.writeAll(c.text);
            if (c.help.len > 0) {
                try w.writeByte('\t');
                for (c.help) |ch| try w.writeByte(if (ch == '\t' or ch == '\n' or ch == '\r') ' ' else ch);
            }
            try w.writeByte('\n');
        },
    }
}

pub const Shell = enum { fish, bash, zsh };

pub fn script(shell: Shell) []const u8 {
    return switch (shell) {
        .fish => fish_script,
        .bash => bash_script,
        .zsh => zsh_script,
    };
}

const fish_script =
    \\# artoo completion for fish: every Tab asks the binary (SPEC 3.5).
    \\function __artoo_complete
    \\    set -l tokens (commandline -xpc 2>/dev/null; or commandline -opc)
    \\    set -l current (commandline -ct)
    \\    set -l lines (command artoo __complete -- $tokens[2..-1] "$current" 2>/dev/null)
    \\    switch "$lines[1]"
    \\        case :file
    \\            __fish_complete_path "$current"
    \\        case '*'
    \\            printf '%s\n' $lines
    \\    end
    \\end
    \\complete -c artoo -f -k -a '(__artoo_complete)'
    \\
;

const bash_script =
    \\# artoo completion for bash (3.2 and later): every Tab asks the binary (SPEC 3.5).
    \\_artoo() {
    \\    local cur="${COMP_WORDS[COMP_CWORD]}" out line i
    \\    local -a args
    \\    # A loop, not a slice: bash 3.2 joins a quoted slice under another IFS.
    \\    for ((i = 1; i <= COMP_CWORD; i++)); do args[i-1]="${COMP_WORDS[i]}"; done
    \\    out=$(command artoo __complete -- "${args[@]}" 2>/dev/null)
    \\    local IFS=$'\n'
    \\    COMPREPLY=()
    \\    case "$out" in
    \\        :file) COMPREPLY=($(compgen -f -- "$cur")); compopt -o filenames 2>/dev/null ;;
    \\        *) for line in $out; do COMPREPLY+=("${line%%$'\t'*}"); done ;;
    \\    esac
    \\}
    \\complete -F _artoo artoo
    \\
;

const zsh_script =
    \\#compdef artoo
    \\# artoo completion for zsh: every Tab asks the binary (SPEC 3.5).
    \\_artoo() {
    \\    local -a lines described plain
    \\    local line
    \\    lines=("${(@f)$(command artoo __complete -- "${(@)words[2,CURRENT]}" 2>/dev/null)}")
    \\    [[ "$lines[1]" == :file ]] && { _files; return; }
    \\    for line in $lines; do
    \\        [[ -n $line ]] || continue
    \\        if [[ $line == *$'\t'* ]]; then
    \\            described+=("${${line%%$'\t'*}//:/\\:}:${line#*$'\t'}")
    \\        else
    \\            plain+=("$line")
    \\        fi
    \\    done
    \\    (( $#described )) && _describe -t values artoo described
    \\    (( $#plain )) && compadd -a plain
    \\}
    \\if [[ "$funcstack[1]" = "_artoo" ]]; then
    \\    _artoo "$@"
    \\else
    \\    compdef _artoo artoo
    \\fi
    \\
;

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn texts(arena: Allocator, root: *const Command, words: []const []const u8, live: []const Candidate) ![]const []const u8 {
    const answer = try candidates(arena, resolve(root, words), words[words.len - 1], live);
    var out: std.ArrayList([]const u8) = .empty;
    switch (answer) {
        .file => try out.append(arena, ":file"),
        .list => |l| for (l) |c| try out.append(arena, c.text),
    }
    return out.items;
}

fn expectTexts(root: *const Command, words: []const []const u8, live: []const Candidate, want: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const got = try texts(arena.allocator(), root, words, live);
    testing.expectEqual(want.len, got.len) catch |e| {
        for (got) |t| std.debug.print("got: {s}\n", .{t});
        return e;
    };
    for (want, got) |x, y| try testing.expectEqualStrings(x, y);
}

const demo = struct {
    fn noop(_: *@import("../app.zig").Context, _: *const command.Invocation) anyerror!void {}
    const rm: Command = .{ .name = "rm", .summary = "Remove", .run = noop, .positionals = &.{.{ .name = "VM", .complete = .vm }}, .flags = &.{.{ .long = "confirm", .kind = .string, .metavar = "TARGET", .help = "Confirm" }} };
    const ssh: Command = .{ .name = "ssh", .summary = "SSH", .run = noop, .positionals = &.{.{ .name = "VM", .complete = .vm }}, .trailing = "CMD" };
    const spec: Command = .{ .name = "spec", .summary = "Spec", .run = noop, .flags = &.{.{ .long = "file", .short = 'f', .kind = .string, .metavar = "PATH", .help = "File" }} };
    const vm: Command = .{ .name = "vm", .summary = "VMs", .children = &.{ rm, ssh } };
    const gw: Command = .{ .name = "gw", .summary = "Gateway", .children = &.{spec} };
    const secret: Command = .{ .name = "__complete", .summary = "", .run = noop, .hidden = true };
    const root: Command = .{ .name = "artoo", .summary = "t", .children = &.{ vm, gw, secret } };
};

test "resolve + candidates: commands, help, flags, values, positionals" {
    const r = &demo.root;
    const live = [_]Candidate{ .{ .text = "naboo", .help = "201 running" }, .{ .text = "hoth" } };
    try expectTexts(r, &.{""}, &.{}, &.{ "vm", "gw", "help" });
    try expectTexts(r, &.{"v"}, &.{}, &.{"vm"});
    try expectTexts(r, &.{ "vm", "" }, &.{}, &.{ "rm", "ssh" });
    try expectTexts(r, &.{ "help", "" }, &.{}, &.{ "vm", "gw" });
    try expectTexts(r, &.{ "help", "vm", "rm", "" }, &live, &.{});
    try expectTexts(r, &.{ "vm", "rm", "" }, &live, &.{ "naboo", "hoth" });
    try expectTexts(r, &.{ "vm", "rm", "n" }, &live, &.{"naboo"});
    try expectTexts(r, &.{ "vm", "rm", "naboo", "" }, &live, &.{});
    try expectTexts(r, &.{ "-o", "json", "vm", "rm", "" }, &live, &.{ "naboo", "hoth" });
    try expectTexts(r, &.{ "vm", "rm", "--confirm", "" }, &live, &.{});
    try expectTexts(r, &.{ "vm", "rm", "-yn", "" }, &live, &.{ "naboo", "hoth" });
    try expectTexts(r, &.{ "vm", "rm", "--co" }, &.{}, &.{ "--confirm", "--color", "--config" });
    try expectTexts(r, &.{ "vm", "-o", "" }, &.{}, &.{ "table", "json" });
    try expectTexts(r, &.{"--output=j"}, &.{}, &.{"--output=json"});
    try expectTexts(r, &.{ "--config", "" }, &.{}, &.{":file"});
    try expectTexts(r, &.{ "gw", "spec", "-f", "" }, &.{}, &.{":file"});
    try expectTexts(r, &.{ "vm", "ssh", "naboo", "--", "" }, &live, &.{});
    try expectTexts(r, &.{ "__complete", "" }, &.{}, &.{});
    try expectTexts(r, &.{ "nope", "" }, &.{}, &.{});
}

test "write: tab-separated, descriptions on one line" {
    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();
    try write(&buf.writer, .{ .list = &.{ .{ .text = "vm", .help = "VMs\tand\nmore" }, .{ .text = "hoth" } } });
    try testing.expectEqualStrings("vm\tVMs and more\nhoth\n", buf.written());
    buf.clearRetainingCapacity();
    try write(&buf.writer, .file);
    try testing.expectEqualStrings(":file\n", buf.written());
}
