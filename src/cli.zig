//! Declarative CLI: command table, parser, help, suggestions (SPEC §3).

const command = @import("cli/command.zig");

pub const Kind = command.Kind;
pub const Flag = command.Flag;
pub const Positional = command.Positional;
pub const Complete = command.Complete;
pub const Choice = command.Choice;
pub const Command = command.Command;
pub const Invocation = command.Invocation;
pub const Globals = command.Globals;
pub const Output = command.Output;
pub const Color = command.Color;
pub const Args = command.Args;
pub const global_flags = command.global_flags;
pub const group = command.group;
pub const leaf = command.leaf;

pub const parse = @import("cli/parse.zig");
pub const help = @import("cli/help.zig");
pub const suggest = @import("cli/suggest.zig");
pub const complete = @import("cli/complete.zig");

test {
    _ = parse;
    _ = help;
    _ = suggest;
    _ = complete;
}
