//! `artoo rex setup VM…` (SPEC §20.3–§20.6). Stub: replaced by the setup work.

const app = @import("../app.zig");
const cli = @import("../cli.zig");

pub const setup = struct {
    pub const name = "setup";
    pub const summary = "Set up Rex, its agent skill, the agent profile and permissions on guests";
    pub fn run(ctx: *app.Context, _: cli.Args(@This())) !void {
        return ctx.fail(error.Usage, "not implemented yet", .{});
    }
};
