//! `artoo rex status [VM…]` (SPEC §20.7). Stub: replaced by the status work.

const app = @import("../app.zig");
const cli = @import("../cli.zig");

pub const status = struct {
    pub const name = "status";
    pub const summary = "Show Rex and the agents on guests tagged rex (read-only)";
    pub fn run(ctx: *app.Context, _: cli.Args(@This())) !void {
        return ctx.fail(error.Usage, "not implemented yet", .{});
    }
};
