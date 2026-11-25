//! `artoo rex hosts sync` (SPEC §20.9). Stub: replaced by the hosts work.

const app = @import("../app.zig");
const cli = @import("../cli.zig");

const sync = struct {
    pub const name = "sync";
    pub const summary = "Keep the workstation's Rex hosts in step with the guests tagged rex";
    pub fn run(ctx: *app.Context, _: cli.Args(@This())) !void {
        return ctx.fail(error.Usage, "not implemented yet", .{});
    }
};

pub const group = cli.group("hosts", "The workstation's Rex hosts for guests (SPEC 20.9)", &.{cli.leaf(sync)});
