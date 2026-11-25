//! `artoo rex …`: Rex and the coding agents on ordinary guests.

const cli = @import("../cli.zig");

pub const group = cli.group("rex", "Rex and the coding agents on guests", &.{
    cli.leaf(@import("rex_setup.zig").setup),
    cli.leaf(@import("rex_status.zig").status),
    @import("rex_hosts.zig").group,
});

test {
    _ = @import("rex_setup.zig");
    _ = @import("rex_status.zig");
    _ = @import("rex_hosts.zig");
    _ = @import("../rex/guest.zig");
    _ = @import("../rex/profile.zig");
    _ = @import("../rex/setup.zig");
    _ = @import("../rex/agy.zig");
}
