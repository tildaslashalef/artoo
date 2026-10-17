//! Shared rendering kit (SPEC §4): every command renders through this.

pub const text = @import("ui/text.zig");
pub const style = @import("ui/style.zig");
pub const values = @import("ui/values.zig");
pub const table = @import("ui/table.zig");
pub const blocks = @import("ui/blocks.zig");
pub const json = @import("ui/json.zig");
pub const Ui = @import("ui/Ui.zig");

test {
    _ = text;
    _ = style;
    _ = values;
    _ = table;
    _ = blocks;
    _ = json;
    _ = Ui;
}
