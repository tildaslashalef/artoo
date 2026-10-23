//! artoo — home-lab CLI for a Proxmox VE host, a UniFi gateway and a Cloudflare zone.
//! Design: docs/SPEC.md. Process wiring only; see dispatch.zig.

const std = @import("std");
const Io = std.Io;

const dispatch = @import("dispatch.zig");
const registry = @import("commands/registry.zig");

test {
    _ = @import("guest/crypt512.zig");
    _ = @import("cli.zig");
    _ = @import("ui.zig");
    _ = @import("files.zig");
    _ = @import("config.zig");
    _ = @import("commands/registry.zig");
    _ = @import("dispatch.zig");
    _ = @import("proc.zig");
    _ = @import("secrets.zig");
    _ = @import("setup_file.zig");
    _ = @import("prompt.zig");
    _ = @import("http.zig");
    _ = @import("exec.zig");
    _ = @import("update/release.zig");
    _ = @import("update/archive.zig");
    _ = @import("update/install.zig");
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);
    const words: []const []const u8 = if (argv.len > 0) argv[1..] else &.{};

    // Streaming (not positional) writers: positional writes would overwrite
    // a redirected file from offset 0 instead of appending to it.
    var out_buf: [16 * 1024]u8 = undefined;
    var out_file: Io.File.Writer = .initStreaming(.stdout(), init.io, &out_buf);
    var err_buf: [4096]u8 = undefined;
    var err_file: Io.File.Writer = .initStreaming(.stderr(), init.io, &err_buf);

    const code = dispatch.run(.{
        .arena = arena,
        .gpa = init.gpa,
        .io = init.io,
        .env = init.environ_map,
        .out = &out_file.interface,
        .err = &err_file.interface,
        .out_file = .stdout(),
        .err_file = .stderr(),
        .argv0 = if (argv.len > 0) argv[0] else "",
    }, &registry.root, words);
    out_file.interface.flush() catch {};
    err_file.interface.flush() catch {};
    std.process.exit(@backingInt(code));
}
