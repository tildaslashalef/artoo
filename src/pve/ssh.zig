//! Root SSH to Proxmox for the one thing the API cannot do: placing the
//! vendor snippet in `local:snippets` (SPEC §9.2, §17.2). BatchMode, strict
//! host-key checking, the configured key only; the remote script is fixed
//! and the snippet travels on stdin. An existing file is never replaced:
//! names are content-addressed, so a file with the right name and other
//! content is reported, not overwritten.

const std = @import("std");
const app = @import("../app.zig");
const files = @import("../files.zig");
const proc = @import("../proc.zig");
const ui = @import("../ui.zig");
const vendor = @import("../guest/vendor.zig");

const Context = app.Context;

pub const Placement = enum { written, present };

/// `ssh … root@<pve.ssh_host> <script>`.
fn argv(ctx: *Context, script: []const u8) ![]const []const u8 {
    const cfg = try ctx.config();
    const identity = files.expandHome(ctx.arena, ctx.env, cfg.pve.ssh_identity) catch
        return ctx.fail(error.ConfigInvalid, "cannot expand pve.ssh_identity: HOME is not set", .{});
    const out = try ctx.arena.dupe([]const u8, &.{
        "/usr/bin/ssh",
        "-i",
        identity,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=10",
        try std.fmt.allocPrint(ctx.arena, "root@{s}", .{cfg.pve.ssh_host}),
        script,
    });
    return out;
}

/// The remote script for `name` (validated: `artoo-vendor-<hex>.yaml`).
pub fn placeScript(arena: std.mem.Allocator, name: []const u8) ![]const u8 {
    std.debug.assert(vendor.validName(name));
    return std.fmt.allocPrint(arena,
        \\set -eu
        \\f={s}/{s}
        \\test -d {s}
        \\if [ -e "$f" ]; then echo present; sha256sum "$f"; exit 0; fi
        \\umask 022
        \\t="$f.artoo-tmp.$$"
        \\trap 'rm -f "$t"' EXIT
        \\cat > "$t"
        \\mv -n "$t" "$f"
        \\echo written; sha256sum "$f"
    , .{ vendor.snippets_dir, name, vendor.snippets_dir });
}

/// Ensure the snippet is on Proxmox with exactly this content.
pub fn placeSnippet(ctx: *Context, s: vendor.Snippet) !Placement {
    if (!vendor.validName(s.name)) return ctx.fail(error.Usage, "refusing snippet name '{s}'", .{s.name});
    const runner = ctx.test_hooks.runner orelse proc.Runner{};
    const cmd = try argv(ctx, try placeScript(ctx.arena, s.name));
    const host = cmd[cmd.len - 2];
    const r = runner.run(ctx.io, ctx.arena, cmd, s.text) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        error.NotFound => return ctx.fail(error.Network, "/usr/bin/ssh not found", .{}),
        error.Failed => return ctx.fail(error.Network, "ssh to {s} failed to run", .{host}),
    };
    if (r.code == null or r.code.? != 0) {
        const why = try firstLine(ctx, r.stderr);
        // 255: ssh itself failed (connect, host key, auth) — nothing ran.
        if (r.code == 255) return ctx.fail(error.Network, "ssh to {s} failed: {s}", .{ host, why });
        return ctx.fail(error.OutcomeUnknown, "placing {s} on Proxmox failed: {s}; check {s}/ before retrying", .{ s.name, why, vendor.snippets_dir });
    }
    var lines = std.mem.tokenizeScalar(u8, r.stdout, '\n');
    const word = lines.next() orelse "";
    const sum = lines.next() orelse "";
    const placement = std.meta.stringToEnum(Placement, word) orelse
        return ctx.fail(error.OutcomeUnknown, "unexpected answer while placing {s}; check {s}/", .{ s.name, vendor.snippets_dir });
    if (!std.mem.startsWith(u8, sum, s.sha256)) {
        return ctx.fail(error.Refused, "{s}/{s} exists on Proxmox with other content; it was not replaced (inspect it over SSH)", .{ vendor.snippets_dir, s.name });
    }
    return placement;
}

fn firstLine(ctx: *Context, text: []const u8) ![]const u8 {
    const t = std.mem.trim(u8, text, " \r\n");
    const line = t[0 .. std.mem.findScalar(u8, t, '\n') orelse t.len];
    return if (line.len == 0) "no message" else ui.text.sanitize(ctx.arena, line, .line);
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "placeScript: fixed script, name and directory only" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const s = try placeScript(a.allocator(), "artoo-vendor-0123456789ab.yaml");
    try testing.expect(std.mem.startsWith(u8, s, "set -eu\nf=/var/lib/vz/snippets/artoo-vendor-0123456789ab.yaml\ntest -d /var/lib/vz/snippets\n"));
    try testing.expect(std.mem.find(u8, s, "mv -n \"$t\" \"$f\"") != null);
}
