//! `artoo completion fish|bash|zsh` and the hidden `artoo __complete`
//! (SPEC §3.5). Candidates come from the command table; VM and template
//! names are read from Proxmox under a 1 s deadline, and a new guest's
//! NAME offers the curated names no VM carries yet. A failure completes
//! nothing beyond offline candidates: stdout is the user's prompt line,
//! never an error message.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const guest_names = @import("../guest/names.zig");

const Context = app.Context;
const complete = cli.complete;

pub const completion = struct {
    pub const name = "completion";
    pub const summary = "Print the shell completion script (fish, bash, zsh)";
    pub const details =
        \\The script asks artoo on every Tab, so new commands and flags complete
        \\without regenerating it. VM and template names are read from Proxmox
        \\(1 s deadline; nothing is completed when Proxmox or the token is not
        \\available); 'vm new' offers the curated names no VM carries yet.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "SHELL", .help = "fish, bash or zsh" }};
    pub const examples = [_][]const u8{
        "artoo completion fish > ~/.config/fish/completions/artoo.fish",
        "artoo completion zsh > \"${fpath[1]}/_artoo\"",
        "echo 'source <(artoo completion bash)' >> ~/.bashrc",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const word = args.pos("SHELL");
        const shell = std.meta.stringToEnum(complete.Shell, word) orelse
            return ctx.fail(error.Usage, "SHELL must be fish, bash or zsh, got '{s}'", .{word});
        try ctx.out.writeAll(complete.script(shell));
    }
};

pub const internal = struct {
    pub const name = "__complete";
    pub const summary = "Completion candidates for the shell scripts";
    pub const hidden = true;
    pub const trailing = "WORDS";

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const words = args.inv.trailing;
        const root = &@import("registry.zig").root;
        const target = complete.resolve(root, if (words.len == 0) &.{""} else words);
        const current = if (words.len == 0) "" else words[words.len - 1];
        const live: []const complete.Candidate = switch (target) {
            .positional => |p| switch (p.complete) {
                .vm, .template => names(ctx, p.complete == .template) catch &.{},
                .guest_name => try curated(ctx),
                else => &.{},
            },
            else => &.{},
        };
        try complete.write(ctx.out, try complete.candidates(ctx.arena, target, current, live));
    }
};

/// VM (or template) names from Proxmox, with their VMID and status.
fn names(ctx: *Context, templates: bool) ![]const complete.Candidate {
    ctx.globals.timeout = 1;
    var c = try pve.Client.open(ctx);
    defer c.deinit();
    var out: std.ArrayList(complete.Candidate) = .empty;
    for (try vms.list(&c)) |v| {
        if (v.template != templates or v.name.len == 0) continue;
        const help = if (templates)
            try std.fmt.allocPrint(ctx.arena, "{d}", .{v.vmid})
        else
            try std.fmt.allocPrint(ctx.arena, "{d} {s}", .{ v.vmid, v.status });
        try out.append(ctx.arena, .{ .text = v.name, .help = help });
    }
    return out.items;
}

/// Curated guest names (SPEC §9.1) no VM or template carries; all of
/// them when Proxmox cannot be asked.
fn curated(ctx: *Context) ![]const complete.Candidate {
    const taken: []const vms.Vm = taken: {
        ctx.globals.timeout = 1;
        var c = pve.Client.open(ctx) catch break :taken &.{};
        defer c.deinit();
        break :taken vms.list(&c) catch &.{};
    };
    var out: std.ArrayList(complete.Candidate) = .empty;
    for (guest_names.star_wars) |n| if (!has(taken, n)) try out.append(ctx.arena, .{ .text = n, .help = "Star Wars" });
    for (guest_names.middle_earth) |n| if (!has(taken, n)) try out.append(ctx.arena, .{ .text = n, .help = "Middle-earth" });
    return out.items;
}

fn has(list: []const vms.Vm, name: []const u8) bool {
    for (list) |v| if (std.mem.eql(u8, v.name, name)) return true;
    return false;
}

const testing = std.testing;
const testkit = @import("../testkit.zig");

test "__complete: commands offline, VM names from Proxmox, nothing on failure" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":200,\"name\":\"bespin\",\"status\":\"running\"},{\"vmid\":9000,\"name\":\"ubuntu-2604\",\"status\":\"stopped\",\"template\":1}]}" } },
        .{ .respond = .{ .status = 500, .body = "" } },
    });
    defer g.deinit();
    const root = &@import("registry.zig").root;
    try testing.expectEqual(testkit.Exit.ok, g.h.run(root, "__complete -- sv"));
    try testing.expectEqualStrings("svc\tService names <name>.apps.<guests.domain> on the edge VM (SPEC §9.6)\n", g.h.stdout());
    try testing.expectEqual(@as(usize, 0), g.sent());
    try testing.expectEqual(testkit.Exit.ok, g.h.runArgs(root, &.{ "__complete", "--", "vm", "rm", "" }));
    try testing.expectEqualStrings("bespin\t200 running\n", g.h.stdout());
    try testing.expectEqual(testkit.Exit.ok, g.h.runArgs(root, &.{ "__complete", "--", "vm", "rm", "" }));
    try testing.expectEqualStrings("", g.h.stdout());
    try testing.expectEqual(testkit.Exit.ok, g.h.run(root, "completion fish"));
    try testing.expect(std.mem.find(u8, g.h.stdout(), "complete -c artoo") != null);
    try testing.expectEqual(testkit.Exit.usage, g.h.run(root, "completion tcsh"));
}

test "__complete: vm new NAME offers free curated names, all of them offline" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":[{\"vmid\":200,\"name\":\"naboo\",\"status\":\"running\"}]}" } },
        .{ .respond = .{ .status = 500, .body = "" } },
    });
    defer g.deinit();
    const root = &@import("registry.zig").root;
    try testing.expectEqual(testkit.Exit.ok, g.h.runArgs(root, &.{ "__complete", "--", "vm", "new", "na" }));
    try testing.expectEqualStrings("nal-hutta\tStar Wars\n", g.h.stdout());
    try testing.expectEqual(testkit.Exit.ok, g.h.runArgs(root, &.{ "__complete", "--", "vm", "new", "na" }));
    try testing.expectEqualStrings("naboo\tStar Wars\nnal-hutta\tStar Wars\n", g.h.stdout());
}

test "every positional named VM completes live VM names" {
    const root = &@import("registry.zig").root;
    try walk(root);
}

fn walk(c: *const cli.Command) !void {
    for (c.positionals) |p| {
        if (std.mem.eql(u8, p.name, "VM")) try testing.expectEqual(cli.Complete.vm, p.complete);
    }
    for (c.children) |*ch| try walk(ch);
}
