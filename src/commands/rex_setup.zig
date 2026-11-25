//! `artoo rex setup VM…` (SPEC §20.3): Rex, its agent skill and the agy
//! bridge on ordinary guests, through the guest agent. One plan for every
//! guest (a change row per step), confirmed once; each step is read first
//! and reported, not redone, when already right.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const k = @import("node.zig");
const setup_mod = @import("../rex/setup.zig");
const agy = @import("../rex/agy.zig");
const profile = @import("../rex/profile.zig");
const vm_new = @import("vm_new.zig");
const rex_status = @import("rex_status.zig");

const Context = app.Context;
const Guest = setup_mod.Guest;

pub const SetupOp = struct {
    c: *pve.Client,
    words: []const []const u8,
    /// `--force-profile`: overwrite profile files changed on the guest.
    force_profile: bool = false,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    guests: []Guest = &.{},
    ledger: exec.Ledger = .{},
    fp: []const u8 = "",
    /// Guests whose steps did not all converge, with what is left.
    left: std.ArrayList([]const u8) = .empty,

    /// Every guest is read first; one refused guest refuses the run.
    pub fn read(op: *SetupOp, ctx: *Context) !void {
        const a = ctx.arena;
        const c = op.c;
        const all = try vms.list(c);
        var guests: std.ArrayList(Guest) = .empty;
        var names: std.ArrayList([]const u8) = .empty;
        var fp: std.ArrayList(u8) = .empty;
        // Loaded (and refused) once, before any guest is read.
        const prof = try profile.loadConfigured(ctx);
        for (op.words) |w| {
            const v = switch (try vms.find(all, a, w)) {
                .vm => |v| v,
                .missing => return ctx.fail(error.NotFound, "no VM '{s}' on {s} (see 'artoo vm ls --all')", .{ try k.clean(ctx, w), c.node }),
                .ambiguous => return ctx.fail(error.Usage, "several VMs are named '{s}'; use a VMID", .{try k.clean(ctx, w)}),
            };
            const seen = for (guests.items) |g| {
                if (g.vm.vmid == v.vmid) break true;
            } else false;
            if (seen) continue;
            const g = try setup_mod.readGuestWith(ctx, c, v, .{ .agent_profile = prof, .force_profile = op.force_profile });
            try guests.append(a, g);
            try names.append(a, try k.clean(ctx, v.name));
            try fp.print(a, "{d}:{s}:{s};", .{ v.vmid, v.tags, g.state.raw });
            for (g.items.items) |it| for (it.changes) |ch| try fp.print(a, "{s}={s};", .{ ch.field, ch.to orelse "" });
        }
        op.guests = guests.items;
        op.target = try std.mem.join(a, ", ", names.items);
        op.fp = fp.items;
    }

    pub fn plan(op: *SetupOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        var notes: std.ArrayList([]const u8) = .empty;
        var todo: usize = 0;
        var install = false;
        for (op.guests) |*g| {
            if (g.items.items.len > 0) todo += 1;
            for (g.items.items) |it| {
                if (it.kind == .package) install = true;
                try changes.append(a, .{ .field = try std.fmt.allocPrint(a, "{s} {s}", .{ g.vm.name, it.label }), .from = it.from, .to = it.to });
                for (it.changes) |ch| try changes.append(a, .{ .field = try std.fmt.allocPrint(a, "{s} {s}", .{ g.vm.name, ch.field }), .from = ch.from, .to = ch.to });
            }
            const cur = try setup_mod.currentText(a, g);
            const skipped = try setup_mod.skippedText(a, g);
            if (g.items.items.len == 0) {
                try notes.append(a, try std.fmt.allocPrint(a, "{s}: nothing to change.", .{g.vm.name}));
            } else if (cur.len > 0) try notes.append(a, try std.fmt.allocPrint(a, "{s}: already right: {s}.", .{ g.vm.name, cur }));
            if (skipped.len > 0) try notes.append(a, try std.fmt.allocPrint(a, "{s}: not set up: {s}.", .{ g.vm.name, skipped }));
            try notes.appendSlice(a, g.notes.items);
        }
        if (todo == 0) return null;
        if (install) try notes.append(a, "Rex comes from pkgs.superlogical.com, signed by the key embedded in artoo and pinned over Ubuntu's unrelated rex; updates arrive with 'artoo vm upgrade'.");
        try notes.append(a, "Commands as the guest user run with REX_AUTOSTART=0: no step starts a Rex server.");
        try notes.append(a, "Steps run in order and stop at the first failure; nothing is undone automatically. Re-running continues.");
        return .{
            .action = if (op.guests.len == 1)
                try std.fmt.allocPrint(a, "Set up Rex on {s} ({d})", .{ op.guests[0].vm.name, op.guests[0].vm.vmid })
            else
                try std.fmt.allocPrint(a, "Set up Rex on {f}", .{ui.values.count(op.guests.len, "guest")}),
            .target = try k.nodeTarget(ctx, op.c),
            .changes = changes.items,
            .impact = try a.dupe([]const u8, &.{"Rex's server starts on first use as the guest user and stops when idle; with linger, sessions outlive the last logout"}),
            .recovery = "on the guest: 'sudo apt-get purge rex' and remove /etc/apt/{keyrings/rex-archive-keyring.gpg,sources.list.d/rex.sources,preferences.d/rex}; drop the tag with 'artoo vm set VM tags=…'",
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *SetupOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *SetupOp, ctx: *Context) !void {
        op.sendSteps(ctx) catch |err| {
            op.ledger.settle(err);
            ctx.out.writeAll("\n") catch {};
            op.ledger.render(ctx.out, &ctx.ui) catch {};
            return err;
        };
    }

    fn sendSteps(op: *SetupOp, ctx: *Context) !void {
        const a = ctx.arena;
        var rows: std.ArrayList(setup_mod.Report.Rows) = .empty;
        for (op.guests) |*g| try rows.append(a, try setup_mod.addRows(a, &op.ledger, g));
        for (op.guests, rows.items) |*g, row| {
            if (g.items.items.len == 0) continue;
            try setup_mod.apply(ctx, op.c, g, .{ .rows = row });
        }
    }

    /// Every guest read again: each step converged.
    pub fn verify(op: *SetupOp, ctx: *Context) !bool {
        const a = ctx.arena;
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        for (op.guests) |*g| {
            const left = try setup_mod.leftover(ctx, op.c, g);
            if (left.len > 0) try op.left.append(a, try std.fmt.allocPrint(a, "{s} ({s})", .{ g.vm.name, left }));
        }
        if (op.left.items.len > 0) {
            try ctx.out.print("\nStill not right: {s}\n", .{try std.mem.join(a, "; ", op.left.items)});
            return false;
        }
        // SPEC §20.3: 'rex status's checks (§20.7) for each guest; a failed one is exit 8.
        var failed: usize = 0;
        for (op.guests) |*g| {
            const rep = try rex_status.report(ctx, op.c, g.vm);
            try ctx.out.print("\n{s} ({d})\n", .{ rep.vm, rep.vmid });
            try vm_new.renderChecks(ctx, rep.checks);
            failed += vm_new.failures(rep.checks);
        }
        return op.ledger.complete() and failed == 0;
    }

    pub fn done(op: *SetupOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "Rex is set up on {s} — 'artoo rex status' to check", .{op.target}) catch "done";
    }
};

pub const setup = struct {
    pub const name = "setup";
    pub const summary = "Set up Rex, its agent skill, the agent profile and permissions on guests";
    pub const details =
        \\Installs Rex on ordinary artoo guests (not the edge, the router or the
        \\watchdog) through the guest agent and keeps it set up. One plan covers
        \\every guest named; each step is read first and only done when it is
        \\not right yet, so a rerun on a set-up guest changes nothing.
        \\
        \\Steps per guest:
        \\  apt key, source (suite rex.channel) and pin: Rex from
        \\    pkgs.superlogical.com, never Ubuntu's unrelated rex
        \\  install rex when it is missing or not Superlogical's (a guest on
        \\    Rex keeps its version; 'artoo vm upgrade' updates it)
        \\  linger for guests.user: sessions survive the last logout
        \\  terminfo: 'rex terminfo setup --system' when not Ready
        \\  agent skill: 'rex skill setup --session-naming' for each agent Rex
        \\    detects (Claude Code, Codex, OpenCode, pi)
        \\  agy bridge, when agy is on the user's PATH: Rex's skill, and hooks
        \\    that give agy Rex's session context and its status per terminal
        \\  agent profile (agents.profile) and the permission kind: a fenced
        \\    guest without private SSH keys runs agents without prompts, every
        \\    other guest keeps them with bypass mode disabled
        \\  tag rex
        \\
        \\A profile file changed on the guest is left alone and named;
        \\--force-profile puts the profile's back. Afterwards the checks of
        \\'artoo rex status' run for each guest.
        \\
        \\Refused, before anything is sent, for a template, a guest without
        \\the artoo tag, the edge, router or watchdog, a stopped guest or one
        \\whose agent does not answer. No step starts a Rex server.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .help = "Guests to set up (VMID or name)", .complete = .vm, .variadic = true }};
    pub const flags = [_]cli.Flag{.{ .long = "force-profile", .help = "Overwrite agent profile files changed on the guest" }};
    pub const examples = [_][]const u8{ "artoo rex setup naboo -n", "artoo rex setup naboo hoth", "artoo rex setup naboo -y", "artoo rex setup naboo --force-profile" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const words = args.rest("VM");
        if (words.len == 0) return ctx.fail(error.Usage, "name the guests to set up", .{});
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SetupOp = .{ .c = &c, .words = words, .force_profile = args.has("force-profile") };
        exec.run(ctx, &op, .{}) catch |err| switch (err) {
            // SPEC §20.3: a set-up guest is "nothing to change", exit 0.
            error.NoChange => {
                ctx.diag = null;
                if (ctx.json()) return ui.json.envelope(ctx.out, .pve, .{ .result = "unchanged", .guests = op.target }, .{});
                try ctx.out.print("Nothing to change: Rex is set up on {s}.\n", .{op.target});
            },
            else => return err,
        };
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const R = testkit.Gateway.FakeServer.Route;

fn r(match: []const u8, body: []const u8) R {
    return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
}

fn agentOut(a: std.mem.Allocator, code: i64, out: []const u8, err: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = code, .@"out-data" = out, .@"err-data" = err } }, .{});
}

const ok_ping = "{\"data\":{\"result\":{}}}";
const pid = "{\"data\":{\"pid\":42}}";
const naboo_list = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"}]}";
const naboo_rex_list = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;rex\"}]}";

/// The agent-profile read of step 9 (SPEC §20.3): no Claude, no profile.
fn profileRead(a: std.mem.Allocator, f: @import("../rex/profile.zig").ProbeFixture) ![2]R {
    return .{ r("agent/exec HTTP", pid), r("exec-status", try agentOut(a, 0, try @import("../rex/profile.zig").probeOut(a, f), "")) };
}

const no_agents: @import("../rex/profile.zig").ProbeFixture = .{ .agents = "" };

fn expectLines(out: []const u8, lines: []const []const u8) !void {
    for (lines) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
}

const root = cli.group("artoo", "t", &.{cli.group("rex", "t", &.{cli.leaf(setup)})});

test "rex setup -n: the hand-installed guest's pin differs from upstream's; done steps are reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const F = setup_mod.Fixture;
    const pr = try profileRead(a, no_agents);
    const probe = try (F{ .a = a, .pin_hash = try setup_mod.sha256Hex(a, "Package: rex\nPin: origin pkgs.superlogical.com\nPin-Priority: 1001\n\nPackage: rex\nPin: release o=Ubuntu\nPin-Priority: -1\n"), .linger = false }).out();
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        r("GET /api2/json/nodes/pve/qemu HTTP", naboo_list),
        r("agent/ping", ok_ping),
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 0, probe, "")),
        pr[0],
        pr[1],
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "rex setup naboo -n"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try expectLines(g.h.stdout(), &.{
        "Plan · Set up Rex on naboo (201)",
        "naboo apt pin  not upstream's → Rex 1001, every other origin -1 (/etc/apt/preferences.d/rex)",
        "naboo linger   off → on for artoo (sessions survive logout)",
        "naboo tag      artoo → artoo;rex",
        "naboo: already right: apt key, apt source, rex 0.1.0~alpha.23, terminfo, agent skill (claude), permissions (trusted-reach).",
        "naboo: not set up: agy bridge (no agy on the PATH).",
        "Dry run: nothing was sent.",
    });
}

test "rex setup: a set-up guest is nothing to change, exit 0" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const pr = try profileRead(a, no_agents);
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        r("GET /api2/json/nodes/pve/qemu HTTP", naboo_rex_list),
        r("agent/ping", ok_ping),
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 0, try (setup_mod.Fixture{ .a = a }).out(), "")),
        pr[0],
        pr[1],
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "rex setup naboo -y"));
    try expectLines(g.h.stdout(), &.{"Nothing to change: Rex is set up on naboo."});
}

test "rex setup: refusals before anything is sent, one refused guest refuses the run" {
    const list = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":202,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge\"},{\"vmid\":203,\"name\":\"hoth\",\"status\":\"stopped\",\"tags\":\"artoo\"},{\"vmid\":204,\"name\":\"pve-web\",\"status\":\"running\",\"tags\":\"\"},{\"vmid\":9000,\"name\":\"ubuntu\",\"status\":\"stopped\",\"tags\":\"artoo-template\",\"template\":1}]}";
    const l = r("GET /api2/json/nodes/pve/qemu HTTP", list);
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{ l, l, l, l });
    defer g.deinit();
    for ([_][2][]const u8{
        .{ "rex setup bespin -y", "bespin is the edge, the router or the watchdog" },
        .{ "rex setup hoth -y", "hoth is stopped; start it first" },
        .{ "rex setup pve-web -y", "pve-web is not an artoo guest" },
        .{ "rex setup ubuntu -y", "ubuntu is a template" },
    }) |case| {
        try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, case[0]));
        try expectLines(g.h.stderr(), &.{case[1]});
    }
    for (g.srv.received) |req| if (req) |q| try testing.expect(std.mem.startsWith(u8, q, "GET "));
}

test "rex setup: the guest agent not answering refuses" {
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        r("GET /api2/json/nodes/pve/qemu HTTP", naboo_list),
        .{ .match = "agent/ping", .behavior = .{ .respond = .{ .status = 500, .body = "{\"errors\":{\"agent\":\"not running\"}}" } } },
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.refused, g.h.run(&root, "rex setup naboo -y"));
    try expectLines(g.h.stderr(), &.{"the guest agent of naboo does not answer"});
}

test "rex setup: a fresh guest installs Rex, decides terminfo and the skill after the install, tags last" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const F = setup_mod.Fixture;
    const fresh = try (F{ .a = a, .key = "-", .sources_hash = "-", .pin_hash = "-", .pkg = "", .linger = false, .terminfo = null, .skill = null }).out();
    // After the install: terminfo already Ready, no agent detected yet.
    const installed = try (F{ .a = a, .linger = false, .skill = "{\"harnesses\":[{\"id\":\"claude\",\"detected\":false,\"items\":[]}]}" }).out();
    const after = try (F{ .a = a, .skill = "{\"harnesses\":[{\"id\":\"claude\",\"detected\":false,\"items\":[]}]}" }).out();
    const ok = try agentOut(a, 0, "", "");
    const pr = try profileRead(a, no_agents);
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        r("GET /api2/json/nodes/pve/qemu HTTP", naboo_list),
        r("agent/ping", ok_ping),
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 0, fresh, "")),
        pr[0],
        pr[1],
        // key, sources, pin, install
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        // read again after the install
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 0, installed, "")),
        // linger
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        // tag
        r("GET /api2/json/nodes/pve/qemu/201/config", "{\"data\":{\"tags\":\"artoo\",\"digest\":\"d1\"}}"),
        r("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        // verify
        r("GET /api2/json/nodes/pve/qemu HTTP", naboo_rex_list),
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 0, after, "")),
        pr[0],
        pr[1],
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "rex setup naboo -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    const out = g.h.stdout();
    try expectLines(out, &.{
        "naboo package      (none) → rex from pkgs.superlogical.com (preview)",
        "naboo terminfo     (none) → rex terminfo setup --system, unless Ready (read after the install)",
        "naboo apt key      done  /etc/apt/keyrings/rex-archive-keyring.gpg",
        "naboo package      done  rex 0.1.0~alpha.23",
        "naboo terminfo     skipped  terminfo",
        "naboo agent skill  skipped  agent skill (no agent detected)",
        "naboo tag          done  rex",
        "Rex is set up on naboo",
    });
    var put: ?[]const u8 = null;
    var wrote_key = false;
    for (g.srv.received) |req| if (req) |q| {
        if (std.mem.startsWith(u8, q, "PUT ")) put = q;
        // The keyring travels as base64 on the agent's stdin.
        if (std.mem.find(u8, q, "rex-archive-keyring.gpg") != null and std.mem.find(u8, q, "input-data=") != null) wrote_key = true;
    };
    try testing.expect(std.mem.endsWith(u8, put.?, "tags=artoo%3Brex&digest=d1"));
    try testing.expect(wrote_key);
}

test "rex setup: a failed install stops the run and shows the ledger" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const probe = try (setup_mod.Fixture{ .a = a, .pkg = "", .terminfo = null, .skill = null }).out();
    const pr = try profileRead(a, no_agents);
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        r("GET /api2/json/nodes/pve/qemu HTTP", naboo_list),
        r("agent/ping", ok_ping),
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 0, probe, "")),
        pr[0],
        pr[1],
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 100, "", "E: Unable to locate package rex")),
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.partial, g.h.run(&root, "rex setup naboo -y"));
    try expectLines(g.h.stdout(), &.{ "naboo package      failed", "naboo terminfo     not run", "naboo tag          not run" });
    try expectLines(g.h.stderr(), &.{"installing rex failed (exit 100): E: Unable to locate package rex"});
}

test "rex setup: the agy bridge is written as the user, other hooks kept" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const F = setup_mod.Fixture;
    const hooks = "{\"mine\":{\"Stop\":[]}}";
    const before = try (F{ .a = a, .agy = "/home/artoo/.local/bin/agy", .hooks = hooks }).out();
    const after = try (F{ .a = a, .agy = "/home/artoo/.local/bin/agy", .agy_files = true, .hooks = (try agy.mergeHooks(a, hooks)).? }).out();
    const ok = try agentOut(a, 0, "", "");
    const pr_before = try profileRead(a, .{ .agents = "agy " });
    const pr_after = try profileRead(a, .{ .agents = "agy ", .fish = @import("../rex/permissions.zig").fishFile(.trusted_reach) });
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        r("GET /api2/json/nodes/pve/qemu HTTP", naboo_rex_list),
        r("agent/ping", ok_ping),
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 0, before, "")),
        pr_before[0],
        pr_before[1],
        // agy skill, hook, hooks
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        // permissions: read again, the user's directories, the fish file
        pr_before[0],
        pr_before[1],
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        r("agent/exec HTTP", pid),
        r("exec-status", ok),
        r("GET /api2/json/nodes/pve/qemu HTTP", naboo_rex_list),
        r("agent/exec HTTP", pid),
        r("exec-status", try agentOut(a, 0, after, "")),
        pr_after[0],
        pr_after[1],
    });
    defer g.deinit();
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "rex setup naboo -y"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try expectLines(g.h.stdout(), &.{
        "naboo agy hooks    other hooks kept → key artoo-rex in ~/.gemini/config/hooks.json (SessionStart, PreInvocation, Stop)",
        "naboo agy hook     done  ~/.config/artoo/agy-rex-hook",
        "naboo permissions  done  1 file written, trusted-reach",
    });
    var user_writes: usize = 0;
    for (g.srv.received) |req| if (req) |q| {
        if (std.mem.find(u8, q, "runuser") != null and std.mem.find(u8, q, "input-data=") != null) user_writes += 1;
        try testing.expect(std.mem.find(u8, q, "runuser%20-l") == null);
    };
    try testing.expectEqual(@as(usize, 3), user_writes);
}
