//! `artoo rex hosts sync`: the workstation's Rex hosts in
//! step with the guests tagged `rex` — one host per guest, label the
//! guest's name, endpoint `ssh://<guests.user>@<fqdn>`. Only hosts artoo
//! recorded in `~/.artoo/rex-hosts.json` are edited or removed.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const dns = @import("../unifi/dns.zig");
const k = @import("node.zig");
const rex = @import("../rex/guest.zig");
const hosts = @import("../rex/hosts.zig");

const Context = app.Context;

/// The hosts the guests tagged `rex` want (templates left out), sorted
/// by label; a guest whose name makes no machine name is skipped.
pub fn wanted(ctx: *Context, list: []const vms.Vm) ![]const hosts.Want {
    const a = ctx.arena;
    const cfg = try ctx.config();
    var out: std.ArrayList(hosts.Want) = .empty;
    for (list) |v| {
        if (v.template or v.name.len == 0 or !rex.tagged(v)) continue;
        if (for (out.items) |w| {
            if (std.ascii.eqlIgnoreCase(w.label, v.name)) break true;
        } else false) continue;
        const fqdn = dns.fqdn(a, v.name, cfg.guests.domain) catch |err| switch (err) {
            error.OutOfMemory => |e| return e,
            else => continue,
        };
        try out.append(a, .{ .label = v.name, .endpoint = try hosts.endpoint(a, cfg.guests.user, fqdn) });
    }
    std.mem.sort(hosts.Want, out.items, {}, struct {
        fn f(_: void, x: hosts.Want, y: hosts.Want) bool {
            return std.ascii.lessThanIgnoreCase(x.label, y.label);
        }
    }.f);
    return out.items;
}

const SyncOp = struct {
    c: *pve.Client,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .local,
    target: []const u8 = "Rex hosts",
    rex: hosts.Rex = undefined,
    listed: []const hosts.Host = &.{},
    recorded: []const []const u8 = &.{},
    wants: []const hosts.Want = &.{},
    actions: []const hosts.Action = &.{},
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *SyncOp, ctx: *Context) !void {
        op.recorded = try hosts.loadRecord(ctx);
        switch (try hosts.connect(ctx)) {
            .unavailable => |why| return ctx.fail(error.Refused, "{s}; start Rex here (or install its CLI), then run 'artoo rex hosts sync' again", .{why}),
            .ok => |c| {
                op.rex = c.rex;
                op.listed = c.hosts;
            },
        }
        op.wants = try wanted(ctx, try vms.list(op.c));
        op.actions = try hosts.diff(ctx.arena, op.wants, op.listed, op.recorded);
        var fp: std.ArrayList(u8) = .empty;
        for (op.listed) |h| {
            try fp.print(ctx.arena, "{s}=", .{h.label});
            for (h.endpoints) |e| try fp.print(ctx.arena, "{s},", .{e});
            try fp.append(ctx.arena, ';');
        }
        try fp.append(ctx.arena, '|');
        for (op.recorded) |r| try fp.print(ctx.arena, "{s};", .{r});
        try fp.append(ctx.arena, '|');
        for (op.wants) |w| try fp.print(ctx.arena, "{s}={s};", .{ w.label, w.endpoint });
        op.fp = fp.items;
    }

    fn foreignNote(ctx: *Context, x: hosts.Action) ![]const u8 {
        return std.fmt.allocPrint(ctx.arena, "Rex host {s} ({s}) was not added by artoo and is left alone; to let artoo manage it: 'rex hosts remove {s}', then 'artoo rex hosts sync'.", .{
            try k.clean(ctx, x.label), try k.clean(ctx, try std.mem.join(ctx.arena, ", ", x.have)), x.label,
        });
    }

    pub fn plan(op: *SyncOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        var notes: std.ArrayList([]const u8) = .empty;
        var sends = false;
        for (op.actions) |x| {
            const label = try k.clean(ctx, x.label);
            const have = try k.clean(ctx, try std.mem.join(a, ", ", x.have));
            switch (x.kind) {
                .add => try changes.append(a, .{ .field = label, .from = null, .to = x.want }),
                .edit => try changes.append(a, .{ .field = label, .from = have, .to = x.want }),
                .remove => try changes.append(a, .{ .field = label, .from = have, .to = null }),
                .adopt => try changes.append(a, .{ .field = label, .from = have, .to = "recorded as artoo's (nothing sent)" }),
                .forget => try changes.append(a, .{ .field = label, .from = "recorded, no longer a Rex host", .to = "dropped from the record" }),
                .foreign => try notes.append(a, try foreignNote(ctx, x)),
            }
            if (x.kind == .add or x.kind == .edit or x.kind == .remove) sends = true;
        }
        if (changes.items.len == 0) {
            if (notes.items.len > 0) return ctx.fail(error.NoChange, "nothing to change: the Rex hosts are in step with the guests tagged rex, except — {s}", .{try std.mem.join(a, " ", notes.items)});
            return null;
        }
        var added: std.ArrayList([]const u8) = .empty;
        for (op.actions) |x| if (x.kind == .add) try added.append(a, try k.clean(ctx, x.label));
        if (added.items.len > 0)
            try notes.append(a, try std.fmt.allocPrint(a, "Rex for Mac lists only the hosts saved in the app, not those added here: to open {s} in the app, 'rex hosts remove' it, then Add Remote Host... there with the same address; the next sync adopts it.", .{try std.mem.join(a, ", ", added.items)}));
        try notes.append(a, try std.fmt.allocPrint(a, "artoo records the labels it manages in {s}; it edits and removes only those.", .{hosts.record_path}));
        if (sends) try notes.append(a, "Steps run in order and stop at the first failure; a re-run continues.");
        return .{
            .action = try std.fmt.allocPrint(a, "Sync Rex hosts with {d} guest{s} tagged rex", .{ op.wants.len, if (op.wants.len == 1) "" else "s" }),
            .target = "this machine's Rex hosts (rex hosts)",
            .changes = changes.items,
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *SyncOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *SyncOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        var steps: std.ArrayList(?usize) = .empty;
        for (op.actions) |x| {
            const name: ?[]const u8 = switch (x.kind) {
                .add => try std.fmt.allocPrint(a, "add {s}", .{x.label}),
                .edit => try std.fmt.allocPrint(a, "edit {s}", .{x.label}),
                .remove => try std.fmt.allocPrint(a, "remove {s}", .{x.label}),
                .adopt => try std.fmt.allocPrint(a, "adopt {s}", .{x.label}),
                .forget => try std.fmt.allocPrint(a, "forget {s}", .{x.label}),
                .foreign => null,
            };
            try steps.append(a, if (name) |n| try l.add(a, n) else null);
        }
        errdefer {
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        var record = op.recorded;
        for (op.actions, steps.items) |x, step| {
            const i = step orelse continue;
            l.set(i, .unknown, "");
            const sent: anyerror!void = switch (x.kind) {
                .add => op.rex.add(x.label, x.want),
                .edit => op.rex.edit(x.label, null, x.want),
                .remove => op.rex.remove(x.label),
                .adopt, .forget, .foreign => {},
            };
            sent catch |err| {
                if (err == error.OutOfMemory or err == error.Canceled) return err;
                const why = ctx.diag orelse @errorName(err);
                l.set(i, .failed, why);
                return ctx.fail(error.Partial, "{s}; run 'artoo rex hosts sync' again once that is fixed", .{why});
            };
            record = try hosts.recordAfter(a, record, &.{x});
            hosts.saveRecord(ctx, record) catch |err| {
                l.set(i, .failed, ctx.diag orelse @errorName(err));
                return ctx.fail(error.Partial, "the Rex host {s} changed, but {s} could not be written: {s}", .{ x.label, hosts.record_path, ctx.diag orelse @errorName(err) });
            };
            l.set(i, .done, switch (x.kind) {
                .add, .edit => x.want,
                .remove => "",
                .adopt, .forget => "record only",
                .foreign => "",
            });
        }
    }

    /// A fresh `rex hosts list` shows every recorded host at its endpoint
    /// and none that was removed.
    pub fn verify(op: *SyncOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const now = try op.rex.list();
        for (op.actions) |x| switch (x.kind) {
            .add, .edit, .adopt => {
                const h = hosts.find(now, x.label) orelse return false;
                if (!hosts.onlyAt(h, x.want)) return false;
            },
            .remove => if (hosts.find(now, x.label) != null) return false,
            .forget, .foreign => {},
        };
        const rec = try hosts.loadRecord(ctx);
        return std.mem.eql(u8, try hosts.renderRecord(ctx.arena, rec), try hosts.renderRecord(ctx.arena, try hosts.recordAfter(ctx.arena, op.recorded, op.actions)));
    }

    pub fn done(op: *SyncOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "Rex hosts in step with {d} guest{s} tagged rex", .{ op.wants.len, if (op.wants.len == 1) "" else "s" }) catch "done";
    }
};

const sync = struct {
    pub const name = "sync";
    pub const summary = "Keep the workstation's Rex hosts in step with the guests tagged rex";
    pub const details =
        \\One Rex host per guest tagged rex: the label is the guest's name, the
        \\endpoint ssh://<guests.user>@<name>.<guests.domain> (the SSH config
        \\of 'artoo vm ssh-config' applies). artoo records the labels it
        \\manages in ~/.artoo/rex-hosts.json:
        \\  - a missing host is added
        \\  - a recorded host whose endpoint differs is edited
        \\  - a recorded host whose guest is gone or no longer tagged rex is
        \\    removed
        \\  - a host with the guest's name and exactly the wanted endpoint is
        \\    adopted (recorded, nothing sent)
        \\  - a host with the guest's name and other endpoints that artoo did
        \\    not add is left alone; 'rex hosts remove LABEL', then sync again,
        \\    lets artoo manage it
        \\
        \\The rex CLI is found on PATH (or in Rex for Mac). Without it, or
        \\without a running Rex, the command refuses. It never starts Rex.
    ;
    pub const examples = [_][]const u8{ "artoo rex hosts sync -n", "artoo rex hosts sync" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var op: SyncOp = .{ .c = &c };
        try exec.run(ctx, &op, .{});
    }
};

pub const group = cli.group("hosts", "The workstation's Rex hosts for guests", &.{cli.leaf(sync)});

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const FakeRunner = @import("../secrets/common.zig").FakeRunner;
const B = testkit.Gateway.FakeServer.Behavior;

test {
    _ = hosts;
}

fn ans(s: []const u8) B {
    return .{ .respond = .{ .body = s } };
}

fn expectAll(out: []const u8, wants: []const []const u8) !void {
    for (wants) |want| if (std.mem.find(u8, out, want) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ want, out });
        return error.TestUnexpectedResult;
    };
}

/// A fake `rex` on PATH (an empty executable; the runner answers).
pub fn fakeRex(g: *testkit.Gateway) ![]const u8 {
    const a = g.h.arena.allocator();
    try g.tmp.dir.createDirPath(testing.io, "bin");
    const dir = try g.tmp.dir.realPathFileAlloc(testing.io, "bin", a);
    const exe = try std.fs.path.join(a, &.{ dir, "rex" });
    const f = try std.Io.Dir.cwd().createFile(testing.io, exe, .{ .permissions = .fromMode(0o755) });
    f.close(testing.io);
    try g.h.env.put("PATH", dir);
    return exe;
}

/// `rex hosts list --json` with these `label=endpoint,endpoint` hosts.
pub fn listJson(a: std.mem.Allocator, items: []const hosts.Host) ![]const u8 {
    const H = struct { host: struct { endpoints: []const []const u8, icon: []const u8 = "globe", id: []const u8 = "h", label: []const u8, updated_at: []const u8 = "2026-11-25T10:00:00Z" }, from: []const u8 = "pve", held: bool = false };
    const list = try a.alloc(H, items.len);
    for (items, list) |x, *h| h.* = .{ .host = .{ .endpoints = x.endpoints, .label = x.label } };
    return std.json.Stringify.valueAlloc(a, .{
        .home = .{ .label = "pve", .endpoint = "unix:///run/rex.sock", .this_machine = true, .reached = true },
        .hosts = list,
        .warnings = &[_][]const u8{},
    }, .{});
}

const vm_list = "{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;rex\"},{\"vmid\":206,\"name\":\"hoth\",\"status\":\"stopped\",\"tags\":\"artoo;rex\"},{\"vmid\":207,\"name\":\"tatooine\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":9000,\"name\":\"tpl\",\"status\":\"stopped\",\"tags\":\"artoo;rex\",\"template\":1}]}";

const root = cli.group("artoo", "t", &.{@import("rex.zig").group});

test "rex hosts sync: adds, edits, removes the recorded, adopts, leaves a foreign host alone" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{ ans(vm_list), ans(vm_list) });
    defer g.deinit();
    const a = g.h.arena.allocator();
    const exe = try fakeRex(&g);
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/rex-hosts.json", .data = "{\"labels\":[\"tatooine\",\"endor\"]}\n" });
    const naboo = "ssh://artoo@naboo.lab.example.com";
    const hoth = "ssh://artoo@hoth.lab.example.com";
    const before = try listJson(a, &.{
        .{ .label = "Naboo", .endpoints = &.{naboo} },
        .{ .label = "tatooine", .endpoints = &.{"ssh://artoo@tatooine.lab.example.com"} },
        .{ .label = "studio", .endpoints = &.{"ssh://me@192.168.1.50"} },
    });
    const after = try listJson(a, &.{
        .{ .label = "Naboo", .endpoints = &.{naboo} },
        .{ .label = "hoth", .endpoints = &.{hoth} },
        .{ .label = "studio", .endpoints = &.{"ssh://me@192.168.1.50"} },
    });
    var fake: FakeRunner = .{ .arena = a };
    const list_argv: []const []const u8 = &.{ exe, "hosts", "list", "--json", "--autostart=false" };
    try fake.expect(list_argv, null, .{ .stdout = before });
    try fake.expect(list_argv, null, .{ .stdout = before });
    try fake.expect(&.{ exe, "hosts", "add", "hoth", hoth, "--autostart=false" }, null, .{});
    try fake.expect(&.{ exe, "hosts", "remove", "tatooine", "--autostart=false" }, null, .{});
    try fake.expect(list_argv, null, .{ .stdout = after });
    g.h.hooks.runner = fake.runner();

    try testing.expectEqual(Exit.ok, g.h.run(&root, "rex hosts sync -n"));
    try expectAll(g.h.stdout(), &.{
        "Plan · Sync Rex hosts with 2 guests tagged rex\n",
        "hoth      (none) → ssh://artoo@hoth.lab.example.com\n",
        "naboo     ssh://artoo@naboo.lab.example.com → recorded as artoo's (nothing sent)\n",
        "tatooine  ssh://artoo@tatooine.lab.example.com → (removed)\n",
        "endor     recorded, no longer a Rex host → dropped from the record\n",
        "Rex for Mac lists only the hosts saved in the app, not those added here: to open hoth in the app,",
        "Dry run: nothing was sent.\n",
    });
    try testing.expectEqual(Exit.ok, g.h.run(&root, "rex hosts sync -y"));
    try fake.done();
    try expectAll(g.h.stdout(), &.{ "✓ add hoth", "✓ adopt naboo", "✓ remove tatooine", "✓ forget endor", "Rex hosts in step with 2 guests tagged rex\n" });
    const rec = try g.tmp.dir.readFileAlloc(testing.io, ".artoo/rex-hosts.json", a, .limited(1 << 16));
    try testing.expectEqualStrings("{\n  \"labels\": [\n    \"hoth\",\n    \"naboo\"\n  ]\n}\n", rec);
    const st = try g.tmp.dir.statFile(testing.io, ".artoo/rex-hosts.json", .{});
    try testing.expectEqual(@as(std.posix.mode_t, 0o600), st.permissions.toMode() & 0o777);
}

test "rex hosts sync: edits a recorded host; a foreign one is named; nothing left is no change" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{ ans(vm_list), ans(vm_list) });
    defer g.deinit();
    const a = g.h.arena.allocator();
    const exe = try fakeRex(&g);
    try g.tmp.dir.createDirPath(testing.io, ".artoo");
    try g.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/rex-hosts.json", .data = "{\"labels\":[\"hoth\"]}\n" });
    const hoth = "ssh://artoo@hoth.lab.example.com";
    const before = try listJson(a, &.{
        .{ .label = "naboo", .endpoints = &.{ "ssh://artoo@naboo.lab.example.com", "http://naboo.example.com:7297" } },
        .{ .label = "hoth", .endpoints = &.{"ssh://artoo@192.168.1.31"} },
    });
    const after = try listJson(a, &.{
        .{ .label = "naboo", .endpoints = &.{ "ssh://artoo@naboo.lab.example.com", "http://naboo.example.com:7297" } },
        .{ .label = "hoth", .endpoints = &.{hoth} },
    });
    var fake: FakeRunner = .{ .arena = a };
    const list_argv: []const []const u8 = &.{ exe, "hosts", "list", "--json", "--autostart=false" };
    try fake.expect(list_argv, null, .{ .stdout = before });
    try fake.expect(&.{ exe, "hosts", "edit", "hoth", "--endpoint", hoth, "--autostart=false" }, null, .{});
    try fake.expect(list_argv, null, .{ .stdout = after });
    try fake.expect(list_argv, null, .{ .stdout = after });
    g.h.hooks.runner = fake.runner();

    try testing.expectEqual(Exit.ok, g.h.run(&root, "rex hosts sync -y"));
    try expectAll(g.h.stdout(), &.{
        "hoth  ssh://artoo@192.168.1.31 → ssh://artoo@hoth.lab.example.com\n",
        "Rex host naboo (ssh://artoo@naboo.lab.example.com, http://naboo.example.com:7297) was not added by artoo and is left alone; to let artoo manage it: 'rex hosts remove naboo', then 'artoo rex hosts sync'.",
        "✓ edit hoth",
    });
    try testing.expectEqual(Exit.refused, g.h.run(&root, "rex hosts sync -y"));
    try fake.done();
    try expectAll(g.h.stderr(), &.{"nothing to change: the Rex hosts are in step with the guests tagged rex, except — Rex host naboo"});
}

test "rex hosts sync: refuses without a CLI or a running Rex, sends nothing" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{});
    defer g.deinit();
    const a = g.h.arena.allocator();
    const exe = try fakeRex(&g);
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(&.{ exe, "hosts", "list", "--json", "--autostart=false" }, null, .{ .code = 1, .stderr = "rex: no server is running\n" });
    g.h.hooks.runner = fake.runner();
    try testing.expectEqual(Exit.refused, g.h.run(&root, "rex hosts sync -y"));
    try fake.done();
    try expectAll(g.h.stderr(), &.{"no running Rex on this machine ('rex hosts list' failed (exit 1): rex: no server is running); start Rex here"});
    try testing.expectEqual(@as(usize, 0), g.sent());
}

test "rex hosts sync: a failed add stops the run, recording only what was done" {
    var g: testkit.Gateway = undefined;
    try g.init(&.{ans(vm_list)});
    defer g.deinit();
    const a = g.h.arena.allocator();
    const exe = try fakeRex(&g);
    var fake: FakeRunner = .{ .arena = a };
    try fake.expect(&.{ exe, "hosts", "list", "--json", "--autostart=false" }, null, .{ .stdout = try listJson(a, &.{}) });
    try fake.expect(&.{ exe, "hosts", "add", "hoth", "ssh://artoo@hoth.lab.example.com", "--autostart=false" }, null, .{});
    try fake.expect(&.{ exe, "hosts", "add", "naboo", "ssh://artoo@naboo.lab.example.com", "--autostart=false" }, null, .{ .code = 1, .stderr = "label taken\n" });
    g.h.hooks.runner = fake.runner();
    try testing.expectEqual(Exit.partial, g.h.run(&root, "rex hosts sync -y"));
    try fake.done();
    try expectAll(g.h.stdout(), &.{ "✓ add hoth", "✗ add naboo  failed  'rex hosts add' failed (exit 1): label taken" });
    const rec = try g.tmp.dir.readFileAlloc(testing.io, ".artoo/rex-hosts.json", a, .limited(1 << 16));
    try testing.expectEqualStrings("{\n  \"labels\": [\n    \"hoth\"\n  ]\n}\n", rec);
}
