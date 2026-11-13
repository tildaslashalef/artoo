//! `artoo vm password VM` (SPEC §9.1, §9.17): reveal the guest user's
//! stored sudo password, or `--reset` it — a new random password set
//! through the guest agent (as a SHA-512 crypt hash) and stored in this
//! machine's secret store, so any machine holding the Proxmox token can
//! get a working password without the one that created the guest.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const clipboard = @import("../clipboard.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const crypt = @import("../guest/crypt512.zig");
const secrets = @import("../secrets.zig");
const template = @import("template.zig");
const vm_new = @import("vm_new.zig");
const k = @import("node.zig");

const Context = app.Context;

pub fn secretName(ctx: *Context, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "guest/{s}", .{name});
}

pub const password = struct {
    pub const name = "password";
    pub const summary = "Copy the guest user's sudo password to the clipboard, or --reset it";
    pub const details =
        \\For sudo and the console. Copied to the clipboard (pbcopy; wl-copy,
        \\xclip or xsel), or with --show printed after confirmation; only from
        \\a terminal, never in JSON.
        \\
        \\--reset sets a new random password for the guest user through the
        \\guest agent (sent as a SHA-512 crypt hash) and stores it in this
        \\machine's secret store as guest/<name>; the guest's shadow entry is
        \\read back to verify. Copies of the old password on other machines
        \\stop working: reset there too, or carry this one with 'artoo config
        \\export --guest-passwords'. SSH keys and open sessions are untouched.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .complete = .vm, .help = "VMID or exact VM name" }};
    pub const flags = [_]cli.Flag{
        .{ .long = "show", .help = "Print the password instead (after confirmation)" },
        .{ .long = "reset", .help = "Set a new password on the guest and store it here" },
    };
    pub const examples = [_][]const u8{
        "artoo vm password web-01",
        "artoo vm password web-01 --show",
        "artoo vm password web-01 --reset -n",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        if (args.has("reset")) {
            if (args.has("show")) return ctx.fail(error.Usage, "--reset and --show do not combine; reset first, then 'artoo vm password {s}'", .{args.pos("VM")});
            var c = try pve.Client.open(ctx);
            defer c.deinit();
            var op: ResetOp = .{ .c = &c, .word = args.pos("VM") };
            return exec.run(ctx, &op, .{});
        }
        if (ctx.json()) return ctx.fail(error.Usage, "the password is never printed as JSON", .{});
        if (ctx.ui.width == null) return ctx.fail(error.Refused, "the password is revealed only to a terminal", .{});
        const word = args.pos("VM");
        const store = try ctx.secretStore();
        // Accept a name without asking Proxmox when the entry exists.
        const nm = if (store.exists(ctx.io, ctx.arena, try secretName(ctx, word)) catch false) word else blk: {
            var c = try pve.Client.open(ctx);
            defer c.deinit();
            break :blk (try vms.resolve(&c, word)).name;
        };
        const secret_name = try secretName(ctx, nm);
        const pw = (try store.get(ctx.io, ctx.arena, secret_name)) orelse
            return ctx.fail(error.SecretMissing, "no stored password {s} on this machine; 'artoo vm password {s} --reset' sets a new one", .{ secret_name, nm });
        if (args.has("show")) {
            try ctx.confirm("Show the password of {s}?", .{nm});
            try ctx.out.print("{s}\n", .{pw});
            return;
        }
        clipboard.copy(ctx.io, ctx.arena, ctx.env, pw, ctx.test_hooks.runner) catch |err| switch (err) {
            error.ClipboardUnavailable => return ctx.fail(error.Refused, "no clipboard helper worked (pbcopy; wl-copy, xclip or xsel with a display); use --show", .{}),
            else => |e| return e,
        };
        try ctx.out.print("Copied the password of {s} to the clipboard.\n", .{nm});
    }
};

/// `vm password --reset` on the mutation pipeline (SPEC §8.2).
const ResetOp = struct {
    c: *pve.Client,
    word: []const u8,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .pve,
    target: []const u8 = "",
    vm: ?vms.Vm = null,
    user: []const u8 = "",
    secret_name: []const u8 = "",
    stored: bool = false,
    where: []const u8 = "",
    hash: []const u8 = "",
    fp: []const u8 = "",
    ledger: exec.Ledger = .{},

    pub fn read(op: *ResetOp, ctx: *Context) !void {
        const v = try vms.resolve(op.c, op.word);
        op.vm = v;
        op.target = try k.clean(ctx, v.name);
        if (v.template) return ctx.fail(error.Refused, "{s} is a template; it has no guest user to reset", .{op.target});
        if (!template.taggedWith(v.tags, vm_new.tag)) return ctx.fail(error.Refused, "{s} is not an artoo guest (no '{s}' tag)", .{ op.target, vm_new.tag });
        if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first ('artoo vm start {s}')", .{ op.target, try k.clean(ctx, v.status), op.target });
        if (!try agent.ping(op.c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer", .{op.target});
        op.user = (try ctx.config()).guests.user;
        op.secret_name = try secretName(ctx, v.name);
        if (!secrets.validName(op.secret_name)) return ctx.fail(error.Refused, "{s} is not a name artoo stores a password under (lowercase letters, digits, '-', '_', '.')", .{op.target});
        const store = try ctx.secretStore();
        op.where = store.describe(ctx.arena);
        // A store that does not answer refuses here, before the guest is
        // changed — not after, when the new password could not be kept.
        op.stored = store.exists(ctx.io, ctx.arena, op.secret_name) catch
            return ctx.fail(error.SecretStoreUnavailable, "{s} did not answer; nothing was changed", .{op.where});
        op.fp = try std.fmt.allocPrint(ctx.arena, "{d} {s}", .{ v.vmid, v.status });
    }

    pub fn plan(op: *ResetOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const v = op.vm.?;
        return .{
            .action = try std.fmt.allocPrint(a, "Reset the sudo password of {s} on {s} ({d})", .{ op.user, op.target, v.vmid }),
            .target = try std.fmt.allocPrint(a, "the guest agent of {s} on {s}; {s}", .{ op.target, try k.nodeTarget(ctx, op.c), op.where }),
            .changes = try a.dupe(ui.blocks.Change, &.{
                .{ .field = try std.fmt.allocPrint(a, "password of {s}", .{op.user}), .from = "current", .to = "new, random (24 characters)" },
                .{ .field = op.secret_name, .from = if (op.stored) "stored" else null, .to = "the new password" },
            }),
            .impact = try a.dupe([]const u8, &.{
                "Copies of the old password on other machines stop working (reset there, or 'artoo config export --guest-passwords')",
                "SSH keys, open sessions and running processes are untouched",
                "The VM's cloud-init password (first boot only) is not changed",
            }),
        };
    }

    pub fn fingerprint(op: *ResetOp) []const u8 {
        return op.fp;
    }

    pub fn send(op: *ResetOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const vmid = op.vm.?.vmid;
        const s_set = try l.add(a, "set password (guest agent)");
        const s_store = try l.add(a, "store password");

        var pw_buf: [crypt.password_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &pw_buf);
        var salt_buf: [crypt.salt_len]u8 = undefined;
        var pw: []const u8 = &pw_buf;
        var salt: []const u8 = &salt_buf;
        if (ctx.test_hooks.guest_password) |fixed| {
            pw = fixed.password;
            salt = fixed.salt;
        } else {
            try crypt.generatePassword(ctx.io, &pw_buf, pw_buf.len);
            try crypt.generateSalt(ctx.io, &salt_buf);
        }
        var buf: [crypt.hash_buf_len]u8 = undefined;
        op.hash = try a.dupe(u8, crypt.sha512Crypt(&buf, pw, salt) catch return ctx.fail(error.Internal, "password hashing failed", .{}));

        // The guest first: if storing then fails, a second reset recovers;
        // the other order could leave a stored password the guest lacks.
        const params = [_]pve.Param{
            .{ .name = "username", .value = op.user },
            .{ .name = "password", .value = op.hash },
            .{ .name = "crypted", .value = "1" },
        };
        _ = op.c.send(.POST, try op.c.nodePath("/qemu/{d}/agent/set-user-password", .{vmid}), &params) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            // Refused before the agent ran: nothing changed.
            error.Usage, error.AuthFailed, error.PermissionDenied, error.NotFound => {
                l.set(s_set, .failed, "");
                return err;
            },
            // A 5xx (the agent timed out: it may still run the command)
            // or a lost answer: the guest decides. Its shadow entry says
            // whether the new hash arrived.
            else => {
                const why = try k.clean(ctx, ctx.diag orelse @errorName(err));
                ctx.diag = null;
                if (!try guestHas(op, ctx)) {
                    l.set(s_set, .unknown, "");
                    return ctx.fail(error.OutcomeUnknown, "setting the password of {s} did not answer clearly ({s}); the guest does not show it yet and may still apply it — the stored password is unchanged; 'artoo vm password {s} --reset' again is safe", .{ op.target, why, op.target });
                }
            },
        };
        l.set(s_set, .done, op.user);

        const store = try ctx.secretStore();
        store.set(ctx.io, a, op.secret_name, pw) catch |err| {
            l.set(s_store, .failed, @errorName(err));
            return ctx.fail(error.Partial, "the password of {s} was changed on the guest but could not be stored in {s}; run 'artoo vm password {s} --reset' again", .{ op.target, op.where, op.target });
        };
        l.set(s_store, .done, op.secret_name);
    }

    pub fn verify(op: *ResetOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const on_guest = guestHas(op, ctx) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => |e| return e,
            else => return ctx.fail(error.Partial, "the password of {s} was set and stored, but its shadow entry could not be read back ({s})", .{ op.target, try k.clean(ctx, ctx.diag orelse @errorName(err)) }),
        };
        if (!on_guest) return false;
        const store = try ctx.secretStore();
        return store.exists(ctx.io, ctx.arena, op.secret_name) catch
            ctx.fail(error.Partial, "the password of {s} was set, but {s} did not answer when read back", .{ op.target, op.where });
    }

    pub fn done(op: *ResetOp) []const u8 {
        return std.fmt.allocPrint(op.c.ctx.arena, "new sudo password of {s} on {s} stored as {s} — 'artoo vm password {s}' copies it", .{ op.user, op.target, op.secret_name, op.target }) catch "password reset";
    }
};

/// Whether the guest user's shadow entry holds exactly the hash sent (the
/// hash is not the password and is already known to Proxmox).
fn guestHas(op: *ResetOp, ctx: *Context) !bool {
    const r = try agent.exec(op.c, op.vm.?.vmid, &.{ "getent", "shadow", op.user }, null, 30_000);
    if (!r.ok()) return ctx.fail(error.TaskFailed, "'getent shadow {s}' failed on {s} (exit {?d})", .{ op.user, op.target, r.code });
    return std.mem.eql(u8, shadowHash(r.out), op.hash);
}

/// `user:HASH:…` → `HASH`.
fn shadowHash(line: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, std.mem.trim(u8, line, " \r\n"), ':');
    _ = it.next();
    return it.next() orelse "";
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const B = testkit.Gateway.FakeServer.Behavior;

const list_body = "{\"data\":[{\"vmid\":205,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":150,\"name\":\"other\",\"status\":\"running\"},{\"vmid\":101,\"name\":\"hoth\",\"status\":\"stopped\",\"tags\":\"artoo\"}]}";
const ping_body = "{\"data\":{\"result\":{}}}";
const pid_body = "{\"data\":{\"pid\":42}}";

fn ans(s: []const u8) B {
    return .{ .respond = .{ .body = s } };
}

fn formValue(a: std.mem.Allocator, body: []const u8, key: []const u8) ![]const u8 {
    var it = std.mem.splitScalar(u8, body, '&');
    while (it.next()) |kv| {
        const eq = std.mem.findScalar(u8, kv, '=') orelse continue;
        if (!std.mem.eql(u8, kv[0..eq], key)) continue;
        const raw = try a.dupe(u8, kv[eq + 1 ..]);
        return std.Uri.percentDecodeInPlace(raw);
    }
    return error.TestUnexpectedResult;
}

test "shadowHash" {
    try testing.expectEqualStrings("$6$s$h", shadowHash("artoo:$6$s$h:20000:0:99999:7:::\n"));
    try testing.expectEqualStrings("", shadowHash(""));
}

test "vm password --reset: dry run shows the plan and sends nothing" {
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{ ans(list_body), ans(ping_body) });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm password naboo --reset -n"));
    try expectAll(g.h.stdout(), &.{
        "Plan · Reset the sudo password of artoo on naboo (205)\n",
        "password of artoo  current → new, random (24 characters)\n",
        "guest/naboo        (none) → the new password\n",
        "Copies of the old password on other machines stop working",
        "Dry run: nothing was sent.\n",
    });
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}

const fixed_pw = "Fixed-Test-Password-0123";
const fixed_salt = "saltsaltsaltsalt";

fn resetRoutes(a: std.mem.Allocator, shadow_hash: []const u8) ![]const testkit.Gateway.FakeServer.Route {
    return resetRoutesWith(a, shadow_hash, ans("{\"data\":null}"), 0);
}

/// The reset's requests; `set` answers the password write, `getent_exit`
/// is the shadow read's exit code.
fn resetRoutesWith(a: std.mem.Allocator, shadow_hash: []const u8, set: B, getent_exit: i64) ![]const testkit.Gateway.FakeServer.Route {
    const shadow = try std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = getent_exit, .@"out-data" = try std.fmt.allocPrint(a, "artoo:{s}:20000:0:99999:7:::\n", .{shadow_hash}) } }, .{});
    return a.dupe(testkit.Gateway.FakeServer.Route, &.{
        .{ .match = "GET /api2/json/nodes/pve/qemu HTTP", .behavior = ans(list_body) },
        .{ .match = "/agent/ping", .behavior = ans(ping_body) },
        .{ .match = "/agent/set-user-password", .behavior = set },
        .{ .match = "/agent/exec HTTP", .behavior = ans(pid_body) },
        .{ .match = "/agent/exec-status", .behavior = ans(shadow) },
        .{ .match = "/agent/exec HTTP", .behavior = ans(pid_body) },
        .{ .match = "/agent/exec-status", .behavior = ans(shadow) },
    });
}

const agent_timeout: B = .{ .respond = .{ .status = 500, .body = "{\"data\":null,\"message\":\"qmp command 'guest-set-user-password' failed - got timeout\\n\"}" } };

test "vm password --reset: an agent timeout is resolved by the guest's shadow entry" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [crypt.hash_buf_len]u8 = undefined;
    const hash = try a.dupe(u8, try crypt.sha512Crypt(&buf, fixed_pw, fixed_salt));
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    {
        // The guest does not show the new hash: unknown, store untouched.
        var g: testkit.Gateway = undefined;
        try g.initRoutes(try resetRoutesWith(a, "$6$old$hash", agent_timeout, 0));
        defer g.deinit();
        g.h.hooks.guest_password = .{ .password = fixed_pw, .salt = fixed_salt };
        try g.mem.map.put(g.h.arena.allocator(), "guest/naboo", "old-password");
        try testing.expectEqual(Exit.unknown, g.h.run(&root, "vm password naboo --reset -y"));
        try testing.expectEqualStrings("old-password", g.mem.map.get("guest/naboo").?);
        try expectAll(g.h.stderr(), &.{ "got timeout", "the stored password is unchanged", "--reset' again is safe" });
    }
    {
        // The agent applied it after all: stored and verified.
        var g: testkit.Gateway = undefined;
        try g.initRoutes(try resetRoutesWith(a, hash, agent_timeout, 0));
        defer g.deinit();
        g.h.hooks.guest_password = .{ .password = fixed_pw, .salt = fixed_salt };
        try testing.expectEqual(Exit.ok, g.h.run(&root, "vm password naboo --reset -y"));
        try testing.expectEqualStrings(fixed_pw, g.mem.map.get("guest/naboo").?);
    }
    {
        // A refusal (403) changed nothing: no shadow read, store untouched.
        var g: testkit.Gateway = undefined;
        try g.initRoutes(try resetRoutesWith(a, hash, .{ .respond = .{ .status = 403, .body = "{\"data\":null}" } }, 0));
        defer g.deinit();
        g.h.hooks.guest_password = .{ .password = fixed_pw, .salt = fixed_salt };
        try testing.expectEqual(Exit.auth, g.h.run(&root, "vm password naboo --reset -y"));
        try testing.expect(g.mem.map.get("guest/naboo") == null);
    }
    {
        // Set and stored, but the read-back fails: partial, and says so.
        var g: testkit.Gateway = undefined;
        try g.initRoutes(try resetRoutesWith(a, hash, ans("{\"data\":null}"), 2));
        defer g.deinit();
        g.h.hooks.guest_password = .{ .password = fixed_pw, .salt = fixed_salt };
        try testing.expectEqual(Exit.partial, g.h.run(&root, "vm password naboo --reset -y"));
        try testing.expectEqualStrings(fixed_pw, g.mem.map.get("guest/naboo").?);
        try expectAll(g.h.stderr(), &.{"was set and stored, but its shadow entry could not be read back"});
    }
}

fn sentBody(g: *testkit.Gateway, needle: []const u8) []const u8 {
    for (g.srv.received) |r| if (r) |req| if (std.mem.find(u8, req, needle) != null)
        return req[(std.mem.find(u8, req, "\r\n\r\n") orelse return "") + 4 ..];
    return "";
}

test "vm password --reset: a crypt hash through the agent, stored here, verified on the guest" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var buf: [crypt.hash_buf_len]u8 = undefined;
    const hash = try a.dupe(u8, try crypt.sha512Crypt(&buf, fixed_pw, fixed_salt));
    var g: testkit.Gateway = undefined;
    try g.initRoutes(try resetRoutes(a, hash));
    defer g.deinit();
    g.h.hooks.guest_password = .{ .password = fixed_pw, .salt = fixed_salt };
    try g.mem.map.put(g.h.arena.allocator(), "guest/naboo", "old-password");
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.ok, g.h.run(&root, "vm password naboo --reset -y"));
    try testing.expectEqualStrings(fixed_pw, g.mem.map.get("guest/naboo").?);
    const body = sentBody(&g, "set-user-password");
    try testing.expectEqualStrings("artoo", try formValue(a, body, "username"));
    try testing.expectEqualStrings("1", try formValue(a, body, "crypted"));
    try testing.expectEqualStrings(hash, try formValue(a, body, "password"));
    // The password itself never leaves the machine or reaches the output.
    for (g.srv.received) |r| if (r) |req| try testing.expect(std.mem.find(u8, req, fixed_pw) == null);
    try testing.expect(std.mem.find(u8, g.h.stdout(), fixed_pw) == null);
    try testing.expect(std.mem.find(u8, g.h.stderr(), fixed_pw) == null);
    try expectAll(g.h.stdout(), &.{
        "guest/naboo        stored → the new password\n",
        "new sudo password of artoo on naboo stored as guest/naboo",
    });
    try testing.expect(std.mem.find(u8, sentBody(&g, "/agent/exec HTTP"), "command=getent&command=shadow&command=artoo") != null);
}

test "vm password --reset: a shadow entry without the new hash is partial" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: testkit.Gateway = undefined;
    try g.initRoutes(try resetRoutes(a, "$6$other$hash"));
    defer g.deinit();
    g.h.hooks.guest_password = .{ .password = fixed_pw, .salt = fixed_salt };
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.partial, g.h.run(&root, "vm password naboo --reset -y"));
}

fn expectAll(out: []const u8, wants: []const []const u8) !void {
    for (wants) |want| if (std.mem.find(u8, out, want) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ want, out });
        return error.TestUnexpectedResult;
    };
}

test "vm password --reset: refusals send nothing" {
    var g: testkit.Gateway = undefined;
    try g.init(&[_]B{ ans(list_body), ans(list_body) });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{@import("vm.zig").group});
    try testing.expectEqual(Exit.usage, g.h.run(&root, "vm password naboo --reset --show"));
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm password other --reset -y"));
    try testing.expectEqualStrings("artoo: other is not an artoo guest (no 'artoo' tag)\n", g.h.stderr());
    try testing.expectEqual(Exit.refused, g.h.run(&root, "vm password hoth --reset -y"));
    try testing.expectEqualStrings("artoo: hoth is stopped; start it first ('artoo vm start hoth')\n", g.h.stderr());
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
}
