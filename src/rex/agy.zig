//! The agy bridge (SPEC §20.4): Rex has no harness for Antigravity's
//! `agy` yet, so artoo gives it Rex's skill stub and three hooks — the
//! session-start context and the program status Rex shows per terminal.
//! Paths are relative to the guest user's home; the files are the user's.

const std = @import("std");
const app = @import("../app.zig");
const config = @import("../config.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const vm_new = @import("../commands/vm_new.zig");
const k = @import("../commands/node.zig");
const setup = @import("setup.zig");

const Context = app.Context;
const Value = std.json.Value;

pub const skill_path = ".gemini/config/skills/rex/SKILL.md";
pub const hooks_path = ".gemini/config/hooks.json";
pub const hook_path = ".config/artoo/agy-rex-hook";
/// The key artoo owns in `hooks.json`; the others are left alone.
pub const hooks_key = "artoo-rex";

/// Rex's own skill stub, for agy: the guide comes from the installed CLI.
pub const skill_stub =
    \\---
    \\name: rex
    \\description: Use the rex CLI to manage Rex sessions, open tabs, arrange panes, run commands, inspect terminal output, and control connected Rex apps.
    \\---
    \\<!-- Installed by 'artoo rex setup' (the agy bridge) until Rex sets up agy itself. -->
    \\
    \\Run `rex __internal skill` and follow the guide it prints. The guide comes from
    \\the installed Rex CLI, so it describes the commands available in that version.
    \\
    \\If the command fails, the installed Rex version predates the guide. Start with
    \\`rex whoami --json`, then use `rex --help` and `rex COMMAND --help`.
    \\
;

/// `agy-rex-hook EVENT`, the event's JSON on stdin. Always one JSON object
/// on stdout and exit 0, so a Rex fault never stops agy. Outside Rex
/// (`REX_BLOCK` unset) it does nothing. Rex's session-start text is
/// agent-neutral, so Claude's serves agy.
pub const hook_script =
    \\#!/bin/sh
    \\# Managed by artoo (the agy bridge to Rex); 'artoo rex setup' overwrites edits.
    \\# agy runs it as 'agy-rex-hook EVENT' with the event's JSON on stdin; it
    \\# always prints one JSON object and exits 0.
    \\ev=${1:-}
    \\in=$(cat 2>/dev/null) || in=
    \\if [ -z "${REX_BLOCK:-}" ]; then
    \\  printf '{}\n'
    \\  exit 0
    \\fi
    \\status() {
    \\  { printf '\033]7501;state=%s:app=agy\033\\' "$1" >/dev/tty; } 2>/dev/null || :
    \\}
    \\case $ev in
    \\SessionStart)
    \\  t=$(REX_AUTOSTART=0 rex __internal session-start --agent claude 2>/dev/null) || t=
    \\  o=
    \\  if [ -n "$t" ]; then
    \\    o=$(printf '%s' "$t" | jq -Rsc '{injectSteps: [{systemMessage: {systemMessage: .}}]}' 2>/dev/null) || o=
    \\  fi
    \\  if [ -n "$o" ]; then printf '%s\n' "$o"; else printf '{}\n'; fi
    \\  ;;
    \\PreInvocation)
    \\  status working
    \\  printf '{}\n'
    \\  ;;
    \\Stop)
    \\  r=$(printf '%s' "$in" | jq -r '.terminationReason // empty' 2>/dev/null) || r=
    \\  case $r in
    \\  USER_CANCELED) s=idle ;;
    \\  ERROR) s=error ;;
    \\  *) s=done ;;
    \\  esac
    \\  status "$s"
    \\  printf '{}\n'
    \\  ;;
    \\*) printf '{}\n' ;;
    \\esac
    \\exit 0
    \\
;

/// The value of `artoo-rex` in `hooks.json` (agy expands `~`).
pub const hooks_entry =
    \\{
    \\  "SessionStart": [{"type": "command", "command": "~/.config/artoo/agy-rex-hook SessionStart", "timeout": 10}],
    \\  "PreInvocation": [{"type": "command", "command": "~/.config/artoo/agy-rex-hook PreInvocation", "timeout": 5}],
    \\  "Stop": [{"type": "command", "command": "~/.config/artoo/agy-rex-hook Stop", "timeout": 5}]
    \\}
;

pub const MergeError = error{ OutOfMemory, NotAnObject };

fn parsed(a: std.mem.Allocator, text: []const u8) MergeError!std.json.ObjectMap {
    if (std.mem.trim(u8, text, " \t\r\n").len == 0) return .empty;
    const v = std.json.parseFromSliceLeaky(Value, a, text, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.NotAnObject,
    };
    if (v != .object) return error.NotAnObject;
    return v.object;
}

fn wanted(a: std.mem.Allocator) MergeError!Value {
    return std.json.parseFromSliceLeaky(Value, a, hooks_entry, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // The constant is tested below; never reached.
        else => return error.NotAnObject,
    };
}

fn canonical(a: std.mem.Allocator, v: Value) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, v, .{});
}

/// `hooks.json` with artoo's key set and every other key kept, or null
/// when it already holds exactly that. `existing` null: no file.
pub fn mergeHooks(a: std.mem.Allocator, existing: ?[]const u8) MergeError!?[]const u8 {
    var tree = try parsed(a, existing orelse "");
    const want = try wanted(a);
    if (tree.get(hooks_key)) |have| {
        if (std.mem.eql(u8, try canonical(a, have), try canonical(a, want))) return null;
    }
    try tree.put(a, hooks_key, want);
    return try config.serialize(a, .{ .object = tree });
}

/// What the guest has of the bridge.
pub const Files = enum { current, missing, changed };

pub fn files(a: std.mem.Allocator, st: setup.State) !Files {
    const skill_ok = std.mem.eql(u8, st.agy_skill, try setup.sha256Hex(a, skill_stub));
    const hook_ok = std.mem.eql(u8, st.agy_hook, try setup.sha256Hex(a, hook_script)) and std.mem.eql(u8, st.agy_hook_mode, "755");
    // A hooks.json that is not an object holds no key of artoo's.
    const tree: ?std.json.ObjectMap = if (st.agy_hooks) |h| (parsed(a, h) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.NotAnObject => null,
    }) else null;
    const keyed = if (tree) |t| t.get(hooks_key) != null else false;
    const hooks_ok = keyed and try mergeHooks(a, st.agy_hooks) == null;
    if (skill_ok and hook_ok and hooks_ok) return .current;
    const any = !std.mem.eql(u8, st.agy_skill, "-") or !std.mem.eql(u8, st.agy_hook, "-") or keyed;
    return if (any) .changed else .missing;
}

/// The `agy bridge` row of `rex status` (SPEC §20.7): current, missing or
/// changed; not checked without agy, or when Rex has its own agy harness.
pub fn check(ctx: *Context, c: *pve.Client, vm: vms.Vm, user: []const u8) !vm_new.Check {
    const label = "agy bridge";
    const st = setup.probe(c, vm.vmid, user) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            const why = try k.clean(ctx, ctx.diag orelse @errorName(err));
            ctx.diag = null;
            return .{ .name = label, .status = .unknown, .detail = why };
        },
    };
    if (st.agy.len == 0) return .{ .name = label, .status = .not_checked, .detail = "no agy on the user's PATH" };
    if (st.agyHarness()) return .{ .name = label, .status = .not_checked, .detail = "Rex sets up agy itself" };
    return switch (try files(ctx.arena, st)) {
        .current => .{ .name = label, .status = .ok, .detail = "current" },
        .missing => .{ .name = label, .status = .warning, .detail = try std.fmt.allocPrint(ctx.arena, "missing — 'artoo rex setup {s}'", .{vm.name}) },
        .changed => .{ .name = label, .status = .warning, .detail = try std.fmt.allocPrint(ctx.arena, "changed — 'artoo rex setup {s}'", .{vm.name}) },
    };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "mergeHooks: other keys kept, artoo's key set once, current gives null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fresh = (try mergeHooks(a, null)).?;
    try testing.expect(std.mem.find(u8, fresh, "\"artoo-rex\"") != null);
    try testing.expect(try mergeHooks(a, fresh) == null);

    const other = "{\"lint\": {\"PreInvocation\": [{\"command\": \"./lint.sh\"}]}, \"artoo-rex\": {\"Stop\": []}}";
    const merged = (try mergeHooks(a, other)).?;
    const tree = try parsed(a, merged);
    try testing.expect(tree.get("lint") != null);
    try testing.expectEqualStrings(try canonical(a, try wanted(a)), try canonical(a, tree.get(hooks_key).?));
    try testing.expect(try mergeHooks(a, merged) == null);
    // The key order of the file is kept: lint stays first.
    try testing.expect(std.mem.find(u8, merged, "lint").? < std.mem.find(u8, merged, hooks_key).?);

    try testing.expect((try mergeHooks(a, "  \n")) != null);
    try testing.expectError(error.NotAnObject, mergeHooks(a, "[1]"));
    try testing.expectError(error.NotAnObject, mergeHooks(a, "{oops"));
}

test "the hooks entry runs the hook for each event" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const v = try wanted(arena.allocator());
    for ([_][]const u8{ "SessionStart", "PreInvocation", "Stop" }) |ev| {
        const list = v.object.get(ev).?.array.items;
        try testing.expectEqual(@as(usize, 1), list.len);
        const cmd = list[0].object.get("command").?.string;
        try testing.expect(std.mem.startsWith(u8, cmd, "~/" ++ hook_path ++ " "));
        try testing.expect(std.mem.endsWith(u8, cmd, ev));
    }
}

const HookRun = struct { out: []const u8, tty: []const u8 };

/// Runs the hook script in a temp dir with a fake `rex` on PATH, `/dev/tty`
/// replaced by a file; null when the machine has no jq.
fn runHook(a: std.mem.Allocator, dir: []const u8, ev: []const u8, in_rex: bool, input: []const u8) !?HookRun {
    const proc = @import("../proc.zig");
    const r: proc.Runner = .{};
    const has_jq = try r.run(testing.io, a, &.{ "sh", "-c", "command -v jq" }, null);
    if (has_jq.code != 0) return null;
    const tty = try std.fmt.allocPrint(a, "{s}/tty", .{dir});
    const script = try std.mem.replaceOwned(u8, a, hook_script, "/dev/tty", tty);
    const path = try std.fmt.allocPrint(a, "{s}/hook", .{dir});
    const rex = try std.fmt.allocPrint(a, "{s}/rex", .{dir});
    try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = path, .data = script });
    try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = rex, .data = "#!/bin/sh\n[ \"$*\" = '__internal session-start --agent claude' ] && printf 'You are in Rex.\\n\"quoted\"\\n'\n" });
    const res = try r.run(testing.io, a, &.{
        "sh", "-c", "chmod 0755 \"$1/rex\"; : > \"$1/tty\"; if [ \"$3\" = yes ]; then export REX_BLOCK=block:1; else unset REX_BLOCK; fi; PATH=\"$1:$PATH\" sh \"$1/hook\" \"$2\"", "sh", dir, ev, if (in_rex) "yes" else "no",
    }, input);
    try testing.expectEqual(@as(?u8, 0), res.code);
    const written = try std.Io.Dir.cwd().readFileAlloc(testing.io, tty, a, .limited(4096));
    return .{ .out = res.stdout, .tty = written };
}

test "the hook: session-start text injected, OSC 7501 per event, {} outside Rex" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(testing.io, ".", a);

    const start = (try runHook(a, dir, "SessionStart", true, "{}")) orelse return error.SkipZigTest;
    const v = try std.json.parseFromSliceLeaky(Value, a, start.out, .{});
    const msg = v.object.get("injectSteps").?.array.items[0].object.get("systemMessage").?.object.get("systemMessage").?.string;
    // The shell's command substitution drops the final newline.
    try testing.expectEqualStrings("You are in Rex.\n\"quoted\"", msg);
    try testing.expectEqualStrings("", start.tty);

    const pre = (try runHook(a, dir, "PreInvocation", true, "{\"invocationNum\":1}")).?;
    try testing.expectEqualStrings("{}\n", pre.out);
    try testing.expectEqualStrings("\x1b]7501;state=working:app=agy\x1b\\", pre.tty);

    for ([_][2][]const u8{
        .{ "{\"terminationReason\":\"NO_TOOL_CALL\"}", "done" },
        .{ "{\"terminationReason\":\"USER_CANCELED\"}", "idle" },
        .{ "{\"terminationReason\":\"ERROR\",\"error\":\"x\"}", "error" },
        .{ "not json", "done" },
    }) |case| {
        const stop = (try runHook(a, dir, "Stop", true, case[0])).?;
        try testing.expectEqualStrings("{}\n", stop.out);
        try testing.expectEqualStrings(try std.fmt.allocPrint(a, "\x1b]7501;state={s}:app=agy\x1b\\", .{case[1]}), stop.tty);
    }

    const other = (try runHook(a, dir, "PostInvocation", true, "{}")).?;
    try testing.expectEqualStrings("{}\n", other.out);
    try testing.expectEqualStrings("", other.tty);

    for ([_][]const u8{ "SessionStart", "PreInvocation", "Stop" }) |ev| {
        const outside = (try runHook(a, dir, ev, false, "{}")).?;
        try testing.expectEqualStrings("{}\n", outside.out);
        try testing.expectEqualStrings("", outside.tty);
    }
}

test "files: changed when some of the bridge is there but differs; a broken hooks.json is no key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ok_skill = try setup.sha256Hex(a, skill_stub);
    const ok_hook = try setup.sha256Hex(a, hook_script);
    const merged = (try mergeHooks(a, null)).?;
    try testing.expectEqual(Files.current, try files(a, .{ .agy_skill = ok_skill, .agy_hook = ok_hook, .agy_hook_mode = "755", .agy_hooks = merged }));
    try testing.expectEqual(Files.changed, try files(a, .{ .agy_skill = ok_skill, .agy_hook = ok_hook, .agy_hook_mode = "644", .agy_hooks = merged }));
    try testing.expectEqual(Files.changed, try files(a, .{ .agy_hooks = "{\"artoo-rex\":{}}" }));
    try testing.expectEqual(Files.missing, try files(a, .{ .agy_hooks = "[" }));
}

const CheckProbe = struct {
    pub const name = "probe";
    pub const summary = "agy check probe";
    pub fn run(ctx: *Context, _: @import("../cli.zig").Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        const ch = try check(ctx, &c, setup.test_vm, "artoo");
        try ctx.out.print("{s}|{t}|{s}\n", .{ ch.name, ch.status, ch.detail });
    }
};

test "check: the agy bridge row from the guest's probe" {
    const testkit = @import("../testkit.zig");
    const cli = @import("../cli.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const probe_out = try (setup.Fixture{ .a = a, .agy = "/home/artoo/.local/bin/agy", .agy_files = true }).out();
    var g: testkit.Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = "{\"data\":{\"pid\":42}}" } },
        .{ .respond = .{ .body = try std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = probe_out } }, .{}) } },
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{cli.leaf(CheckProbe)});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "probe"));
    // No hooks.json on the guest: the skill and hook are there, the key is not.
    try testing.expectEqualStrings("agy bridge|warning|changed — 'artoo rex setup naboo'\n", g.h.stdout());
}
