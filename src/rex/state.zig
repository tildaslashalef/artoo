//! What Rex looks like on a guest: one embedded
//! probe, run as root through the guest agent, prints one JSON object of
//! the fields below — nothing else leaves the guest — parsed into a
//! typed `State`, then judged into `rex status`'s and `vm verify`'s
//! check rows. `agents` is the lighter read the reboot guard and
//! `vm upgrade`'s plan use.

const std = @import("std");
const app = @import("../app.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const agent = @import("../pve/agent.zig");
const k = @import("../commands/node.zig");
const vm_new = @import("../commands/vm_new.zig");
const guest = @import("guest.zig");
const vms = @import("../pve/vm.zig");
const template = @import("../commands/template.zig");

const Context = app.Context;
const Check = vm_new.Check;

/// The program status of one terminal, as the guest reports
/// it (sanitize before rendering).
pub const Agent = struct {
    /// The Rex session's label.
    session: []const u8 = "",
    block: []const u8 = "",
    app: []const u8 = "",
    /// idle, working, done, blocked or error.
    state: []const u8 = "",
    title: []const u8 = "",
    updated_at: []const u8 = "",

    /// `working` or `blocked`: a reboot would cut it off.
    pub fn busy(x: Agent) bool {
        return std.mem.eql(u8, x.state, "working") or std.mem.eql(u8, x.state, "blocked");
    }
};

pub const Policy = struct {
    installed: []const u8 = "",
    candidate: []const u8 = "",
    /// rex: from pkgs.superlogical.com; other: another origin; local: only
    /// dpkg's status (a .deb installed by hand); empty: not installed.
    installed_origin: []const u8 = "",
    /// The highest pin priority of a version from Rex's origin / from any
    /// other origin (Ubuntu's archive); null when apt knows none.
    rex_priority: ?i64 = null,
    other_priority: ?i64 = null,
};

pub const Server = struct {
    running: bool = false,
    /// `rex_version` of the running server.
    version: []const u8 = "",
    sessions: i64 = 0,
};

pub const Harness = struct {
    id: []const u8 = "",
    detected: bool = false,
    session_naming: bool = true,
    items: []const Item = &.{},

    pub const Item = struct { kind: []const u8 = "", state: []const u8 = "" };
};

/// The guest user's side, read with `REX_AUTOSTART=0`.
pub const User = struct {
    server: Server = .{},
    /// `rex terminfo status --json`'s conclusion; null when unreadable.
    terminfo: ?[]const u8 = null,
    /// `rex skill status --json`'s harnesses; null when unreadable.
    skills: ?[]const Harness = null,
    /// One per program-status record; `State.agents` folds them per terminal.
    agents: []const Agent = &.{},
    /// The reads that failed (`rex ls`, `rex block ls`, `program_status`).
    errors: []const []const u8 = &.{},
};

pub const Package = struct {
    /// dpkg's abbreviated status (`ii` when installed).
    status: []const u8 = "",
    version: []const u8 = "",
    maintainer: []const u8 = "",
};

pub const State = struct {
    package: Package = .{},
    policy: ?Policy = null,
    /// `/etc/apt/preferences.d/rex`: upstream, other or missing.
    pin_file: []const u8 = "",
    linger: bool = false,
    /// The installed `rex version` (`0.1.0-snapshot.N`).
    rex_version: []const u8 = "",
    /// Null when Rex is not installed or the user's side was unreadable.
    user: ?User = null,

    /// Rex's own package is installed (Superlogical's, not Ubuntu's Perl `rex`).
    pub fn isRex(st: State) bool {
        return std.mem.eql(u8, st.package.status, "ii") and std.mem.find(u8, st.package.maintainer, "Superlogical") != null;
    }

    /// The agents, one per terminal (the most pressing record of each).
    pub fn agents(st: State, a: std.mem.Allocator) ![]const Agent {
        const u = st.user orelse return &.{};
        return perTerminal(a, u.agents);
    }
};

// ---------------------------------------------------------------- probe

/// As the guest user: the server, then each session's terminals' program
/// status, one JSON object per line (`{"err": …}` for a failed read),
/// folded by jq into `AGENTS` (`{agents, errors}`); `SERVER` is the
/// server's object.
const user_agents =
    \\tab=$(printf '\t')
    \\sock="$XDG_RUNTIME_DIR/rex/server.sock"
    \\srv=$(rex server status --json 2>/dev/null) || srv=
    \\g='{"agents":[],"errors":[]}'
    \\if [ -n "$srv" ]; then
    \\  s=$(printf '%s' "$srv" | jq -c '{running: true, version: (.rex_version // ""), sessions: (.session_count // 0)}') || s='{"running":true}'
    \\elif [ -S "$sock" ]; then
    \\  # A socket that does not answer: not "not running" — unknown.
    \\  s='{"running":true}'
    \\  g='{"agents":[],"errors":["rex server status"]}'
    \\else
    \\  s='{"running":false}'
    \\fi
    \\if [ -n "$srv" ]; then
    \\  g=$( {
    \\    # Each jq's own status counts: a shape it cannot read is an error
    \\    # record, never "no sessions".
    \\    # jq -e: 4 is "no output" (nothing listed), anything else not 0 an error.
    \\    l=$(rex ls --json 2>/dev/null) || l=
    \\    ids=$(printf '%s' "$l" | jq -er '(.sessions // error("no sessions")) | .[] | [.session_id, (.label // "")] | @tsv' 2>/dev/null); rc=$?
    \\    if [ -z "$l" ] || { [ $rc -ne 0 ] && [ $rc -ne 4 ]; }; then echo '{"err":"rex ls"}'; ids=; fi
    \\    printf '%s\n' "$ids" | while IFS="$tab" read -r sid lab; do
    \\      [ -n "$sid" ] || continue
    \\      b=$(rex block ls -s "$sid" --json 2>/dev/null) || b=
    \\      bids=$(printf '%s' "$b" | jq -er '(.blocks // error("no blocks")) | .[] | select((.flavor // "com.superlogical.terminal") | startswith("com.superlogical.terminal")) | .block_id' 2>/dev/null); rc=$?
    \\      if [ -z "$b" ] || { [ $rc -ne 0 ] && [ $rc -ne 4 ]; }; then echo '{"err":"rex block ls"}'; continue; fi
    \\      printf '%s\n' "$bids" | while read -r bid; do
    \\        [ -n "$bid" ] || continue
    \\        r=$(rex block call -b "$bid" program_status 2>/dev/null) || { echo '{"err":"program_status"}'; continue; }
    \\        printf '%s' "$r" | jq -ec --arg s "$lab" --arg b "$bid" '(.records // error("no records")) | .[] | {session: $s, block: $b, app: (.effective_app // .app // ""), state: (.state // ""), title: (.title // ""), updated_at: (.updated_at // "")}' 2>/dev/null; rc=$?
    \\        if [ $rc -ne 0 ] && [ $rc -ne 4 ]; then echo '{"err":"program_status"}'; fi
    \\      done
    \\    done
    \\  } | jq -sc '{agents: [.[] | select(has("err") | not)], errors: [.[] | select(has("err")) | .err]}') || g='{"agents":[],"errors":["agents"]}'
    \\fi
    \\
;

/// The user's side for `agents`: `{server, agents, errors}`.
const user_light = user_agents ++
    \\jq -nc --argjson s "$s" --argjson g "$g" '{server: $s} + $g'
;

/// The user's side for `probe`: also terminfo and the agent skill.
const user_full = user_agents ++
    \\t=$(rex terminfo status --json 2>/dev/null) && t=$(printf '%s' "$t" | jq -c '.conclusion // ""') || t=null
    \\h=$(rex skill status --json 2>/dev/null) && h=$(printf '%s' "$h" | jq -c '[.harnesses[]? | {id: (.id // ""), detected: (.detected // false), session_naming: (.session_naming // true), items: [.items[]? | {kind: (.kind // ""), state: (.state // "")}]}]') || h=null
    \\jq -nc --argjson s "$s" --argjson g "$g" --argjson t "$t" --argjson h "$h" '{server: $s, terminfo: $t, skills: $h} + $g'
;

/// `apt-cache policy rex` summarized: each version line carries its pin
/// priority, the lines under it (a right-aligned priority after seven
/// spaces, then the source) its origins.
const policy_awk =
    \\awk '
    \\function flush() {
    \\  if (v != "") {
    \\    if (rex) { if (rp == "" || p + 0 > rp + 0) rp = p; if (v == inst) io = "rex" }
    \\    else if (oth) { if (op == "" || p + 0 > op + 0) op = p; if (v == inst && io == "") io = "other" }
    \\    else if (v == inst && io == "") io = "local"
    \\  }
    \\  v = ""; rex = 0; oth = 0
    \\}
    \\/^  Installed:/ { inst = $2 }
    \\/^  Candidate:/ { cand = $2 }
    \\/^ \*\*\* / || /^     [^ ]/ { flush(); if ($1 == "***") { v = $2; p = $3 } else { v = $1; p = $2 }; next }
    \\/^       +-?[0-9]+ / { if ($2 ~ /pkgs\.superlogical\.com/) rex = 1; else if ($2 != "/var/lib/dpkg/status") oth = 1 }
    \\END {
    \\  flush()
    \\  if (inst == "") exit
    \\  if (inst == "(none)") { inst = ""; io = "" }
    \\  printf "{\"installed\":\"%s\",\"candidate\":\"%s\",\"installed_origin\":\"%s\",\"rex_priority\":%s,\"other_priority\":%s}\n", inst, cand, io, (rp == "" ? "null" : rp), (op == "" ? "null" : op)
    \\}'
;

/// The root side of `probe`; `{user_script}` is `guest.asUser(user_full)`.
fn probeScript(a: std.mem.Allocator, user: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a,
        \\u={s}
        \\p=$(dpkg-query -W -f='${{db:Status-Abbrev}}\t${{Version}}\t${{Maintainer}}' rex 2>/dev/null) || p=
        \\st=$(printf '%s' "$p" | cut -f1 | tr -d ' '); ver=$(printf '%s' "$p" | cut -f2); mt=$(printf '%s' "$p" | cut -f3)
        \\pol=$(LC_ALL=C apt-cache policy rex 2>/dev/null | {s})
        \\[ -n "$pol" ] || pol=null
        \\pf=missing
        \\if [ -f /etc/apt/preferences.d/rex ]; then
        \\  want=$(printf 'Package: rex\nPin: origin pkgs.superlogical.com\nPin-Priority: 1001\nPackage: rex\nPin: release *\nPin-Priority: -1')
        \\  have=$(sed -e 's/[[:space:]]*$//' -e '/^$/d' -e '/^#/d' -e '/^Explanation:/d' /etc/apt/preferences.d/rex)
        \\  if [ "$have" = "$want" ]; then pf=upstream; else pf=other; fi
        \\fi
        \\lg=false
        \\if [ -e "/var/lib/systemd/linger/$u" ] || [ "$(loginctl show-user "$u" -p Linger --value 2>/dev/null)" = yes ]; then lg=true; fi
        \\rv=; us=null
        \\if [ "$st" = ii ] && printf '%s' "$mt" | grep -q Superlogical; then
        \\  rv=$(REX_AUTOSTART=0 rex version 2>/dev/null | sed -n '1s/^rex //p')
        \\  us=$({s}) || us=null
        \\  printf '%s' "$us" | jq -e . >/dev/null 2>&1 || us=null
        \\fi
        \\jq -nc --arg st "$st" --arg ver "$ver" --arg mt "$mt" --argjson pol "$pol" --arg pf "$pf" --argjson lg "$lg" --arg rv "$rv" --argjson us "$us" '{{package: {{status: $st, version: $ver, maintainer: $mt}}, policy: $pol, pin_file: $pf, linger: $lg, rex_version: $rv, user: $us}}'
    , .{ user, policy_awk, try guest.asUser(a, user, user_full) });
}

/// Read Rex's state on a running guest whose agent answers. `user` is
/// `guests.user`. A script that fails or prints no JSON is an error.
pub fn probe(ctx: *Context, c: *pve.Client, vmid: u32, user: []const u8) !State {
    const r = try agent.sh(c, vmid, try probeScript(ctx.arena, user), 60_000);
    if (!r.ok()) return ctx.fail(error.TaskFailed, "the Rex probe exited {?d}: {s}", .{ r.code, try k.clean(ctx, firstLine(r.err)) });
    return parse(ctx.arena, r.out) catch ctx.fail(error.Protocol, "the Rex probe printed no state: {s}", .{try k.clean(ctx, firstLine(if (r.out.len > 0) r.out else r.err))});
}

pub fn parse(a: std.mem.Allocator, out: []const u8) !State {
    return std.json.parseFromSliceLeaky(State, a, std.mem.trim(u8, out, " \t\r\n"), .{ .ignore_unknown_fields = true });
}

/// The agents on a guest for the reboot guard, one per
/// terminal. A server that is not running has none; a status that cannot
/// be read is an error (the caller skips the guest).
pub fn agents(ctx: *Context, c: *pve.Client, vmid: u32, user: []const u8) ![]const Agent {
    const r = try agent.sh(c, vmid, try guest.asUser(ctx.arena, user, user_light), 60_000);
    if (!r.ok()) {
        const why = try k.clean(ctx, firstLine(r.err));
        return ctx.fail(error.TaskFailed, "the read exited {?d}{s}{s}", .{ r.code, if (why.len > 0) ": " else "", why });
    }
    const u = std.json.parseFromSliceLeaky(User, ctx.arena, std.mem.trim(u8, r.out, " \t\r\n"), .{ .ignore_unknown_fields = true }) catch
        return ctx.fail(error.Protocol, "the read printed no status: {s}", .{try k.clean(ctx, firstLine(if (r.out.len > 0) r.out else r.err))});
    if (u.errors.len > 0) return ctx.fail(error.TaskFailed, "{s} failed", .{try k.clean(ctx, try std.mem.join(ctx.arena, ", ", u.errors))});
    return perTerminal(ctx.arena, u.agents);
}

fn rank(state: []const u8) u8 {
    const order = [_][]const u8{ "idle", "done", "working", "error", "blocked" };
    for (order, 1..) |s, i| if (std.mem.eql(u8, s, state)) return @intCast(i);
    return 0;
}

/// One agent per terminal: a block's records (an agent and its
/// subagents) fold into the most pressing one, its title kept when the
/// chosen record has none.
pub fn perTerminal(a: std.mem.Allocator, records: []const Agent) ![]const Agent {
    var out: std.ArrayList(Agent) = .empty;
    for (records) |r| {
        for (out.items) |*o| {
            if (!std.mem.eql(u8, o.block, r.block)) continue;
            if (rank(r.state) > rank(o.state)) {
                const title = if (r.title.len == 0) o.title else r.title;
                o.* = r;
                o.title = title;
            } else if (o.title.len == 0 and r.title.len > 0 and std.mem.eql(u8, o.state, r.state)) o.title = r.title;
            break;
        } else try out.append(a, r);
    }
    return out.items;
}

/// "claude-code working in naboo-api" (sanitized).
pub fn describe(ctx: *Context, x: Agent) ![]const u8 {
    const app_name = if (x.app.len > 0) x.app else "a program";
    const where = if (x.session.len > 0) x.session else "a session";
    return k.clean(ctx, try std.fmt.allocPrint(ctx.arena, "{s} {s} in {s}", .{ app_name, if (x.state.len > 0) x.state else "reporting", where }));
}

/// The busy agents of `list`, described and joined ("…, …"); null when none is.
pub fn busyText(ctx: *Context, list: []const Agent) !?[]const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    for (list) |x| if (x.busy()) try parts.append(ctx.arena, try describe(ctx, x));
    if (parts.items.len == 0) return null;
    return try std.mem.join(ctx.arena, ", ", parts.items);
}

// ---------------------------------------------------------------- checks

/// A deb version (`0.1.0~alpha.N`) and `rex version`'s
/// (`0.1.0-snapshot.N`) in one form, so the two compare.
pub fn normalVersion(a: std.mem.Allocator, v: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (std.mem.trim(u8, v, " \t\r\n")) |ch| try out.append(a, if (ch == '~') '-' else ch);
    const alpha = "-alpha.";
    if (std.mem.find(u8, out.items, alpha)) |i| {
        try out.replaceRange(a, i, alpha.len, "-snapshot.");
    }
    return out.items;
}

pub fn sameVersion(a: std.mem.Allocator, x: []const u8, y: []const u8) !bool {
    return std.mem.eql(u8, try normalVersion(a, x), try normalVersion(a, y));
}

/// The rows `rex status` and `vm verify` show, all not checked, saying why
/// ("VM stopped", "no guest agent").
pub fn notChecked(ctx: *Context, why: []const u8) ![]const Check {
    const names = [_][]const u8{ "package", "apt pin", "linger", "server", "terminfo", "skill" };
    const out = try ctx.arena.alloc(Check, names.len);
    for (names, out) |n, *ch| ch.* = .{ .name = n, .status = .not_checked, .detail = why };
    return out;
}

/// `rex status`'s rows for `st`, without the agent rows (`agentChecks`).
/// `vm` names the guest in the hints ('artoo rex setup VM').
pub fn checks(ctx: *Context, st: State, vm: []const u8) ![]const Check {
    const a = ctx.arena;
    const name = try k.clean(ctx, vm);
    const setup = try std.fmt.allocPrint(a, "'artoo rex setup {s}'", .{name});
    var out: std.ArrayList(Check) = .empty;

    // package
    const pkg_ok = st.isRex() and st.policy != null and std.mem.eql(u8, st.policy.?.installed_origin, "rex");
    try out.append(a, if (!std.mem.eql(u8, st.package.status, "ii"))
        .{ .name = "package", .status = .failed, .detail = try std.fmt.allocPrint(a, "not installed — {s}", .{setup}) }
    else if (!st.isRex())
        .{ .name = "package", .status = .failed, .detail = try std.fmt.allocPrint(a, "rex {s} is another package (Maintainer {s}), not Rex — {s}", .{ try k.clean(ctx, st.package.version), try k.clean(ctx, st.package.maintainer), setup }) }
    else if (!pkg_ok)
        .{ .name = "package", .status = .failed, .detail = try std.fmt.allocPrint(a, "{s} not from Rex's origin (pkgs.superlogical.com) — {s}", .{ try k.clean(ctx, st.package.version), setup }) }
    else
        .{ .name = "package", .status = .ok, .detail = try std.fmt.allocPrint(a, "{s} from pkgs.superlogical.com", .{try k.clean(ctx, st.package.version)}) });

    // apt pin: the priorities apt applies, and the file that sets them.
    try out.append(a, try pinCheck(ctx, st, setup));

    try out.append(a, if (st.linger)
        .{ .name = "linger", .status = .ok, .detail = "on" }
    else
        .{ .name = "linger", .status = .warning, .detail = try std.fmt.allocPrint(a, "off (sessions end at logout) — {s}", .{setup}) });

    if (!st.isRex()) {
        for ([_][]const u8{ "server", "terminfo", "skill" }) |n| try out.append(a, .{ .name = n, .status = .not_checked, .detail = "Rex not installed" });
        return out.items;
    }
    const u = st.user orelse {
        for ([_][]const u8{ "server", "terminfo", "skill" }) |n| try out.append(a, .{ .name = n, .status = .warning, .detail = "could not be read as the guest user" });
        return out.items;
    };

    // server: the running version against the installed one.
    const installed = if (st.rex_version.len > 0) st.rex_version else st.package.version;
    try out.append(a, if (!u.server.running)
        .{ .name = "server", .status = .warning, .detail = "not running (it starts with the first session)" }
    else if (u.server.version.len > 0 and !try sameVersion(a, u.server.version, installed))
        .{ .name = "server", .status = .warning, .detail = try std.fmt.allocPrint(a, "runs {s}; {s} once it stops", .{ try k.clean(ctx, u.server.version), try k.clean(ctx, installed) }) }
    else
        .{ .name = "server", .status = .ok, .detail = try std.fmt.allocPrint(a, "{s}, {f}", .{ try k.clean(ctx, if (u.server.version.len > 0) u.server.version else installed), ui.values.count(@max(u.server.sessions, 0), "session") }) });

    try out.append(a, if (u.terminfo) |t|
        (if (std.mem.startsWith(u8, t, "Ready"))
            Check{ .name = "terminfo", .status = .ok, .detail = try k.clean(ctx, t) }
        else
            Check{ .name = "terminfo", .status = .warning, .detail = try std.fmt.allocPrint(a, "{s} — {s}", .{ try k.clean(ctx, if (t.len > 0) t else "not ready"), setup }) })
    else
        Check{ .name = "terminfo", .status = .warning, .detail = "status unreadable" });

    try skillChecks(ctx, &out, u.skills, setup);

    return out.items;
}

/// The agy bridge row and the profile and permissions rows
///, each from its own read of the guest: shown after
/// `checks` by `rex status` and `vm verify`.
pub fn extraChecks(ctx: *Context, c: *pve.Client, v: vms.Vm, user: []const u8) ![]const Check {
    const a = ctx.arena;
    var out: std.ArrayList(Check) = .empty;
    try out.append(a, try @import("agy.zig").check(ctx, c, v, user));
    const profile = @import("profile.zig");
    const prof = profile.loadConfigured(ctx) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            defer ctx.diag = null;
            try out.append(a, .{ .name = "profile", .status = .failed, .detail = try k.clean(ctx, ctx.diag orelse @errorName(err)) });
            return out.items;
        },
    };
    const fenced = template.taggedWith(v.tags, @import("../commands/vm_fence.zig").tag);
    const rows = profile.checks(ctx, c, v.vmid, user, prof, fenced) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            defer ctx.diag = null;
            try out.append(a, .{ .name = "profile", .status = .failed, .detail = try k.clean(ctx, ctx.diag orelse @errorName(err)) });
            return out.items;
        },
    };
    try out.appendSlice(a, rows);
    return out.items;
}

fn pinCheck(ctx: *Context, st: State, setup: []const u8) !Check {
    const a = ctx.arena;
    const p = st.policy orelse Policy{};
    var bad: std.ArrayList([]const u8) = .empty;
    if (p.other_priority) |o| if (o != -1)
        try bad.append(a, try std.fmt.allocPrint(a, "Ubuntu's rex at {d}, not −1", .{o}));
    if (p.rex_priority) |r| {
        if (r != 1001) try bad.append(a, try std.fmt.allocPrint(a, "Rex's origin at {d}, not 1001", .{r}));
    } else try bad.append(a, "no version from Rex's origin in apt's lists");
    if (std.mem.eql(u8, st.pin_file, "missing"))
        try bad.append(a, "no /etc/apt/preferences.d/rex")
    else if (!std.mem.eql(u8, st.pin_file, "upstream"))
        try bad.append(a, "/etc/apt/preferences.d/rex is not upstream's");
    if (bad.items.len > 0) return .{ .name = "apt pin", .status = .warning, .detail = try std.fmt.allocPrint(a, "{s} — {s}", .{ try std.mem.join(a, "; ", bad.items), setup }) };
    return .{ .name = "apt pin", .status = .ok, .detail = "Rex 1001, others −1" };
}

/// One row per harness `rex skill status` detects.
fn skillChecks(ctx: *Context, out: *std.ArrayList(Check), skills: ?[]const Harness, setup: []const u8) !void {
    const a = ctx.arena;
    const hs = skills orelse return out.append(a, .{ .name = "skill", .status = .warning, .detail = "status unreadable" });
    var any = false;
    for (hs) |h| {
        if (!h.detected) continue;
        any = true;
        // Outdated or missing items and session naming off are what
        // 'rex setup' repairs (a warning); a foreign or unreadable item
        // is left alone by it, so it is named, not warned about.
        var off: std.ArrayList([]const u8) = .empty;
        var alone: std.ArrayList([]const u8) = .empty;
        for (h.items) |it| {
            if (std.mem.eql(u8, it.state, "current")) continue;
            const text = try std.fmt.allocPrint(a, "{s} {s}", .{ try k.clean(ctx, it.kind), try k.clean(ctx, it.state) });
            const repairable = std.mem.eql(u8, it.state, "outdated") or std.mem.eql(u8, it.state, "missing");
            try (if (repairable) &off else &alone).append(a, text);
        }
        if (!h.session_naming) try off.append(a, "session naming off");
        const label = try std.fmt.allocPrint(a, "skill {s}", .{try k.clean(ctx, h.id)});
        const left = if (alone.items.len > 0) try std.fmt.allocPrint(a, "; {s}, left alone", .{try std.mem.join(a, ", ", alone.items)}) else "";
        try out.append(a, if (off.items.len == 0)
            .{ .name = label, .status = .ok, .detail = try std.fmt.allocPrint(a, "current{s}", .{left}) }
        else
            .{ .name = label, .status = .warning, .detail = try std.fmt.allocPrint(a, "{s} — {s}{s}", .{ try std.mem.join(a, ", ", off.items), setup, left }) });
    }
    if (!any) try out.append(a, .{ .name = "skill", .status = .not_checked, .detail = "no agent harness detected (Claude Code, Codex, OpenCode, pi)" });
}

/// `rex status`'s agent rows: one per terminal with a status; blocked and
/// error are warnings. Reads that failed are one warning row.
pub fn agentChecks(ctx: *Context, st: State) ![]const Check {
    const a = ctx.arena;
    var out: std.ArrayList(Check) = .empty;
    const u = st.user orelse return out.items;
    for (try st.agents(a)) |x| {
        var detail = try describe(ctx, x);
        if (x.title.len > 0) detail = try std.fmt.allocPrint(a, "{s}: {s}", .{ detail, try k.clean(ctx, x.title) });
        const status: ui.style.Status = if (std.mem.eql(u8, x.state, "blocked")) blk: {
            detail = try std.fmt.allocPrint(a, "{s} (waiting for the operator)", .{detail});
            break :blk .warning;
        } else if (std.mem.eql(u8, x.state, "error")) .warning else .ok;
        try out.append(a, .{ .name = "agent", .status = status, .detail = detail });
    }
    if (u.errors.len > 0) try out.append(a, .{ .name = "agents", .status = .warning, .detail = try std.fmt.allocPrint(a, "not all read ({s} failed)", .{try k.clean(ctx, try std.mem.join(a, ", ", u.errors))}) });
    return out.items;
}

/// `vm verify`'s rows for a guest tagged `rex` (`rex status`'s,
/// the agent rows excepted): not checked without an answering agent.
pub fn verifyChecks(ctx: *Context, c: *pve.Client, v: vms.Vm, agent_ok: bool) ![]const Check {
    const vmid = v.vmid;
    const vm = v.name;
    if (!agent_ok) return notChecked(ctx, "no guest agent");
    const user = (try ctx.config()).guests.user;
    const st = probe(ctx, c, vmid, user) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            defer ctx.diag = null;
            const one = try ctx.arena.alloc(Check, 1);
            one[0] = .{ .name = "rex", .status = .failed, .detail = try k.clean(ctx, ctx.diag orelse @errorName(err)) };
            return one;
        },
    };
    var rows: std.ArrayList(Check) = .empty;
    try rows.appendSlice(ctx.arena, try checks(ctx, st, vm));
    if (st.isRex()) try rows.appendSlice(ctx.arena, try extraChecks(ctx, c, v, user));
    return rows.items;
}

fn firstLine(s: []const u8) []const u8 {
    const t = std.mem.trim(u8, s, " \t\r\n");
    return t[0 .. std.mem.findScalar(u8, t, '\n') orelse t.len];
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

/// A probe answer: `user` is the user's side (JSON) or null.
pub fn sample(a: std.mem.Allocator, opts: struct {
    status: []const u8 = "ii",
    version: []const u8 = "0.1.0~alpha.23",
    maintainer: []const u8 = "Superlogical <packages@example.com>",
    origin: []const u8 = "rex",
    rex_priority: ?i64 = 1001,
    other_priority: ?i64 = -1,
    pin_file: []const u8 = "upstream",
    linger: bool = true,
    rex_version: []const u8 = "0.1.0-snapshot.23",
    user: ?[]const u8 = "{\"server\":{\"running\":true,\"version\":\"0.1.0-snapshot.23\",\"sessions\":2},\"terminfo\":\"Ready: xterm-rex resolves.\",\"skills\":[{\"id\":\"claude\",\"detected\":true,\"items\":[{\"kind\":\"skill\",\"state\":\"current\"},{\"kind\":\"hook\",\"state\":\"current\"}]},{\"id\":\"codex\",\"detected\":false,\"items\":[]}],\"agents\":[],\"errors\":[]}",
}) ![]const u8 {
    const pol = if (opts.origin.len == 0 and opts.rex_priority == null and opts.other_priority == null)
        "null"
    else
        try std.fmt.allocPrint(a, "{{\"installed\":\"{s}\",\"candidate\":\"{s}\",\"installed_origin\":\"{s}\",\"rex_priority\":{?d},\"other_priority\":{?d}}}", .{ opts.version, opts.version, opts.origin, opts.rex_priority, opts.other_priority });
    return std.fmt.allocPrint(a, "{{\"package\":{{\"status\":\"{s}\",\"version\":\"{s}\",\"maintainer\":\"{s}\"}},\"policy\":{s},\"pin_file\":\"{s}\",\"linger\":{},\"rex_version\":\"{s}\",\"user\":{s}}}", .{
        opts.status, opts.version, opts.maintainer, pol, opts.pin_file, opts.linger, opts.rex_version, opts.user orelse "null",
    });
}

fn find(cs: []const Check, name: []const u8) ?Check {
    for (cs) |ch| if (std.mem.eql(u8, ch.name, name)) return ch;
    return null;
}

test "normalVersion: a snapshot deb and its rex version compare equal" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect(try sameVersion(a, "0.1.0~alpha.23", "0.1.0-snapshot.23"));
    try testing.expect(try sameVersion(a, "0.1.0~preview.23", "0.1.0-preview.23"));
    try testing.expect(!try sameVersion(a, "0.1.0~alpha.23", "0.1.0-snapshot.22"));
    try testing.expect(!try sameVersion(a, "0.1.0-preview.22", "0.1.0-preview.23"));
}

test "perTerminal folds a block's records into the most pressing one" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const recs = [_]Agent{
        .{ .session = "naboo-api", .block = "block:1", .app = "claude-code", .state = "idle" },
        .{ .session = "naboo-api", .block = "block:1", .app = "claude-code", .state = "working", .title = "fix the tests" },
        .{ .session = "naboo-api", .block = "block:1", .app = "claude-code", .state = "done" },
        .{ .session = "naboo-web", .block = "block:2", .app = "agy", .state = "blocked" },
    };
    const out = try perTerminal(a, &recs);
    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqualStrings("working", out[0].state);
    try testing.expectEqualStrings("fix the tests", out[0].title);
    try testing.expect(out[1].busy());
}

test "parse: the probe's JSON for each state" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // A fresh guest: nothing installed, no pin file, apt knows only Ubuntu's rex.
    const fresh = try parse(a, try sample(a, .{ .status = "", .version = "", .maintainer = "", .origin = "", .rex_priority = null, .other_priority = 500, .pin_file = "missing", .linger = false, .rex_version = "", .user = null }));
    try testing.expect(!fresh.isRex());
    try testing.expectEqual(@as(?i64, 500), fresh.policy.?.other_priority);
    // Ubuntu's Perl rex.
    const perl = try parse(a, try sample(a, .{ .version = "1.16.0-1", .maintainer = "Ubuntu Developers <ubuntu-devel-discuss@example.com>", .origin = "other", .user = null }));
    try testing.expect(!perl.isRex());
    // Set up, an agent working.
    const busy = try parse(a, try sample(a, .{ .user = "{\"server\":{\"running\":true,\"version\":\"0.1.0-snapshot.23\",\"sessions\":1},\"terminfo\":\"Ready\",\"skills\":[],\"agents\":[{\"session\":\"naboo-api\",\"block\":\"block:1\",\"app\":\"claude-code\",\"state\":\"working\",\"title\":\"\",\"updated_at\":\"2026-11-25T01:52:40+01:00\"}],\"errors\":[]}" }));
    try testing.expect(busy.isRex());
    try testing.expectEqual(@as(usize, 1), (try busy.agents(a)).len);
    try testing.expect((try busy.agents(a))[0].busy());
}
