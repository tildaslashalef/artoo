//! Rex on one guest: read its state through the guest agent
//! in one probe, judge each step (already right, or a change), apply the
//! changes in order. `rex setup` (one ledger row per step) and `vm new
//! --rex` (one ledger step) share `readGuest` and `apply`.

const std = @import("std");
const app = @import("../app.zig");
const exec = @import("../exec.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const agent = @import("../pve/agent.zig");
const edge = @import("../commands/edge.zig");
const files = @import("../edge/files.zig");
const template = @import("../commands/template.zig");
const k = @import("../commands/node.zig");
const guest = @import("guest.zig");
const agy = @import("agy.zig");
const profile = @import("profile.zig");
const permissions = @import("permissions.zig");

const Context = app.Context;
const Allocator = std.mem.Allocator;
const Value = std.json.Value;

pub const sha256Hex = files.sha256Hex;

// ---------------------------------------------------------------- facts

/// Superlogical's binary keyring, embedded (never fetched by the guest).
pub const keyring = @embedFile("../guest/rex-archive-keyring.gpg");
pub const keyring_sha256 = "07a92e758ac2fc189efa17c24bf3df70d75e4216f6c262283a5c812377deb83e";
pub const keyring_fingerprint = "E28636AC71905C6DDE40C1EDFAA6B80F641307A7";
pub const keyring_path = "/etc/apt/keyrings/rex-archive-keyring.gpg";
pub const sources_path = "/etc/apt/sources.list.d/rex.sources";
pub const pin_path = "/etc/apt/preferences.d/rex";
pub const repo = "https://pkgs.superlogical.com/rex/apt";

/// Upstream's pin, byte for byte: Rex's origin wins, every other `rex`
/// (Ubuntu's Perl tool) never does.
pub const pin =
    \\Package: rex
    \\Pin: origin pkgs.superlogical.com
    \\Pin-Priority: 1001
    \\
    \\Package: rex
    \\Pin: release *
    \\Pin-Priority: -1
    \\
;

/// Upstream's deb822 source for `channel` on `arch`.
pub fn sources(a: Allocator, channel: []const u8, arch: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a,
        \\Types: deb
        \\URIs: {s}
        \\Suites: {s}
        \\Components: main
        \\Architectures: {s}
        \\Signed-By: {s}
        \\
    , .{ repo, channel, arch, keyring_path });
}

/// `apt-get update`, then upstream's install command (waiting for a
/// dpkg lock another apt run holds, as `vm upgrade` does).
pub const install_script =
    \\set -eu
    \\export DEBIAN_FRONTEND=noninteractive
    \\apt-get update -q -o DPkg::Lock::Timeout=300 >/dev/null
    \\apt-get install -y --allow-downgrades -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold rex >/dev/null
    \\
;

const terminfo_script = "HOME=/root REX_AUTOSTART=0 /usr/bin/rex --autostart=false terminfo setup --system >/dev/null";

const install_timeout_ms = 15 * 60 * 1000;
const step_timeout_ms = 2 * 60 * 1000;

// ---------------------------------------------------------------- probe

/// As root; `$1` is the guest user. Only these lines leave the guest.
const probe_root =
    \\f() { s=$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1); echo "${s:--}"; }
    \\echo "key $(f /etc/apt/keyrings/rex-archive-keyring.gpg)"
    \\echo "sources $(f /etc/apt/sources.list.d/rex.sources)"
    \\echo "suite $(sed -n 's/^Suites: *//p' /etc/apt/sources.list.d/rex.sources 2>/dev/null | head -n 1)"
    \\echo "pin $(f /etc/apt/preferences.d/rex)"
    \\echo "arch $(dpkg --print-architecture 2>/dev/null)"
    \\echo "pkg $(dpkg-query -W -f '${db:Status-Status}|${Version}|${Maintainer}' rex 2>/dev/null)"
    \\echo "uid $(id -u "$1" 2>/dev/null)"
    \\if [ -e "/var/lib/systemd/linger/$1" ]; then echo "linger yes"; else echo "linger no"; fi
    \\id -u "$1" >/dev/null 2>&1 || exit 0
    \\
;

/// As the guest user (`guest.asUser`): Rex's own status, only when the
/// installed `rex` is Superlogical's (Ubuntu's Perl `rex` would run a
/// task), and the agy bridge's files.
const probe_user =
    \\f() { s=$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1); echo "${s:--}"; }
    \\b() { base64 -w0 2>/dev/null; }
    \\case "$(dpkg-query -W -f '${Maintainer}' rex 2>/dev/null)" in
    \\*[Ss]uperlogical*)
    \\  echo "terminfo $(/usr/bin/rex --autostart=false terminfo status --json 2>/dev/null | b)"
    \\  echo "skill $(/usr/bin/rex --autostart=false skill status --json 2>/dev/null | b)"
    \\  ;;
    \\esac
    \\echo "agy $(command -v agy 2>/dev/null)"
    \\echo "agy_skill $(f "$HOME/.gemini/config/skills/rex/SKILL.md")"
    \\echo "agy_hook $(f "$HOME/.config/artoo/agy-rex-hook")"
    \\echo "agy_hook_mode $(stat -c %a "$HOME/.config/artoo/agy-rex-hook" 2>/dev/null)"
    \\if [ -f "$HOME/.gemini/config/hooks.json" ]; then echo "agy_hooks $(b < "$HOME/.gemini/config/hooks.json")"; fi
    \\
;

pub const Harness = struct {
    id: []const u8,
    detected: bool,
    session_naming: bool,
    /// Some item is `outdated` or `missing`.
    stale: bool,
    /// Items Rex did not install (`foreign`, `unreadable`): left alone.
    foreign: []const []const u8,
};

pub const State = struct {
    key: []const u8 = "-",
    sources: []const u8 = "-",
    suite: []const u8 = "",
    pin: []const u8 = "-",
    arch: []const u8 = "",
    pkg_status: []const u8 = "",
    pkg_version: []const u8 = "",
    maintainer: []const u8 = "",
    uid: []const u8 = "",
    linger: bool = false,
    /// `rex terminfo status --json`'s conclusion; null: not read.
    terminfo: ?[]const u8 = null,
    /// `rex skill status --json`'s harnesses; null: not read.
    harnesses: ?[]const Harness = null,
    /// `agy` on the user's PATH, or empty.
    agy: []const u8 = "",
    agy_skill: []const u8 = "-",
    agy_hook: []const u8 = "-",
    agy_hook_mode: []const u8 = "",
    /// `~/.gemini/config/hooks.json`; null: no file.
    agy_hooks: ?[]const u8 = null,
    raw: []const u8 = "",

    pub fn installed(s: State) bool {
        return std.mem.eql(u8, s.pkg_status, "installed");
    }

    /// Installed and Superlogical's (its Maintainer field).
    pub fn ours(s: State) bool {
        return s.installed() and std.ascii.findIgnoreCase(s.maintainer, "superlogical") != null;
    }

    pub fn ready(s: State) bool {
        return if (s.terminfo) |t| std.mem.startsWith(u8, t, "Ready") else false;
    }

    /// Rex lists a harness for agy: the bridge steps aside.
    pub fn agyHarness(s: State) bool {
        for (s.harnesses orelse &.{}) |h| if (std.mem.eql(u8, h.id, "agy")) return true;
        return false;
    }
};

fn decoded(a: Allocator, b64: []const u8) ?[]const u8 {
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64) catch return null;
    const out = a.alloc(u8, n) catch return null;
    dec.decode(out, b64) catch return null;
    return out;
}

fn parseHarnesses(a: Allocator, text: []const u8) !?[]const Harness {
    const v = std.json.parseFromSliceLeaky(Value, a, text, .{}) catch return null;
    const list = pve.obj(v, "harnesses");
    if (list != .array) return null;
    var out: std.ArrayList(Harness) = .empty;
    for (list.array.items) |h| {
        const id = pve.str(h, "id") orelse continue;
        var stale = false;
        var foreign: std.ArrayList([]const u8) = .empty;
        for (pve.items(pve.obj(h, "items"))) |it| {
            const st = pve.str(it, "state") orelse "";
            if (std.mem.eql(u8, st, "outdated") or std.mem.eql(u8, st, "missing")) stale = true;
            if (std.mem.eql(u8, st, "foreign") or std.mem.eql(u8, st, "unreadable"))
                try foreign.append(a, pve.str(it, "path") orelse pve.str(it, "kind") orelse "?");
        }
        try out.append(a, .{
            .id = id,
            .detected = pve.obj(h, "detected") == .bool and pve.obj(h, "detected").bool,
            .session_naming = pve.obj(h, "session_naming") == .bool and pve.obj(h, "session_naming").bool,
            .stale = stale,
            .foreign = foreign.items,
        });
    }
    return out.items;
}

pub fn parseState(a: Allocator, out: []const u8) !State {
    var st: State = .{ .raw = out };
    var lines = std.mem.tokenizeScalar(u8, out, '\n');
    while (lines.next()) |line| {
        const key, const val = std.mem.cut(u8, line, " ") orelse .{ line, "" };
        if (std.mem.eql(u8, key, "key")) st.key = val;
        if (std.mem.eql(u8, key, "sources")) st.sources = val;
        if (std.mem.eql(u8, key, "suite")) st.suite = val;
        if (std.mem.eql(u8, key, "pin")) st.pin = val;
        if (std.mem.eql(u8, key, "arch")) st.arch = val;
        if (std.mem.eql(u8, key, "uid")) st.uid = val;
        if (std.mem.eql(u8, key, "linger")) st.linger = std.mem.eql(u8, val, "yes");
        if (std.mem.eql(u8, key, "pkg")) {
            var parts = std.mem.splitScalar(u8, val, '|');
            st.pkg_status = parts.next() orelse "";
            st.pkg_version = parts.next() orelse "";
            st.maintainer = parts.rest();
        }
        if (std.mem.eql(u8, key, "terminfo")) {
            st.terminfo = "";
            if (decoded(a, val)) |j| {
                const v = std.json.parseFromSliceLeaky(Value, a, j, .{}) catch Value.null;
                st.terminfo = pve.str(v, "conclusion") orelse "";
            }
        }
        if (std.mem.eql(u8, key, "skill")) st.harnesses = if (decoded(a, val)) |j| try parseHarnesses(a, j) else null;
        if (std.mem.eql(u8, key, "agy")) st.agy = val;
        if (std.mem.eql(u8, key, "agy_skill")) st.agy_skill = val;
        if (std.mem.eql(u8, key, "agy_hook")) st.agy_hook = val;
        if (std.mem.eql(u8, key, "agy_hook_mode")) st.agy_hook_mode = val;
        if (std.mem.eql(u8, key, "agy_hooks")) st.agy_hooks = decoded(a, val) orelse "";
    }
    return st;
}

/// The probe script for `user` (a validated Linux name).
pub fn probeScript(a: Allocator, user: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "{s}{s}\n", .{ probe_root, try guest.asUser(a, user, probe_user) });
}

/// One read of the guest's Rex state (as root, then as `user`).
pub fn probe(c: *pve.Client, vmid: u32, user: []const u8) !State {
    const ctx = c.ctx;
    const r = try agent.exec(c, vmid, &.{ "sh", "-c", try probeScript(ctx.arena, user), "sh", user }, null, step_timeout_ms);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading Rex's state in VM {d} failed: {s}", .{ vmid, try k.clean(ctx, edge.firstLine(if (r.err.len > 0) r.err else r.out)) });
    return parseState(ctx.arena, r.out);
}

// ---------------------------------------------------------------- judge

/// The steps of `rex setup`, in order. Step 9 (agent profile, permission
/// kind) slots in before `tag`.
pub const Kind = enum {
    key,
    sources,
    pin,
    package,
    linger,
    terminfo,
    skill,
    agy_skill,
    agy_hook,
    agy_hooks,
    /// Step 9: the agent profile and the permission kind.
    profile,
    tag,
};

/// One change on one guest: a plan row and a ledger step.
pub const Item = struct {
    kind: Kind,
    /// "apt pin": the plan's and the ledger's word.
    label: []const u8,
    from: ?[]const u8,
    to: []const u8,
    /// Decided again once Rex is installed (it needs `rex`).
    after_install: bool = false,
    /// The file the step writes.
    content: []const u8 = "",
    /// `rex skill setup --agent` ids.
    agents: []const []const u8 = &.{},
    /// Set by `apply`: not needed once Rex is installed (why).
    skip: ?[]const u8 = null,
    /// `.profile`: the plan confirmed (`profile.apply` plans again from a
    /// fresh read) and its per-file rows.
    profile_plan: ?profile.Plan = null,
    changes: []const ui.blocks.Change = &.{},
};

/// A step that needs nothing: already right, or not wanted (and why).
pub const Done = struct { kind: Kind, text: []const u8 };

pub const Guest = struct {
    vm: vms.Vm,
    user: []const u8,
    channel: []const u8,
    state: State = .{},
    items: std.ArrayList(Item) = .empty,
    /// Reported, not redone.
    current: std.ArrayList(Done) = .empty,
    /// Not wanted on this guest ("no agy on the PATH").
    skipped: std.ArrayList(Done) = .empty,
    /// Plan notes for this guest (appendable by later steps).
    notes: std.ArrayList([]const u8) = .empty,
    /// Why the guest cannot be set up (the run refuses).
    refused: ?[]const u8 = null,
    /// Step 9's inputs: the loaded `agents.profile` (null: none) and
    /// `--force-profile`.
    agent_profile: ?profile.Profile = null,
    force_profile: bool = false,

    pub fn has(g: *const Guest, kind: Kind) ?Item {
        for (g.items.items) |it| if (it.kind == kind) return it;
        return null;
    }

    /// Why `kind` needs nothing (current or skipped), or null.
    pub fn reason(g: *const Guest, kind: Kind) ?[]const u8 {
        for (g.current.items) |d| if (d.kind == kind) return d.text;
        for (g.skipped.items) |d| if (d.kind == kind) return d.text;
        return null;
    }
};

fn clean(a: Allocator, s: []const u8) ![]const u8 {
    return ui.text.sanitize(a, s, .line);
}

fn validAgent(id: []const u8) bool {
    if (id.len == 0 or id.len > 32) return false;
    for (id) |ch| if (!(std.ascii.isLower(ch) or std.ascii.isDigit(ch) or ch == '-' or ch == '_')) return false;
    return true;
}

/// Fill `items`, `current` and `skipped` from `g.state` and `g.vm.tags`.
pub fn judge(a: Allocator, g: *Guest) !void {
    g.items = .empty;
    g.current = .empty;
    g.skipped = .empty;
    g.notes = .empty;
    g.refused = null;
    const st = g.state;
    const items = &g.items;
    if (st.uid.len == 0) {
        g.refused = try std.fmt.allocPrint(a, "the user {s} does not exist on the guest", .{g.user});
        return;
    }
    if (st.arch.len == 0) {
        g.refused = "'dpkg --print-architecture' names no architecture";
        return;
    }
    const arch = try clean(a, st.arch);

    // 1. apt key, by SHA-256.
    if (std.mem.eql(u8, st.key, keyring_sha256)) {
        try g.current.append(a, .{ .kind = .key, .text = "apt key" });
    } else try items.append(a, .{ .kind = .key, .label = "apt key", .from = if (std.mem.eql(u8, st.key, "-")) null else "another keyring", .to = "Superlogical's signing key " ++ keyring_fingerprint, .content = keyring });

    // 2. apt source: suite rex.channel, the guest's architecture.
    const src = try sources(a, g.channel, arch);
    if (std.mem.eql(u8, st.sources, try sha256Hex(a, src))) {
        try g.current.append(a, .{ .kind = .sources, .text = "apt source" });
    } else try items.append(a, .{
        .kind = .sources,
        .label = "apt source",
        .from = if (std.mem.eql(u8, st.sources, "-")) null else if (st.suite.len > 0) try std.fmt.allocPrint(a, "suite {s}, differs", .{try clean(a, st.suite)}) else "differs",
        .to = try std.fmt.allocPrint(a, "suite {s}, {s} ({s})", .{ g.channel, arch, sources_path }),
        .content = src,
    });

    // 3. apt pin: exactly upstream's.
    if (std.mem.eql(u8, st.pin, try sha256Hex(a, pin))) {
        try g.current.append(a, .{ .kind = .pin, .text = "apt pin" });
    } else try items.append(a, .{ .kind = .pin, .label = "apt pin", .from = if (std.mem.eql(u8, st.pin, "-")) null else "not upstream's", .to = "Rex 1001, every other origin -1 (" ++ pin_path ++ ")", .content = pin });

    // 4. package: installed only when missing or not Superlogical's.
    if (st.ours()) {
        try g.current.append(a, .{ .kind = .package, .text = try std.fmt.allocPrint(a, "rex {s}", .{try clean(a, st.pkg_version)}) });
    } else try items.append(a, .{
        .kind = .package,
        .label = "package",
        .from = if (st.installed()) try std.fmt.allocPrint(a, "rex {s}, not Superlogical's", .{try clean(a, st.pkg_version)}) else null,
        .to = try std.fmt.allocPrint(a, "rex from pkgs.superlogical.com ({s})", .{g.channel}),
    });

    // 5. linger.
    if (st.linger) {
        try g.current.append(a, .{ .kind = .linger, .text = "linger" });
    } else try items.append(a, .{ .kind = .linger, .label = "linger", .from = "off", .to = try std.fmt.allocPrint(a, "on for {s} (sessions survive logout)", .{g.user}) });

    // 6. terminfo.
    if (!st.ours()) {
        try items.append(a, .{ .kind = .terminfo, .label = "terminfo", .from = null, .to = "rex terminfo setup --system, unless Ready (read after the install)", .after_install = true });
    } else if (st.ready()) {
        try g.current.append(a, .{ .kind = .terminfo, .text = "terminfo" });
    } else try items.append(a, .{ .kind = .terminfo, .label = "terminfo", .from = if (st.terminfo) |t| (if (t.len > 0) try clean(a, t) else "unknown") else "unknown", .to = "rex terminfo setup --system" });

    // 7. agent skill, for each harness Rex detects.
    if (!st.ours()) {
        try items.append(a, .{ .kind = .skill, .label = "agent skill", .from = null, .to = "rex skill setup --session-naming for each agent Rex detects (read after the install)", .after_install = true });
    } else if (st.harnesses) |hs| {
        var ids: std.ArrayList([]const u8) = .empty;
        var stale: std.ArrayList([]const u8) = .empty;
        // The profile creates ~/.claude when the guest has none yet, and
        // Rex detects Claude by it: name Claude now, or its skill and hook
        // wait for the next run.
        const claude_soon = profile.writesClaude(g.agent_profile);
        for (hs) |h| {
            const detected = h.detected or (claude_soon and std.mem.eql(u8, h.id, "claude"));
            if (!detected or !validAgent(h.id)) continue;
            try ids.append(a, h.id);
            if (h.stale or !h.session_naming) try stale.append(a, h.id);
            for (h.foreign) |p| try g.notes.append(a, try std.fmt.allocPrint(a, "{s}: {s}'s {s} was not installed by Rex; left alone (rex skill setup --force replaces it).", .{ g.vm.name, h.id, try clean(a, p) }));
        }
        if (ids.items.len == 0) {
            try g.skipped.append(a, .{ .kind = .skill, .text = "agent skill (no agent detected)" });
        } else if (stale.items.len == 0) {
            try g.current.append(a, .{ .kind = .skill, .text = try std.fmt.allocPrint(a, "agent skill ({s})", .{try std.mem.join(a, ", ", ids.items)}) });
        } else {
            var cmd: std.ArrayList(u8) = .empty;
            try cmd.appendSlice(a, "rex skill setup --session-naming");
            for (ids.items) |id| try cmd.print(a, " --agent {s}", .{id});
            try items.append(a, .{ .kind = .skill, .label = "agent skill", .from = try std.fmt.allocPrint(a, "outdated or missing: {s}", .{try std.mem.join(a, ", ", stale.items)}), .to = cmd.items, .agents = ids.items });
        }
    } else try g.skipped.append(a, .{ .kind = .skill, .text = "agent skill ('rex skill status' gave no answer)" });

    // 8. agy bridge, when agy is on the user's PATH and Rex has no agy harness.
    try judgeBridge(a, g);

    // 9. profile and permissions: `judgeProfile` (it reads the guest).

    // 10. tag, last.
    if (guest.tagged(g.vm)) {
        try g.current.append(a, .{ .kind = .tag, .text = "tag " ++ guest.tag });
    } else try items.append(a, .{ .kind = .tag, .label = "tag", .from = if (g.vm.tags.len > 0) try clean(a, g.vm.tags) else null, .to = try withTag(a, g.vm.tags) });
}

fn judgeBridge(a: Allocator, g: *Guest) !void {
    const st = g.state;
    const bridge: []const Kind = &.{ .agy_skill, .agy_hook, .agy_hooks };
    if (st.agy.len == 0) {
        for (bridge) |kind| try g.skipped.append(a, .{ .kind = kind, .text = "agy bridge (no agy on the PATH)" });
        return;
    }
    if (st.agyHarness()) {
        for (bridge) |kind| try g.skipped.append(a, .{ .kind = kind, .text = "agy bridge (Rex sets up agy itself)" });
        return;
    }
    var n: usize = 0;
    if (!std.mem.eql(u8, st.agy_skill, try sha256Hex(a, agy.skill_stub))) {
        try g.items.append(a, .{ .kind = .agy_skill, .label = "agy skill", .from = if (std.mem.eql(u8, st.agy_skill, "-")) null else "changed", .to = "~/" ++ agy.skill_path, .content = agy.skill_stub });
        n += 1;
    }
    if (!std.mem.eql(u8, st.agy_hook, try sha256Hex(a, agy.hook_script)) or !std.mem.eql(u8, st.agy_hook_mode, "755")) {
        try g.items.append(a, .{ .kind = .agy_hook, .label = "agy hook", .from = if (std.mem.eql(u8, st.agy_hook, "-")) null else "changed", .to = "~/" ++ agy.hook_path ++ " (0755)", .content = agy.hook_script });
        n += 1;
    }
    const merged = agy.mergeHooks(a, st.agy_hooks) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        error.NotAnObject => {
            g.refused = "~/" ++ agy.hooks_path ++ " is not a JSON object; fix or remove it";
            return;
        },
    };
    if (merged) |text| {
        try g.items.append(a, .{ .kind = .agy_hooks, .label = "agy hooks", .from = if (st.agy_hooks == null) null else "other hooks kept", .to = "key " ++ agy.hooks_key ++ " in ~/" ++ agy.hooks_path ++ " (SessionStart, PreInvocation, Stop)", .content = text });
        n += 1;
    }
    if (n == 0) for (bridge) |kind| try g.current.append(a, .{ .kind = kind, .text = "agy bridge" });
}

/// `tags` with `rex` added last (`;`-separated, as Proxmox writes them).
pub fn withTag(a: Allocator, tags: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, tags, ";, ");
    while (it.next()) |t| {
        if (std.mem.eql(u8, t, guest.tag)) continue;
        if (out.items.len > 0) try out.append(a, ';');
        try out.appendSlice(a, t);
    }
    if (out.items.len > 0) try out.append(a, ';');
    try out.appendSlice(a, guest.tag);
    return out.items;
}

/// The texts of steps already right ("apt key, apt source"), each once.
pub fn currentText(a: Allocator, g: *const Guest) ![]const u8 {
    return doneText(a, g.current.items);
}

pub fn skippedText(a: Allocator, g: *const Guest) ![]const u8 {
    return doneText(a, g.skipped.items);
}

fn doneText(a: Allocator, list: []const Done) ![]const u8 {
    var seen: std.ArrayList([]const u8) = .empty;
    outer: for (list) |d| {
        for (seen.items) |s| if (std.mem.eql(u8, s, d.text)) continue :outer;
        try seen.append(a, d.text);
    }
    return std.mem.join(a, ", ", seen.items);
}

// ---------------------------------------------------------------- read

/// `v` read for Rex: refused (error.Refused, nothing sent) when it may not
/// have Rex, else probed and judged.
pub fn readGuest(ctx: *Context, c: *pve.Client, v: vms.Vm) !Guest {
    return readGuestWith(ctx, c, v, .{ .agent_profile = try profile.loadConfigured(ctx) });
}

pub const Opts = struct { agent_profile: ?profile.Profile = null, force_profile: bool = false };

pub fn readGuestWith(ctx: *Context, c: *pve.Client, v: vms.Vm, opts: Opts) !Guest {
    const cfg = try ctx.config();
    if (guest.refusal(v)) |why| return ctx.fail(error.Refused, "{s} is {s}; Rex is for ordinary artoo guests — nothing was sent", .{ try k.clean(ctx, v.name), why });
    if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first — nothing was sent", .{ v.name, v.status });
    if (!try agent.ping(c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer — nothing was sent", .{v.name});
    var g: Guest = .{ .vm = v, .user = cfg.guests.user, .channel = @tagName(cfg.rex.channel), .agent_profile = opts.agent_profile, .force_profile = opts.force_profile };
    g.state = try probe(c, v.vmid, g.user);
    try judge(ctx.arena, &g);
    if (g.refused) |why| return ctx.fail(error.Refused, "{s}: {s} — nothing was sent", .{ v.name, why });
    try judgeProfile(ctx, c, &g);
    return g;
}

/// Step 9: read the guest's agent files, plan the profile and
/// the permission kind, and slot the step in before the tag.
pub fn judgeProfile(ctx: *Context, c: *pve.Client, g: *Guest) !void {
    const a = ctx.arena;
    const pg = try profile.read(ctx, c, g.vm.vmid, g.user, g.agent_profile);
    const fence = try fenceOf(ctx, c, g.vm);
    const kind = profile.kindOf(fence, pg.ssh_keys);
    const p = try profile.plan(a, g.agent_profile, pg, kind, g.force_profile);
    try g.notes.appendSlice(a, p.notes);
    // Only a fenced guest needs the reason: it would be sandboxed but for
    // its keys.
    if (fence != .none and kind == .trusted_reach)
        try g.notes.append(a, try std.fmt.allocPrint(a, "Permissions: {s}", .{try permissions.reason(a, fence, pg.ssh_keys)}));
    const what = if (g.agent_profile == null) "permissions" else "agent profile";
    if (p.empty()) {
        try g.current.append(a, .{ .kind = .profile, .text = try std.fmt.allocPrint(a, "{s} ({s})", .{ what, kind.word() }) });
        return;
    }
    const item: Item = .{
        .kind = .profile,
        // Not "permissions": that is the detail row below it.
        .label = if (g.agent_profile == null) "permission files" else what,
        .from = null,
        .to = try std.fmt.allocPrint(a, "{f}, {s}", .{ ui.values.count(p.writes.len, "file"), kind.word() }),
        .profile_plan = p,
        .changes = p.changes,
    };
    // Before the tag, which stays last.
    const at = for (g.items.items, 0..) |it, i| {
        if (it.kind == .tag) break i;
    } else g.items.items.len;
    try g.items.insert(a, at, item);
}

/// Whether `v`'s fence holds: tagged `fenced` and `vm verify`'s fence
/// check ok (rules as derived, the datacenter firewall on). The tag alone
/// never sandboxes a guest.
pub fn fenceOf(ctx: *Context, c: *pve.Client, v: vms.Vm) !permissions.Fence {
    const vm_fence = @import("../commands/vm_fence.zig");
    if (!template.taggedWith(v.tags, vm_fence.tag)) return .none;
    const ck = vm_fence.check(ctx, c, v) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => {
            defer ctx.diag = null;
            return .{ .broken = try k.clean(ctx, ctx.diag orelse @errorName(err)) };
        },
    };
    return if (ck.status == .ok) .holds else .{ .broken = ck.detail };
}

/// Re-read `g` (state and tags) and judge it again.
pub fn reread(ctx: *Context, c: *pve.Client, g: *Guest) !void {
    for (try vms.list(c)) |v| if (v.vmid == g.vm.vmid) {
        g.vm = v;
    };
    g.state = try probe(c, g.vm.vmid, g.user);
    try judge(ctx.arena, g);
    if (g.refused == null) try judgeProfile(ctx, c, g);
}

/// What is still not right after a run ("apt pin, tag"); empty when
/// every step converged.
pub fn leftover(ctx: *Context, c: *pve.Client, g: *Guest) ![]const u8 {
    try reread(ctx, c, g);
    if (g.refused) |why| return why;
    var labels: std.ArrayList([]const u8) = .empty;
    for (g.items.items) |it| try labels.append(ctx.arena, it.label);
    return std.mem.join(ctx.arena, ", ", labels.items);
}

// ---------------------------------------------------------------- apply

/// Where `apply` reports: one ledger row per item (added by the caller,
/// in item order, from `first`), or one ledger step for the whole setup.
pub const Report = union(enum) {
    rows: Rows,
    step: exec.Note,

    pub const Rows = struct { ledger: *exec.Ledger, first: usize };

    fn start(r: Report, i: usize, label: []const u8) void {
        switch (r) {
            .rows => |x| x.ledger.set(x.first + i, .unknown, ""),
            .step => |n| n.say(label),
        }
    }

    fn end(r: Report, i: usize, state: exec.Ledger.State, detail: []const u8) void {
        switch (r) {
            .rows => |x| x.ledger.set(x.first + i, state, detail),
            .step => {},
        }
    }
};

/// The ledger row names of `g`'s items ("naboo apt pin").
pub fn addRows(a: Allocator, l: *exec.Ledger, g: *const Guest) !Report.Rows {
    const first = l.steps.items.len;
    for (g.items.items) |it| _ = try l.add(a, try std.fmt.allocPrint(a, "{s} {s}", .{ g.vm.name, it.label }));
    return .{ .ledger = l, .first = first };
}

/// Apply `g`'s items in order. After the package step the guest is read
/// again: the steps that need Rex are decided then (skipped when already
/// right). Stops at the first failure (ctx.fail, error.Partial).
pub fn apply(ctx: *Context, c: *pve.Client, g: *Guest, report: Report) !void {
    const a = ctx.arena;
    var i: usize = 0;
    while (i < g.items.items.len) : (i += 1) {
        const it = g.items.items[i];
        report.start(i, it.label);
        if (it.skip) |why| {
            report.end(i, .skipped, why);
            continue;
        }
        var detail = try applyItem(ctx, c, g, it);
        if (it.kind == .skill and g.has(.profile) == null) {
            // Rex's skill setup may have just created ~/.claude/settings.json,
            // which step 9 (planned from the earlier read, empty then) now
            // has to bring to the kind the plan named.
            const pg = try profile.read(ctx, c, g.vm.vmid, g.user, g.agent_profile);
            const kind = profile.kindOf(try fenceOf(ctx, c, g.vm), pg.ssh_keys);
            const p = try profile.plan(a, g.agent_profile, pg, kind, g.force_profile);
            if (!p.empty()) {
                try profile.write(ctx, c, g.vm.vmid, g.user, p);
                detail = try std.fmt.allocPrint(a, "{s}; then the permission kind {s} ({f})", .{ detail, kind.word(), ui.values.count(p.writes.len, "file") });
            }
        }
        if (it.kind != .package) {
            report.end(i, .done, detail);
            continue;
        }
        // Rex is installed now: decide its own steps from a fresh read.
        var fresh = g.*;
        fresh.state = try probe(c, g.vm.vmid, g.user);
        if (!fresh.state.ours()) {
            report.end(i, .failed, try clean(a, fresh.state.maintainer));
            return ctx.fail(error.Partial, "rex on {s} is still not Superlogical's after the install ({s}); check 'apt-cache policy rex' there", .{ g.vm.name, try k.clean(ctx, fresh.state.pkg_version) });
        }
        try judge(a, &fresh);
        if (fresh.refused) |why| {
            report.end(i, .failed, why);
            return ctx.fail(error.Partial, "{s}: {s}", .{ g.vm.name, why });
        }
        report.end(i, .done, try std.fmt.allocPrint(a, "rex {s}", .{try clean(a, fresh.state.pkg_version)}));
        for (g.items.items[i + 1 ..]) |*later| {
            // Step 9 was planned from its own read; `profile.apply` reads again.
            if (later.kind == .profile) continue;
            if (fresh.has(later.kind)) |now| {
                const label = later.label;
                later.* = now;
                later.label = label;
            } else later.skip = fresh.reason(later.kind) orelse "already right";
        }
        g.state = fresh.state;
        g.notes = fresh.notes;
    }
}

fn applyItem(ctx: *Context, c: *pve.Client, g: *Guest, it: Item) ![]const u8 {
    const a = ctx.arena;
    const id = g.vm.vmid;
    switch (it.kind) {
        .key => {
            try edge.writeFile(c, id, .{ .path = keyring_path, .mode = "0644", .owner = "root:root", .content = keyring });
            return keyring_path;
        },
        .sources => {
            try edge.writeFile(c, id, .{ .path = sources_path, .mode = "0644", .owner = "root:root", .content = it.content });
            return try std.fmt.allocPrint(a, "suite {s}", .{g.channel});
        },
        .pin => {
            try edge.writeFile(c, id, .{ .path = pin_path, .mode = "0644", .owner = "root:root", .content = pin });
            return pin_path;
        },
        .package => {
            try edge.run(c, id, "installing rex", install_script, install_timeout_ms);
            return "installed";
        },
        .linger => {
            const r = try agent.exec(c, id, &.{ "loginctl", "enable-linger", g.user }, null, step_timeout_ms);
            if (!r.ok()) return ctx.fail(error.Partial, "loginctl enable-linger {s} failed on {s}: {s}", .{ g.user, g.vm.name, try k.clean(ctx, edge.firstLine(r.err)) });
            return "on";
        },
        .terminfo => {
            try edge.run(c, id, "rex terminfo setup --system", terminfo_script, step_timeout_ms);
            return "set up";
        },
        .skill => {
            var cmd: std.ArrayList(u8) = .empty;
            try cmd.appendSlice(a, "rex --autostart=false skill setup --session-naming");
            for (it.agents) |agent_id| {
                if (!validAgent(agent_id)) return ctx.fail(error.Protocol, "rex skill status on {s} names an agent '{s}'", .{ g.vm.name, try k.clean(ctx, agent_id) });
                try cmd.print(a, " --agent {s}", .{agent_id});
            }
            try cmd.appendSlice(a, " >/dev/null");
            try edge.run(c, id, "rex skill setup", try guest.asUser(a, g.user, cmd.items), step_timeout_ms);
            return std.mem.join(a, ", ", it.agents);
        },
        .agy_skill => {
            try writeUserFile(c, id, g.user, agy.skill_path, "0644", it.content);
            return "~/" ++ agy.skill_path;
        },
        .agy_hook => {
            try writeUserFile(c, id, g.user, agy.hook_path, "0755", it.content);
            return "~/" ++ agy.hook_path;
        },
        .agy_hooks => {
            try writeUserFile(c, id, g.user, agy.hooks_path, "0644", it.content);
            return "key " ++ agy.hooks_key;
        },
        .profile => {
            const done = try profile.apply(ctx, c, id, g.user, it.profile_plan.?);
            return std.fmt.allocPrint(a, "{f} written, {s}", .{ ui.values.count(done.writes.len, "file"), done.kind.word() });
        },
        .tag => {
            const cfg = try vms.config(c, id);
            const tags = pve.str(cfg, "tags") orelse "";
            if (template.taggedWith(tags, guest.tag)) return "already tagged";
            _ = try c.send(.PUT, try c.nodePath("/qemu/{d}/config", .{id}), &.{
                .{ .name = "tags", .value = try withTag(a, tags) },
                .{ .name = "digest", .value = pve.str(cfg, "digest") orelse "" },
            });
            return guest.tag;
        },
    }
}

/// As the user (`$1` relative to the home, `$2` mode, base64 on stdin):
/// directories and file are the user's.
const user_write =
    \\set -eu
    \\p="$HOME/$1"
    \\mkdir -p "$(dirname "$p")"
    \\t=$(mktemp "$p.artoo.XXXXXX")
    \\base64 -d > "$t"
    \\chmod "$2" "$t"
    \\mv -f "$t" "$p"
    \\
;

/// Write `content` to `rel` (under the user's home) as the guest user.
pub fn writeUserFile(c: *pve.Client, vmid: u32, user: []const u8, rel: []const u8, mode: []const u8, content: []const u8) !void {
    const ctx = c.ctx;
    const a = ctx.arena;
    if (content.len > files.part_bytes) return ctx.fail(error.Partial, "~/{s} would be {d} bytes, over the {d} artoo writes in one go", .{ rel, content.len, files.part_bytes });
    const script = try std.fmt.allocPrint(a, "{s} sh \"$1\" \"$2\"", .{try guest.asUser(a, user, user_write)});
    const enc = std.base64.standard.Encoder;
    const b64 = try a.alloc(u8, enc.calcSize(content.len));
    const r = try agent.exec(c, vmid, &.{ "sh", "-c", script, "sh", rel, mode }, enc.encode(b64, content), 60_000);
    if (!r.ok()) return ctx.fail(error.Partial, "writing ~/{s} failed: {s}", .{ rel, try k.clean(ctx, edge.firstLine(r.err)) });
}

/// `vm new --rex`: set Rex up on the new guest as `rex setup`
/// does, reported into one ledger step; the step's detail.
pub fn setUpNew(ctx: *Context, c: *pve.Client, v: vms.Vm, note: exec.Note) ![]const u8 {
    var g = try readGuest(ctx, c, v);
    if (g.items.items.len == 0) return "already set up";
    try apply(ctx, c, &g, .{ .step = note });
    const left = try leftover(ctx, c, &g);
    if (left.len > 0) return ctx.fail(error.Partial, "Rex on {s}: still not right after setup: {s}", .{ v.name, left });
    return std.fmt.allocPrint(ctx.arena, "rex {s}, tag {s}", .{ try k.clean(ctx, g.state.pkg_version), guest.tag });
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "the embedded keyring is Superlogical's" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqual(@as(usize, 2854), keyring.len);
    try testing.expectEqualStrings(keyring_sha256, try sha256Hex(arena.allocator(), keyring));
}

test "sources and pin are upstream's files" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings(
        "Types: deb\nURIs: https://pkgs.superlogical.com/rex/apt\nSuites: preview\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/rex-archive-keyring.gpg\n",
        try sources(arena.allocator(), "preview", "amd64"),
    );
    try testing.expectEqualStrings("Package: rex\nPin: origin pkgs.superlogical.com\nPin-Priority: 1001\n\nPackage: rex\nPin: release *\nPin-Priority: -1\n", pin);
    try testing.expect(std.mem.find(u8, install_script, "apt-get install -y --allow-downgrades -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold rex") != null);
}

test "withTag: rex last, once" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("artoo;fenced;rex", try withTag(a, "artoo,fenced"));
    try testing.expectEqualStrings("artoo;rex", try withTag(a, "rex;artoo"));
    try testing.expectEqualStrings("rex", try withTag(a, ""));
}

test "the probe runs the user's part as the user, never a login shell" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const s = try probeScript(arena.allocator(), "artoo");
    try testing.expect(std.mem.find(u8, s, "runuser -u \"$u\" -- env HOME=") != null);
    try testing.expect(std.mem.find(u8, s, "REX_AUTOSTART=0") != null);
    try testing.expect(std.mem.find(u8, s, "runuser -l") == null);
}

/// Probe output for tests (`Fixture` builds its variants).
pub const Fixture = struct {
    a: Allocator,
    key: []const u8 = keyring_sha256,
    sources_hash: ?[]const u8 = null,
    pin_hash: ?[]const u8 = null,
    pkg: []const u8 = "installed|0.1.0~alpha.23|Superlogical <packages@superlogical.com>",
    linger: bool = true,
    terminfo: ?[]const u8 = "{\"conclusion\":\"Ready: xterm-rex is installed\"}",
    skill: ?[]const u8 = "{\"harnesses\":[{\"id\":\"claude\",\"detected\":true,\"session_naming\":true,\"items\":[{\"kind\":\"skill\",\"state\":\"current\"},{\"kind\":\"hook\",\"state\":\"current\"}]},{\"id\":\"codex\",\"detected\":false,\"session_naming\":true,\"items\":[{\"kind\":\"skill\",\"state\":\"missing\"}]}]}",
    agy: []const u8 = "",
    agy_files: bool = false,
    hooks: ?[]const u8 = null,

    fn b64(a: Allocator, s: []const u8) ![]const u8 {
        const enc = std.base64.standard.Encoder;
        const buf = try a.alloc(u8, enc.calcSize(s.len));
        return enc.encode(buf, s);
    }

    pub fn out(f: Fixture) ![]const u8 {
        const a = f.a;
        var o: std.ArrayList(u8) = .empty;
        try o.print(a, "key {s}\nsources {s}\nsuite preview\npin {s}\narch amd64\npkg {s}\nuid 1000\nlinger {s}\n", .{
            f.key,
            f.sources_hash orelse try sha256Hex(a, try sources(a, "preview", "amd64")),
            f.pin_hash orelse try sha256Hex(a, pin),
            f.pkg,
            if (f.linger) "yes" else "no",
        });
        if (f.terminfo) |t| try o.print(a, "terminfo {s}\n", .{try b64(a, t)});
        if (f.skill) |s| try o.print(a, "skill {s}\n", .{try b64(a, s)});
        try o.print(a, "agy {s}\n", .{f.agy});
        if (f.agy_files) {
            try o.print(a, "agy_skill {s}\nagy_hook {s}\nagy_hook_mode 755\n", .{ try sha256Hex(a, agy.skill_stub), try sha256Hex(a, agy.hook_script) });
        } else try o.appendSlice(a, "agy_skill -\nagy_hook -\nagy_hook_mode \n");
        if (f.hooks) |h| try o.print(a, "agy_hooks {s}\n", .{try b64(a, h)});
        return o.items;
    }
};

pub const test_vm: vms.Vm = .{ .vmid = 201, .name = "naboo", .status = "running", .tags = "artoo;rex", .template = false, .cpus = null, .cpu = null, .mem = null, .maxmem = null, .maxdisk = null, .uptime = null, .lock = null };

fn judged(a: Allocator, f: Fixture, tags: []const u8) !Guest {
    var v = test_vm;
    v.tags = tags;
    var g: Guest = .{ .vm = v, .user = "artoo", .channel = "preview", .state = try parseState(a, try f.out()) };
    try judge(a, &g);
    return g;
}

fn kinds(a: Allocator, g: *const Guest) ![]const u8 {
    var o: std.ArrayList(u8) = .empty;
    for (g.items.items) |it| {
        if (o.items.len > 0) try o.append(a, ' ');
        try o.appendSlice(a, @tagName(it.kind));
    }
    return o.items;
}

test "judge: a set-up guest needs nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const g = try judged(a, .{ .a = a }, "artoo;rex");
    try testing.expectEqualStrings("", try kinds(a, &g));
    try testing.expectEqualStrings("apt key, apt source, apt pin, rex 0.1.0~alpha.23, linger, terminfo, agent skill (claude), tag rex", try currentText(a, &g));
    try testing.expectEqualStrings("agy bridge (no agy on the PATH)", try skippedText(a, &g));
}

test "judge: a fresh guest needs every step; Rex's own steps wait for the install" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const g = try judged(a, .{ .a = a, .key = "-", .sources_hash = "-", .pin_hash = "-", .pkg = "", .linger = false, .terminfo = null, .skill = null }, "artoo");
    try testing.expectEqualStrings("key sources pin package linger terminfo skill tag", try kinds(a, &g));
    try testing.expect(g.has(.terminfo).?.after_install and g.has(.skill).?.after_install);
    try testing.expect(g.has(.package).?.from == null);
    try testing.expectEqualStrings("artoo;rex", g.has(.tag).?.to);
}

test "judge: Rex installed by hand with Ubuntu's pin, Perl's rex, linger off, skill outdated, terminfo not ready" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // The live test guest: the pin's second record says o=Ubuntu.
    const pinned = try judged(a, .{ .a = a, .pin_hash = try sha256Hex(a, "Package: rex\nPin: origin pkgs.superlogical.com\nPin-Priority: 1001\n\nPackage: rex\nPin: release o=Ubuntu\nPin-Priority: -1\n") }, "artoo");
    try testing.expectEqualStrings("pin tag", try kinds(a, &pinned));
    try testing.expectEqualStrings("not upstream's", pinned.has(.pin).?.from.?);

    const perl = try judged(a, .{ .a = a, .pkg = "installed|1.16.0-1|Debian Perl Group <pkg-perl-maintainers@lists.alioth.debian.org>", .terminfo = null, .skill = null }, "artoo;rex");
    try testing.expectEqualStrings("package terminfo skill", try kinds(a, &perl));
    try testing.expectEqualStrings("rex 1.16.0-1, not Superlogical's", perl.has(.package).?.from.?);

    const stale = try judged(a, .{
        .a = a,
        .linger = false,
        .terminfo = "{\"conclusion\":\"Not ready: the xterm-rex entry is not installed for this account.\"}",
        .skill = "{\"harnesses\":[{\"id\":\"claude\",\"detected\":true,\"session_naming\":false,\"items\":[{\"kind\":\"skill\",\"state\":\"current\"}]},{\"id\":\"pi\",\"detected\":true,\"session_naming\":true,\"items\":[{\"kind\":\"skill\",\"path\":\"/home/artoo/.pi/skills/rex\",\"state\":\"foreign\"},{\"kind\":\"hook\",\"state\":\"outdated\"}]}]}",
    }, "artoo;rex");
    try testing.expectEqualStrings("linger terminfo skill", try kinds(a, &stale));
    try testing.expectEqualStrings("rex skill setup --session-naming --agent claude --agent pi", stale.has(.skill).?.to);
    try testing.expectEqualStrings("Not ready: the xterm-rex entry is not installed for this account.", stale.has(.terminfo).?.from.?);
    try testing.expectEqual(@as(usize, 1), stale.notes.items.len);
    try testing.expect(std.mem.find(u8, stale.notes.items[0], "/home/artoo/.pi/skills/rex was not installed by Rex") != null);

    const none = try judged(a, .{ .a = a, .skill = "{\"harnesses\":[{\"id\":\"claude\",\"detected\":false,\"items\":[]}]}" }, "artoo;rex");
    try testing.expectEqualStrings("", try kinds(a, &none));
    try testing.expectEqualStrings("agent skill (no agent detected), agy bridge (no agy on the PATH)", try skippedText(a, &none));
}

test "judge: a profile that writes ~/.claude names Claude before Rex can detect it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f: Fixture = .{ .a = a, .skill = "{\"harnesses\":[{\"id\":\"claude\",\"detected\":false,\"items\":[{\"kind\":\"skill\",\"state\":\"missing\"},{\"kind\":\"hook\",\"state\":\"missing\"}]},{\"id\":\"pi\",\"detected\":false,\"items\":[{\"kind\":\"skill\",\"state\":\"missing\"}]}]}" };
    const entries = [_]profile.Entry{.{ .source = "rules/AGENTS.md", .target = ".claude/CLAUDE.md", .content = "x" }};
    var g: Guest = .{ .vm = test_vm, .user = "artoo", .channel = "preview", .state = try parseState(a, try f.out()), .agent_profile = .{ .dir = "/p", .entries = &entries, .files = 1, .bytes = 1 } };
    try judge(a, &g);
    try testing.expectEqualStrings("rex skill setup --session-naming --agent claude", g.has(.skill).?.to);
    // Without a profile, nothing is detected and nothing is named.
    const none = try judged(a, f, "artoo;rex");
    try testing.expect(none.has(.skill) == null);
}

test "judge: the agy bridge when agy is on the PATH; steps aside for Rex's own harness; a broken hooks.json refuses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const fresh = try judged(a, .{ .a = a, .agy = "/home/artoo/.local/bin/agy", .hooks = "{\"mine\":{\"Stop\":[]}}" }, "artoo;rex");
    try testing.expectEqualStrings("agy_skill agy_hook agy_hooks", try kinds(a, &fresh));
    try testing.expect(std.mem.find(u8, fresh.has(.agy_hooks).?.content, "\"mine\"") != null);

    const done = try judged(a, .{ .a = a, .agy = "/home/artoo/.local/bin/agy", .agy_files = true, .hooks = (try agy.mergeHooks(a, null)).? }, "artoo;rex");
    try testing.expectEqualStrings("", try kinds(a, &done));
    try testing.expectEqual(agy.Files.current, try agy.files(a, done.state));
    try testing.expectEqual(agy.Files.missing, try agy.files(a, fresh.state));

    const native = try judged(a, .{ .a = a, .agy = "/usr/bin/agy", .skill = "{\"harnesses\":[{\"id\":\"agy\",\"detected\":true,\"session_naming\":true,\"items\":[]}]}" }, "artoo;rex");
    try testing.expectEqualStrings("", try kinds(a, &native));
    try testing.expectEqualStrings("agy bridge (Rex sets up agy itself)", try skippedText(a, &native));

    const broken = try judged(a, .{ .a = a, .agy = "/usr/bin/agy", .hooks = "[" }, "artoo;rex");
    try testing.expect(broken.refused != null);
}

test "judge: a missing user or architecture refuses" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var g: Guest = .{ .vm = test_vm, .user = "artoo", .channel = "preview", .state = try parseState(a, "key -\narch amd64\nuid \n") };
    try judge(a, &g);
    try testing.expectEqualStrings("the user artoo does not exist on the guest", g.refused.?);
    g.state = try parseState(a, "uid 1000\narch \n");
    try judge(a, &g);
    try testing.expect(g.refused != null);
}

const NewProbe = struct {
    pub const name = "probe";
    pub const summary = "setUpNew probe";
    pub fn run(ctx: *Context, _: @import("../cli.zig").Args(@This())) !void {
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var l: exec.Ledger = .{};
        const i = try l.add(ctx.arena, "set up Rex");
        var v = test_vm;
        v.tags = "artoo";
        try ctx.out.print("{s}\n", .{try setUpNew(ctx, &c, v, l.noter(i))});
    }
};

test "setUpNew: vm new's one step runs rex setup's steps and checks they converged" {
    const testkit = @import("../testkit.zig");
    const cli = @import("../cli.zig");
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const probe_out = try std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = try (Fixture{ .a = a }).out() } }, .{});
    const profile_out = try std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = 0, .@"out-data" = try profile.probeOut(a, .{ .agents = "" }) } }, .{});
    const R = testkit.Gateway.FakeServer.Route;
    const r = struct {
        fn f(match: []const u8, body: []const u8) R {
            return .{ .match = match, .behavior = .{ .respond = .{ .body = body } } };
        }
    }.f;
    var g: testkit.Gateway = undefined;
    try g.initRoutes(&.{
        r("agent/ping", "{\"data\":{\"result\":{}}}"),
        r("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        r("exec-status", probe_out),
        r("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        r("exec-status", profile_out),
        r("GET /api2/json/nodes/pve/qemu/201/config", "{\"data\":{\"tags\":\"artoo\",\"digest\":\"d1\"}}"),
        r("PUT /api2/json/nodes/pve/qemu/201/config", "{\"data\":null}"),
        r("GET /api2/json/nodes/pve/qemu HTTP", "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;rex\"}]}"),
        r("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        r("exec-status", probe_out),
        r("agent/exec HTTP", "{\"data\":{\"pid\":44}}"),
        r("exec-status", profile_out),
    });
    defer g.deinit();
    const root = cli.group("artoo", "t", &.{cli.leaf(NewProbe)});
    try testing.expectEqual(testkit.Exit.ok, g.h.run(&root, "probe"));
    try testing.expectEqual(@as(usize, 0), g.srv.unused());
    try testing.expectEqualStrings("rex 0.1.0~alpha.23, tag rex\n", g.h.stdout());
}

test "the setup scripts are ASCII (the guest agent wedges on anything else)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ try probeScript(arena.allocator(), "user"), install_script, terminfo_script, user_write }) |s|
        for (s) |b| try std.testing.expect(b < 0x80);
}
