//! apt on a guest (SPEC §9.12): the simulated upgrade `vm verify` counts
//! and `vm upgrade` plans from, read on the guest's current package lists
//! (never refreshed), and the script that installs it.

const std = @import("std");

/// `lists` / `now` lines, then `apt-get -s` itself (its exit code is the
/// script's). Root through the guest agent; `-s` changes nothing.
pub const simulate_script =
    \\echo "lists $(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null)"
    \\echo "now $(date +%s)"
    \\LC_ALL=C apt-get -s -q --with-new-pkgs upgrade
;

/// apt's status lines (`APT::Status-Fd`) become the step's live detail.
pub const stage_file = "/run/artoo-upgrade.stage";

/// The single write: install what the simulation listed. Its output goes
/// to the log; a failure prints the log's last lines on stderr.
pub const upgrade_script =
    \\export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a LC_ALL=C
    \\s=/run/artoo-upgrade.stage rc=/run/artoo-upgrade.rc log=/var/log/artoo-upgrade.log
    \\rm -f "$s" "$rc"
    \\{ apt-get -y -q --with-new-pkgs -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o APT::Status-Fd=3 upgrade 3>&1 >"$log" 2>&1; echo $? >"$rc"; } |
    \\  while IFS= read -r l; do m=${l##*:}; p=${l%:*}; p=${p##*:}; printf '%s%% %s\n' "${p%%.*}" "$m" >"$s"; done
    \\code=$(cat "$rc" 2>/dev/null || echo 1)
    \\rm -f "$s" "$rc"
    \\[ "$code" = 0 ] || { tail -n 5 "$log" >&2; exit "$code"; }
;

pub const Package = struct {
    name: []const u8,
    /// Null for a package not installed yet (the next kernel).
    from: ?[]const u8,
    to: []const u8,
    security: bool,
};

pub const Pending = struct {
    packages: []const Package = &.{},
    /// Held back by Ubuntu's phased updates; not installed now.
    deferred: usize = 0,
    /// Would need a removal; `--with-new-pkgs` never removes.
    kept_back: usize = 0,
    /// When the package lists were last refreshed (Unix seconds).
    lists: ?i64 = null,
    now: ?i64 = null,

    pub fn security(p: Pending) usize {
        var n: usize = 0;
        for (p.packages) |pk| n += @intFromBool(pk.security);
        return n;
    }

    /// Seconds since the lists were refreshed, when both times are known.
    pub fn listsAge(p: Pending) ?u64 {
        const l = p.lists orelse return null;
        const n = p.now orelse return null;
        return @intCast(@max(0, n - l));
    }

    /// Still pending at the version `pk` planned (a newer one does not count).
    pub fn has(p: Pending, pk: Package) bool {
        for (p.packages) |q| {
            if (std.mem.eql(u8, q.name, pk.name) and std.mem.eql(u8, q.to, pk.to)) return true;
        }
        return false;
    }
};

/// The output of `simulate_script`. Unknown lines are ignored.
pub fn parse(arena: std.mem.Allocator, out: []const u8) !Pending {
    var p: Pending = .{};
    var pkgs: std.ArrayList(Package) = .empty;
    const List = enum { none, deferred, kept_back };
    var list: List = .none;
    var lines = std.mem.tokenizeAny(u8, out, "\r\n");
    while (lines.next()) |line| {
        if (line[0] == ' ') {
            var names = std.mem.tokenizeScalar(u8, line, ' ');
            while (names.next()) |_| switch (list) {
                .none => {},
                .deferred => p.deferred += 1,
                .kept_back => p.kept_back += 1,
            };
            continue;
        }
        list = .none;
        if (std.mem.cutPrefix(u8, line, "lists ")) |v| {
            p.lists = std.fmt.parseInt(i64, std.mem.trim(u8, v, " "), 10) catch null;
        } else if (std.mem.cutPrefix(u8, line, "now ")) |v| {
            p.now = std.fmt.parseInt(i64, std.mem.trim(u8, v, " "), 10) catch null;
        } else if (std.mem.cutPrefix(u8, line, "Inst ")) |rest| {
            if (inst(rest)) |pk| try pkgs.append(arena, pk);
        } else if (std.mem.startsWith(u8, line, "The following upgrades have been deferred due to phasing")) {
            list = .deferred;
        } else if (std.mem.startsWith(u8, line, "The following packages have been kept back")) {
            list = .kept_back;
        }
    }
    p.packages = pkgs.items;
    return p;
}

/// `tmux [3.6a-2ubuntu0.1] (3.6a-2ubuntu0.2 Ubuntu:26.04/resolute-updates [amd64])`;
/// a new package has no `[installed]`.
fn inst(rest: []const u8) ?Package {
    const sp = std.mem.findScalar(u8, rest, ' ') orelse return null;
    const name = rest[0..sp];
    var tail = std.mem.trimStart(u8, rest[sp + 1 ..], " ");
    var from: ?[]const u8 = null;
    if (tail.len > 0 and tail[0] == '[') {
        const close = std.mem.findScalar(u8, tail, ']') orelse return null;
        from = tail[1..close];
        tail = std.mem.trimStart(u8, tail[close + 1 ..], " ");
    }
    if (tail.len == 0 or tail[0] != '(') return null;
    const close = std.mem.findScalar(u8, tail, ')') orelse return null;
    const inner = tail[1..close];
    const vsp = std.mem.findScalar(u8, inner, ' ') orelse inner.len;
    if (name.len == 0 or vsp == 0) return null;
    return .{ .name = name, .from = from, .to = inner[0..vsp], .security = std.mem.find(u8, inner[vsp..], "-security") != null };
}

const testing = std.testing;

/// As printed on a 26.04 guest (2026-10-25), shortened, plus a security
/// update and a new kernel.
pub const sample =
    \\lists 1000
    \\now 4600
    \\NOTE: This is only a simulation!
    \\Calculating upgrade...
    \\The following upgrades have been deferred due to phasing:
    \\  libnss-systemd libpam-systemd systemd
    \\  udev
    \\The following packages have been kept back:
    \\  ubuntu-pro-client
    \\The following packages will be upgraded:
    \\  libssl3t64 linux-generic tmux
    \\3 upgraded, 1 newly installed, 0 to remove and 5 not upgraded.
    \\Inst libssl3t64 [3.5.3-1ubuntu1] (3.5.3-1ubuntu1.1 Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security [amd64]) []
    \\Inst linux-image-7.0.0-40-generic (7.0.0-40.40 Ubuntu:26.04/resolute-updates [amd64])
    \\Inst tmux [3.6a-2ubuntu0.1] (3.6a-2ubuntu0.2 Ubuntu:26.04/resolute-updates [amd64])
    \\Conf tmux (3.6a-2ubuntu0.2 Ubuntu:26.04/resolute-updates [amd64])
    \\
;

test "parse: packages, security pockets, new packages, phased and kept back" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try parse(arena.allocator(), sample);
    try testing.expectEqual(@as(usize, 3), p.packages.len);
    try testing.expectEqualStrings("libssl3t64", p.packages[0].name);
    try testing.expectEqualStrings("3.5.3-1ubuntu1", p.packages[0].from.?);
    try testing.expectEqualStrings("3.5.3-1ubuntu1.1", p.packages[0].to);
    try testing.expect(p.packages[0].security);
    try testing.expectEqualStrings("linux-image-7.0.0-40-generic", p.packages[1].name);
    try testing.expect(p.packages[1].from == null);
    try testing.expectEqualStrings("7.0.0-40.40", p.packages[1].to);
    try testing.expect(!p.packages[1].security and !p.packages[2].security);
    try testing.expectEqual(@as(usize, 1), p.security());
    try testing.expectEqual(@as(usize, 4), p.deferred);
    try testing.expectEqual(@as(usize, 1), p.kept_back);
    try testing.expectEqual(@as(?u64, 3600), p.listsAge());
    try testing.expect(p.has(.{ .name = "tmux", .from = null, .to = "3.6a-2ubuntu0.2", .security = false }));
    try testing.expect(!p.has(.{ .name = "tmux", .from = null, .to = "3.6a-2ubuntu0.1", .security = false }));

    const none = try parse(arena.allocator(), "lists \nnow 5\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n");
    try testing.expectEqual(@as(usize, 0), none.packages.len);
    try testing.expect(none.listsAge() == null);
    try testing.expect(inst("broken") == null);
    try testing.expect(inst("x [1.0") == null);
}
