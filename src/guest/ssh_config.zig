//! `~/.artoo/ssh_config` (SPEC §9.10): one `Host` block per artoo guest
//! with `vm ssh`'s settings, so plain ssh, scp and rsync are as strict as
//! `vm ssh` once the operator includes the file from `~/.ssh/config`.
//! artoo owns the file and rewrites it whole; it never edits
//! `~/.ssh/config`.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const default_path = "~/.artoo/ssh_config";

const header =
    \\# Written by artoo vm ssh-config; vm new and vm rm rewrite it. Do not edit.
    \\# Include it from ~/.ssh/config, above the first Host or Match line:
    \\#   Include ~/.artoo/ssh_config
    \\
;

/// One guest.
pub const Block = struct {
    /// VM name: first `Host` pattern and `HostKeyAlias`.
    name: []const u8,
    /// The guest's address (`HostName`).
    address: []const u8,
    jump: bool,
};

/// What every block shares; paths absolute.
pub const Settings = struct {
    domain: []const u8,
    /// The guest account (`guests.user`).
    user: []const u8,
    identity: []const u8,
    known_hosts: []const u8,
    /// `ProxyCommand` value for `ssh-jump` guests.
    proxy: []const u8,
};

/// A VM name usable as a `Host` pattern and alias.
pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 63) return false;
    for (name) |ch| if (!(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '.')) return false;
    return true;
}

/// A dotted IPv4 address.
pub fn validAddress(address: []const u8) bool {
    var it = std.mem.splitScalar(u8, address, '.');
    var n: usize = 0;
    while (it.next()) |part| : (n += 1) {
        if (part.len == 0 or part.len > 3) return false;
        _ = std.fmt.parseInt(u8, part, 10) catch return false;
    }
    return n == 4;
}

/// A value written unquoted: no whitespace, quotes or controls.
pub fn plainValue(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |ch| if (ch <= ' ' or ch == '"' or ch == '\'' or ch == 0x7f) return false;
    return true;
}

pub fn renderBlock(arena: Allocator, s: Settings, b: Block) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(arena,
        \\Host {s} {s}.{s}
        \\  HostName {s}
        \\  User {s}
        \\  IdentityFile {s}
        \\  IdentitiesOnly yes
        \\  UserKnownHostsFile {s}
        \\  HostKeyAlias {s}
        \\  StrictHostKeyChecking yes
        \\
    , .{ b.name, b.name, s.domain, b.address, s.user, s.identity, s.known_hosts, b.name });
    if (b.jump) try out.print(arena, "  ProxyCommand {s}\n", .{s.proxy});
    return out.items;
}

/// The whole file for `blocks`, sorted by name.
pub fn render(arena: Allocator, s: Settings, blocks: []const Block) ![]const u8 {
    const sorted = try arena.dupe(Block, blocks);
    std.mem.sort(Block, sorted, {}, struct {
        fn lt(_: void, a: Block, b: Block) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
    var texts: std.ArrayList([]const u8) = .empty;
    for (sorted) |b| try texts.append(arena, try renderBlock(arena, s, b));
    return join(arena, texts.items);
}

fn join(arena: Allocator, texts: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, header);
    for (texts) |ch| {
        try out.append(arena, '\n');
        try out.appendSlice(arena, ch);
    }
    return out.items;
}

const Chunk = struct { name: []const u8, text: []const u8 };

/// The `Host` blocks of a file artoo wrote, verbatim.
fn blocksOf(arena: Allocator, text: []const u8) ![]Chunk {
    var out: std.ArrayList(Chunk) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var cur: ?Chunk = null;
    var buf: std.ArrayList(u8) = .empty;
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "Host ")) {
            if (cur) |*c| {
                c.text = try arena.dupe(u8, buf.items);
                try out.append(arena, c.*);
            }
            buf = .empty;
            var words = std.mem.tokenizeScalar(u8, line["Host ".len..], ' ');
            cur = .{ .name = words.next() orelse "", .text = "" };
        }
        if (cur == null or line.len == 0) continue;
        try buf.appendSlice(arena, line);
        try buf.append(arena, '\n');
    }
    if (cur) |*c| {
        c.text = try arena.dupe(u8, buf.items);
        try out.append(arena, c.*);
    }
    return out.items;
}

pub fn hasBlock(arena: Allocator, text: []const u8, name: []const u8) !bool {
    for (try blocksOf(arena, text)) |c| if (std.mem.eql(u8, c.name, name)) return true;
    return false;
}

/// `text` with the block for `name` replaced by `block` (null: removed);
/// the other blocks stay as they are.
pub fn update(arena: Allocator, text: []const u8, s: Settings, name: []const u8, block: ?Block) ![]const u8 {
    var kept: std.ArrayList(Chunk) = .empty;
    for (try blocksOf(arena, text)) |c| if (!std.mem.eql(u8, c.name, name)) try kept.append(arena, c);
    if (block) |b| try kept.append(arena, .{ .name = b.name, .text = try renderBlock(arena, s, b) });
    std.mem.sort(Chunk, kept.items, {}, struct {
        fn lt(_: void, a: Chunk, b: Chunk) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.lt);
    var texts: std.ArrayList([]const u8) = .empty;
    for (kept.items) |c| try texts.append(arena, c.text);
    return join(arena, texts.items);
}

/// Whether `ssh -G <alias>` output shows the file in effect.
pub fn includeActive(ssh_g: []const u8, alias: []const u8) bool {
    var lines = std.mem.tokenizeScalar(u8, ssh_g, '\n');
    while (lines.next()) |line| {
        const rest = std.mem.cutPrefix(u8, line, "hostkeyalias ") orelse continue;
        return std.mem.eql(u8, std.mem.trim(u8, rest, " \r"), alias);
    }
    return false;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const test_settings: Settings = .{
    .domain = "lab.example.com",
    .user = "artoo",
    .identity = "/home/me/.ssh/id_ed25519",
    .known_hosts = "/home/me/.artoo/known_hosts",
    .proxy = "/usr/bin/ssh -i /home/me/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -W %h:%p root@192.168.1.10",
};

const naboo_block =
    \\Host naboo naboo.lab.example.com
    \\  HostName 192.168.1.230
    \\  User artoo
    \\  IdentityFile /home/me/.ssh/id_ed25519
    \\  IdentitiesOnly yes
    \\  UserKnownHostsFile /home/me/.artoo/known_hosts
    \\  HostKeyAlias naboo
    \\  StrictHostKeyChecking yes
    \\
;

test "render: sorted blocks; ssh-jump guests get the Proxmox ProxyCommand" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const text = try render(a.allocator(), test_settings, &.{
        .{ .name = "naboo", .address = "192.168.1.230", .jump = false },
        .{ .name = "bespin", .address = "192.168.1.200", .jump = true },
    });
    try testing.expectEqualStrings(header ++ "\n" ++
        \\Host bespin bespin.lab.example.com
        \\  HostName 192.168.1.200
        \\  User artoo
        \\  IdentityFile /home/me/.ssh/id_ed25519
        \\  IdentitiesOnly yes
        \\  UserKnownHostsFile /home/me/.artoo/known_hosts
        \\  HostKeyAlias bespin
        \\  StrictHostKeyChecking yes
        \\  ProxyCommand /usr/bin/ssh -i /home/me/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -W %h:%p root@192.168.1.10
        \\
    ++ "\n" ++ naboo_block, text);
    try testing.expectEqualStrings(header, try render(a.allocator(), test_settings, &.{}));
}

test "update: one block replaced, added or removed; the others kept" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const one = try render(ar, test_settings, &.{.{ .name = "naboo", .address = "192.168.1.230", .jump = false }});
    try testing.expect(try hasBlock(ar, one, "naboo"));
    try testing.expect(!try hasBlock(ar, one, "hoth"));
    const two = try update(ar, one, test_settings, "hoth", .{ .name = "hoth", .address = "192.168.1.231", .jump = true });
    try testing.expectEqualStrings(try render(ar, test_settings, &.{
        .{ .name = "naboo", .address = "192.168.1.230", .jump = false },
        .{ .name = "hoth", .address = "192.168.1.231", .jump = true },
    }), two);
    try testing.expectEqualStrings(one, try update(ar, two, test_settings, "hoth", null));
    try testing.expectEqualStrings(header, try update(ar, one, test_settings, "naboo", null));
}

test "validation and the include check" {
    try testing.expect(validName("bespin") and validName("web-01"));
    try testing.expect(!validName("a b") and !validName("") and !validName("x*"));
    try testing.expect(validAddress("192.168.1.200"));
    try testing.expect(!validAddress("192.168.1") and !validAddress("192.168.1.300") and !validAddress("a.b.c.d"));
    try testing.expect(plainValue("/Users/me/.ssh/id_ed25519"));
    try testing.expect(!plainValue("/Users/a b/.ssh/id") and !plainValue("x\"y"));
    try testing.expect(includeActive("user artoo\nhostkeyalias naboo\nport 22\n", "naboo"));
    try testing.expect(!includeActive("user artoo\nport 22\n", "naboo"));
}
