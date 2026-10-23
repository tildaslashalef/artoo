//! Configuration, schema 1 (SPEC §5): non-secret settings in
//! `~/.artoo/config.json` (dir 0700, file 0600). Absent keys take the
//! defaults below; unknown keys and other schemas are rejected with a message.
//! The file is kept as a JSON tree so `set`/`unset` change only one key.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const cli = @import("cli.zig");
const files = @import("files.zig");
const suggest = @import("cli/suggest.zig");

pub const schema_version = 1;
pub const default_path = "~/.artoo/config.json";

pub const Store = enum { auto, keychain, @"secret-service", file };

pub const Config = struct {
    output: Output = .{},
    credentials: Credentials = .{},
    pve: Pve = .{},
    unifi: Unifi = .{},
    cloudflare: Cloudflare = .{},
    guests: Guests = .{},

    pub const Output = struct {
        format: cli.Output = .table,
        color: cli.Color = .auto,
    };
    pub const Credentials = struct {
        store: Store = .auto,
    };
    pub const Pve = struct {
        endpoint: []const u8 = "https://pve.home.arpa:8006",
        node: []const u8 = "pve",
        token_id: []const u8 = "artoo@pve!cli",
        ca_bundle: []const u8 = "~/.artoo/tls/rootCA.pem",
        timeout_seconds: u32 = 15,
        /// Root SSH for the one thing the API cannot do: placing the
        /// vendor snippet (SPEC §9.2). An address: the host key is known
        /// under it.
        ssh_host: []const u8 = "192.168.1.10",
        ssh_identity: []const u8 = "~/.ssh/id_ed25519",
    };
    pub const Unifi = struct {
        endpoint: []const u8 = "https://unifi.home.arpa/proxy/network/integration",
        site: []const u8 = "default",
        ca_bundle: []const u8 = "~/.artoo/tls/rootCA.pem",
        timeout_seconds: u32 = 10,
    };
    /// SPEC §15: the public API, verified against the system roots.
    pub const Cloudflare = struct {
        zone: []const u8 = "example.com",
        timeout_seconds: u32 = 10,
        /// The lab's remotely managed tunnel (run by the edge VM).
        tunnel: []const u8 = "lab",
    };
    pub const Guests = struct {
        domain: []const u8 = "lab.example.com",
        template: []const u8 = "ubuntu-2604",
        ssh_public_key: []const u8 = "~/.ssh/id_ed25519.pub",
        /// More public key files `vm new` installs for the guest user
        /// beside `ssh_public_key` (comma-separated paths): the other
        /// machines that log in. artoo itself uses `ssh_public_key`.
        extra_ssh_keys: []const u8 = "",
        address_pool: []const u8 = "192.168.1.200-192.168.1.254",
        /// Guests' default gateway and subnet; also their DNS server.
        gateway: []const u8 = "192.168.1.1/24",
        /// The account `vm new` creates on every guest (SSH key, sudo
        /// with a generated password); `vm ssh` and `vm cp` log in as it.
        user: []const u8 = "artoo",
        /// Never a guest name and never published (SPEC §9.6): the lab's
        /// own host and equipment names beyond the node and endpoints.
        reserved_names: []const u8 = "",
        /// Outbound exceptions of fenced guests (SPEC §9.11): `VM PEER
        /// PROTO PORTS` entries separated by `;`.
        fence_allow_out: []const u8 = "",
    };
};

pub const Check = enum { none, https_url, path, ident, token_id, hostname, seconds, ipv4_range, ipv4_cidr, username, label_list, fence_list, path_list };

pub const Key = struct {
    name: []const u8,
    help: []const u8,
    check: Check = .none,
};

/// Every settable key, in display order.
pub const keys = [_]Key{
    .{ .name = "output.format", .help = "Default output format" },
    .{ .name = "output.color", .help = "Color policy" },
    .{ .name = "credentials.store", .help = "Secret store backend" },
    .{ .name = "pve.endpoint", .help = "Proxmox API base URL", .check = .https_url },
    .{ .name = "pve.node", .help = "Proxmox node name", .check = .ident },
    .{ .name = "pve.token_id", .help = "API token id (user@realm!name)", .check = .token_id },
    .{ .name = "pve.ca_bundle", .help = "CA bundle (PEM) for TLS verification", .check = .path },
    .{ .name = "pve.timeout_seconds", .help = "Per-request deadline", .check = .seconds },
    .{ .name = "pve.ssh_host", .help = "Proxmox address for root SSH (vendor snippet)", .check = .hostname },
    .{ .name = "pve.ssh_identity", .help = "SSH private key for root on Proxmox", .check = .path },
    .{ .name = "unifi.endpoint", .help = "Integration API base URL", .check = .https_url },
    .{ .name = "unifi.site", .help = "Site internal reference", .check = .ident },
    .{ .name = "unifi.ca_bundle", .help = "CA bundle (PEM) for TLS verification", .check = .path },
    .{ .name = "unifi.timeout_seconds", .help = "Per-request deadline", .check = .seconds },
    .{ .name = "cloudflare.zone", .help = "Cloudflare zone artoo manages", .check = .hostname },
    .{ .name = "cloudflare.timeout_seconds", .help = "Per-request deadline", .check = .seconds },
    .{ .name = "cloudflare.tunnel", .help = "Name of the lab's Cloudflare Tunnel", .check = .ident },
    .{ .name = "guests.domain", .help = "DNS domain for guest names", .check = .hostname },
    .{ .name = "guests.template", .help = "Default template name", .check = .ident },
    .{ .name = "guests.ssh_public_key", .help = "Public key installed for the guest user", .check = .path },
    .{ .name = "guests.extra_ssh_keys", .help = "More public key files for the guest user (comma-separated paths)", .check = .path_list },
    .{ .name = "guests.address_pool", .help = "Static guest addresses (A-B)", .check = .ipv4_range },
    .{ .name = "guests.gateway", .help = "Guest gateway and DNS server, with prefix (A/N)", .check = .ipv4_cidr },
    .{ .name = "guests.user", .help = "Account created on every guest", .check = .username },
    .{ .name = "guests.reserved_names", .help = "Host and equipment names never used or published (comma-separated)", .check = .label_list },
    .{ .name = "guests.fence_allow_out", .help = "Fenced guests' outbound exceptions: 'VM PEER tcp|udp PORTS' entries separated by ';'", .check = .fence_list },
};

comptime {
    // Every Config field has exactly one key entry.
    var count = 0;
    for (@typeInfo(Config).@"struct".field_names, @typeInfo(Config).@"struct".field_types) |sec, T| {
        for (@typeInfo(T).@"struct".field_names) |f| {
            _ = keyIndex(sec ++ "." ++ f);
            count += 1;
        }
    }
    if (count != keys.len) @compileError("config.keys and Config disagree");
}

fn keyIndex(comptime name: []const u8) usize {
    for (keys, 0..) |k, i| {
        if (std.mem.eql(u8, k.name, name)) return i;
    }
    @compileError("no config key " ++ name);
}

fn split(comptime name: []const u8) struct { []const u8, []const u8 } {
    const dot = std.mem.findScalar(u8, name, '.').?;
    return .{ name[0..dot], name[dot + 1 ..] };
}

pub fn find(name: []const u8) ?Key {
    for (keys) |k| {
        if (std.mem.eql(u8, k.name, name)) return k;
    }
    return null;
}

/// Help text listing every key, generated for `config set`.
pub const key_help = blk: {
    var text: []const u8 = "Keys:";
    var width = 0;
    for (keys) |k| width = @max(width, k.name.len);
    for (keys) |k| {
        const pad: [width - k.name.len + 2]u8 = @splat(' ');
        const extra = if (choices(k.name)) |c| " (" ++ c ++ ")" else "";
        text = text ++ "\n  " ++ k.name ++ &pad ++ k.help ++ extra;
    }
    break :blk text;
};

/// Allowed values for enum-typed keys, e.g. "table|json"; null otherwise.
pub fn choices(comptime name: []const u8) ?[]const u8 {
    const sec, const fld = split(name);
    const T = @FieldType(@FieldType(Config, sec), fld);
    if (@typeInfo(T) != .@"enum") return null;
    var out: []const u8 = "";
    for (@typeInfo(T).@"enum".field_names, 0..) |n, i| out = out ++ (if (i > 0) "|" else "") ++ n;
    return out;
}

pub fn choicesOf(name: []const u8) ?[]const u8 {
    inline for (keys) |k| {
        if (std.mem.eql(u8, k.name, name)) return comptime choices(k.name);
    }
    return null;
}

/// The value of `name` rendered as text (strings raw, enums by tag).
pub fn get(cfg: *const Config, arena: Allocator, name: []const u8) Allocator.Error!?[]const u8 {
    inline for (keys) |k| {
        if (std.mem.eql(u8, k.name, name)) {
            const sec, const fld = comptime split(k.name);
            const v = @field(@field(cfg, sec), fld);
            return switch (@typeInfo(@TypeOf(v))) {
                .int => try std.fmt.allocPrint(arena, "{d}", .{v}),
                .@"enum" => @tagName(v),
                else => v,
            };
        }
    }
    return null;
}

/// Validate `value` for key `name`; on success store it into `cfg` and
/// return the JSON value to persist. On failure `msg` says why.
pub fn assign(cfg: *Config, arena: Allocator, name: []const u8, value: std.json.Value, msg: *[]const u8) Allocator.Error!?std.json.Value {
    inline for (keys) |k| {
        if (std.mem.eql(u8, k.name, name)) {
            const sec, const fld = comptime split(k.name);
            const T = @FieldType(@FieldType(Config, sec), fld);
            switch (@typeInfo(T)) {
                .int => {
                    const n: i64 = switch (value) {
                        .integer => |i| i,
                        .string => |s| std.fmt.parseInt(i64, s, 10) catch {
                            msg.* = try std.fmt.allocPrint(arena, "{s}: expected a number, got '{s}'", .{ name, s });
                            return null;
                        },
                        else => {
                            msg.* = try std.fmt.allocPrint(arena, "{s}: expected a number", .{name});
                            return null;
                        },
                    };
                    if (try checkInt(arena, k, n, msg)) {
                        @field(@field(cfg, sec), fld) = @intCast(n);
                        return .{ .integer = n };
                    }
                    return null;
                },
                .@"enum" => {
                    const s = if (value == .string) value.string else "";
                    if (std.meta.stringToEnum(T, s)) |e| {
                        @field(@field(cfg, sec), fld) = e;
                        return .{ .string = @tagName(e) };
                    }
                    msg.* = try std.fmt.allocPrint(arena, "{s}: expected {s}", .{ name, comptime choices(k.name).? });
                    return null;
                },
                else => {
                    if (value != .string) {
                        msg.* = try std.fmt.allocPrint(arena, "{s}: expected a string", .{name});
                        return null;
                    }
                    if (try checkString(arena, k, value.string, msg)) {
                        @field(@field(cfg, sec), fld) = value.string;
                        return value;
                    }
                    return null;
                },
            }
        }
    }
    msg.* = try unknownKeyMessage(arena, name);
    return null;
}

pub fn unknownKeyMessage(arena: Allocator, name: []const u8) Allocator.Error![]const u8 {
    var names: [keys.len][]const u8 = undefined;
    for (keys, 0..) |k, i| names[i] = k.name;
    if (suggest.closest(name, &names)) |s| {
        return std.fmt.allocPrint(arena, "unknown config key '{s}' — did you mean '{s}'?", .{ name, s });
    }
    return std.fmt.allocPrint(arena, "unknown config key '{s}' (see 'artoo config show')", .{name});
}

fn checkInt(arena: Allocator, k: Key, n: i64, msg: *[]const u8) Allocator.Error!bool {
    if (k.check == .seconds and (n < 1 or n > 3600)) {
        msg.* = try std.fmt.allocPrint(arena, "{s}: expected 1..3600 seconds, got {d}", .{ k.name, n });
        return false;
    }
    return true;
}

fn checkString(arena: Allocator, k: Key, s: []const u8, msg: *[]const u8) Allocator.Error!bool {
    const ok = switch (k.check) {
        .none, .seconds => true,
        .https_url => validHttpsUrl(s),
        .path => s.len > 0 and std.mem.findScalar(u8, s, 0) == null,
        .ident => s.len > 0 and allChars(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"),
        .token_id => validTokenId(s),
        .hostname => validHostname(s),
        .ipv4_range => parseRange(s) != null,
        .ipv4_cidr => parseCidr(s) != null,
        .username => validUsername(s),
        .label_list => validLabelList(s),
        .fence_list => validFenceList(s),
        .path_list => validPathList(s),
    };
    if (ok) return true;
    const want = switch (k.check) {
        .https_url => "an https:// URL with a host",
        .path => "a file path",
        .ident => "letters, digits, '.', '_' or '-'",
        .token_id => "user@realm!tokenname",
        .hostname => "a DNS name like home.arpa",
        .ipv4_range => "an IPv4 range A-B with A <= B",
        .ipv4_cidr => "an IPv4 address with prefix length, like 192.168.1.1/24",
        .username => "a Linux user name (lowercase letter first; letters, digits, '_' or '-'; at most 32; not root)",
        .label_list => "DNS labels separated by commas",
        .path_list => "file paths separated by commas",
        .fence_list => "entries 'VM PEER PROTO PORTS' separated by ';' (PEER a guest name or IPv4 address/CIDR, PROTO tcp or udp, PORTS like 5432, 80,443 or 6000:6010)",
        else => "a valid value",
    };
    msg.* = try std.fmt.allocPrint(arena, "{s}: expected {s}, got '{s}'", .{ k.name, want, s });
    return false;
}

fn allChars(s: []const u8, allowed: []const u8) bool {
    for (s) |c| {
        if (std.mem.findScalar(u8, allowed, c) == null) return false;
    }
    return true;
}

fn validHttpsUrl(s: []const u8) bool {
    const uri = std.Uri.parse(s) catch return false;
    if (!std.mem.eql(u8, uri.scheme, "https")) return false;
    const host = uri.host orelse return false;
    return switch (host) {
        inline else => |h| h.len > 0,
    } and uri.query == null and uri.fragment == null;
}

fn validTokenId(s: []const u8) bool {
    const at = std.mem.findScalar(u8, s, '@') orelse return false;
    const bang = std.mem.findScalar(u8, s, '!') orelse return false;
    if (at == 0 or bang <= at + 1 or bang + 1 >= s.len) return false;
    return allChars(s[bang + 1 ..], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-");
}

fn validUsername(s: []const u8) bool {
    if (s.len == 0 or s.len > 32 or !std.ascii.isLower(s[0]) or std.mem.eql(u8, s, "root")) return false;
    return allChars(s, "abcdefghijklmnopqrstuvwxyz0123456789_-");
}

fn validLabelList(s: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, s, ", ");
    while (it.next()) |l| {
        if (std.mem.findScalar(u8, l, '.') != null or !validHostname(l)) return false;
    }
    return true;
}

fn validPathList(s: []const u8) bool {
    if (std.mem.findScalar(u8, s, 0) != null) return false;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |p| {
        if (std.mem.trim(u8, p, " ").len == 0 and std.mem.trim(u8, s, " ").len > 0) return false;
    }
    return true;
}

/// The entries of a `path_list` value, trimmed (empty value: none).
pub fn pathList(arena: Allocator, s: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, s, ',');
    while (it.next()) |p| {
        const t = std.mem.trim(u8, p, " ");
        if (t.len > 0) try out.append(arena, t);
    }
    return out.items;
}

/// One `guests.fence_allow_out` entry (SPEC §9.11).
pub const FenceAllow = struct {
    vm: []const u8,
    /// A guest name, or an IPv4 address or CIDR.
    peer: []const u8,
    proto: []const u8,
    /// A Proxmox port list: ports and `A:B` ranges, comma-separated.
    ports: []const u8,

    pub fn peerIsAddress(f: FenceAllow) bool {
        return parseIp4Net(f.peer) != null;
    }
};

/// The entries of `guests.fence_allow_out`, in order; null when one is
/// malformed.
pub fn fenceAllows(arena: Allocator, s: []const u8) Allocator.Error!?[]const FenceAllow {
    var out: std.ArrayList(FenceAllow) = .empty;
    var entries = std.mem.splitScalar(u8, s, ';');
    while (entries.next()) |entry| {
        if (std.mem.trim(u8, entry, " ").len == 0) continue;
        var w = std.mem.tokenizeScalar(u8, entry, ' ');
        const f: FenceAllow = .{
            .vm = w.next() orelse return null,
            .peer = w.next() orelse return null,
            .proto = w.next() orelse return null,
            .ports = w.next() orelse return null,
        };
        if (w.next() != null) return null;
        if (!validGuestLabel(f.vm)) return null;
        if (!validGuestLabel(f.peer) and parseIp4Net(f.peer) == null) return null;
        if (!std.mem.eql(u8, f.proto, "tcp") and !std.mem.eql(u8, f.proto, "udp")) return null;
        if (!validPortList(f.ports)) return null;
        try out.append(arena, f);
    }
    return out.items;
}

fn validFenceList(s: []const u8) bool {
    var buf: [4096]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    return (fenceAllows(fba.allocator(), s) catch return false) != null;
}

/// A guest name: one DNS label, letter first.
fn validGuestLabel(s: []const u8) bool {
    return s.len > 0 and std.ascii.isLower(s[0]) and validHostname(s) and std.mem.findScalar(u8, s, '.') == null;
}

/// `5432`, `80,443`, `6000:6010` — ports 1-65535, ranges ascending.
pub fn validPortList(s: []const u8) bool {
    if (s.len == 0) return false;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |part| {
        const lo, const hi = std.mem.cut(u8, part, ":") orelse .{ part, part };
        const a = std.fmt.parseInt(u16, lo, 10) catch return false;
        const b = std.fmt.parseInt(u16, hi, 10) catch return false;
        if (a == 0 or b < a) return false;
    }
    return true;
}

pub const Ip4Net = struct { address: u32, prefix: u6 };

/// `203.0.113.7` (a /32) or `203.0.113.0/24`, prefix 1-32.
pub fn parseIp4Net(s: []const u8) ?Ip4Net {
    const a, const b = std.mem.cut(u8, s, "/") orelse .{ s, "32" };
    const ip = Io.net.Ip4Address.parse(a, 0) catch return null;
    const prefix = std.fmt.parseInt(u6, b, 10) catch return null;
    if (prefix < 1 or prefix > 32) return null;
    return .{ .address = std.mem.readInt(u32, &ip.bytes, .big), .prefix = prefix };
}

/// Whether `net` contains `addr`.
pub fn netContains(net: Ip4Net, addr: u32) bool {
    if (net.prefix == 32) return net.address == addr;
    const mask: u32 = ~@as(u32, 0) << @intCast(32 - @as(u32, net.prefix));
    return net.address & mask == addr & mask;
}

fn validHostname(s: []const u8) bool {
    if (s.len == 0 or s.len > 253) return false;
    var labels = std.mem.splitScalar(u8, s, '.');
    while (labels.next()) |l| {
        if (l.len == 0 or l.len > 63 or l[0] == '-' or l[l.len - 1] == '-') return false;
        if (!allChars(l, "abcdefghijklmnopqrstuvwxyz0123456789-")) return false;
    }
    return true;
}

pub const Cidr = struct { address: u32, prefix: u6 };

/// `192.168.1.1/24`.
pub fn parseCidr(s: []const u8) ?Cidr {
    const a, const b = std.mem.cut(u8, s, "/") orelse return null;
    const ip = Io.net.Ip4Address.parse(a, 0) catch return null;
    const prefix = std.fmt.parseInt(u6, b, 10) catch return null;
    if (prefix < 8 or prefix > 30) return null;
    return .{ .address = std.mem.readInt(u32, &ip.bytes, .big), .prefix = prefix };
}

pub const Range = struct { first: u32, last: u32 };

pub fn parseRange(s: []const u8) ?Range {
    const a, const b = std.mem.cut(u8, s, "-") orelse return null;
    const first = Io.net.Ip4Address.parse(a, 0) catch return null;
    const last = Io.net.Ip4Address.parse(b, 0) catch return null;
    const f = std.mem.readInt(u32, &first.bytes, .big);
    const l = std.mem.readInt(u32, &last.bytes, .big);
    if (f > l) return null;
    return .{ .first = f, .last = l };
}

pub const Loaded = struct {
    path: []const u8,
    exists: bool,
    config: Config,
    /// The file's JSON object (empty when absent).
    tree: std.json.ObjectMap,

    /// True when the file sets `name` explicitly.
    pub fn explicit(l: *const Loaded, name: []const u8) bool {
        const dot = std.mem.findScalar(u8, name, '.') orelse return false;
        const sec = l.tree.get(name[0..dot]) orelse return false;
        if (sec != .object) return false;
        return sec.object.get(name[dot + 1 ..]) != null;
    }
};

pub const LoadError = error{ ConfigInvalid, UnsafePath, HomeUnknown, Io } || Allocator.Error || Io.Cancelable;

pub fn resolvePath(arena: Allocator, env: *const std.process.Environ.Map, override: ?[]const u8) error{ HomeUnknown, OutOfMemory }![]const u8 {
    return files.expandHome(arena, env, override orelse default_path);
}

/// Load and validate; a missing file yields the defaults. `msg` explains a
/// `ConfigInvalid`.
pub fn load(io: Io, arena: Allocator, path: []const u8, msg: *[]const u8) LoadError!Loaded {
    const bytes = Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => return .{ .path = path, .exists = false, .config = .{}, .tree = .empty },
        error.Canceled => return error.Canceled,
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            msg.* = try std.fmt.allocPrint(arena, "cannot read {s}: {s}", .{ path, @errorName(err) });
            return error.ConfigInvalid;
        },
    };
    var loaded = parse(arena, bytes, msg) catch |err| {
        if (err == error.ConfigInvalid) msg.* = try std.fmt.allocPrint(arena, "{s}: {s}", .{ path, msg.* });
        return err;
    };
    loaded.path = path;
    return loaded;
}

pub fn parse(arena: Allocator, bytes: []const u8, msg: *[]const u8) (error{ConfigInvalid} || Allocator.Error)!Loaded {
    msg.* = "";
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, bytes, .{}) catch |err| {
        msg.* = try std.fmt.allocPrint(arena, "not valid JSON ({s})", .{@errorName(err)});
        return error.ConfigInvalid;
    };
    if (root != .object) {
        msg.* = "expected a JSON object";
        return error.ConfigInvalid;
    }
    const version = root.object.get("schema_version") orelse .null;
    if (version != .integer or version.integer != schema_version) {
        msg.* = "unsupported config (schema_version must be 1); there is no migration — move it aside and run 'artoo config init'";
        return error.ConfigInvalid;
    }
    var cfg: Config = .{};
    var it = root.object.iterator();
    while (it.next()) |entry| {
        const sec = entry.key_ptr.*;
        if (std.mem.eql(u8, sec, "schema_version")) continue;
        if (entry.value_ptr.* != .object) {
            msg.* = try std.fmt.allocPrint(arena, "'{s}' must be an object", .{sec});
            return error.ConfigInvalid;
        }
        var fields = entry.value_ptr.object.iterator();
        while (fields.next()) |f| {
            const name = try std.fmt.allocPrint(arena, "{s}.{s}", .{ sec, f.key_ptr.* });
            if (try assign(&cfg, arena, name, f.value_ptr.*, msg) == null) return error.ConfigInvalid;
        }
    }
    return .{ .path = "", .exists = true, .config = cfg, .tree = root.object };
}

/// Set (`value` non-null) or remove one key in the tree; returns the
/// serialized file.
pub fn edit(arena: Allocator, tree: *std.json.ObjectMap, name: []const u8, value: ?std.json.Value) Allocator.Error![]const u8 {
    const dot = std.mem.findScalar(u8, name, '.').?;
    const sec_name = name[0..dot];
    const field = name[dot + 1 ..];
    if (tree.get("schema_version") == null) try tree.put(arena, "schema_version", .{ .integer = schema_version });
    if (value) |v| {
        const gop = try tree.getOrPut(arena, sec_name);
        if (!gop.found_existing or gop.value_ptr.* != .object) gop.value_ptr.* = .{ .object = .empty };
        try gop.value_ptr.object.put(arena, field, v);
    } else if (tree.getPtr(sec_name)) |sec| {
        if (sec.* == .object) _ = sec.object.orderedRemove(field);
    }
    return serialize(arena, .{ .object = tree.* });
}

pub fn serialize(arena: Allocator, root: std.json.Value) Allocator.Error![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    std.json.Stringify.value(root, .{ .whitespace = .indent_2 }, &out.writer) catch return error.OutOfMemory;
    out.writer.writeByte('\n') catch return error.OutOfMemory;
    return out.written();
}

/// The full default file written by `config init`.
pub fn defaultFile(arena: Allocator) Allocator.Error![]const u8 {
    var tree: std.json.ObjectMap = .empty;
    try tree.put(arena, "schema_version", .{ .integer = schema_version });
    const cfg: Config = .{};
    inline for (keys) |k| {
        const sec, const fld = comptime split(k.name);
        const v = @field(@field(cfg, sec), fld);
        const jv: std.json.Value = switch (@typeInfo(@TypeOf(v))) {
            .int => .{ .integer = v },
            .@"enum" => .{ .string = @tagName(v) },
            else => .{ .string = v },
        };
        _ = try edit(arena, &tree, k.name, jv);
    }
    return serialize(arena, .{ .object = tree });
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "defaults round-trip through the default file" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const text = try defaultFile(ar);
    try testing.expect(std.mem.startsWith(u8, text, "{\n  \"schema_version\": 1,\n  \"output\": {\n    \"format\": \"table\","));
    var msg: []const u8 = "";
    const l = try parse(ar, text, &msg);
    try testing.expectEqualDeep(Config{}, l.config);
    try testing.expect(l.explicit("pve.node"));
}

test "parse: rejections with messages" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "nope", "not valid JSON (SyntaxError)" },
        .{ "[]", "expected a JSON object" },
        .{ "{\"schema_version\":2,\"default_profile\":\"mutation\"}", "unsupported config (schema_version must be 1); there is no migration — move it aside and run 'artoo config init'" },
        .{ "{\"schema_version\":1,\"pve\":{\"tokenid\":\"x\"}}", "unknown config key 'pve.tokenid' — did you mean 'pve.token_id'?" },
        .{ "{\"schema_version\":1,\"pve\":{\"timeout_seconds\":0}}", "pve.timeout_seconds: expected 1..3600 seconds, got 0" },
        .{ "{\"schema_version\":1,\"pve\":{\"endpoint\":\"http://pve:8006\"}}", "pve.endpoint: expected an https:// URL with a host, got 'http://pve:8006'" },
        .{ "{\"schema_version\":1,\"output\":{\"format\":\"yaml\"}}", "output.format: expected table|json" },
        .{ "{\"schema_version\":1,\"guests\":{\"address_pool\":\"192.168.1.249-192.168.1.200\"}}", "guests.address_pool: expected an IPv4 range A-B with A <= B, got '192.168.1.249-192.168.1.200'" },
        .{ "{\"schema_version\":1,\"pve\":\"x\"}", "'pve' must be an object" },
        .{ "{\"schema_version\":1,\"pve\":{\"token_id\":\"artoo@pve\"}}", "pve.token_id: expected user@realm!tokenname, got 'artoo@pve'" },
    };
    for (cases) |c| {
        var msg: []const u8 = "";
        try testing.expectError(error.ConfigInvalid, parse(ar, c[0], &msg));
        testing.expectEqualStrings(c[1], msg) catch |err| {
            std.debug.print("input: {s}\n", .{c[0]});
            return err;
        };
    }
}

test "partial file: explicit keys override defaults, others default" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var msg: []const u8 = "";
    const l = try parse(ar, "{\"schema_version\":1,\"unifi\":{\"timeout_seconds\":20},\"credentials\":{\"store\":\"secret-service\"}}", &msg);
    try testing.expectEqual(@as(u32, 20), l.config.unifi.timeout_seconds);
    try testing.expectEqual(Store.@"secret-service", l.config.credentials.store);
    try testing.expectEqualStrings("pve", l.config.pve.node);
    try testing.expect(l.explicit("unifi.timeout_seconds"));
    try testing.expect(!l.explicit("unifi.site"));
    try testing.expectEqualStrings("20", (try get(&l.config, ar, "unifi.timeout_seconds")).?);
    try testing.expectEqualStrings("secret-service", (try get(&l.config, ar, "credentials.store")).?);
    try testing.expect((try get(&l.config, ar, "nope")) == null);
}

test "edit: set and unset one key, keep the rest" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    var msg: []const u8 = "";
    var l = try parse(ar, "{\"schema_version\":1,\"pve\":{\"node\":\"pve\"}}", &msg);
    const v = (try assign(&l.config, ar, "pve.timeout_seconds", .{ .string = "30" }, &msg)).?;
    const text = try edit(ar, &l.tree, "pve.timeout_seconds", v);
    try testing.expectEqualStrings(
        \\{
        \\  "schema_version": 1,
        \\  "pve": {
        \\    "node": "pve",
        \\    "timeout_seconds": 30
        \\  }
        \\}
        \\
    , text);
    const text2 = try edit(ar, &l.tree, "pve.node", null);
    try testing.expect(std.mem.find(u8, text2, "node") == null);
    const text3 = try edit(ar, &l.tree, "guests.domain", .{ .string = "lab.arpa" });
    try testing.expect(std.mem.find(u8, text3, "\"guests\": {\n    \"domain\": \"lab.arpa\"") != null);
}

test "validators" {
    try testing.expect(validHttpsUrl("https://unifi.home.arpa/proxy/network/integration"));
    try testing.expect(validHttpsUrl("https://192.168.1.10:8006"));
    try testing.expect(!validHttpsUrl("https://"));
    try testing.expect(!validHttpsUrl("ftp://x"));
    try testing.expect(validTokenId("artoo@pve!cli"));
    try testing.expect(!validTokenId("artoo@pve!"));
    try testing.expect(!validTokenId("@pve!x"));
    try testing.expect(validHostname("home.arpa"));
    try testing.expect(!validHostname("Home.arpa"));
    try testing.expect(!validHostname("a..b"));
    const r = parseRange("192.168.1.200-192.168.1.249").?;
    try testing.expectEqual(@as(u32, 50), r.last - r.first + 1);
    try testing.expect(parseRange("192.168.1.200") == null);
    try testing.expectEqualStrings("auto|keychain|secret-service|file", choicesOf("credentials.store").?);
    try testing.expect(choicesOf("pve.node") == null);
    try testing.expect(validPathList(""));
    try testing.expect(validPathList("~/.artoo/keys/a.pub, /etc/b.pub"));
    try testing.expect(!validPathList("a.pub,,b.pub"));
    try testing.expect(!validPathList("a.pub,"));
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const paths = try pathList(arena.allocator(), " a.pub , b.pub ");
    try testing.expectEqual(@as(usize, 2), paths.len);
    try testing.expectEqualStrings("b.pub", paths[1]);
}

test "fenceAllows: entries, peers, ports; malformed lists refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const got = (try fenceAllows(a, "hoth naboo tcp 5432; hoth 203.0.113.0/24 udp 51820,6000:6010 ;")).?;
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualStrings("naboo", got[0].peer);
    try testing.expect(!got[0].peerIsAddress() and got[1].peerIsAddress());
    try testing.expectEqualStrings("51820,6000:6010", got[1].ports);
    try testing.expectEqual(@as(usize, 0), (try fenceAllows(a, "")).?.len);
    for ([_][]const u8{ "hoth naboo tcp", "hoth naboo icmp 1", "hoth naboo tcp 0", "hoth naboo tcp 10:5", "Hoth naboo tcp 1", "hoth naboo tcp 1 extra", "hoth 10.0.0.0/33 tcp 1" }) |bad|
        try testing.expect((try fenceAllows(a, bad)) == null);
    try testing.expect(validFenceList("hoth naboo tcp 5432"));
    try testing.expect(!validFenceList("hoth"));
    const net = parseIp4Net("192.168.0.0/16").?;
    try testing.expect(netContains(net, parseIp4Net("192.168.1.10").?.address));
    try testing.expect(!netContains(parseIp4Net("192.168.1.11").?, parseIp4Net("192.168.1.10").?.address));
}
