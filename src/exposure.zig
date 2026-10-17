//! The hard rule of SPEC §9.6: the Proxmox host and the UniFi gateway are
//! never publicly exposed. Every operation that could publish a name or
//! route (Cloudflare records and tunnels, edge routes, public names under
//! the guest domain) asks `protected` first; there is no override.
//!
//! What counts as the infrastructure comes from the configuration
//! (`Infra.of`): the node name, the endpoints' and SSH host's first labels
//! and addresses, the guests' gateway, `guests.reserved_names`, and the
//! generic words in `names.reserved`.

const std = @import("std");
const config = @import("config.zig");
const names = @import("guest/names.zig");

/// The private infrastructure domain; names under it never leave the LAN.
pub const private_domain = "home.arpa";

pub const max_names = 32;

/// Host labels and LAN addresses that name the infrastructure.
pub const Infra = struct {
    names: [max_names][]const u8 = undefined,
    n_names: usize = 0,
    addresses: [4][]const u8 = undefined,
    n_addresses: usize = 0,

    pub fn of(cfg: *const config.Config) Infra {
        var self: Infra = .{};
        for (names.reserved) |r| self.addName(r);
        self.addName(cfg.pve.node);
        self.addHost(urlHost(cfg.pve.endpoint));
        self.addHost(urlHost(cfg.unifi.endpoint));
        self.addHost(cfg.pve.ssh_host);
        self.addAddress(cfg.guests.gateway[0 .. std.mem.findScalar(u8, cfg.guests.gateway, '/') orelse cfg.guests.gateway.len]);
        var it = std.mem.tokenizeAny(u8, cfg.guests.reserved_names, ", ");
        while (it.next()) |r| self.addName(r);
        return self;
    }

    /// A literal address, or the first label of a DNS name.
    fn addHost(self: *Infra, host: []const u8) void {
        if (host.len == 0) return;
        if (isIpv4(host)) return self.addAddress(host);
        self.addName(host[0 .. std.mem.findScalar(u8, host, '.') orelse host.len]);
    }

    fn addName(self: *Infra, n: []const u8) void {
        if (n.len == 0 or self.n_names == max_names) return;
        self.names[self.n_names] = n;
        self.n_names += 1;
    }

    fn addAddress(self: *Infra, a: []const u8) void {
        if (!isIpv4(a) or self.n_addresses == self.addresses.len) return;
        self.addresses[self.n_addresses] = a;
        self.n_addresses += 1;
    }

    /// True when `label` is one of the infrastructure's names.
    pub fn isName(self: *const Infra, label: []const u8) bool {
        for (self.names[0..self.n_names]) |p| {
            if (std.ascii.eqlIgnoreCase(label, p)) return true;
        }
        return false;
    }

    /// Why `name` (an FQDN or label) or `address` refers to protected
    /// infrastructure, or null. Any label of the name counts, so
    /// `pve.lab.example.com` and `www.pve.example` are both refused.
    pub fn protected(self: *const Infra, name: ?[]const u8, address: ?[]const u8) ?[]const u8 {
        if (address) |a| {
            for (self.addresses[0..self.n_addresses]) |p| {
                if (std.mem.eql(u8, a, p)) return "the address belongs to the Proxmox host or the gateway";
            }
        }
        if (name) |n| {
            var labels = std.mem.splitScalar(u8, std.mem.trimEnd(u8, n, "."), '.');
            while (labels.next()) |l| {
                if (self.isName(l)) return "the name refers to the Proxmox host, the gateway or the lab's equipment";
            }
        }
        return null;
    }
};

/// `protected` for the context's configuration.
pub fn protected(cfg: *const config.Config, name: ?[]const u8, address: ?[]const u8) ?[]const u8 {
    const infra: Infra = .of(cfg);
    return infra.protected(name, address);
}

fn urlHost(url: []const u8) []const u8 {
    const uri = std.Uri.parse(url) catch return "";
    const host = uri.host orelse return "";
    return switch (host) {
        inline else => |h| h,
    };
}

fn isIpv4(s: []const u8) bool {
    _ = std.Io.net.Ip4Address.parse(s, 0) catch return false;
    return true;
}

/// True for `home.arpa` and names under it.
pub fn isPrivate(fqdn: []const u8) bool {
    const n = std.mem.trimEnd(u8, fqdn, ".");
    if (std.ascii.eqlIgnoreCase(n, private_domain)) return true;
    return n.len > private_domain.len and n[n.len - private_domain.len - 1] == '.' and
        std.ascii.eqlIgnoreCase(n[n.len - private_domain.len ..], private_domain);
}

const testing = std.testing;

test "protected: names by any label, addresses exactly" {
    const cfg: config.Config = .{};
    try testing.expect(protected(&cfg, "pve.lab.example.com", null) != null);
    try testing.expect(protected(&cfg, "UNIFI.home.arpa.", null) != null);
    try testing.expect(protected(&cfg, "www.gateway.example", null) != null);
    try testing.expect(protected(&cfg, "web-01.lab.example.com", "192.168.1.10") != null);
    try testing.expect(protected(&cfg, null, "192.168.1.1") != null);
    try testing.expect(protected(&cfg, "web-01.lab.example.com", "192.168.1.201") == null);
    try testing.expect(protected(&cfg, "pves.lab.example.com", "192.168.1.11") == null);
}

test "protected: names and addresses from the configuration" {
    var cfg: config.Config = .{};
    cfg.pve.node = "node1";
    cfg.pve.endpoint = "https://hv.home.arpa:8006";
    cfg.pve.ssh_host = "10.0.0.5";
    cfg.unifi.endpoint = "https://10.0.0.1/proxy/network/integration";
    cfg.guests.gateway = "10.0.0.1/24";
    cfg.guests.reserved_names = "router, nas,ap1";
    for ([_][]const u8{ "node1", "hv.example.com", "www.router.example", "nas", "AP1.lab.example.com" }) |n|
        try testing.expect(protected(&cfg, n, null) != null);
    try testing.expect(protected(&cfg, null, "10.0.0.5") != null);
    try testing.expect(protected(&cfg, null, "10.0.0.1") != null);
    try testing.expect(protected(&cfg, "naboo", "10.0.0.20") == null);
}

test "isPrivate" {
    try testing.expect(isPrivate("pve.home.arpa"));
    try testing.expect(isPrivate("home.arpa."));
    try testing.expect(!isPrivate("pve.lab.example.com"));
    try testing.expect(!isPrivate("evilhome.arpa"));
}
