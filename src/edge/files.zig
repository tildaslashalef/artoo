//! What `artoo edge setup` puts on the edge VM (SPEC §9.7): every file is
//! rendered here from config, so addresses cannot drift from the lab's.
//! Each carries a header naming artoo as its owner.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Pinned build inputs (SPEC §9.7). Bumping one is a deliberate SPEC edit.
pub const caddy_version = "v2.11.7";
pub const cloudflare_module = "github.com/caddy-dns/cloudflare";
pub const cloudflare_module_version = "v0.2.4";
pub const xcaddy_version = "v0.4.7";
/// Ubuntu 26.04's Go (1.26.8 at design time; Caddy needs ≥ 1.26.0).
pub const go_package = "golang-1.26-go";
pub const go_bin = "/usr/lib/go-1.26/bin/go";

/// Cloudflare's apt signing key, byte for byte as published
/// (`https://pkg.cloudflare.com/cloudflare-main.gpg`, SHA-256
/// 1bd95f40…721d), fingerprint below.
pub const cloudflare_key = @embedFile("cloudflare-main.gpg");
pub const cloudflare_key_fingerprint = "CC94B39C77AE7342A68B89628A682D308D4E5E73";

pub const Addresses = struct {
    pve: []const u8,
    gateway: []const u8,
    /// `192.168.1.0/24`.
    lan: []const u8,
    /// `192.168.1.200-192.168.1.254`.
    pool: []const u8,
};

pub const File = struct {
    path: []const u8,
    mode: []const u8,
    owner: []const u8,
    content: []const u8,
};

const header = "# Managed by artoo (SPEC §9.7); 'artoo edge setup' overwrites edits.\n";

/// nftables policy: SSH only from Proxmox, HTTP(S) from the LAN; egress to
/// the internet, UniFi's DNS and the guest pool (not their SSH) only.
/// Named counters feed `edge status`. IPv6 neighbor discovery and MLD
/// reports (link-local multicast, sent at every boot) are allowed so the
/// counters only count real attempts (seen live 2026-10-10: 4 × 76-byte
/// MLDv2 reports after a reboot).
pub fn nftables(a: Allocator, ad: Addresses) ![]const u8 {
    return std.fmt.allocPrint(a,
        \\#!/usr/sbin/nft -f
        \\{s}
        \\flush ruleset
        \\
        \\define pve = {s}
        \\define gateway = {s}
        \\define lan = {s}
        \\define pool = {s}
        \\define private4 = {{ 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 169.254.0.0/16 }}
        \\
        \\table inet artoo_edge {{
        \\    counter to_pve {{ }}
        \\    counter to_gateway {{ }}
        \\    counter to_lan {{ }}
        \\    counter out_other {{ }}
        \\    counter in_dropped {{ }}
        \\
        \\    chain input {{
        \\        type filter hook input priority filter; policy drop;
        \\        iif "lo" accept
        \\        ct state established,related accept
        \\        ct state invalid drop
        \\        icmp type {{ echo-request, destination-unreachable, time-exceeded }} accept
        \\        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, echo-request, destination-unreachable, packet-too-big, time-exceeded }} accept
        \\        ip saddr $pve tcp dport 22 accept
        \\        ip saddr $lan tcp dport {{ 80, 443 }} accept
        \\        counter name in_dropped drop
        \\    }}
        \\
        \\    chain forward {{
        \\        type filter hook forward priority filter; policy drop;
        \\    }}
        \\
        \\    chain output {{
        \\        type filter hook output priority filter; policy drop;
        \\        oif "lo" accept
        \\        ct state established,related accept
        \\        ip daddr $pve counter name to_pve drop
        \\        ip daddr $gateway meta l4proto {{ tcp, udp }} th dport 53 accept
        \\        ip daddr $gateway counter name to_gateway drop
        \\        ip daddr $pool tcp dport != 22 accept
        \\        ip daddr $lan counter name to_lan drop
        \\        ip daddr $private4 counter name to_lan drop
        \\        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report, mld2-listener-report }} accept
        \\        ip6 daddr != 2000::/3 counter name to_lan drop
        \\        icmp type echo-request accept
        \\        tcp dport {{ 80, 443, 7844 }} accept
        \\        udp dport {{ 123, 443, 7844 }} accept
        \\        counter name out_other drop
        \\    }}
        \\}}
        \\
    , .{ header, ad.pve, ad.gateway, ad.lan, ad.pool });
}

pub const sysctl = header ++
    \\net.ipv4.ip_forward = 0
    \\net.ipv6.conf.all.forwarding = 0
    \\net.ipv4.conf.all.rp_filter = 1
    \\net.ipv4.conf.default.rp_filter = 1
    \\net.ipv4.conf.all.accept_redirects = 0
    \\net.ipv4.conf.default.accept_redirects = 0
    \\net.ipv6.conf.all.accept_redirects = 0
    \\net.ipv6.conf.default.accept_redirects = 0
    \\net.ipv4.conf.all.send_redirects = 0
    \\net.ipv4.conf.all.accept_source_route = 0
    \\net.ipv6.conf.all.accept_source_route = 0
    \\net.ipv4.tcp_syncookies = 1
    \\kernel.kptr_restrict = 2
    \\kernel.dmesg_restrict = 1
    \\kernel.unprivileged_bpf_disabled = 1
    \\net.core.bpf_jit_harden = 2
    \\
;

/// Caddy as user `caddy`, sandboxed; no `--environ` (it would print the
/// DNS token into the journal).
pub const caddy_unit = header ++
    \\[Unit]
    \\Description=Caddy, artoo edge (SPEC 9.7)
    \\After=network-online.target nftables.service
    \\Wants=network-online.target
    \\ConditionPathExists=/etc/caddy/cloudflare.env
    \\
    \\[Service]
    \\Type=notify
    \\User=caddy
    \\Group=caddy
    \\EnvironmentFile=/etc/caddy/cloudflare.env
    \\Environment=XDG_DATA_HOME=/var/lib/caddy XDG_CONFIG_HOME=/var/lib/caddy
    \\ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile
    \\ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile --force
    \\TimeoutStopSec=5s
    \\LimitNOFILE=1048576
    \\Restart=on-failure
    \\AmbientCapabilities=CAP_NET_BIND_SERVICE
    \\CapabilityBoundingSet=CAP_NET_BIND_SERVICE
    \\NoNewPrivileges=true
    \\ProtectSystem=strict
    \\ProtectHome=true
    \\ReadWritePaths=/var/lib/caddy /var/log/caddy
    \\PrivateTmp=true
    \\PrivateDevices=true
    \\ProtectKernelTunables=true
    \\ProtectKernelModules=true
    \\ProtectKernelLogs=true
    \\ProtectControlGroups=true
    \\ProtectClock=true
    \\ProtectHostname=true
    \\RestrictNamespaces=true
    \\RestrictRealtime=true
    \\RestrictSUIDSGID=true
    \\LockPersonality=true
    \\RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
    \\SystemCallArchitectures=native
    \\SystemCallFilter=@system-service
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\
;

/// cloudflared as user `cloudflared`, sandboxed, running the remotely
/// managed tunnel; the token comes from `TUNNEL_TOKEN` in the environment
/// file `artoo edge tunnel` writes (never argv, never the journal).
pub const cloudflared_unit = header ++
    \\[Unit]
    \\Description=cloudflared, artoo edge (SPEC 9.7)
    \\After=network-online.target nftables.service caddy.service
    \\Wants=network-online.target
    \\ConditionPathExists=/etc/cloudflared/tunnel.env
    \\
    \\[Service]
    \\Type=notify
    \\User=cloudflared
    \\Group=cloudflared
    \\EnvironmentFile=/etc/cloudflared/tunnel.env
    \\ExecStart=/usr/bin/cloudflared tunnel --no-autoupdate --metrics localhost:20241 run
    \\Restart=on-failure
    \\RestartSec=5s
    \\TimeoutStartSec=30s
    \\NoNewPrivileges=true
    \\CapabilityBoundingSet=
    \\ProtectSystem=strict
    \\ProtectHome=true
    \\PrivateTmp=true
    \\PrivateDevices=true
    \\ProtectKernelTunables=true
    \\ProtectKernelModules=true
    \\ProtectKernelLogs=true
    \\ProtectControlGroups=true
    \\ProtectClock=true
    \\ProtectHostname=true
    \\RestrictNamespaces=true
    \\RestrictRealtime=true
    \\RestrictSUIDSGID=true
    \\LockPersonality=true
    \\RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
    \\SystemCallArchitectures=native
    \\SystemCallFilter=@system-service
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\
;

/// The wildcard site; service routes are imported from
/// `/etc/caddy/services/*.caddy` (SPEC §9.6, task: service names).
/// Caddy's own propagation check would query Cloudflare's nameservers
/// directly, which the egress policy forbids (DNS only via UniFi):
/// it is off, and a fixed 60 s delay lets the record propagate before Let's
/// Encrypt checks it (SPEC §9.7).
pub fn caddyfile(a: Allocator, apps_domain: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a,
        \\{s}
        \\{{
        \\    admin localhost:2019
        \\}}
        \\
        \\*.{s} {{
        \\    tls {{
        \\        dns cloudflare {{env.CF_API_TOKEN}}
        \\        propagation_delay 60s
        \\        propagation_timeout -1
        \\    }}
        \\    log {{
        \\        output file /var/log/caddy/access.json {{
        \\            roll_size 10MiB
        \\            roll_keep 5
        \\        }}
        \\        format json
        \\    }}
        \\    header {{
        \\        Strict-Transport-Security "max-age=31536000"
        \\        X-Content-Type-Options nosniff
        \\        Referrer-Policy strict-origin-when-cross-origin
        \\        -Server
        \\    }}
        \\    import /etc/caddy/services/*.caddy
        \\    handle {{
        \\        respond "no such service" 404
        \\    }}
        \\}}
        \\
    , .{ std.mem.trimEnd(u8, header, "\n"), apps_domain });
}

pub const cloudflared_list = header ++
    \\deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main
    \\
;

/// Security updates also for cloudflared (Release `Origin: cloudflared`).
pub const unattended = header ++
    \\Unattended-Upgrade::Origins-Pattern {
    \\    "origin=cloudflared";
    \\};
    \\
;

/// The Caddy build (root, through the guest agent): pinned versions, Go's
/// checksum database, no toolchain download; verifies the module and
/// version before installing; leaves no compiler behind.
/// Where the build writes its current stage (`agent.Watch`).
pub const build_stage_file = "/run/artoo-caddy-build.stage";

pub const build_script = std.fmt.comptimePrint(
    \\set -eu
    \\export DEBIAN_FRONTEND=noninteractive
    \\S={[stage]s}
    \\stage() {{ echo "$1" > "$S"; }}
    \\stage "installing Go"
    \\apt-get install -y --no-install-recommends {[go]s} ca-certificates
    \\W=$(mktemp -d /var/tmp/artoo-caddy.XXXXXX)
    \\trap 'rm -rf "$W" "$S"' EXIT
    \\export GOTOOLCHAIN=local GOFLAGS=-modcacherw HOME="$W" GOPATH="$W/go" GOCACHE="$W/cache" GOMODCACHE="$W/mod"
    \\export PATH="$(dirname {[go_bin]s}):$PATH"
    \\stage "building xcaddy {[xcaddy]s}"
    \\GOBIN="$W/bin" go install github.com/caddyserver/xcaddy/cmd/xcaddy@{[xcaddy]s}
    \\cd "$W"
    \\stage "building Caddy {[caddy]s} with {[module]s} (modules, then compile)"
    \\"$W/bin/xcaddy" build {[caddy]s} --with {[module]s}@{[module_version]s} --output "$W/caddy"
    \\stage "checking the binary"
    \\"$W/caddy" list-modules | grep -qx 'dns.providers.cloudflare'
    \\"$W/caddy" version | grep -q '^{[caddy]s} '
    \\install -m 0755 "$W/caddy" /usr/local/bin/caddy
    \\stage "removing Go"
    \\apt-get purge -y {[go]s}
    \\apt-get autoremove -y
    \\
, .{ .stage = build_stage_file, .go = go_package, .go_bin = go_bin, .xcaddy = xcaddy_version, .caddy = caddy_version, .module = cloudflare_module, .module_version = cloudflare_module_version });

/// Accounts and directories for Caddy and cloudflared.
pub const caddy_prepare =
    \\set -eu
    \\getent group caddy >/dev/null || groupadd --system caddy
    \\getent passwd caddy >/dev/null || useradd --system --gid caddy --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
    \\install -d -m 0750 -o caddy -g caddy /var/lib/caddy /var/log/caddy
    \\install -d -m 0755 /etc/caddy
    \\install -d -m 0755 /etc/caddy/services
    \\getent group cloudflared >/dev/null || groupadd --system cloudflared
    \\getent passwd cloudflared >/dev/null || useradd --system --gid cloudflared --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin cloudflared
    \\install -d -m 0750 -o root -g cloudflared /etc/cloudflared
    \\
;

/// `sh -c` body writing base64 stdin to `$1` atomically with mode `$2`
/// and owner `$3` (every file, binary and secrets included: nothing in
/// argv).
pub const write_file =
    \\set -eu
    \\d=$(dirname "$1")
    \\install -d -m 0755 "$d"
    \\t=$(mktemp "$1.artoo.XXXXXX")
    \\base64 -d > "$t"
    \\chmod "$2" "$t"
    \\chown "$3" "$t"
    \\mv -f "$t" "$1"
    \\
;

/// Large files go in parts: Proxmox caps the agent's `input-data` at
/// 65536 characters. `$1` path, `$2` `first` or `next`; base64 on stdin is
/// appended to `$1.artoo-part` (0600 until finished).
pub const write_part =
    \\set -eu
    \\install -d -m 0755 "$(dirname "$1")"
    \\p="$1.artoo-part"
    \\if [ "$2" = first ]; then : > "$p"; chmod 0600 "$p"; fi
    \\base64 -d >> "$p"
    \\
;

/// Moves the assembled part into place with mode `$2` and owner `$3`.
pub const write_finish =
    \\set -eu
    \\p="$1.artoo-part"
    \\chmod "$2" "$p"
    \\chown "$3" "$p"
    \\mv -f "$p" "$1"
    \\
;

/// Raw bytes per part: base64 makes 60000 characters, under Proxmox's cap.
pub const part_bytes = 45_000;

/// The managed files, in the order they are applied.
pub fn all(a: Allocator, ad: Addresses, apps_domain: []const u8) ![]const File {
    return a.dupe(File, &.{
        .{ .path = "/etc/sysctl.d/90-artoo-edge.conf", .mode = "0644", .owner = "root:root", .content = sysctl },
        .{ .path = "/etc/nftables.conf", .mode = "0644", .owner = "root:root", .content = try nftables(a, ad) },
        .{ .path = "/usr/share/keyrings/cloudflare-main.gpg", .mode = "0644", .owner = "root:root", .content = cloudflare_key },
        .{ .path = "/etc/apt/sources.list.d/cloudflared.list", .mode = "0644", .owner = "root:root", .content = cloudflared_list },
        .{ .path = "/etc/apt/apt.conf.d/52artoo-edge", .mode = "0644", .owner = "root:root", .content = unattended },
        .{ .path = "/etc/systemd/system/caddy.service", .mode = "0644", .owner = "root:root", .content = caddy_unit },
        .{ .path = "/etc/systemd/system/cloudflared.service", .mode = "0644", .owner = "root:root", .content = cloudflared_unit },
        .{ .path = "/etc/caddy/Caddyfile", .mode = "0644", .owner = "root:root", .content = try caddyfile(a, apps_domain) },
        .{ .path = "/etc/caddy/services/000-none.caddy", .mode = "0644", .owner = "root:root", .content = "# Service routes (SPEC §9.6) are added next to this file.\n" },
    });
}

/// Hex SHA-256 (compared with `sha256sum` in the guest).
pub fn sha256Hex(a: Allocator, data: []const u8) ![]const u8 {
    var d: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &d, .{});
    return a.dupe(u8, &std.fmt.bytesToHex(d, .lower));
}

const testing = std.testing;

test "nftables: Proxmox dropped, SSH only from Proxmox, pool reachable but not its SSH" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const nft = try nftables(arena.allocator(), .{ .pve = "192.168.1.10", .gateway = "192.168.1.1", .lan = "192.168.1.0/24", .pool = "192.168.1.200-192.168.1.254" });
    for ([_][]const u8{
        "define pve = 192.168.1.10\n",
        "ip saddr $pve tcp dport 22 accept\n",
        "ip daddr $pve counter name to_pve drop\n",
        "ip daddr $pool tcp dport != 22 accept\n",
        "policy drop;",
    }) |want| try testing.expect(std.mem.find(u8, nft, want) != null);
    // Proxmox is dropped before anything could accept it.
    try testing.expect(std.mem.find(u8, nft, "ip daddr $pve").? < std.mem.find(u8, nft, "tcp dport { 80, 443, 7844 } accept").?);
}

test "the Caddy unit never prints its environment; the key is Cloudflare's file" {
    try testing.expect(std.mem.find(u8, caddy_unit, "--environ") == null);
    var a0 = std.heap.ArenaAllocator.init(testing.allocator);
    defer a0.deinit();
    try testing.expect(std.mem.find(u8, try caddyfile(a0.allocator(), "apps.lab.example.com"), "propagation_timeout -1") != null);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectEqualStrings("1bd95f4082b320d541bee351560fc2765aa9f9cd8efa4c9e32135e63f252721d", try sha256Hex(arena.allocator(), cloudflare_key));
    try testing.expect(std.mem.find(u8, build_script, "xcaddy\" build v2.11.7 --with github.com/caddy-dns/cloudflare@v0.2.4") != null);
    // The stage file: written before each long part, removed on exit.
    try testing.expect(std.mem.find(u8, build_script, "S=/run/artoo-caddy-build.stage\n") != null);
    try testing.expect(std.mem.find(u8, build_script, "stage \"building Caddy v2.11.7 with github.com/caddy-dns/cloudflare (modules, then compile)\"\n") != null);
    try testing.expect(std.mem.find(u8, build_script, "trap 'rm -rf \"$W\" \"$S\"' EXIT\n") != null);
}
