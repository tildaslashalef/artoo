//! The shared cloud-init vendor-data snippet (SPEC §9.1, §9.2): the guest
//! baseline every VM receives through `cicustom: vendor=…`. Secret-free
//! and identity-free — user, password hash, SSH key, hostname and address
//! come from the VM's own cloud-init settings (Proxmox's user-data, which
//! takes precedence over vendor-data key by key).
//!
//! The document is rendered from the embedded payload; its name carries a
//! content hash (`artoo-vendor-<rev>.yaml`), so a changed payload is a new
//! snippet and existing guests never see a changed file.

const std = @import("std");
const Allocator = std.mem.Allocator;
const watch = @import("../watch/files.zig");

/// Directory of `local:snippets` on Proxmox.
pub const snippets_dir = "/var/lib/vz/snippets";

pub const File = struct {
    path: []const u8,
    bytes: []const u8,
    mode: []const u8 = "0644",
};

/// Payload files written into the guest user's home (payload/README.md),
/// paths relative to it (`home`). The Ghostty
/// terminfo is not among them: it is compiled system-wide (`bootcmd`).
pub const payload = [_]File{
    .{ .path = ".config/fish/config.fish", .bytes = @embedFile("payload/fish/config.fish") },
    .{ .path = ".config/fish/functions/bakit.fish", .bytes = @embedFile("payload/fish/functions/bakit.fish") },
    .{ .path = ".config/fish/functions/extract.fish", .bytes = @embedFile("payload/fish/functions/extract.fish") },
    .{ .path = ".config/fish/functions/journal.fish", .bytes = @embedFile("payload/fish/functions/journal.fish") },
    .{ .path = ".config/fish/functions/killport.fish", .bytes = @embedFile("payload/fish/functions/killport.fish") },
    .{ .path = ".config/fish/functions/myip.fish", .bytes = @embedFile("payload/fish/functions/myip.fish") },
    .{ .path = ".config/fish/functions/ports.fish", .bytes = @embedFile("payload/fish/functions/ports.fish") },
    .{ .path = ".config/fish/functions/ts.fish", .bytes = @embedFile("payload/fish/functions/ts.fish") },
    .{ .path = ".config/fish/functions/upd.fish", .bytes = @embedFile("payload/fish/functions/upd.fish") },
    .{ .path = ".config/tmux/tmux.conf", .bytes = @embedFile("payload/tmux/tmux.conf") },
    .{ .path = ".config/starship.toml", .bytes = @embedFile("payload/starship.toml") },
    .{ .path = ".vimrc", .bytes = @embedFile("payload/vimrc") },
};

/// `/home/<user>`.
pub fn home(arena: Allocator, user: []const u8) ![]const u8 {
    return std.fmt.allocPrint(arena, "/home/{s}", .{user});
}

/// A payload file's absolute path on the guest.
pub fn payloadPath(arena: Allocator, user: []const u8, f: File) ![]const u8 {
    return std.fmt.allocPrint(arena, "/home/{s}/{s}", .{ user, f.path });
}

pub const terminfo = @embedFile("payload/terminfo/xterm-ghostty.terminfo");
pub const terminfo_source = "/usr/local/share/artoo/xterm-ghostty.terminfo";

/// Tailscale's package signing key (fingerprint
/// 2596A99EAAB33821893C0A79458CA832957F5868), pinned instead of fetched at
/// boot.
pub const tailscale_key = @embedFile("tailscale.asc");

/// payload/README.md, plus Tailscale (installed, never enrolled); Alloy at
/// its pin follows (SPEC §9.9: installed, started only by `watch enroll`).
pub const packages = [_][]const u8{
    "git",       "vim",              "jq",     "coreutils", "curl", "ca-certificates", "tmux",    "htop",
    "fzf",       "eza",              "zoxide", "starship",  "fish", "ripgrep",         "fd-find", "unzip",
    "tailscale", "qemu-guest-agent",
};

/// Overrides cloud-init's `NOPASSWD` rule for the default user: sudoers
/// applies the last matching entry, and `99-` sorts after
/// `90-cloud-init-users`.
const sudoers_fmt =
    \\# artoo: sudo asks for {s}'s password (overrides 90-cloud-init-users)
    \\{s} ALL=(ALL:ALL) ALL
    \\
;

/// Ubuntu 26.04 cloud images build the initramfs with dracut, whose
/// systemd-networkd module DHCPs every NIC on every boot. A NIC that is up
/// cannot be renamed, so Proxmox's network config (`eth0`, matched by MAC)
/// never applies and the guest keeps a DHCP lease (live, 2026-10-10). The
/// root disk is local: the initramfs needs no network.
const dracut_no_network =
    \\# artoo: no networking in the initramfs (root is local), so udev can name
    \\# the NIC as netplan says and the static address applies (SPEC §9.1)
    \\omit_dracutmodules+=" dyn-netconf systemd-networkd network network-legacy "
    \\
;

/// sshd keeps the first value it reads; `10-` comes before cloud-init's
/// and the cloud image's drop-ins.
const sshd =
    \\# artoo guest baseline: key-only login, no root login
    \\PermitRootLogin no
    \\PasswordAuthentication no
    \\KbdInteractiveAuthentication no
    \\
;

pub const Snippet = struct {
    /// `artoo-vendor-<rev>.yaml`.
    name: []const u8,
    /// First 12 hex digits of the document's SHA-256.
    rev: []const u8,
    /// Full SHA-256 (hex) of `text`, as `sha256sum` prints it.
    sha256: []const u8,
    text: []const u8,

    /// `local:snippets/<name>`.
    pub fn volid(s: Snippet, arena: Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "local:snippets/{s}", .{s.name});
    }

    pub fn path(s: Snippet, arena: Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "{s}/{s}", .{ snippets_dir, s.name });
    }
};

/// Security updates daily, Tailscale's too, never a reboot (SPEC §9.1).
/// Merged with the image's `50unattended-upgrades` (its Allowed-Origins
/// keep the release and `-security` pockets).
pub const unattended_path = "/etc/apt/apt.conf.d/52artoo-unattended-upgrades";
pub const unattended =
    \\// artoo guest baseline (SPEC §9.1): security updates daily, no reboot.
    \\APT::Periodic::Update-Package-Lists "1";
    \\APT::Periodic::Unattended-Upgrade "1";
    \\Unattended-Upgrade::Origins-Pattern {
    \\        "origin=Tailscale,codename=${distro_codename}";
    \\};
    \\Unattended-Upgrade::Automatic-Reboot "false";
    \\Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
    \\
;

/// Render the vendor-data for an Ubuntu release (`codename` selects the
/// Tailscale suite) and the guest account `user` (`guests.user`).
pub fn render(arena: Allocator, codename: []const u8, user: []const u8) !Snippet {
    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try w.writeAll(
        \\#cloud-config
        \\# artoo guest baseline (vendor-data, SPEC §9.1). Shared by every guest and
        \\# secret-free: user, password hash, SSH key, hostname and address come from
        \\# the VM's own cloud-init settings.
        \\ssh_pwauth: false
        \\disable_root: true
        \\
    );

    // Ghostty terminfo, system-wide for every user including root, before
    // packages are installed. Once per instance; the source stays in place.
    try w.print(
        \\bootcmd:
        \\  - [cloud-init-per, instance, artoo-terminfo, sh, -c, "install -d -m 0755 /usr/local/share/artoo /etc/terminfo && printf %s '{s}' | base64 -d > {s} && tic -x -o /etc/terminfo {s}"]
        \\
    , .{ try b64(arena, terminfo), terminfo_source, terminfo_source });
    // First boot only: the initramfs already brought the NIC up under its
    // kernel name; netplan renames it and applies the static address.
    // Later boots have no initramfs network (dracut drop-in below).
    try w.writeAll("  - [cloud-init-per, instance, artoo-netplan, netplan, apply]\n");

    try w.print(
        \\apt:
        \\  sources:
        \\    tailscale.list:
        \\      source: "deb [signed-by=$KEY_FILE] https://pkgs.tailscale.com/stable/ubuntu {s} main"
        \\      key: |
        \\
    , .{codename});
    try keyBlock(w, tailscale_key);
    // Alloy (SPEC §9.9): Grafana's repository, the key embedded in artoo.
    try w.writeAll(
        \\    grafana.list:
        \\      source: "deb [signed-by=$KEY_FILE] https://apt.grafana.com stable main"
        \\      key: |
        \\
    );
    try keyBlock(w, watch.grafana_key);

    try w.writeAll("packages:\n");
    for (packages) |p| try w.print("  - {s}\n", .{p});
    try w.print("  - [alloy, \"{s}\"]\n", .{watch.alloy_version});

    try w.writeAll("write_files:\n");
    try file(arena, w, .{ .path = "/etc/sudoers.d/99-artoo-sudo-password", .bytes = try std.fmt.allocPrint(arena, sudoers_fmt, .{ user, user }), .mode = "0440" }, "root:root", false);
    try file(arena, w, .{ .path = "/etc/ssh/sshd_config.d/10-artoo.conf", .bytes = sshd }, "root:root", false);
    try file(arena, w, .{ .path = "/etc/dracut.conf.d/90-artoo-no-initrd-network.conf", .bytes = dracut_no_network }, "root:root", false);
    try file(arena, w, .{ .path = unattended_path, .bytes = unattended }, "root:root", false);
    // Before packages: Alloy stays off and LAN-only until `watch enroll`.
    try file(arena, w, .{ .path = watch.alloy_dropin_path, .bytes = watch.alloy_dropin }, "root:root", false);
    try file(arena, w, .{ .path = "/etc/apt/preferences.d/artoo-alloy", .bytes = try watch.aptPins(arena, &watch.guest_packages) }, "root:root", false);
    // Deferred to the final stage: the user exists by then.
    const owner = try std.fmt.allocPrint(arena, "{s}:{s}", .{ user, user });
    for (payload) |f| try file(arena, w, .{ .path = try payloadPath(arena, user, f), .bytes = f.bytes, .mode = f.mode }, owner, true);

    // After packages and deferred files. write_files creates missing parent
    // directories as root, hence the ownership repair.
    const h = try home(arena, user);
    try w.print(
        \\runcmd:
        \\  - [chsh, -s, /usr/bin/fish, {[u]s}]
        \\  - [install, -d, -o, {[u]s}, -g, {[u]s}, {[h]s}/.local, {[h]s}/.local/bin, {[h]s}/.local/share, {[h]s}/.local/share/fish]
        \\  - [ln, -sfn, /usr/bin/fdfind, {[h]s}/.local/bin/fd]
        \\  - [chown, -hR, "{[u]s}:{[u]s}", {[h]s}/.config, {[h]s}/.local]
        \\  - [systemctl, start, qemu-guest-agent]
        \\  - [systemctl, try-reload-or-restart, ssh.service]
        \\  - [dracut, -f, --regenerate-all]
        \\  - [systemctl, mask, --now, fwupd-refresh.timer]
        \\  - [sh, -c, "systemctl reset-failed systemd-networkd-wait-online.service || true"]
        \\
    , .{ .u = user, .h = h });

    const text = out.written();
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &digest, .{});
    const hex = try std.fmt.allocPrint(arena, "{x}", .{&digest});
    return .{
        .name = try std.fmt.allocPrint(arena, "artoo-vendor-{s}.yaml", .{hex[0..12]}),
        .rev = hex[0..12],
        .sha256 = hex,
        .text = text,
    };
}

fn keyBlock(w: *std.Io.Writer, key: []const u8) !void {
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, key, "\n"), '\n');
    while (lines.next()) |line| {
        if (line.len == 0) try w.writeByte('\n') else try w.print("        {s}\n", .{line});
    }
}

fn b64(arena: Allocator, bytes: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(bytes.len));
    return enc.encode(out, bytes);
}

fn file(arena: Allocator, w: *std.Io.Writer, f: File, owner: []const u8, deferred: bool) !void {
    try w.print(
        \\  - path: {s}
        \\    owner: "{s}"
        \\    permissions: "{s}"
        \\    encoding: b64
        \\    content: {s}
        \\
    , .{ f.path, owner, f.mode, try b64(arena, f.bytes) });
    if (deferred) try w.writeAll("    defer: true\n");
}

/// `artoo-vendor-<12 hex>.yaml`: the only names artoo writes or reads in
/// the snippets directory.
pub fn validName(name: []const u8) bool {
    const rev = std.mem.cutPrefix(u8, name, "artoo-vendor-") orelse return false;
    const hex = std.mem.cutSuffix(u8, rev, ".yaml") orelse return false;
    if (hex.len != 12) return false;
    for (hex) |ch| if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return false;
    return true;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "render: deterministic, content-addressed, secret- and identity-free" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const s = try render(ar, "resolute", "ops");
    const again = try render(ar, "resolute", "ops");
    try testing.expectEqualStrings(s.text, again.text);
    try testing.expect(validName(s.name));
    try testing.expectEqualStrings(s.rev, s.sha256[0..12]);
    try testing.expect(!std.mem.eql(u8, s.rev, (try render(ar, "noble", "ops")).rev));
    try testing.expectEqualStrings("local:snippets/" ++ "artoo-vendor-", (try s.volid(ar))[0..28]);

    const t = s.text;
    try testing.expect(std.mem.startsWith(u8, t, "#cloud-config\n"));
    for ([_][]const u8{ "$6$", "passwd", "ssh_authorized_keys", "hostname:", "PRIVATE KEY", "authkey" }) |bad| {
        try testing.expect(std.mem.find(u8, t, bad) == null);
    }
    for ([_][]const u8{
        "ssh_pwauth: false\n",
        "  - [cloud-init-per, instance, artoo-terminfo, sh, -c, \"install -d -m 0755 /usr/local/share/artoo /etc/terminfo && printf %s '",
        "| base64 -d > /usr/local/share/artoo/xterm-ghostty.terminfo && tic -x -o /etc/terminfo /usr/local/share/artoo/xterm-ghostty.terminfo\"]\n",
        "      source: \"deb [signed-by=$KEY_FILE] https://pkgs.tailscale.com/stable/ubuntu resolute main\"\n",
        "        -----BEGIN PGP PUBLIC KEY BLOCK-----\n\n        mQINBF5UmbgBEADAA5mxC8EoWEf53RVdlhQJbNnQW7fctUA5yNcGUbGGGTk6XFqO\n",
        "  - tailscale\n  - qemu-guest-agent\n  - [alloy, \"1.20.1-1\"]\nwrite_files:\n",
        "    grafana.list:\n      source: \"deb [signed-by=$KEY_FILE] https://apt.grafana.com stable main\"\n",
        "  - path: /etc/systemd/system/alloy.service.d/10-artoo.conf\n",
        "  - path: /etc/sudoers.d/99-artoo-sudo-password\n    owner: \"root:root\"\n    permissions: \"0440\"\n",
        "  - path: /home/ops/.vimrc\n    owner: \"ops:ops\"\n    permissions: \"0644\"\n    encoding: b64\n    content: ",
        "  - [chsh, -s, /usr/bin/fish, ops]\n",
        "  - [cloud-init-per, instance, artoo-netplan, netplan, apply]\n",
        "  - path: /etc/dracut.conf.d/90-artoo-no-initrd-network.conf\n",
        "  - [dracut, -f, --regenerate-all]\n",
        "  - [systemctl, mask, --now, fwupd-refresh.timer]\n",
        "  - path: /etc/apt/apt.conf.d/52artoo-unattended-upgrades\n    owner: \"root:root\"\n",
        "  - [sh, -c, \"systemctl reset-failed systemd-networkd-wait-online.service || true\"]\n",
    }) |want| {
        if (std.mem.find(u8, t, want) == null) {
            std.debug.print("missing: {s}\n", .{want});
            return error.TestUnexpectedResult;
        }
    }
    // Every payload file is deferred (the user exists only after the init stage).
    try testing.expectEqual(payload.len, std.mem.count(u8, t, "    defer: true\n"));
}

test "unattended upgrades: Tailscale's origin, never a reboot" {
    for ([_][]const u8{
        "APT::Periodic::Unattended-Upgrade \"1\";\n",
        "        \"origin=Tailscale,codename=${distro_codename}\";\n",
        "Unattended-Upgrade::Automatic-Reboot \"false\";\n",
    }) |want| try testing.expect(std.mem.find(u8, unattended, want) != null);
}

test "terminfo round-trips through the bootcmd base64" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const t = (try render(ar, "resolute", "ops")).text;
    const start = (std.mem.find(u8, t, "printf %s '") orelse return error.TestUnexpectedResult) + "printf %s '".len;
    const end = std.mem.findScalarPos(u8, t, start, '\'') orelse return error.TestUnexpectedResult;
    const dec = std.base64.standard.Decoder;
    const buf = try ar.alloc(u8, try dec.calcSizeForSlice(t[start..end]));
    try dec.decode(buf, t[start..end]);
    try testing.expectEqualStrings(terminfo, buf);
    try testing.expect(std.mem.startsWith(u8, terminfo, "xterm-ghostty|") or std.mem.find(u8, terminfo, "\nxterm-ghostty|") != null);
}

test "validName" {
    try testing.expect(validName("artoo-vendor-0123456789ab.yaml"));
    try testing.expect(!validName("artoo-vendor-0123456789AB.yaml"));
    try testing.expect(!validName("artoo-vendor-../x.yaml"));
    try testing.expect(!validName("other.yaml"));
}
