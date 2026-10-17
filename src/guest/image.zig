//! Pinned guest images (SPEC §9.1, §9.2). Proxmox downloads them itself
//! into `local:import` and verifies the SHA-256 before keeping the file;
//! no image is ever stored on the workstation. Advancing a pin changes
//! new templates only — existing guests never change.

const std = @import("std");

/// Storage that holds imported images (dir `/var/lib/vz`, content `import`).
pub const storage = "local";

pub const Pin = struct {
    /// `ubuntu-2604`: the IMAGE word, and the default template's name.
    name: []const u8,
    release: []const u8,
    /// Ubuntu codename (`resolute`): selects the Tailscale apt suite.
    codename: []const u8,
    build: []const u8,
    url: []const u8,
    sha256: []const u8,
    size: u64,
    /// PVE accepts only `.qcow2|.raw|.vmdk|.ova` in `import`; Ubuntu's
    /// `.img` is qcow2, so it is saved under a `.qcow2` name.
    file: []const u8,

    pub fn volid(comptime p: Pin) []const u8 {
        return storage ++ ":import/" ++ p.file;
    }

    pub fn volidAlloc(p: *const Pin, arena: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(arena, "{s}:import/{s}", .{ storage, p.file });
    }
};

fn ubuntu(comptime name: []const u8, comptime release: []const u8, comptime codename: []const u8, comptime build: []const u8, comptime sha256: []const u8, comptime size: u64) Pin {
    return .{
        .name = name,
        .release = release,
        .codename = codename,
        .build = build,
        .url = "https://cloud-images.ubuntu.com/releases/" ++ codename ++ "/release-" ++ build ++ "/ubuntu-" ++ release ++ "-server-cloudimg-amd64.img",
        .sha256 = sha256,
        .size = size,
        .file = "ubuntu-" ++ release ++ "-" ++ build ++ "-amd64.qcow2",
    };
}

/// Pinned 2026-10-10 from the release's SHA256SUMS, whose signature was
/// checked against Ubuntu's cloud-image key D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81.
pub const pins = [_]Pin{
    ubuntu("ubuntu-2604", "26.04", "resolute", "20260927", "8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2", 865_115_136),
};

pub fn find(name: []const u8) ?*const Pin {
    for (&pins) |*p| {
        if (std.mem.eql(u8, p.name, name)) return p;
    }
    return null;
}

/// `local:import/x.qcow2` → `x.qcow2` (null for another storage or type).
pub fn fileOf(volid: []const u8) ?[]const u8 {
    return std.mem.cutPrefix(u8, volid, storage ++ ":import/");
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "pins: names, files and checksums are well-formed" {
    for (pins, 0..) |p, i| {
        try testing.expect(std.mem.endsWith(u8, p.file, ".qcow2"));
        try testing.expect(std.mem.startsWith(u8, p.url, "https://cloud-images.ubuntu.com/"));
        try testing.expectEqual(@as(usize, 64), p.sha256.len);
        for (p.sha256) |ch| try testing.expect(std.ascii.isDigit(ch) or (ch >= 'a' and ch <= 'f'));
        for (pins[i + 1 ..]) |q| try testing.expect(!std.mem.eql(u8, p.name, q.name));
    }
    const p = find("ubuntu-2604").?;
    try testing.expectEqualStrings("https://cloud-images.ubuntu.com/releases/resolute/release-20260927/ubuntu-26.04-server-cloudimg-amd64.img", p.url);
    try testing.expectEqualStrings("local:import/ubuntu-26.04-20260927-amd64.qcow2", comptime pins[0].volid());
    try testing.expect(find("ubuntu-2404") == null);
    try testing.expectEqualStrings("a.qcow2", fileOf("local:import/a.qcow2").?);
    try testing.expect(fileOf("local:iso/a.iso") == null);
}
