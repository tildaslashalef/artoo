//! Release archive checks for `artoo update` (SPEC §18): the SHA-256 line
//! in `SHA256SUMS`, GitHub's asset digest, and the one binary entry read
//! from the gzip + tar stream with the stdlib only. Nothing here touches
//! the file system: the entry is streamed to a writer the caller owns.

const std = @import("std");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Digest = [Sha256.digest_length]u8;

pub fn sha256(data: []const u8) Digest {
    var d: Digest = undefined;
    Sha256.hash(data, &d, .{});
    return d;
}

pub fn hex(d: Digest) [Sha256.digest_length * 2]u8 {
    return std.fmt.bytesToHex(d, .lower);
}

pub const SumsError = error{ SumMissing, SumAmbiguous, SumMalformed };

/// The SHA-256 that `SHA256SUMS` (`shasum -a 256` output: `<hex>  <name>`,
/// or `<hex> *<name>`) gives for `name`; exactly one line must name it.
pub fn expectedSum(sums: []const u8, name: []const u8) SumsError!Digest {
    var found: ?Digest = null;
    var lines = std.mem.splitScalar(u8, sums, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        const sp = std.mem.findScalar(u8, line, ' ') orelse continue;
        var file = std.mem.trimStart(u8, line[sp..], " ");
        file = std.mem.cutPrefix(u8, file, "*") orelse file;
        if (!std.mem.eql(u8, file, name)) continue;
        if (found != null) return error.SumAmbiguous;
        const digest_hex = line[0..sp];
        if (digest_hex.len != 64) return error.SumMalformed;
        var d: Digest = undefined;
        _ = std.fmt.hexToBytes(&d, digest_hex) catch return error.SumMalformed;
        found = d;
    }
    return found orelse error.SumMissing;
}

/// GitHub's `digest` field: `sha256:<hex>` → the digest; null for any
/// other form (an algorithm artoo does not check).
pub fn githubDigest(field: []const u8) ?Digest {
    const h = std.mem.cutPrefix(u8, field, "sha256:") orelse return null;
    if (h.len != 64) return null;
    var d: Digest = undefined;
    _ = std.fmt.hexToBytes(&d, h) catch return null;
    return d;
}

pub const ExtractError = error{
    /// Not gzip, not tar, or cut short.
    ArchiveMalformed,
    EntryMissing,
    EntryDuplicate,
    EntryNotFile,
    EntryTooLarge,
    WriteFailed,
};

/// Stream the regular file `entry` of the gzip-compressed tar `data` into
/// `out`; returns its size. Every other entry is read past and never
/// written anywhere, so names, links and `..` in the archive cannot place
/// anything.
pub fn extract(data: []const u8, entry: []const u8, out: *Io.Writer, max: u64) ExtractError!u64 {
    var in: Io.Reader = .fixed(data);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var gz: std.compress.flate.Decompress = .init(&in, .gzip, &window);
    var name_buf: [std.fs.max_path_bytes]u8 = undefined;
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&gz.reader, .{ .file_name_buffer = &name_buf, .link_name_buffer = &link_buf });
    var size: ?u64 = null;
    while (true) {
        const f = (it.next() catch return error.ArchiveMalformed) orelse break;
        if (!std.mem.eql(u8, f.name, entry)) continue;
        if (size != null) return error.EntryDuplicate;
        if (f.kind != .file) return error.EntryNotFile;
        if (f.size > max) return error.EntryTooLarge;
        it.streamRemaining(f, out) catch |err| return switch (err) {
            error.WriteFailed => error.WriteFailed,
            else => error.ArchiveMalformed,
        };
        size = f.size;
    }
    return size orelse error.EntryMissing;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

pub const TestEntry = struct {
    name: []const u8,
    data: []const u8 = "",
    kind: enum { file, dir, link } = .file,
    mode: u32 = 0o755,
};

/// A gzip-compressed tar of `entries`, as `scripts/release-binaries.sh`
/// makes them (for tests here and in `commands/update.zig`).
pub fn testArchive(gpa: std.mem.Allocator, entries: []const TestEntry) ![]u8 {
    var tar_bytes: Io.Writer.Allocating = .init(gpa);
    defer tar_bytes.deinit();
    var tw: std.tar.Writer = .{ .underlying_writer = &tar_bytes.writer };
    for (entries) |e| switch (e.kind) {
        .file => try tw.writeFileBytes(e.name, e.data, .{ .mode = e.mode }),
        .dir => try tw.writeDir(e.name, .{ .mode = 0o755 }),
        .link => try tw.writeLink(e.name, e.data, .{}),
    };
    try tw.finishPedantically();

    var gz_bytes: Io.Writer.Allocating = try .initCapacity(gpa, 64);
    errdefer gz_bytes.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var c: std.compress.flate.Compress = try .init(&gz_bytes.writer, &window, .gzip, .default);
    try c.writer.writeAll(tar_bytes.written());
    try c.finish();
    return gz_bytes.toOwnedSlice();
}

test "expectedSum: one line per name, both shasum forms" {
    const a: [64]u8 = @splat('a');
    const b: [64]u8 = @splat('b');
    const sums = a ++ "  artoo-0.4.0-aarch64-macos.tar.gz\n" ++ b ++ " *artoo-0.4.0-x86_64-linux.tar.gz\r\n";
    try testing.expectEqualStrings(&a, &hex(try expectedSum(sums, "artoo-0.4.0-aarch64-macos.tar.gz")));
    try testing.expectEqualStrings(&b, &hex(try expectedSum(sums, "artoo-0.4.0-x86_64-linux.tar.gz")));
    try testing.expectError(error.SumMissing, expectedSum(sums, "artoo-0.4.0-aarch64-linux.tar.gz"));
    try testing.expectError(error.SumMissing, expectedSum(sums, "aarch64-macos.tar.gz"));
    try testing.expectError(error.SumAmbiguous, expectedSum(sums ++ sums, "artoo-0.4.0-aarch64-macos.tar.gz"));
    try testing.expectError(error.SumMalformed, expectedSum("abc  x.tar.gz\n", "x.tar.gz"));
    try testing.expectError(error.SumMalformed, expectedSum(@as([64]u8, @splat('z')) ++ "  x.tar.gz\n", "x.tar.gz"));
}

test "githubDigest" {
    const h = "0123456789abcdef" ++ "0123456789abcdef" ++ "0123456789abcdef" ++ "0123456789abcdef";
    try testing.expectEqualStrings(h, &hex(githubDigest("sha256:" ++ h).?));
    try testing.expectEqual(@as(?Digest, null), githubDigest("sha512:" ++ h));
    try testing.expectEqual(@as(?Digest, null), githubDigest("sha256:abc"));
}

test "extract: the one entry; others skipped; refusals" {
    const gpa = testing.allocator;
    const entry = "artoo-0.4.0-aarch64-macos/artoo";
    const good = try testArchive(gpa, &.{
        .{ .name = "artoo-0.4.0-aarch64-macos", .kind = .dir },
        .{ .name = "artoo-0.4.0-aarch64-macos/LICENSE", .data = "license", .mode = 0o644 },
        .{ .name = "../../artoo", .data = "evil" },
        .{ .name = "artoo-0.4.0-aarch64-macos/x", .data = "/etc/passwd", .kind = .link },
        .{ .name = entry, .data = "#!/bin/sh\necho artoo 0.4.0\n" },
        .{ .name = "artoo-0.4.0-aarch64-macos/README.md", .data = "readme", .mode = 0o644 },
    });
    defer gpa.free(good);
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try testing.expectEqual(@as(u64, 27), try extract(good, entry, &out.writer, 1 << 20));
    try testing.expectEqualStrings("#!/bin/sh\necho artoo 0.4.0\n", out.written());

    out.clearRetainingCapacity();
    try testing.expectError(error.EntryTooLarge, extract(good, entry, &out.writer, 8));
    try testing.expectError(error.EntryMissing, extract(good, "artoo-0.4.0-x86_64-linux/artoo", &out.writer, 1 << 20));
    try testing.expectError(error.EntryNotFile, extract(good, "artoo-0.4.0-aarch64-macos/x", &out.writer, 1 << 20));

    const twice = try testArchive(gpa, &.{ .{ .name = entry, .data = "a" }, .{ .name = entry, .data = "b" } });
    defer gpa.free(twice);
    try testing.expectError(error.EntryDuplicate, extract(twice, entry, &out.writer, 1 << 20));

    try testing.expectError(error.ArchiveMalformed, extract("not a gzip stream at all", entry, &out.writer, 1 << 20));
    try testing.expectError(error.ArchiveMalformed, extract(good[0 .. good.len / 2], entry, &out.writer, 1 << 20));
}
