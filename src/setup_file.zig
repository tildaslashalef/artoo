//! The encrypted setup file of `config export|import` (SPEC §6.1): a
//! passphrase-sealed copy of the config, the CA bundles and the API
//! credentials, so artoo can be set up on another machine.
//!
//! Binary layout, ASCII-armored (base64 between BEGIN/END lines):
//!
//!     magic "artoo-setup\x00" (12) | version 1 (1) | Argon2id t (u32 LE)
//!     | m KiB (u32 LE) | p = 1 (1) | salt (16) | nonce (24)
//!     | XChaCha20-Poly1305 ciphertext | tag (16)
//!
//! The key is Argon2id(passphrase, salt); the header is the associated
//! data, so a changed parameter fails like a wrong passphrase. Parameters
//! read from a file are bounded before any work is done.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const argon2 = std.crypto.pwhash.argon2;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const Params = struct {
    t: u32,
    m_kib: u32,
};

/// 64 MiB, 3 passes, one lane: a few hundred milliseconds per attempt on
/// a laptop and within reach of a 1 GiB guest.
pub const default_params: Params = .{ .t = 3, .m_kib = 64 * 1024 };

pub const min_passphrase = 12;
pub const max_passphrase = 1024;

const magic = "artoo-setup\x00";
const version = 1;
const salt_len = 16;
const header_len = magic.len + 1 + 4 + 4 + 1 + salt_len + Aead.nonce_length;
const begin = "-----BEGIN ARTOO SETUP-----";
const end = "-----END ARTOO SETUP-----";

pub const Error = error{
    /// Not an artoo setup file (no armor, bad base64, wrong magic).
    NotSetupFile,
    /// A newer or unknown format version.
    UnsupportedVersion,
    /// Parameters outside the accepted bounds.
    BadParameters,
    /// Wrong passphrase or a changed file: authentication failed.
    Unauthenticated,
} || Allocator.Error;

/// Seal `plaintext` under `passphrase`; returns the armored text.
pub fn seal(arena: Allocator, io: Io, plaintext: []const u8, passphrase: []const u8, params: Params) Error![]const u8 {
    var header: [header_len]u8 = undefined;
    @memcpy(header[0..magic.len], magic);
    header[magic.len] = version;
    std.mem.writeInt(u32, header[magic.len + 1 ..][0..4], params.t, .little);
    std.mem.writeInt(u32, header[magic.len + 5 ..][0..4], params.m_kib, .little);
    header[magic.len + 9] = 1;
    const salt = header[magic.len + 10 ..][0..salt_len];
    const nonce = header[magic.len + 10 + salt_len ..][0..Aead.nonce_length];
    io.random(salt);
    io.random(nonce);

    var key: [Aead.key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try derive(arena, io, &key, passphrase, salt, params);

    const bin = try arena.alloc(u8, header_len + plaintext.len + Aead.tag_length);
    @memcpy(bin[0..header_len], &header);
    Aead.encrypt(bin[header_len..][0..plaintext.len], bin[header_len + plaintext.len ..][0..Aead.tag_length], plaintext, &header, nonce.*, key);
    return armor(arena, bin);
}

/// Open an armored setup file; the plaintext, or why not.
pub fn open(arena: Allocator, io: Io, text: []const u8, passphrase: []const u8) Error![]const u8 {
    const bin = try unarmor(arena, text);
    if (bin.len < header_len + Aead.tag_length or !std.mem.eql(u8, bin[0..magic.len], magic)) return error.NotSetupFile;
    if (bin[magic.len] != version) return error.UnsupportedVersion;
    const header = bin[0..header_len];
    const params: Params = .{
        .t = std.mem.readInt(u32, header[magic.len + 1 ..][0..4], .little),
        .m_kib = std.mem.readInt(u32, header[magic.len + 5 ..][0..4], .little),
    };
    if (header[magic.len + 9] != 1 or !boundedParams(params)) return error.BadParameters;
    const salt = header[magic.len + 10 ..][0..salt_len];
    const nonce = header[magic.len + 10 + salt_len ..][0..Aead.nonce_length];

    var key: [Aead.key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    try derive(arena, io, &key, passphrase, salt, params);

    const body = bin[header_len..];
    const ct = body[0 .. body.len - Aead.tag_length];
    const out = try arena.alloc(u8, ct.len);
    Aead.decrypt(out, ct, body[ct.len..][0..Aead.tag_length].*, header, nonce.*, key) catch return error.Unauthenticated;
    return out;
}

/// Accepted when reading: 1–10 passes, 8 KiB – 1 GiB.
fn boundedParams(p: Params) bool {
    return p.t >= 1 and p.t <= 10 and p.m_kib >= 8 and p.m_kib <= 1024 * 1024;
}

fn derive(arena: Allocator, io: Io, key: *[Aead.key_length]u8, passphrase: []const u8, salt: []const u8, params: Params) Error!void {
    argon2.kdf(arena, key, passphrase, salt, .{ .t = params.t, .m = params.m_kib, .p = 1 }, .argon2id, io) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadParameters,
    };
}

fn armor(arena: Allocator, bin: []const u8) Allocator.Error![]const u8 {
    const enc = std.base64.standard.Encoder;
    const b64 = try arena.alloc(u8, enc.calcSize(bin.len));
    _ = enc.encode(b64, bin);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, begin ++ "\n");
    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        try out.appendSlice(arena, b64[i..@min(i + 64, b64.len)]);
        try out.append(arena, '\n');
    }
    try out.appendSlice(arena, end ++ "\n");
    return out.items;
}

fn unarmor(arena: Allocator, text: []const u8) Error![]u8 {
    const b = std.mem.find(u8, text, begin) orelse return error.NotSetupFile;
    const rest = text[b + begin.len ..];
    const e = std.mem.find(u8, rest, end) orelse return error.NotSetupFile;
    const dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const out = try arena.alloc(u8, dec.calcSizeUpperBound(e));
    const n = dec.decode(out, rest[0..e]) catch return error.NotSetupFile;
    return out[0..n];
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const fast: Params = .{ .t = 1, .m_kib = 64 };

test "seal/open round trip; armor shape" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text = try seal(a, testing.io, "{\"schema\":1}", "correct horse battery", fast);
    try testing.expect(std.mem.startsWith(u8, text, begin ++ "\n"));
    try testing.expect(std.mem.endsWith(u8, text, "\n" ++ end ++ "\n"));
    try testing.expect(std.mem.find(u8, text, "schema") == null);
    try testing.expectEqualStrings("{\"schema\":1}", try open(a, testing.io, text, "correct horse battery"));
    // Fresh salt and nonce every time.
    try testing.expect(!std.mem.eql(u8, text, try seal(a, testing.io, "{\"schema\":1}", "correct horse battery", fast)));
}

test "wrong passphrase, tampering, bounds and junk are refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const text = try seal(a, testing.io, "secret payload", "correct horse battery", fast);
    try testing.expectError(error.Unauthenticated, open(a, testing.io, text, "correct horse batterY"));

    const bin = try unarmor(a, text);
    // A changed header byte (the salt) is authenticated data.
    bin[magic.len + 12] ^= 1;
    try testing.expectError(error.Unauthenticated, open(a, testing.io, try armor(a, bin), "correct horse battery"));
    bin[magic.len + 12] ^= 1;
    // A changed ciphertext byte.
    bin[header_len] ^= 1;
    try testing.expectError(error.Unauthenticated, open(a, testing.io, try armor(a, bin), "correct horse battery"));
    bin[header_len] ^= 1;
    // Absurd memory: refused before any work.
    std.mem.writeInt(u32, bin[magic.len + 5 ..][0..4], 64 * 1024 * 1024, .little);
    try testing.expectError(error.BadParameters, open(a, testing.io, try armor(a, bin), "correct horse battery"));
    bin[magic.len] = 2;
    try testing.expectError(error.UnsupportedVersion, open(a, testing.io, try armor(a, bin), "x"));

    try testing.expectError(error.NotSetupFile, open(a, testing.io, "hello", "x"));
    try testing.expectError(error.NotSetupFile, open(a, testing.io, begin ++ "\n!!!\n" ++ end, "x"));
    try testing.expectError(error.NotSetupFile, open(a, testing.io, begin ++ "\nYWJj\n" ++ end, "x"));
}
