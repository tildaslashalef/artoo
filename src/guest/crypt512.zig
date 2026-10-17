//! sha512-crypt (the `$6$` hash Proxmox's `cipassword` field accepts
//! unchanged) plus the per-guest password generation of SPEC §9.1.
//!
//! The plaintext never leaves the workstation: it is generated here into
//! caller-provided buffers, stored in the SecretStore (`guest/<name>`),
//! and only the hash is sent to Proxmox.
//!
//! Algorithm implemented against the SHA-crypt reference (Drepper),
//! rounds fixed at the default 5000 — the format artoo emits is always
//! `$6$<salt>$<hash>`. Ground truth: the test vectors below were produced
//! with `openssl passwd -6 -salt ...` on the workstation (2026-10-10).
//!
//! No allocator on the secret paths (fixed buffers in and out), entropy
//! through the explicit `Io`, no globals.

const std = @import("std");
const Io = std.Io;

/// b64 alphabet used by the crypt format ("./0-9A-Za-z", LSB-first).
const b64_alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Fixed intended password length (24 chars over a 54-char
/// ambiguity-free alphabet — about 138 bits). Long enough to type from a
/// keyring viewer to a console.
pub const password_len = 24;

/// Ambiguity-light alphabet (no `0/O/1/l/I` or `5/S` confusion pairs for
/// eyeball transcription from the keychain UI).
const password_alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// Salt length (16 is the crypt format maximum; full entropy).
pub const salt_len = 16;

/// Longest emitted hash string: "$6$" + 16 salt + "$" + 86 chars.
pub const hash_buf_len = 128;

const rounds: usize = 5000;

const Sha512 = std.crypto.hash.sha2.Sha512;

/// Fill `out[0..len]` with `len` <= password_len characters from the
/// unambiguous alphabet, CSPRNG-sourced with rejection sampling (no
/// modulo bias). `out` must be at least `len`; the uncovered part of the
/// buffer (caller-fixed) is the caller's to wipe.
pub fn generatePassword(io: Io, out: []u8, len: usize) error{ BufferTooSmall, EntropyUnavailable, Canceled }!void {
    if (len > out.len or len > password_buf_max) return error.BufferTooSmall;
    const alphabet = password_alphabet;
    // Reject raw bytes above the largest multiple of the alphabet size
    // (alphabet.len * k <= 256) so every character stays unbiased.
    const cutoff: u8 = @intCast(256 - (256 % alphabet.len));
    for (out[0..len]) |*ch| {
        while (true) {
            var raw: [1]u8 = undefined;
            try Io.randomSecure(io, &raw);
            if (raw[0] < cutoff) {
                ch.* = alphabet[raw[0] % alphabet.len];
                break;
            }
        }
    }
}

/// Generate a fresh crypt salt into `out[0..salt_len]`. Alphanumeric
/// only, so the `$6$salt$` framing stays unambiguous.
pub fn generateSalt(io: Io, out: []u8) error{ BufferTooSmall, EntropyUnavailable, Canceled }!void {
    if (salt_len > out.len) return error.BufferTooSmall;
    try generatePassword(io, out, salt_len);
}

/// Compute `$6$<salt>$<hash>` for `password` into `out`. Salt and
/// password may be arbitrary bytes (salt must not contain `$` per the
/// format; generated salts never do). The result carries no secret
/// plaintext, so it may legally travel through rendering and logging
/// paths without redaction. No allocation happens.
pub fn sha512Crypt(out: *[hash_buf_len]u8, password: []const u8, salt: []const u8) error{SaltTooLong}![]const u8 {
    if (salt.len > salt_len) return error.SaltTooLong;
    if (password.len > password_buf_max) return error.SaltTooLong;

    // --- steps 1-5: digest A, folded with digest B by password length.
    var a = Sha512.init(.{});
    a.update(password);
    a.update(salt);

    var bd = Sha512.init(.{});
    bd.update(password);
    bd.update(salt);
    bd.update(password);
    var b_digest: [64]u8 = undefined;
    bd.final(&b_digest);

    var cnt: usize = password.len;
    while (cnt >= 64) : (cnt -= 64) a.update(&b_digest);
    a.update(b_digest[0..cnt]);
    // Length bits (reference step 11): for i = password.len; i > 0;
    // i >>= 1 — a 1-bit adds digest B, a 0-bit adds the password.
    var i: usize = password.len;
    while (i > 0) : (i >>= 1) {
        if (i & 1 == 1) a.update(&b_digest) else a.update(password);
    }
    var prev: [64]u8 = undefined;
    a.final(&prev);

    // --- steps 13-20: DP/P and DS/S sequences. DP adds the whole
    // password once per character in it (step 14); DS adds the salt
    // `16 + A[0]` times (A[0] = first digest byte, unsigned) and never
    // consumes digest A itself (steps 17-18).
    var p_seq: [password_buf_max]u8 = undefined;
    var dp = Sha512.init(.{});
    for (0..password.len) |_| dp.update(password);
    var dp_digest: [64]u8 = undefined;
    dp.final(&dp_digest);
    fillSeq(&p_seq, password.len, &dp_digest);

    var s_seq: [salt_len]u8 = undefined;
    var ds = Sha512.init(.{});
    var times: usize = 16 + @as(usize, prev[0]);
    while (times > 0) : (times -= 1) ds.update(salt);
    var ds_digest: [64]u8 = undefined;
    ds.final(&ds_digest);
    fillSeq(&s_seq, salt.len, &ds_digest);

    // --- step 12: 5000 rounds. Even rounds open with the previous
    // digest, odd rounds with P; S when i % 3 != 0; P when i % 7 != 0;
    // the tail mirrors the head (prev on odd, P on even).
    for (0..rounds) |r| {
        var c = Sha512.init(.{});
        if (r % 2 == 1) {
            c.update(p_seq[0..password.len]);
        } else {
            c.update(&prev);
        }
        if (r % 3 != 0) c.update(s_seq[0..salt.len]);
        if (r % 7 != 0) c.update(p_seq[0..password.len]);
        if (r % 2 == 1) {
            c.update(&prev);
        } else {
            c.update(p_seq[0..password.len]);
        }
        c.final(&prev);
    }

    // "$6$<salt>$<encoded>" (LSB-first 6-bit groups over the reference
    // (b2,b1,b0) triplet permutation, then the 2-char group over
    // dig[63]) — the frame is built in a separate buffer because `out`
    // backs both the encode scratch and the destination.
    const triplets = [_][3]u8{
        .{ 0, 21, 42 },  .{ 22, 43, 1 },  .{ 44, 2, 23 },  .{ 3, 24, 45 },
        .{ 25, 46, 4 },  .{ 47, 5, 26 },  .{ 6, 27, 48 },  .{ 28, 49, 7 },
        .{ 50, 8, 29 },  .{ 9, 30, 51 },  .{ 31, 52, 10 }, .{ 53, 11, 32 },
        .{ 12, 33, 54 }, .{ 34, 55, 13 }, .{ 56, 14, 35 }, .{ 15, 36, 57 },
        .{ 37, 58, 16 }, .{ 59, 17, 38 }, .{ 18, 39, 60 }, .{ 40, 61, 19 },
        .{ 62, 20, 41 },
    };
    var encoded: [86]u8 = undefined;
    var enc: usize = 0;
    for (triplets) |t| {
        enc += emit24(&encoded, enc, prev[t[0]], prev[t[1]], prev[t[2]], 4);
    }
    // Final group: only dig[63] contributes; the `*` slots are the
    // literal zero byte value and only two characters are emitted.
    enc += emit24(&encoded, enc, 0, 0, prev[63], 2);
    var fixed = Io.Writer.fixed(out[0..hash_buf_len]);
    fixed.print("$6${s}${s}", .{ salt, encoded[0..enc] }) catch return error.SaltTooLong;
    return out[0..fixed.end];
}

/// crypt password lengths artoo ever hashes stay far below this.
const password_buf_max: usize = 256;

fn fillSeq(dst: []u8, want: usize, digest64: *const [64]u8) void {
    var written: usize = 0;
    while (written + 64 <= want) : (written += 64) {
        @memcpy(dst[written..][0..64], digest64);
    }
    if (written < want) {
        const rem = want - written;
        @memcpy(dst[written..][0..rem], digest64[0..rem]);
    }
}

fn emit24(out: []u8, off: usize, b2: u8, b1: u8, b0: u8, nchars: usize) usize {
    const wide: u32 = (@as(u32, b2) << 16) |
        (@as(u32, b1) << 8) |
        @as(u32, b0);
    for (0..nchars) |n| {
        const shift: u5 = @intCast(6 * n);
        const v: u8 = @intCast((wide >> shift) & 0x3f);
        out[off + n] = b64_alphabet[v];
    }
    return nchars;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "generatePassword: length, alphabet, variance" {
    const io = testing.io;
    var buf: [password_len]u8 = undefined;
    try generatePassword(io, &buf, password_len);
    for (buf) |c| {
        try testing.expect(std.mem.indexOfScalar(u8, password_alphabet, c) != null);
    }
    // Two generations differ with overwhelming probability (never equal
    // over 24 unbiased characters).
    var second: [password_len]u8 = undefined;
    try generatePassword(io, &second, password_len);
    try testing.expect(!std.mem.eql(u8, &buf, &second));
    try testing.expectError(error.BufferTooSmall, generatePassword(io, buf[0..4], password_len));
}

test "generateSalt: fixed length, sane alphabet" {
    var salt: [salt_len]u8 = undefined;
    try generateSalt(testing.io, &salt);
    for (salt) |c| {
        try testing.expect(std.mem.indexOfScalar(u8, password_alphabet, c) != null);
    }
    try testing.expect(std.mem.indexOfScalar(u8, &salt, '$') == null);
}

fn cryptEqual(password: []const u8, salt: []const u8, expected: []const u8) !void {
    var out: [hash_buf_len]u8 = undefined;
    const got = try sha512Crypt(&out, password, salt);
    try testing.expectEqualStrings(expected, got);
    // Deterministic: same inputs produce the identical hash.
    var out2: [hash_buf_len]u8 = undefined;
    const again = try sha512Crypt(&out2, password, salt);
    try testing.expectEqualStrings(expected, again);
}

// Reference vectors generated with `openssl passwd -6 -salt <salt>
// -stdin` on the workstation (2026-10-10). The first is also the
// canonical SHA-crypt document vector.
test "sha512Crypt matches openssl/SHA-crypt reference vectors" {
    try cryptEqual(
        "Hello world!",
        "saltstring",
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
    );
    try cryptEqual(
        "foo",
        "-barsic",
        "$6$-barsic$mRjDvoueMj3O7U/p51Ty.Gn30YNbak7oZxPZCoNuODQIwMnfmOijTTLs01TosxWuFUcvG8KbSk0L2Kg0BLfE01",
    );
    try cryptEqual(
        "a-much-longer-password-for-rounding-tests",
        "saltsalt",
        "$6$saltsalt$XeyMvE.7nWr/SWNU0yuly9QhcHFoK/rV8npFP5zUEhQDvLlzTEvSF6yPcH2PgzQ.A8ywGbmsreXbGSMwMRZ83/",
    );
}

test "sha512Crypt block-boundary vectors (63/64/65-byte passwords)" {
    var pw64: [64]u8 = @splat('p');
    try cryptEqual(&pw64, "sixtyfour", "$6$sixtyfour$Ki6W/j4NuUS3M6H8mKcS5IqlgI6czBjbIyo76RLpCEnmBwLl/6bFuu.HX/ZbKUZD69mJRUnNLiUqUhAK7ZhNA.");
    var pw63: [63]u8 = @splat('q');
    try cryptEqual(&pw63, "sixtythree", "$6$sixtythree$ItnmYNzj6Y1KbPj1cMR2Gnspq0KkXg4mZUeK7kROiOqiOtuk8IZp2R5AnskRuNo6Jz64944k7EaSz4TKN7NNY/");
    var pw65: [65]u8 = @splat('r');
    try cryptEqual(&pw65, "sixtyfive", "$6$sixtyfive$obIYD.9X0ba6BC8cPmjF8D5iU3bwVpe4C006CN47cQKq67sXlTPYfzyttxImVLu8IiaDydknQ4W.0.46w31yI/");
}

test "sha512Crypt: 16-char salt, dollar-in-password" {
    try cryptEqual(
        "pw-with-$6-dollar-and./slash",
        "0123456789abcdef",
        "$6$0123456789abcdef$vPj2sOSXrcQQ6Pb0cIMq4R3EGaHitNug41/AtH/Sn5JuvDgLZZAkXN8gHgt2vwQdZQlQnD8h.y96lGdf/9ODv.",
    );
}

test "sha512Crypt: output framing and length" {
    var hash_buf: [hash_buf_len]u8 = undefined;
    var salt: [salt_len]u8 = undefined;
    try generateSalt(testing.io, &salt);
    const got = try sha512Crypt(&hash_buf, "some-password", &salt);
    // Framing: "$6$" + salt + "$" + 86 encoded chars.
    try testing.expect(std.mem.startsWith(u8, got, "$6$"));
    const after_marker = got["$6$".len..];
    try testing.expect(std.mem.startsWith(u8, after_marker, &salt));
    try testing.expectEqual(@as(usize, 86), got.len - "$6$".len - salt.len - 1);
}
