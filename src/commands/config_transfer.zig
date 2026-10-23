//! `artoo config export|import` (SPEC §6.1): carry artoo's setup — the
//! config file, the CA bundles it names and the API credentials — to
//! another Mac or Linux machine in one passphrase-sealed file. Guest
//! passwords and SSH keys never travel; secret values are never shown.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const config = @import("../config.zig");
const files = @import("../files.zig");
const prompt = @import("../prompt.zig");
const secrets = @import("../secrets.zig");
const setup_file = @import("../setup_file.zig");
const ui = @import("../ui.zig");

const Context = app.Context;

/// The credentials that travel (`guest/<name>` passwords do not).
const credential_names = [_][]const u8{ "pve", "unifi", "cloudflare" };

/// The sealed payload.
const Bundle = struct {
    schema: u32 = 1,
    /// `$HOME` of the exporting machine: paths under it are rehomed.
    home: []const u8,
    config: []const u8,
    ca: []const Ca = &.{},
    secrets: []const Secret = &.{},

    const Ca = struct { path: []const u8, pem: []const u8 };
    const Secret = struct { name: []const u8, value: []const u8 };
};

const file_limit = 1 << 20;

pub const export_cmd = struct {
    pub const name = "export";
    pub const summary = "Write artoo's setup to an encrypted file (config, CA, credentials)";
    pub const details =
        \\Seals the config file, the CA bundles it names (pve.ca_bundle,
        \\unifi.ca_bundle) and the stored pve, unifi and cloudflare
        \\credentials into FILE under a passphrase (Argon2id, 64 MiB;
        \\XChaCha20-Poly1305), for 'artoo config import' on another Mac or
        \\Linux machine. Guest passwords and SSH keys are not included. The
        \\passphrase comes from a hidden prompt (asked twice) or the first
        \\line of --stdin; at least 12 characters. FILE is written with mode
        \\0600 and opened again to check it. Anyone with FILE and the
        \\passphrase holds your lab credentials: delete it after importing.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "FILE", .help = "Output file (e.g. ~/artoo-setup.txt)" }};
    pub const flags = [_]cli.Flag{
        .{ .long = "stdin", .help = "Read the passphrase from standard input" },
        .{ .long = "force", .help = "Replace an existing FILE" },
    };
    pub const examples = [_][]const u8{
        "artoo config export ~/artoo-setup.txt",
        "artoo config export -n ~/artoo-setup.txt",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const a = ctx.arena;
        const l = try loadedConfig(ctx);
        if (!l.exists) return ctx.fail(error.ConfigMissing, "no config file at {s} to export; create one with 'artoo config init'", .{ctx.tilde(l.path)});
        const out = try home(ctx, args.pos("FILE"));
        if (!args.has("force") and try files.exists(ctx.io, out))
            return ctx.fail(error.Refused, "{s} already exists; choose another name or add --force", .{ctx.tilde(out)});

        const store = try ctx.secretStore();
        const where = store.describe(a);
        var cas: std.ArrayList(Bundle.Ca) = .empty;
        var creds: std.ArrayList(Bundle.Secret) = .empty;
        var fields: std.ArrayList(ui.blocks.Field) = .empty;
        try fields.append(a, .{ .key = "config", .value = ctx.tilde(l.path) });
        var seen: std.ArrayList([]const u8) = .empty;
        for (try caPaths(a, &l.config)) |p| {
            const full = try home(ctx, p);
            if (contains(seen.items, full)) continue;
            try seen.append(a, full);
            const pem = Io.Dir.cwd().readFileAlloc(ctx.io, full, a, .limited(file_limit)) catch {
                try fields.append(a, .{ .key = "CA bundle", .value = try std.fmt.allocPrint(a, "{s} (missing, not included)", .{ctx.tilde(full)}), .role = .warn });
                continue;
            };
            try cas.append(a, .{ .path = p, .pem = pem });
            try fields.append(a, .{ .key = "CA bundle", .value = ctx.tilde(full) });
        }
        for (credential_names) |n| {
            const v = store.get(ctx.io, a, n) catch |err| return storeError(ctx, err, where);
            if (v) |secret| {
                try creds.append(a, .{ .name = n, .value = secret });
                try fields.append(a, .{ .key = n, .value = "credential" });
            } else try fields.append(a, .{ .key = n, .value = "not stored, not included", .role = .muted });
        }
        try fields.append(a, .{ .key = "file", .value = try std.fmt.allocPrint(a, "{s} (0600, passphrase-sealed)", .{ctx.tilde(out)}), .role = .changed });
        try plan(ctx, "config export", where, fields.items, &.{
            "Not included: guest passwords, SSH keys.",
            "Anyone with the file and the passphrase holds these credentials; delete it after importing.",
        });

        if (ctx.globals.dry_run) return ctx.out.writeAll("Dry run: nothing written.\n");
        try ctx.confirm("Write the encrypted setup to {s}?", .{ctx.tilde(out)});
        const pass = try passphrase(ctx, args.has("stdin"), true);

        const bundle: Bundle = .{
            .home = ctx.env.get("HOME") orelse "",
            .config = try Io.Dir.cwd().readFileAlloc(ctx.io, l.path, a, .limited(file_limit)),
            .ca = cas.items,
            .secrets = creds.items,
        };
        const plain = try std.json.Stringify.valueAlloc(a, bundle, .{});
        const params: setup_file.Params = if (ctx.test_hooks.kdf_kib) |m| .{ .t = 1, .m_kib = m } else setup_file.default_params;
        const sealed = try setup_file.seal(a, ctx.io, plain, pass, params);
        try writeFile(ctx, out, sealed, true);
        // Opened again: the file on disk must give back what was sealed.
        const back = try Io.Dir.cwd().readFileAlloc(ctx.io, out, a, .limited(file_limit));
        const reopened = setup_file.open(a, ctx.io, back, pass) catch
            return ctx.fail(error.Partial, "{s} was written but does not open again; do not rely on it", .{ctx.tilde(out)});
        if (!std.mem.eql(u8, reopened, plain))
            return ctx.fail(error.Partial, "{s} was written but reads back differently; do not rely on it", .{ctx.tilde(out)});
        try ctx.out.print("Wrote {s}: config, {d} CA bundle(s), {d} credential(s); checked.\nOn the other machine: 'artoo config import {s}'.\n", .{
            ctx.tilde(out), bundle.ca.len, bundle.secrets.len, ctx.tilde(out),
        });
    }
};

pub const import_cmd = struct {
    pub const name = "import";
    pub const summary = "Set artoo up from a file written by 'config export'";
    pub const details =
        \\Opens FILE with its passphrase (hidden prompt or --stdin) and
        \\installs the config file, its CA bundles and the credentials into
        \\this machine's secret store (credentials.store). Paths under the
        \\exporting machine's home move to this home; a store this system
        \\lacks (keychain off macOS, secret-service on macOS) becomes auto.
        \\Each item is new, same (skipped) or different; replacing anything
        \\different needs --force. SSH keys are this machine's own: set
        \\guests.ssh_public_key and pve.ssh_identity, then 'artoo doctor
        \\--connect'.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "FILE", .help = "File from 'artoo config export'" }};
    pub const flags = [_]cli.Flag{
        .{ .long = "stdin", .help = "Read the passphrase from standard input" },
        .{ .long = "force", .help = "Replace a different config, CA bundle or credential" },
    };
    pub const examples = [_][]const u8{
        "artoo config import ~/artoo-setup.txt",
        "artoo config import -n ~/artoo-setup.txt",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const a = ctx.arena;
        const in = try home(ctx, args.pos("FILE"));
        const text = Io.Dir.cwd().readFileAlloc(ctx.io, in, a, .limited(file_limit)) catch
            return ctx.fail(error.NotFound, "cannot read {s}", .{ctx.tilde(in)});
        const pass = try passphrase(ctx, args.has("stdin"), false);
        const plain = setup_file.open(a, ctx.io, text, pass) catch |err| return switch (err) {
            error.OutOfMemory => |e| e,
            error.Unauthenticated => ctx.fail(error.Refused, "wrong passphrase, or {s} was changed", .{ctx.tilde(in)}),
            error.UnsupportedVersion => ctx.fail(error.Usage, "{s} needs a newer artoo", .{ctx.tilde(in)}),
            else => ctx.fail(error.Usage, "{s} is not an artoo setup file", .{ctx.tilde(in)}),
        };
        const bundle = std.json.parseFromSliceLeaky(Bundle, a, plain, .{ .ignore_unknown_fields = true }) catch
            return ctx.fail(error.Usage, "{s} opened, but its contents are not understood", .{ctx.tilde(in)});
        if (bundle.schema != 1) return ctx.fail(error.Usage, "{s} needs a newer artoo", .{ctx.tilde(in)});

        var notes: std.ArrayList([]const u8) = .empty;
        const adapted = try adapt(ctx, bundle, &notes);
        const cfg_path = switch (ctx.loaded) {
            .ok => |l| l.path,
            .failed => try config.resolvePath(a, ctx.env, ctx.globals.config),
        };

        var fields: std.ArrayList(ui.blocks.Field) = .empty;
        var changes: usize = 0;
        var different: std.ArrayList([]const u8) = .empty;
        const cfg_state = try compareFile(ctx, cfg_path, adapted.text);
        try note(ctx, &fields, "config", ctx.tilde(cfg_path), cfg_state, &changes, &different);
        var ca_targets: std.ArrayList([]const u8) = .empty;
        for (bundle.ca) |c| {
            const p = try home(ctx, try rehome(a, c.path, bundle.home));
            try ca_targets.append(a, p);
            try note(ctx, &fields, "CA bundle", ctx.tilde(p), try compareFile(ctx, p, c.pem), &changes, &different);
        }
        const store = try storeFor(ctx, adapted.store);
        const where = store.describe(a);
        for (bundle.secrets) |s| {
            if (!isCredential(s.name) or !secrets.validSecret(s.value))
                return ctx.fail(error.Usage, "{s} holds an unexpected entry '{s}'", .{ ctx.tilde(in), s.name });
            const have = store.get(ctx.io, a, s.name) catch |err| return storeError(ctx, err, where);
            const st: State = if (have == null) .new else if (std.mem.eql(u8, have.?, s.value)) .same else .different;
            try note(ctx, &fields, s.name, where, st, &changes, &different);
        }
        try plan(ctx, "config import", ctx.tilde(in), fields.items, notes.items);

        if (changes == 0) return ctx.out.writeAll("This machine already has this setup; nothing to do.\n");
        if (different.items.len > 0 and !args.has("force"))
            return ctx.fail(error.Refused, "{s} differ on this machine; re-run with --force to replace them", .{try std.mem.join(a, ", ", different.items)});
        if (ctx.globals.dry_run) return ctx.out.writeAll("Dry run: nothing written.\n");
        try ctx.confirm("Install this setup on this machine?", .{});

        for (bundle.ca, ca_targets.items) |c, p| {
            if (try compareFile(ctx, p, c.pem) == .same) continue;
            const dir = std.fs.path.dirname(p) orelse ".";
            Io.Dir.cwd().createDirPath(ctx.io, dir) catch return ctx.fail(error.Partial, "cannot create {s}", .{ctx.tilde(dir)});
            try writeFile(ctx, p, c.pem, false);
        }
        if (cfg_state != .same) try writeFile(ctx, cfg_path, adapted.text, false);
        for (bundle.secrets) |s| {
            const have = store.get(ctx.io, a, s.name) catch |err| return storeError(ctx, err, where);
            if (have != null and std.mem.eql(u8, have.?, s.value)) continue;
            store.set(ctx.io, a, s.name, s.value) catch |err| return storeError(ctx, err, where);
        }
        try ctx.out.print(
            \\Installed {d} item(s).
            \\Next on this machine: an SSH key of its own (guests.ssh_public_key,
            \\pve.ssh_identity), added to root's authorized_keys on Proxmox and to
            \\guests.extra_ssh_keys on your main machine; then 'artoo doctor --connect'.
            \\Delete {s} once you no longer need it.
            \\
        , .{ changes, ctx.tilde(in) });
    }
};

const State = enum { new, same, different };

fn note(ctx: *Context, fields: *std.ArrayList(ui.blocks.Field), key: []const u8, where: []const u8, st: State, changes: *usize, different: *std.ArrayList([]const u8)) !void {
    if (st != .same) changes.* += 1;
    if (st == .different) try different.append(ctx.arena, key);
    try fields.append(ctx.arena, .{
        .key = key,
        .value = try std.fmt.allocPrint(ctx.arena, "{t}  {s}", .{ st, where }),
        .role = switch (st) {
            .new => .changed,
            .same => .muted,
            .different => .warn,
        },
    });
}

fn compareFile(ctx: *Context, path: []const u8, want: []const u8) !State {
    const have = Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(file_limit)) catch |err| switch (err) {
        error.FileNotFound => return .new,
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return .different,
    };
    return if (std.mem.eql(u8, have, want)) .same else .different;
}

const Adapted = struct { text: []const u8, store: config.Store };

/// The bundle's config made fit for this machine: valid, paths under the
/// old home rehomed, a store this system lacks replaced by `auto`.
fn adapt(ctx: *Context, b: Bundle, notes: *std.ArrayList([]const u8)) !Adapted {
    const a = ctx.arena;
    var msg: []const u8 = "";
    var l = config.parse(a, b.config, &msg) catch |err| switch (err) {
        error.ConfigInvalid => return ctx.fail(error.ConfigInvalid, "the exported config is not valid here: {s}", .{msg}),
        else => |e| return e,
    };
    var text = b.config;
    for (config.keys) |k| {
        if (k.check != .path and k.check != .path_list) continue;
        if (!l.explicit(k.name)) continue;
        const before = (try config.get(&l.config, a, k.name)).?;
        const after = try rehomeList(a, before, b.home);
        if (std.mem.eql(u8, before, after)) continue;
        text = try config.edit(a, &l.tree, k.name, .{ .string = after });
        _ = try config.assign(&l.config, a, k.name, .{ .string = after }, &msg);
        try notes.append(a, try std.fmt.allocPrint(a, "{s}: {s} → {s}", .{ k.name, before, after }));
    }
    var store = l.config.credentials.store;
    if (!storeAvailableHere(store, builtin.os.tag.isDarwin())) {
        try notes.append(a, try std.fmt.allocPrint(a, "credentials.store: {t} is not available on this system → auto", .{store}));
        text = try config.edit(a, &l.tree, "credentials.store", .{ .string = "auto" });
        store = .auto;
    }
    return .{ .text = text, .store = store };
}

fn storeAvailableHere(s: config.Store, is_mac: bool) bool {
    return switch (s) {
        .auto, .file => true,
        .keychain => is_mac,
        .@"secret-service" => !is_mac,
    };
}

/// `/Users/me/x` with old home `/Users/me` → `~/x`; anything else unchanged.
fn rehome(a: Allocator, path: []const u8, old_home: []const u8) ![]const u8 {
    if (old_home.len == 0) return path;
    const rest = std.mem.cutPrefix(u8, path, old_home) orelse return path;
    if (rest.len == 0 or rest[0] != '/') return path;
    return std.fmt.allocPrint(a, "~{s}", .{rest});
}

fn rehomeList(a: Allocator, value: []const u8, old_home: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, value, ',');
    var first = true;
    while (it.next()) |raw| {
        if (!first) try out.append(a, ',');
        first = false;
        const lead = raw.len - std.mem.trimStart(u8, raw, " ").len;
        try out.appendSlice(a, raw[0..lead]);
        try out.appendSlice(a, try rehome(a, std.mem.trim(u8, raw, " "), old_home));
    }
    return out.items;
}

fn caPaths(a: Allocator, cfg: *const config.Config) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ cfg.pve.ca_bundle, cfg.unifi.ca_bundle }) |p| {
        for (out.items) |seen| {
            if (std.mem.eql(u8, seen, p)) break;
        } else try out.append(a, p);
    }
    return out.items;
}

fn isCredential(n: []const u8) bool {
    return contains(&credential_names, n);
}

fn contains(list: []const []const u8, s: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

fn loadedConfig(ctx: *Context) !*config.Loaded {
    return switch (ctx.loaded) {
        .ok => |*l| l,
        .failed => |f| ctx.fail(f.err, "{s}", .{f.message}),
    };
}

fn home(ctx: *Context, path: []const u8) ![]const u8 {
    return files.expandHome(ctx.arena, ctx.env, path) catch ctx.fail(error.ConfigInvalid, "HOME is not set; cannot resolve {s}", .{path});
}

/// The store the imported config selects (tests inject one).
fn storeFor(ctx: *Context, choice: config.Store) !secrets.Store {
    if (ctx.store_override) |s| return s;
    return secrets.open(ctx.io, ctx.arena, ctx.env, choice, .{}) catch |err| switch (err) {
        error.SecretStoreUnavailable => ctx.fail(error.SecretStoreUnavailable, "secret store '{t}' is not available on this system", .{choice}),
        error.HomeUnknown => ctx.fail(error.SecretStoreUnavailable, "HOME is not set; cannot locate the secrets file", .{}),
        else => |e| e,
    };
}

fn passphrase(ctx: *Context, from_stdin: bool, twice: bool) ![]const u8 {
    const pass = if (from_stdin) blk: {
        const all = try prompt.readAll(ctx.input, ctx.io, ctx.arena, setup_file.max_passphrase + 2);
        break :blk all[0 .. std.mem.findScalar(u8, all, '\n') orelse all.len];
    } else blk: {
        if (!try prompt.interactive(ctx.input, ctx.io))
            return ctx.fail(error.NonInteractive, "not a terminal: pipe the passphrase with --stdin", .{});
        const p = try prompt.askHidden(ctx.input, ctx.io, ctx.arena, ctx.err, "Passphrase");
        if (twice) {
            const again = try prompt.askHidden(ctx.input, ctx.io, ctx.arena, ctx.err, "Passphrase again");
            if (!std.mem.eql(u8, p, again)) return ctx.fail(error.Usage, "the passphrases differ; nothing written", .{});
        }
        break :blk p;
    };
    if (twice and pass.len < setup_file.min_passphrase)
        return ctx.fail(error.Usage, "the passphrase needs at least {d} characters", .{setup_file.min_passphrase});
    if (pass.len == 0 or pass.len > setup_file.max_passphrase)
        return ctx.fail(error.Usage, "the passphrase must be 1-{d} characters", .{setup_file.max_passphrase});
    return pass;
}

fn plan(ctx: *Context, what: []const u8, right: []const u8, fields: []const ui.blocks.Field, notes: []const []const u8) !void {
    const u = &ctx.ui;
    try ui.blocks.header(ctx.out, u, what, right);
    try ui.blocks.detail(ctx.out, u, &.{.{ .fields = fields }});
    for (notes) |n| try ctx.out.print("{s}{s}{s}\n", .{ u.palette.on(.muted), n, u.palette.off(.muted) });
    try ctx.out.writeAll("\n");
}

/// Atomic 0600 write. The export's lock file is removed afterwards (FILE
/// may sit in a shared directory such as ~/Downloads); artoo's own files
/// keep theirs, like 'config set'.
fn writeFile(ctx: *Context, path: []const u8, bytes: []const u8, drop_lock: bool) !void {
    files.atomicWrite(ctx.io, ctx.arena, path, bytes) catch |err| switch (err) {
        error.UnsafePath => return ctx.fail(error.UnsafePath, "refusing to write {s}: it is a symlink", .{ctx.tilde(path)}),
        else => |e| return ctx.fail(e, "cannot write {s} ({s})", .{ ctx.tilde(path), @errorName(e) }),
    };
    if (drop_lock) Io.Dir.cwd().deleteFile(ctx.io, try std.fmt.allocPrint(ctx.arena, "{s}.lock", .{path})) catch {};
}

fn storeError(ctx: *Context, err: anyerror, where: []const u8) anyerror {
    return switch (err) {
        error.UnsafePath => ctx.fail(error.UnsafePath, "refusing {s}: it must be a regular file owned by you with mode 0600 (not a symlink)", .{where}),
        error.SecretStoreUnavailable => ctx.fail(error.SecretStoreUnavailable, "{s} did not answer as expected", .{where}),
        else => err,
    };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;
const Harness = @import("../testkit.zig").Harness;
const root = cli.group("artoo", "test", &.{@import("config.zig").group});

test "rehome and stores per system" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("~/.artoo/tls/rootCA.pem", try rehome(a, "/Users/me/.artoo/tls/rootCA.pem", "/Users/me"));
    try testing.expectEqualStrings("/Users/meg/x", try rehome(a, "/Users/meg/x", "/Users/me"));
    try testing.expectEqualStrings("~/k.pub", try rehome(a, "~/k.pub", "/Users/me"));
    try testing.expectEqualStrings("/etc/ca.pem", try rehome(a, "/etc/ca.pem", ""));
    try testing.expectEqualStrings("~/a.pub, ~/b.pub,/opt/c.pub", try rehomeList(a, "/Users/me/a.pub, ~/b.pub,/opt/c.pub", "/Users/me"));
    try testing.expect(storeAvailableHere(.keychain, true));
    try testing.expect(!storeAvailableHere(.keychain, false));
    try testing.expect(!storeAvailableHere(.@"secret-service", true));
    try testing.expect(storeAvailableHere(.file, false));
}

fn tmpHome(h: *Harness, tmp: *testing.TmpDir) ![]const u8 {
    const p = try tmp.dir.realPathFileAlloc(testing.io, ".", h.arena.allocator());
    try h.env.put("HOME", p);
    return p;
}

test "config export then import on another machine: rehomed, same skipped, different needs --force" {
    const ca = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const pass = "correct horse battery\n";

    // The exporting machine.
    var h1 = try Harness.init();
    defer h1.deinit();
    var t1 = testing.tmpDir(.{});
    defer t1.cleanup();
    const home1 = try tmpHome(&h1, &t1);
    var mem1: secrets.Memory = .{ .gpa = h1.arena.allocator() };
    try mem1.map.put(h1.arena.allocator(), "pve", "pve-secret-value");
    try mem1.map.put(h1.arena.allocator(), "unifi", "unifi-key-value");
    try mem1.map.put(h1.arena.allocator(), "guest/naboo", "never-exported");
    h1.store = .{ .memory = &mem1 };
    h1.hooks.kdf_kib = 64;
    var s1: prompt.Script = .{ .interactive = false, .piped = pass };
    h1.input = .{ .script = &s1 };
    try t1.dir.createDirPath(testing.io, ".artoo/tls");
    try t1.dir.writeFile(testing.io, .{ .sub_path = ".artoo/tls/rootCA.pem", .data = ca });
    try t1.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = try std.fmt.allocPrint(h1.arena.allocator(),
        \\{{"schema_version":1,"credentials":{{"store":"keychain"}},"pve":{{"ca_bundle":"{s}/.artoo/tls/rootCA.pem"}},"unifi":{{"ca_bundle":"~/.artoo/tls/rootCA.pem"}}}}
        \\
    , .{home1}) });

    try testing.expectEqual(.ok, h1.run(&root, "config export -n ~/setup.txt"));
    try testing.expect(!(try files.exists(testing.io, try std.fmt.allocPrint(h1.arena.allocator(), "{s}/setup.txt", .{home1}))));
    try testing.expectEqual(.refused, h1.run(&root, "config export ~/setup.txt --stdin"));
    try testing.expectEqual(.ok, h1.run(&root, "config export ~/setup.txt --stdin -y"));
    const out1 = h1.stdout();
    for ([_][]const u8{ "config      ~/.artoo/config.json", "pve         credential", "cloudflare  not stored", "Wrote ~/setup.txt: config, 1 CA bundle(s), 2 credential(s); checked." }) |want| {
        if (std.mem.find(u8, out1, want) == null) {
            std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ want, out1 });
            return error.TestUnexpectedResult;
        }
    }
    const sealed = try t1.dir.readFileAlloc(testing.io, "setup.txt", h1.arena.allocator(), .limited(1 << 20));
    for ([_][]const u8{ "pve-secret-value", "unifi-key-value", "never-exported", "MIIB" }) |bad| try testing.expect(std.mem.find(u8, sealed, bad) == null);
    try testing.expect(!(try files.exists(testing.io, try std.fmt.allocPrint(h1.arena.allocator(), "{s}/setup.txt.lock", .{home1}))));
    const st = try t1.dir.statFile(testing.io, "setup.txt", .{});
    try testing.expectEqual(@as(u32, 0o600), @as(u32, @intCast(st.permissions.toMode() & 0o777)));
    try testing.expectEqual(.refused, h1.run(&root, "config export ~/setup.txt --stdin -y"));
    s1 = .{ .interactive = false, .piped = "too short\n" };
    try testing.expectEqual(.usage, h1.run(&root, "config export ~/setup.txt --stdin -y --force"));

    // The importing machine: another home, an empty store.
    var h2 = try Harness.init();
    defer h2.deinit();
    var t2 = testing.tmpDir(.{});
    defer t2.cleanup();
    _ = try tmpHome(&h2, &t2);
    var mem2: secrets.Memory = .{ .gpa = h2.arena.allocator() };
    h2.store = .{ .memory = &mem2 };
    var s2: prompt.Script = .{ .interactive = false, .piped = "wrong passphrase!\n" };
    h2.input = .{ .script = &s2 };
    try t2.dir.writeFile(testing.io, .{ .sub_path = "setup.txt", .data = sealed });

    try testing.expectEqual(.refused, h2.run(&root, "config import ~/setup.txt --stdin -y"));
    try testing.expect(std.mem.find(u8, h2.stderr(), "wrong passphrase") != null);
    s2 = .{ .interactive = false, .piped = pass };
    try testing.expectEqual(.ok, h2.run(&root, "config import -n ~/setup.txt --stdin"));
    try testing.expectEqual(@as(usize, 0), mem2.map.count());
    s2 = .{ .interactive = false, .piped = pass };
    try testing.expectEqual(.ok, h2.run(&root, "config import ~/setup.txt --stdin -y"));
    try testing.expectEqualStrings("pve-secret-value", mem2.map.get("pve").?);
    try testing.expectEqualStrings("unifi-key-value", mem2.map.get("unifi").?);
    try testing.expect(mem2.map.get("guest/naboo") == null);
    try testing.expectEqualStrings(ca, try t2.dir.readFileAlloc(testing.io, ".artoo/tls/rootCA.pem", h2.arena.allocator(), .limited(4096)));
    const cfg2 = try t2.dir.readFileAlloc(testing.io, ".artoo/config.json", h2.arena.allocator(), .limited(4096));
    try testing.expect(std.mem.find(u8, cfg2, home1) == null);
    try testing.expect(std.mem.find(u8, cfg2, "\"~/.artoo/tls/rootCA.pem\"") != null);
    try testing.expect(std.mem.find(u8, cfg2, if (builtin.os.tag.isDarwin()) "\"keychain\"" else "\"auto\"") != null);
    try testing.expect(std.mem.find(u8, h2.stdout(), "pve.ca_bundle: ") != null);
    try testing.expect(std.mem.find(u8, h2.stdout(), "Installed 4 item(s).") != null);

    // Again: all the same.
    s2 = .{ .interactive = false, .piped = pass };
    try testing.expectEqual(.ok, h2.run(&root, "config import ~/setup.txt --stdin -y"));
    try testing.expect(std.mem.find(u8, h2.stdout(), "nothing to do") != null);
    // A different credential is replaced only with --force.
    try mem2.map.put(h2.arena.allocator(), "pve", "rotated-here");
    s2 = .{ .interactive = false, .piped = pass };
    try testing.expectEqual(.refused, h2.run(&root, "config import ~/setup.txt --stdin -y"));
    try testing.expect(std.mem.find(u8, h2.stderr(), "pve differ") != null);
    try testing.expectEqualStrings("rotated-here", mem2.map.get("pve").?);
    s2 = .{ .interactive = false, .piped = pass };
    try testing.expectEqual(.ok, h2.run(&root, "config import ~/setup.txt --stdin -y --force"));
    try testing.expectEqualStrings("pve-secret-value", mem2.map.get("pve").?);
    // Not a setup file.
    try t2.dir.writeFile(testing.io, .{ .sub_path = "junk.txt", .data = "hello\n" });
    s2 = .{ .interactive = false, .piped = pass };
    try testing.expectEqual(.usage, h2.run(&root, "config import ~/junk.txt --stdin -y"));
    // Secret values never reach the output.
    for ([_][]const u8{ h1.stdout(), h1.stderr(), h2.stdout(), h2.stderr() }) |o| try testing.expect(std.mem.find(u8, o, "pve-secret-value") == null);
}
