//! `artoo ts …` (SPEC §19): the lab's side of the tailnet through the
//! Tailscale API — devices, routes, DNS, auth key metadata and the policy
//! (read-only). Writes go through the one mutation pipeline and touch lab
//! devices only (artoo's tags, or a machine name that is a VM tagged
//! `artoo`); a key's value is never shown.

const std = @import("std");
const Io = std.Io;
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const files = @import("../files.zig");
const ui = @import("../ui.zig");
const pve = @import("../pve/client.zig");
const vms = @import("../pve/vm.zig");
const template = @import("template.zig");
const ts = @import("../tailscale/client.zig");
const tn = @import("../tailscale/tailnet.zig");
const exec = @import("../exec.zig");
const config = @import("../config.zig");
const guest_names = @import("../guest/names.zig");
const router = @import("router.zig");
const vm_new = @import("vm_new.zig");

const Context = app.Context;
const Value = std.json.Value;

/// The tags artoo's join keys carry: its devices.
pub fn labTags(ctx: *Context) ![]const []const u8 {
    return ctx.arena.dupe([]const u8, &.{tn.router_tag});
}

/// Who owns what (SPEC §19). Writes need Proxmox (`required`); listings
/// fall back to the tags alone when it cannot be read.
pub fn ownership(ctx: *Context, required: bool) !tn.Ownership {
    const tags = try labTags(ctx);
    var c = pve.Client.open(ctx) catch |err| {
        if (required or err == error.OutOfMemory or err == error.Canceled) return err;
        ctx.diag = null;
        return .{ .artoo_vms = &.{}, .tags = tags, .vms_known = false };
    };
    defer c.deinit();
    const list = vms.list(&c) catch |err| {
        if (required or err == error.OutOfMemory or err == error.Canceled) return err;
        ctx.diag = null;
        return .{ .artoo_vms = &.{}, .tags = tags, .vms_known = false };
    };
    return .{ .artoo_vms = try artooVms(ctx.arena, list), .tags = tags };
}

pub fn artooVms(a: std.mem.Allocator, list: []const vms.Vm) ![]const []const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    for (list) |v| if (!v.template and v.name.len > 0 and template.taggedWith(v.tags, "artoo")) try names.append(a, v.name);
    return names.items;
}

/// The device NAME names (node ID, MagicDNS or machine name).
pub fn resolveDevice(ctx: *Context, list: []const tn.Device, word: []const u8) !tn.Device {
    return switch (try tn.find(ctx.arena, list, word)) {
        .device => |d| d,
        .missing => ctx.fail(error.NotFound, "no device '{s}' on the tailnet (see 'artoo ts devices ls')", .{word}),
        .ambiguous => |hits| blk: {
            var ids: std.ArrayList(u8) = .empty;
            for (hits, 0..) |h, i| try ids.print(ctx.arena, "{s}{s} ({s})", .{ if (i > 0) ", " else "", h.id, try clean(ctx, h.name) });
            break :blk ctx.fail(error.Usage, "{d} devices match '{s}'; use a node ID: {s}", .{ hits.len, word, ids.items });
        },
    };
}

pub fn clean(ctx: *Context, s: []const u8) ![]const u8 {
    return ui.text.sanitize(ctx.arena, s, .line);
}

fn joinClean(ctx: *Context, list: []const []const u8) ![]const u8 {
    if (list.len == 0) return ui.values.missing;
    return clean(ctx, try std.mem.join(ctx.arena, ", ", list));
}

fn header(ctx: *Context, c: *const ts.Client) !void {
    try ui.blocks.header(ctx.out, &ctx.ui, ctx.path, try std.fmt.allocPrint(ctx.arena, "tailscale {s} tailnet {s} {s} {f}", .{
        ctx.ui.glyphs.dot, try clean(ctx, c.tailnet), ctx.ui.glyphs.dot, ui.values.clock(ctx.ui.now, &ctx.ui.zone),
    }));
}

fn ipv4(d: tn.Device) []const u8 {
    for (d.addresses) |x| if (std.mem.findScalar(u8, x, ':') == null) return x;
    return if (d.addresses.len > 0) d.addresses[0] else ui.values.missing;
}

fn seenText(ctx: *Context, d: tn.Device) ![]const u8 {
    if (d.connected) return "connected";
    return std.fmt.allocPrint(ctx.arena, "{f}", .{ui.values.relative(ctx.ui.now, d.last_seen)});
}

fn expiryText(ctx: *Context, d: tn.Device) ![]const u8 {
    if (d.key_expiry_disabled) return "off";
    return std.fmt.allocPrint(ctx.arena, "{f}", .{ui.values.relative(ctx.ui.now, d.expires)});
}

/// `192.168.1.0/24 (approved)` for each advertised route.
fn routesText(ctx: *Context, d: tn.Device) ![]const u8 {
    if (d.advertised.len == 0 and d.enabled.len == 0) return ui.values.missing;
    var out: std.ArrayList(u8) = .empty;
    for (d.advertised) |r| try out.print(ctx.arena, "{s}{s}{s}", .{ if (out.items.len > 0) ", " else "", r, if (tn.contains(d.enabled, r)) " (approved)" else " (not approved)" });
    for (d.enabled) |r| if (!tn.contains(d.advertised, r)) try out.print(ctx.arena, "{s}{s} (approved, not advertised)", .{ if (out.items.len > 0) ", " else "", r });
    return clean(ctx, out.items);
}

/// The JSON view of a device (SPEC §4.2: raw units, epoch seconds).
pub const DeviceView = struct {
    id: []const u8,
    name: []const u8,
    machine: []const u8,
    hostname: []const u8,
    os: []const u8,
    client_version: []const u8,
    addresses: []const []const u8,
    tags: []const []const u8,
    connected: bool,
    last_seen: ?i64,
    key_expiry_disabled: bool,
    key_expires: ?i64,
    advertised_routes: []const []const u8,
    approved_routes: []const []const u8,
    lab: bool,
    /// `tag` or `vm`; null for the operator's own devices.
    lab_reason: ?[]const u8,

    pub fn of(d: tn.Device, own: tn.Ownership) DeviceView {
        const why = own.reason(d);
        return .{
            .id = d.id,
            .name = d.name,
            .machine = d.machine,
            .hostname = d.hostname,
            .os = d.os,
            .client_version = d.client_version,
            .addresses = d.addresses,
            .tags = d.tags,
            .connected = d.connected,
            .last_seen = d.last_seen,
            .key_expiry_disabled = d.key_expiry_disabled,
            .key_expires = d.expires,
            .advertised_routes = d.advertised,
            .approved_routes = d.enabled,
            .lab = why != null,
            .lab_reason = why,
        };
    }
};

fn labText(own: tn.Ownership, d: tn.Device) []const u8 {
    const why = own.reason(d) orelse return if (own.vms_known) "no" else "?";
    return if (std.mem.eql(u8, why, "tag")) "yes (tag)" else "yes (vm)";
}

pub const devices_ls = struct {
    pub const name = "ls";
    pub const summary = "List the tailnet's devices; LAB marks the ones artoo may change";
    pub const details =
        \\A lab device carries one of artoo's tags (tag:lab-router) or has the
        \\machine name of a Proxmox VM tagged artoo; the operator's own devices
        \\are listed but never changed. Without Proxmox, LAB is known by tag only.
    ;
    pub const examples = [_][]const u8{ "artoo ts devices ls", "artoo ts devices ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        const list = try tn.devices(&c);
        const own = try ownership(ctx, false);
        if (ctx.json()) {
            const views = try ctx.arena.alloc(DeviceView, list.len);
            for (list, views) |d, *v| v.* = .of(d, own);
            return ui.json.envelope(ctx.out, .tailscale, views, .{ .collected_at = ctx.ui.now, .tailnet = c.tailnet, .vms_known = own.vms_known });
        }
        try header(ctx, &c);
        if (list.len == 0) return ctx.out.print("{s}No devices.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
        const rows = try ctx.arena.alloc([]const ui.table.Cell, list.len);
        for (list, rows) |d, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 9);
            const lab = labText(own, d);
            cells[0] = .{ .text = try clean(ctx, d.machine) };
            cells[1] = .{ .text = try joinClean(ctx, d.tags) };
            cells[2] = .{ .text = try clean(ctx, ipv4(d)) };
            cells[3] = .{ .text = try clean(ctx, if (d.os.len > 0) d.os else ui.values.missing) };
            cells[4] = .{ .text = try seenText(ctx, d), .role = if (d.connected) .ok else .muted };
            cells[5] = .{ .text = try expiryText(ctx, d) };
            cells[6] = .{ .text = try routesText(ctx, d) };
            cells[7] = .{ .text = lab, .role = if (std.mem.startsWith(u8, lab, "yes")) .text else .muted };
            cells[8] = .{ .text = try clean(ctx, d.id), .role = .id };
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "NAME", .truncate = false },
            .{ .title = "TAGS", .drop = 2 },
            .{ .title = "ADDRESS", .truncate = false },
            .{ .title = "OS", .drop = 3 },
            .{ .title = "LAST SEEN", .drop = 1 },
            .{ .title = "KEY EXPIRY", .drop = 1 },
            .{ .title = "ROUTES", .drop = 2 },
            .{ .title = "LAB" },
            .{ .title = "ID", .truncate = false, .drop = 4 },
        }, rows);
        if (!own.vms_known) try ctx.out.print("\n{s}Proxmox could not be read: LAB is known by tag only.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
    }
};

const device_arg = [_]cli.Positional{.{ .name = "NAME", .help = "Machine name, MagicDNS name or node ID" }};

pub const device_show = struct {
    pub const name = "show";
    pub const summary = "One device: addresses, tags, key expiry, routes, ownership";
    pub const positionals = device_arg;
    pub const examples = [_][]const u8{ "artoo ts device show dagobah", "artoo ts device show naboo -o json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        const d = try resolveDevice(ctx, try tn.devices(&c), args.pos("NAME"));
        const own = try ownership(ctx, false);
        if (ctx.json()) return ui.json.envelope(ctx.out, .tailscale, DeviceView.of(d, own), .{ .collected_at = ctx.ui.now, .tailnet = c.tailnet, .vms_known = own.vms_known });
        try header(ctx, &c);
        const z = &ctx.ui.zone;
        const a = ctx.arena;
        try ui.blocks.detail(ctx.out, &ctx.ui, &.{
            .{ .title = try clean(ctx, d.machine), .fields = try a.dupe(ui.blocks.Field, &.{
                .{ .key = "Name", .value = try clean(ctx, d.name) },
                .{ .key = "Node ID", .value = try clean(ctx, d.id), .role = .id },
                .{ .key = "Hostname", .value = try clean(ctx, if (d.hostname.len > 0) d.hostname else ui.values.missing) },
                .{ .key = "OS", .value = try clean(ctx, if (d.os.len > 0) d.os else ui.values.missing) },
                .{ .key = "Version", .value = try clean(ctx, if (d.client_version.len > 0) d.client_version else ui.values.missing) },
                .{ .key = "Addresses", .value = if (d.addresses.len > 0) try ui.text.sanitize(a, try std.mem.join(a, "\n", d.addresses), .block) else ui.values.missing },
                .{ .key = "Tags", .value = try joinClean(ctx, d.tags) },
                .{ .key = "Lab device", .value = labText(own, d) },
            }) },
            .{ .title = "Connection", .fields = try a.dupe(ui.blocks.Field, &.{
                .{ .key = "Last seen", .value = if (d.connected) "connected" else try std.fmt.allocPrint(a, "{f} ({f})", .{ ui.values.relative(ctx.ui.now, d.last_seen), ui.values.absolute(d.last_seen, z) }) },
                .{ .key = "Key expiry", .value = if (d.key_expiry_disabled) "off" else try std.fmt.allocPrint(a, "{f} ({f})", .{ ui.values.relative(ctx.ui.now, d.expires), ui.values.absolute(d.expires, z) }), .role = if (d.key_expiry_disabled) .text else .warn },
                .{ .key = "Authorized", .value = if (d.authorized) "yes" else "no" },
                .{ .key = "Routes", .value = try routesText(ctx, d) },
            }) },
        });
    }
};

pub const dns_show = struct {
    pub const name = "show";
    pub const summary = "Nameservers, MagicDNS, search paths and split DNS";
    pub const examples = [_][]const u8{ "artoo ts dns show", "artoo ts dns show -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        const d = try tn.dns(&c);
        if (ctx.json()) return ui.json.envelope(ctx.out, .tailscale, d, .{ .collected_at = ctx.ui.now, .tailnet = c.tailnet });
        try header(ctx, &c);
        const a = ctx.arena;
        var split: std.ArrayList(ui.blocks.Field) = .empty;
        for (d.split) |s| try split.append(a, .{ .key = try clean(ctx, s.domain), .value = try joinClean(ctx, s.nameservers) });
        if (split.items.len == 0) try split.append(a, .{ .key = "(none)", .value = ui.values.missing });
        try ui.blocks.detail(ctx.out, &ctx.ui, &.{
            .{ .title = "Global", .fields = try a.dupe(ui.blocks.Field, &.{
                .{ .key = "Nameservers", .value = try joinClean(ctx, d.nameservers) },
                .{ .key = "Override local", .value = if (d.override_local) "yes" else "no" },
                .{ .key = "MagicDNS", .value = if (d.magic_dns) "on" else "off" },
                .{ .key = "Search paths", .value = try joinClean(ctx, d.search_paths) },
            }) },
            .{ .title = "Split DNS", .fields = split.items },
        });
    }
};

fn yesNo(b: ?bool) []const u8 {
    const v = b orelse return ui.values.missing;
    return if (v) "yes" else "no";
}

pub const keys_ls = struct {
    pub const name = "ls";
    pub const summary = "Key metadata the OAuth client may see (never a key's value)";
    pub const details = "ID, type, description, tags, flags, created and expiry. A key's secret is sent by Tailscale only when it is created and is never shown.";
    pub const examples = [_][]const u8{ "artoo ts keys ls", "artoo ts keys ls -o json" };

    pub fn run(ctx: *Context, _: cli.Args(@This())) !void {
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        const list = try tn.keys(&c);
        if (ctx.json()) return ui.json.envelope(ctx.out, .tailscale, list, .{ .collected_at = ctx.ui.now, .tailnet = c.tailnet });
        try header(ctx, &c);
        if (list.len == 0) return ctx.out.print("{s}No keys visible to this client.{s}\n", .{ ctx.ui.palette.on(.muted), ctx.ui.palette.off(.muted) });
        const rows = try ctx.arena.alloc([]const ui.table.Cell, list.len);
        for (list, rows) |k, *row| {
            const cells = try ctx.arena.alloc(ui.table.Cell, 8);
            var flags: std.ArrayList(u8) = .empty;
            if (k.reusable) |r| try flags.appendSlice(ctx.arena, if (r) "reusable" else "single-use");
            if (k.ephemeral orelse false) try flags.appendSlice(ctx.arena, ", ephemeral");
            if (k.preauthorized orelse false) try flags.appendSlice(ctx.arena, ", preauthorized");
            cells[0] = .{ .text = try clean(ctx, k.id), .role = .id };
            cells[1] = .{ .text = try clean(ctx, if (k.type.len > 0) k.type else ui.values.missing) };
            cells[2] = .{ .text = try clean(ctx, if (k.description.len > 0) k.description else ui.values.missing) };
            cells[3] = .{ .text = try joinClean(ctx, k.tags) };
            cells[4] = .{ .text = if (flags.items.len > 0) flags.items else ui.values.missing };
            cells[5] = .{ .text = try std.fmt.allocPrint(ctx.arena, "{f}", .{ui.values.relative(ctx.ui.now, k.created)}) };
            cells[6] = .{ .text = try std.fmt.allocPrint(ctx.arena, "{f}", .{ui.values.relative(ctx.ui.now, k.expires)}) };
            cells[7] = .{ .text = if (k.invalid) "invalid" else "valid", .role = if (k.invalid) .muted else .text };
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, ctx.arena, &.{
            .{ .title = "ID", .truncate = false },
            .{ .title = "TYPE" },
            .{ .title = "DESCRIPTION" },
            .{ .title = "TAGS", .drop = 2 },
            .{ .title = "FLAGS", .drop = 3 },
            .{ .title = "CREATED", .drop = 1 },
            .{ .title = "EXPIRES" },
            .{ .title = "STATE", .drop = 1 },
        }, rows);
    }
};

const policy_limit = 1 << 20;

pub const policy_show = struct {
    pub const name = "show";
    pub const summary = "The tailnet policy as stored (HuJSON), or as JSON";
    pub const details = "Read-only; artoo never changes the policy with this client (SPEC §19).";
    pub const flags = [_]cli.Flag{.{ .long = "json", .help = "The policy as JSON instead of HuJSON" }};
    pub const examples = [_][]const u8{ "artoo ts policy show", "artoo ts policy show --json" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        const as_json = args.has("json") or ctx.json();
        const p = try tn.policy(&c, as_json);
        if (ctx.json()) {
            const v = std.json.parseFromSliceLeaky(Value, ctx.arena, p.text, .{}) catch
                return ctx.fail(error.Protocol, "Tailscale sent a policy that is not JSON", .{});
            return ui.json.envelope(ctx.out, .tailscale, v, .{ .collected_at = ctx.ui.now, .tailnet = c.tailnet, .etag = p.etag });
        }
        const text = try ui.text.sanitize(ctx.arena, p.text, .block);
        try ctx.out.writeAll(text);
        if (text.len > 0 and text[text.len - 1] != '\n') try ctx.out.writeByte('\n');
    }
};

/// A local policy file (`~` expanded), at most 1 MiB.
pub fn readPolicyFile(ctx: *Context, word: []const u8) ![]const u8 {
    const path = files.expandHome(ctx.arena, ctx.env, word) catch return ctx.fail(error.Usage, "cannot resolve {s}: HOME is not set", .{word});
    return Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(policy_limit)) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| e,
        error.StreamTooLong => ctx.fail(error.Usage, "{s} is larger than 1 MiB", .{ctx.tilde(path)}),
        else => ctx.fail(error.NotFound, "cannot read {s} ({s})", .{ ctx.tilde(path), @errorName(err) }),
    };
}

pub const Validation = struct {
    ok: bool,
    message: []const u8,
    /// `subject: error` lines, sanitized.
    errors: []const []const u8,
    warnings: []const []const u8,
};

/// `POST acl/validate` with a HuJSON policy (Tailscale also runs its
/// `tests`). Changes nothing.
pub fn validate(c: *ts.Client, text: []const u8) !Validation {
    const ctx = c.ctx;
    const a = ctx.arena;
    const v = try c.jsonOpts(.POST, try c.tailnetPath("/acl/validate", .{}), text, .{ .content_type = "application/hujson", .read_only = true });
    var errs: std.ArrayList([]const u8) = .empty;
    var warns: std.ArrayList([]const u8) = .empty;
    const data = ts.field(v, "data");
    if (data == .array) for (data.array.items) |item| {
        const who = ts.str(item, "user") orelse "";
        for (try ts.strings(a, item, "errors")) |e| try errs.append(a, try clean(ctx, try std.fmt.allocPrint(a, "{s}{s}{s}", .{ who, if (who.len > 0) ": " else "", e })));
        for (try ts.strings(a, item, "warnings")) |e| try warns.append(a, try clean(ctx, try std.fmt.allocPrint(a, "{s}{s}{s}", .{ who, if (who.len > 0) ": " else "", e })));
    };
    const message = try clean(ctx, ts.str(v, "message") orelse "");
    // `{}` is success; a message with only warnings is still valid.
    const valid = errs.items.len == 0 and (message.len == 0 or warns.items.len > 0);
    return .{ .ok = valid, .message = message, .errors = errs.items, .warnings = warns.items };
}

pub const policy_validate = struct {
    pub const name = "validate";
    pub const summary = "Check a policy file with Tailscale (its tests run too); changes nothing";
    pub const positionals = [_]cli.Positional{.{ .name = "FILE", .help = "HuJSON policy file", .complete = .file }};
    pub const examples = [_][]const u8{"artoo ts policy validate policy.hujson"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const text = try readPolicyFile(ctx, args.pos("FILE"));
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        const r = try validate(&c, text);
        if (ctx.json()) {
            try ui.json.envelope(ctx.out, .tailscale, r, .{ .tailnet = c.tailnet });
        } else {
            const p = ctx.ui.palette;
            for (r.errors) |e| try ctx.out.print("{s}{s}{s} {s}\n", .{ p.on(.fail), ctx.ui.glyphs.fail, p.off(.fail), e });
            for (r.warnings) |w| try ctx.out.print("{s}{s}{s} {s}\n", .{ p.on(.warn), ctx.ui.glyphs.warn, p.off(.warn), w });
            if (r.ok) try ctx.out.print("{s}{s}{s} {s} is valid and its tests pass\n", .{ p.on(.ok), ctx.ui.glyphs.ok, p.off(.ok), args.pos("FILE") });
        }
        if (!r.ok) return ctx.fail(error.Partial, "the policy did not validate{s}{s}", .{ if (r.message.len > 0) ": " else "", r.message });
    }
};

pub const policy_preview = struct {
    pub const name = "preview";
    pub const summary = "Which rules of the live policy match a user or IP:PORT";
    pub const positionals = [_]cli.Positional{.{ .name = "FOR", .help = "A user's email, or IP:PORT (100.64.0.1:22)" }};
    pub const examples = [_][]const u8{ "artoo ts policy preview user@example.com", "artoo ts policy preview 192.168.1.10:8006" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const a = ctx.arena;
        const who = args.pos("FOR");
        const kind: []const u8 = if (std.mem.findScalar(u8, who, '@') != null) "user" else blk: {
            const colon = std.mem.findScalarLast(u8, who, ':') orelse return ctx.fail(error.Usage, "FOR must be a user's email or IP:PORT, got '{s}'", .{who});
            _ = std.fmt.parseInt(u16, who[colon + 1 ..], 10) catch return ctx.fail(error.Usage, "FOR must be a user's email or IP:PORT, got '{s}'", .{who});
            break :blk "ipport";
        };
        for (who) |ch| if (ch <= 0x20 or ch == 0x7f) return ctx.fail(error.Usage, "FOR must be printable", .{});
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        const live = try tn.policy(&c, false);
        const query = try pve.form(a, &.{ .{ .name = "type", .value = kind }, .{ .name = "previewFor", .value = who } });
        const v = try c.jsonOpts(.POST, try c.tailnetPath("/acl/preview?{s}", .{query}), live.text, .{ .content_type = "application/hujson", .read_only = true });
        const Rule = struct { users: []const []const u8, ports: []const []const u8, line: ?i64 };
        var rules: std.ArrayList(Rule) = .empty;
        const m = ts.field(v, "matches");
        if (m == .array) for (m.array.items) |it| try rules.append(a, .{ .users = try ts.strings(a, it, "users"), .ports = try ts.strings(a, it, "ports"), .line = ts.int(it, "lineNumber") });
        if (ctx.json()) return ui.json.envelope(ctx.out, .tailscale, .{ .type = kind, .preview_for = who, .matches = rules.items }, .{ .tailnet = c.tailnet });
        try header(ctx, &c);
        if (rules.items.len == 0) return ctx.out.print("{s}No rule matches {s}.{s}\n", .{ ctx.ui.palette.on(.muted), try clean(ctx, who), ctx.ui.palette.off(.muted) });
        const rows = try a.alloc([]const ui.table.Cell, rules.items.len);
        for (rules.items, rows) |r, *row| {
            const cells = try a.alloc(ui.table.Cell, 3);
            cells[0] = .{ .text = if (r.line) |l| try std.fmt.allocPrint(a, "{d}", .{l}) else ui.values.missing };
            cells[1] = .{ .text = try joinClean(ctx, r.users) };
            cells[2] = .{ .text = try joinClean(ctx, r.ports) };
            row.* = cells;
        }
        try ui.table.render(ctx.out, &ctx.ui, a, &.{
            .{ .title = "LINE", .alignment = .right },
            .{ .title = "SOURCES" },
            .{ .title = "DESTINATIONS" },
        }, rows);
    }
};

// ---------------------------------------------------------------- writes

/// The device NAME names, refused unless it is a lab device (SPEC §19).
fn labDevice(ctx: *Context, c: *ts.Client, word: []const u8) !struct { tn.Device, []const u8 } {
    const d = try resolveDevice(ctx, try tn.devices(c), word);
    const own = try ownership(ctx, true);
    const why = own.reason(d) orelse return ctx.fail(error.Refused, "{s} is not a lab device (no tag {s}, no VM tagged artoo of that name); artoo changes lab devices only (SPEC §19)", .{ try clean(ctx, d.machine), tn.router_tag });
    return .{ d, why };
}

fn deviceTarget(ctx: *Context, c: *const ts.Client) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena, "Tailscale (tailnet {s})", .{try clean(ctx, c.tailnet)});
}

const RenameOp = struct {
    c: *ts.Client,
    word: []const u8,
    new: []const u8,
    target: []const u8 = "",
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .tailscale,
    dev: tn.Device = undefined,
    state: []const u8 = "",

    pub fn read(op: *RenameOp, ctx: *Context) !void {
        const list = try tn.devices(op.c);
        op.dev, _ = try labDevice(ctx, op.c, op.word);
        op.target = op.dev.machine;
        for (list) |d| if (!std.mem.eql(u8, d.id, op.dev.id) and std.ascii.eqlIgnoreCase(d.machine, op.new))
            return ctx.fail(error.Refused, "another device is already named {s} ({s})", .{ op.new, try clean(ctx, d.id) });
        op.state = try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ op.dev.id, op.dev.name });
    }

    pub fn plan(op: *RenameOp, ctx: *Context) !?@import("../exec.zig").Plan {
        if (std.mem.eql(u8, op.dev.machine, op.new)) return null;
        const a = ctx.arena;
        return .{
            .action = try std.fmt.allocPrint(a, "Rename tailnet device {s} to {s}", .{ try clean(ctx, op.dev.machine), op.new }),
            .target = try deviceTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{.{ .field = "name", .from = try clean(ctx, op.dev.name), .to = op.new }}),
            .impact = try a.dupe([]const u8, &.{try std.fmt.allocPrint(a, "MagicDNS names under {s} stop resolving at once", .{try clean(ctx, op.dev.machine)})}),
            .recovery = try std.fmt.allocPrint(a, "artoo ts device rename {s} {s}", .{ op.new, try clean(ctx, op.dev.machine) }),
        };
    }

    pub fn fingerprint(op: *RenameOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *RenameOp, _: *Context) !void {
        try tn.renameDevice(op.c, op.dev.id, op.new);
    }

    pub fn verify(op: *RenameOp, _: *Context) !bool {
        const d = (try tn.getDevice(op.c, op.dev.id)) orelse return false;
        return std.mem.eql(u8, d.machine, op.new);
    }

    pub fn done(_: *RenameOp) []const u8 {
        return "device renamed and verified";
    }
};

pub const device_rename = struct {
    pub const name = "rename";
    pub const summary = "Rename a lab device on the tailnet (its MagicDNS name)";
    pub const details = "Lab devices only. For a guest, 'artoo vm rename' renames everything at once (SPEC §9.18).";
    pub const positionals = [_]cli.Positional{
        device_arg[0],
        .{ .name = "NEW", .help = "New machine name (one DNS label)" },
    };
    pub const examples = [_][]const u8{"artoo ts device rename naboo-1 naboo"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const new = args.pos("NEW");
        if (!guest_names.valid(new)) return ctx.fail(error.Usage, "NEW must be one lowercase DNS label (letter first, 2-40 characters), got '{s}'", .{new});
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        var op: RenameOp = .{ .c = &c, .word = args.pos("NAME"), .new = new };
        try exec.run(ctx, &op, .{});
    }
};

const RmOp = struct {
    c: *ts.Client,
    word: []const u8,
    target: []const u8 = "",
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .tailscale,
    dev: tn.Device = undefined,
    state: []const u8 = "",

    pub fn read(op: *RmOp, ctx: *Context) !void {
        op.dev, _ = try labDevice(ctx, op.c, op.word);
        op.target = op.dev.machine;
        op.state = op.dev.id;
    }

    pub fn plan(op: *RmOp, ctx: *Context) !?@import("../exec.zig").Plan {
        const a = ctx.arena;
        return .{
            .action = try std.fmt.allocPrint(a, "Remove {s} from the tailnet", .{try clean(ctx, op.dev.machine)}),
            .risk = .destructive,
            .target = try deviceTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{.{ .field = "device", .from = try std.fmt.allocPrint(a, "{s} ({s}, {s})", .{ try clean(ctx, op.dev.name), try clean(ctx, ipv4(op.dev)), try clean(ctx, op.dev.id) }), .to = null }}),
            .impact = try a.dupe([]const u8, &.{"The device loses tailnet access until it joins again with a new key"}),
            .recovery = if (op.dev.hasTag(tn.router_tag)) "artoo router setup (joins it again)" else "join it again with a new auth key",
        };
    }

    pub fn fingerprint(op: *RmOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *RmOp, _: *Context) !void {
        try tn.deleteDevice(op.c, op.dev.id);
    }

    pub fn verify(op: *RmOp, _: *Context) !bool {
        return (try tn.getDevice(op.c, op.dev.id)) == null;
    }

    pub fn done(_: *RmOp) []const u8 {
        return "device removed and verified (Tailscale answers 404)";
    }
};

pub const device_rm = struct {
    pub const name = "rm";
    pub const summary = "Remove a lab device from the tailnet (destructive)";
    pub const details =
        \\Lab devices only. Interactive: type the machine name to confirm.
        \\Non-interactive: --yes --confirm NAME.
    ;
    pub const positionals = device_arg;
    pub const flags = [_]cli.Flag{.{ .long = "confirm", .kind = .string, .metavar = "NAME", .help = "Non-interactive confirmation (with --yes)" }};
    pub const examples = [_][]const u8{ "artoo ts device rm naboo", "artoo ts device rm naboo --yes --confirm naboo" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        var op: RmOp = .{ .c = &c, .word = args.pos("NAME") };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

/// Approve exactly the LAN on a lab device that advertises it (SPEC §19):
/// never an exit node, never another subnet.
pub const ApproveOp = struct {
    c: *ts.Client,
    word: []const u8,
    lan: []const u8,
    target: []const u8 = "",
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .tailscale,
    dev: tn.Device = undefined,
    current: tn.Routes = .{ .advertised = &.{}, .enabled = &.{} },
    state: []const u8 = "",

    pub fn read(op: *ApproveOp, ctx: *Context) !void {
        op.dev, _ = try labDevice(ctx, op.c, op.word);
        op.target = op.dev.machine;
        op.current = try tn.routes(op.c, op.dev.id);
        if (!tn.contains(op.current.advertised, op.lan))
            return ctx.fail(error.Refused, "{s} does not advertise {s} (it advertises {s}); 'artoo router setup' advertises the LAN", .{ try clean(ctx, op.dev.machine), op.lan, try joinClean(ctx, op.current.advertised) });
        op.state = try std.fmt.allocPrint(ctx.arena, "{s} {s}", .{ try std.mem.join(ctx.arena, ",", op.current.advertised), try std.mem.join(ctx.arena, ",", op.current.enabled) });
    }

    pub fn plan(op: *ApproveOp, ctx: *Context) !?@import("../exec.zig").Plan {
        if (tn.sameSet(op.current.enabled, &.{op.lan})) return null;
        const a = ctx.arena;
        var notes: std.ArrayList([]const u8) = .empty;
        for (op.current.enabled) |r| if (!std.mem.eql(u8, r, op.lan)) try notes.append(a, try std.fmt.allocPrint(a, "{s} was approved and is withdrawn: artoo approves the LAN only", .{try clean(ctx, r)}));
        return .{
            .action = try std.fmt.allocPrint(a, "Approve {s} on {s}", .{ op.lan, try clean(ctx, op.dev.machine) }),
            .target = try deviceTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{.{ .field = "approved routes", .from = try joinClean(ctx, op.current.enabled), .to = op.lan }}),
            .impact = try a.dupe([]const u8, &.{try std.fmt.allocPrint(a, "Tailnet devices reach {s} through {s}, as the policy allows", .{ op.lan, try clean(ctx, op.dev.machine) })}),
            .recovery = "approve or withdraw routes in the Tailscale console",
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *ApproveOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *ApproveOp, _: *Context) !void {
        try tn.setRoutes(op.c, op.dev.id, &.{op.lan});
    }

    pub fn verify(op: *ApproveOp, _: *Context) !bool {
        const r = try tn.routes(op.c, op.dev.id);
        return tn.sameSet(r.enabled, &.{op.lan});
    }

    pub fn done(_: *ApproveOp) []const u8 {
        return "route approved and verified";
    }
};

pub const routes_approve = struct {
    pub const name = "approve";
    pub const summary = "Approve the LAN route a lab router advertises (only the LAN)";
    pub const details = "Reads what the device advertises; refused when it does not advertise the LAN of guests.gateway. Exactly that route is approved — never an exit node or another subnet.";
    pub const positionals = [_]cli.Positional{.{ .name = "ROUTER", .help = "The router's machine name or node ID" }};
    pub const examples = [_][]const u8{"artoo ts routes approve dagobah"};

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const lan = try router.lan(ctx);
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        var op: ApproveOp = .{ .c = &c, .word = args.pos("ROUTER"), .lan = lan };
        try exec.run(ctx, &op, .{});
    }
};

/// The gateway's address (`guests.gateway`), the only split-DNS server.
pub fn gatewayAddress(ctx: *Context) ![]const u8 {
    const cfg = try ctx.config();
    const gw = config.parseCidr(cfg.guests.gateway) orelse return ctx.fail(error.ConfigInvalid, "guests.gateway is not A/N", .{});
    return vm_new.ip4Text(ctx.arena, gw.address);
}

const SplitOp = struct {
    c: *ts.Client,
    domain: []const u8,
    servers: []const []const u8,
    target: []const u8,
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .tailscale,
    current: []const []const u8 = &.{},
    state: []const u8 = "",

    pub fn read(op: *SplitOp, ctx: *Context) !void {
        op.current = &.{};
        for (try tn.splitDns(op.c)) |s| if (std.ascii.eqlIgnoreCase(s.domain, op.domain)) {
            op.current = s.nameservers;
        };
        op.state = try std.mem.join(ctx.arena, ",", op.current);
    }

    pub fn plan(op: *SplitOp, ctx: *Context) !?@import("../exec.zig").Plan {
        if (tn.sameSet(op.current, op.servers)) return null;
        const a = ctx.arena;
        return .{
            .action = try std.fmt.allocPrint(a, "Set split DNS for {s}", .{op.domain}),
            .target = try deviceTarget(ctx, op.c),
            .changes = try a.dupe(ui.blocks.Change, &.{.{ .field = op.domain, .from = if (op.current.len > 0) try joinClean(ctx, op.current) else null, .to = try std.mem.join(a, ", ", op.servers) }}),
            .impact = try a.dupe([]const u8, &.{try std.fmt.allocPrint(a, "Tailnet devices resolve *.{s} through {s}", .{ op.domain, try std.mem.join(a, ", ", op.servers) })}),
            .recovery = if (op.current.len > 0) try std.fmt.allocPrint(a, "artoo ts dns split set {s} {s}", .{ op.domain, try std.mem.join(a, " ", op.current) }) else "remove the domain in the Tailscale console (DNS)",
            .notes = try a.dupe([]const u8, &.{"Only this domain is sent; the other split-DNS domains stay as they are."}),
        };
    }

    pub fn fingerprint(op: *SplitOp) []const u8 {
        return op.state;
    }

    pub fn send(op: *SplitOp, _: *Context) !void {
        try tn.patchSplit(op.c, op.domain, op.servers);
    }

    pub fn verify(op: *SplitOp, _: *Context) !bool {
        for (try tn.splitDns(op.c)) |s| if (std.ascii.eqlIgnoreCase(s.domain, op.domain)) return tn.sameSet(s.nameservers, op.servers);
        return false;
    }

    pub fn done(_: *SplitOp) []const u8 {
        return "split DNS set and verified";
    }
};

pub const dns_split_set = struct {
    pub const name = "set";
    pub const summary = "Point a lab domain (guests.domain or home.arpa) at the gateway on the tailnet";
    pub const details = "Split DNS for guests.domain and home.arpa only, and only to the gateway (guests.gateway's address); other domains are untouched (SPEC §19).";
    pub const positionals = [_]cli.Positional{
        .{ .name = "DOMAIN", .help = "guests.domain or home.arpa" },
        .{ .name = "NAMESERVER", .help = "The gateway's address", .variadic = true },
    };
    pub const examples = [_][]const u8{ "artoo ts dns split set lab.example.com 192.168.1.1", "artoo ts dns split set home.arpa 192.168.1.1" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const cfg = try ctx.config();
        const domain = std.mem.trimEnd(u8, args.pos("DOMAIN"), ".");
        if (!std.ascii.eqlIgnoreCase(domain, cfg.guests.domain) and !std.ascii.eqlIgnoreCase(domain, "home.arpa"))
            return ctx.fail(error.Refused, "artoo sets split DNS only for {s} and home.arpa, not '{s}' (SPEC §19)", .{ cfg.guests.domain, domain });
        const gw = try gatewayAddress(ctx);
        const servers = args.rest("NAMESERVER");
        if (servers.len == 0) return ctx.fail(error.Usage, "name the nameserver: {s}", .{gw});
        for (servers) |s| if (!std.mem.eql(u8, s, gw))
            return ctx.fail(error.Refused, "split DNS for the lab points at the gateway {s} only, not '{s}' (SPEC §19)", .{ gw, s });
        var c = try ts.Client.open(ctx, .main);
        defer c.deinit();
        var op: SplitOp = .{ .c = &c, .domain = try std.ascii.allocLowerString(ctx.arena, domain), .servers = &.{gw}, .target = domain };
        try exec.run(ctx, &op, .{});
    }
};

pub const group = cli.group("ts", "Tailscale: the lab's devices, routes, split DNS and keys on the tailnet (SPEC §19)", &.{
    cli.group("devices", "Devices on the tailnet", &.{cli.leaf(devices_ls)}),
    cli.group("device", "One device", &.{ cli.leaf(device_show), cli.leaf(device_rename), cli.leaf(device_rm) }),
    cli.group("routes", "Subnet routes", &.{cli.leaf(routes_approve)}),
    cli.group("dns", "Tailnet DNS", &.{ cli.leaf(dns_show), cli.group("split", "Split DNS for the lab's domains", &.{cli.leaf(dns_split_set)}) }),
    cli.group("keys", "Auth key metadata", &.{cli.leaf(keys_ls)}),
    cli.group("policy", "The tailnet policy (read-only)", &.{ cli.leaf(policy_show), cli.leaf(policy_validate), cli.leaf(policy_preview) }),
});

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const Fixture = testkit.Gateway;
pub const root = cli.group("artoo", "test", &.{group});

pub const token_ok = "{\"access_token\":\"tskey-access-xyz\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"devices:core devices:routes auth_keys dns policy_file:read\"}";
pub const vms_body = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;tailnet\"},{\"vmid\":202,\"name\":\"dagobah\",\"status\":\"running\",\"tags\":\"artoo;role-router\"}]}";
pub const devices_body =
    \\{"devices":[
    \\{"id":"1","nodeId":"nRouter","name":"dagobah.example.ts.net","hostname":"dagobah","os":"linux","clientVersion":"1.90.0","addresses":["100.64.0.2","fd7a:115c:a1e0::2"],"tags":["tag:lab-router"],"connectedToControl":true,"keyExpiryDisabled":true,"authorized":true,"advertisedRoutes":["192.168.1.0/24"],"enabledRoutes":["192.168.1.0/24"]},
    \\{"id":"2","nodeId":"nNaboo","name":"naboo.example.ts.net","hostname":"naboo","os":"linux","addresses":["100.64.0.5"],"tags":[],"lastSeen":"2026-11-15T09:00:00Z","expires":"2027-05-01T00:00:00Z","authorized":true},
    \\{"id":"3","nodeId":"nPhone","name":"phone.example.ts.net","hostname":"phone","os":"iOS","addresses":["100.64.0.9"],"user":"me@example.com","lastSeen":"2026-11-14T09:00:00Z","expires":"2027-01-01T00:00:00Z","authorized":true}]}
;

pub fn ok(body: []const u8) Fixture.FakeServer.Behavior {
    return .{ .respond = .{ .body = body } };
}

pub fn route(match: []const u8, body: []const u8) Fixture.FakeServer.Route {
    return .{ .match = match, .behavior = ok(body) };
}

pub fn expectHas(out: []const u8, lines: []const []const u8) !void {
    for (lines) |line| if (std.mem.find(u8, out, line) == null) {
        std.debug.print("missing: {s}\n--- output:\n{s}\n", .{ line, out });
        return error.TestUnexpectedResult;
    };
}

test "ts devices ls: token exchange, all fields, lab devices by tag and by VM" {
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        .{ .match = "/qemu", .behavior = .{ .respond = .{ .status = 500, .reason = "down" } } },
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts devices ls"));
    try expectHas(f.h.stdout(), &.{
        "NAME     TAGS            ADDRESS     OS     LAST SEEN",
        "dagobah  tag:lab-router  100.64.0.2  linux  connected",
        "192.168.1.0/24 (approved)  yes (tag)  nRouter",
        "naboo    --              100.64.0.5  linux",
        "yes (vm)   nNaboo",
        "phone    --              100.64.0.9  iOS",
        "no         nPhone",
    });
    // The access token, never the client secret, authorizes API calls.
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "GET /tailnet")) {
        try testing.expect(std.mem.find(u8, q, "authorization: Bearer tskey-access-xyz") != null);
        try testing.expect(std.mem.find(u8, q, "tskey-client") == null);
    };
    // Proxmox down: lab devices by tag only, and said so.
    try testing.expectEqual(Exit.ok, f.h.run(&root, "-o json ts devices ls"));
    try expectHas(f.h.stdout(), &.{ "\"vms_known\": false", "\"lab_reason\": \"tag\"" });
}

test "ts: without tailscale.client_id nothing is sent; Tailscale's messages and 429 reach the user" {
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        .{ .match = "GET /tailnet/-/devices", .behavior = .{ .respond = .{ .status = 429, .body = "{\"message\":\"rate limited\"}" } } },
        route("POST /oauth/token", token_ok),
        .{ .match = "GET /tailnet/-/keys", .behavior = .{ .respond = .{ .status = 403, .body = "{\"message\":\"missing scope auth_keys:read\"}" } } },
    });
    defer f.deinit();
    try testing.expectEqual(Exit.usage, f.h.run(&root, "ts devices ls"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "tailscale.client_id is not set") != null);
    try testing.expectEqual(@as(usize, 0), f.sent());
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.network, f.h.run(&root, "ts devices ls"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "(429): rate limited") != null);
    try testing.expectEqual(Exit.auth, f.h.run(&root, "ts keys ls"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "missing scope auth_keys:read") != null);
}

test "ts device show and dns show" {
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/dns/configuration",
            \\{"nameservers":[{"address":"1.1.1.1"}],"splitDNS":{"lab.example.com":[{"address":"192.168.1.1"}],"home.arpa":[{"address":"192.168.1.1"}]},"searchPaths":[],"preferences":{"magicDNS":true,"overrideLocalDNS":false}}
        ),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts device show dagobah"));
    try expectHas(f.h.stdout(), &.{ "Node ID     nRouter", "Lab device  yes (tag)", "Key expiry  off", "Routes      192.168.1.0/24 (approved)" });
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts dns show"));
    try expectHas(f.h.stdout(), &.{ "Nameservers      1.1.1.1", "MagicDNS         on", "home.arpa        192.168.1.1", "lab.example.com  192.168.1.1" });
}

test "ts keys ls: metadata only, never a key value" {
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/keys",
            \\{"keys":[{"id":"kAuth1","key":"tskey-auth-LEAKED","keyType":"auth","description":"artoo router dagobah","capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true,"tags":["tag:lab-router"]}}},"created":"2026-11-15T10:00:00Z","expires":"2026-11-15T10:10:00Z"},
            \\{"id":"kClient","keyType":"client","description":"artoo","scopes":["devices:core"],"tags":["tag:lab-router"],"created":"2026-11-01T10:00:00Z"}]}
        ),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/keys", "{\"keys\":[{\"id\":\"kAuth1\",\"key\":\"tskey-auth-LEAKED\",\"keyType\":\"auth\"}]}"),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts keys ls"));
    try expectHas(f.h.stdout(), &.{ "kAuth1", "single-use, preauthorized", "kClient" });
    try testing.expect(std.mem.find(u8, f.h.stdout(), "LEAKED") == null);
    try testing.expectEqual(Exit.ok, f.h.run(&root, "-o json ts keys ls"));
    try testing.expect(std.mem.find(u8, f.h.stdout(), "LEAKED") == null);
    try testing.expect(std.mem.find(u8, f.h.stderr(), "LEAKED") == null);
}

test "ts policy show, validate and preview: read-only calls with HuJSON" {
    var f: Fixture = undefined;
    const policy = "// lab policy\n{\"acls\":[{\"action\":\"accept\",\"src\":[\"autogroup:member\"],\"dst\":[\"tag:lab-router:*\"]}]}\n";
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        .{ .match = "GET /tailnet/-/acl", .behavior = .{ .respond = .{ .body = policy, .extra = "etag: \"e1\"\r\n" } } },
        route("POST /oauth/token", token_ok),
        route("POST /tailnet/-/acl/validate", "{}"),
        route("POST /oauth/token", token_ok),
        route("POST /tailnet/-/acl/validate", "{\"message\":\"test(s) failed\",\"data\":[{\"user\":\"me@example.com\",\"errors\":[\"address \\\"192.168.1.10:22\\\": want: Accept, got: Drop\"]}]}"),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/acl", policy),
        route("POST /tailnet/-/acl/preview?type=ipport&previewFor=192.168.1.10%3A8006", "{\"matches\":[{\"users\":[\"autogroup:member\"],\"ports\":[\"192.168.1.10:8006\"],\"lineNumber\":3}],\"type\":\"ipport\",\"previewFor\":\"192.168.1.10:8006\"}"),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts policy show"));
    try testing.expectEqualStrings(policy, f.h.stdout());
    const file = try f.file("policy.hujson", policy);
    try testing.expectEqual(Exit.ok, f.h.runArgs(&root, &.{ "ts", "policy", "validate", file }));
    try testing.expect(std.mem.find(u8, f.h.stdout(), "is valid and its tests pass") != null);
    try testing.expectEqual(Exit.partial, f.h.runArgs(&root, &.{ "ts", "policy", "validate", file }));
    try testing.expect(std.mem.find(u8, f.h.stdout(), "me@example.com: address \"192.168.1.10:22\": want: Accept, got: Drop") != null);
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts policy preview 192.168.1.10:8006"));
    try expectHas(f.h.stdout(), &.{"   3  autogroup:member  192.168.1.10:8006"});
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    // The validate request carried the file as HuJSON.
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "POST /tailnet/-/acl/validate")) {
        try testing.expect(std.mem.find(u8, q, "content-type: application/hujson") != null);
        try testing.expect(std.mem.endsWith(u8, q, policy));
    };
    try testing.expectEqual(Exit.usage, f.h.run(&root, "ts policy preview nobody"));
}

test "ts device rename: lab devices only, POST name, verified by a fresh read" {
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("POST /device/nNaboo/name", "{}"),
        route("GET /device/nNaboo?fields=all", "{\"nodeId\":\"nNaboo\",\"name\":\"hoth.example.ts.net\"}"),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    // The operator's phone is never renamed.
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts device rename phone hoth -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "not a lab device") != null);
    try testing.expectEqual(Exit.usage, f.h.run(&root, "ts device rename naboo Hoth_1 -y"));
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts device rename naboo hoth -y"));
    try expectHas(f.h.stdout(), &.{ "Plan · Rename tailnet device naboo to hoth", "name  naboo.example.ts.net → hoth", "✓ device renamed and verified" });
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "POST /device/nNaboo/name")) try testing.expect(std.mem.endsWith(u8, q, "{\"name\":\"hoth\"}"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
}

test "ts device rm: typed confirmation; DELETE verified by 404; never the operator's devices" {
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("DELETE /device/nNaboo", ""),
        .{ .match = "GET /device/nNaboo", .behavior = .{ .respond = .{ .status = 404, .body = "{\"message\":\"device not found\"}" } } },
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts device rm phone -y --confirm phone"));
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts device rm naboo -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "--confirm naboo") != null);
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts device rm naboo -y --confirm naboo"));
    try testing.expect(std.mem.endsWith(u8, f.h.stdout(), "✓ device removed and verified (Tailscale answers 404)\n"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
}

test "ts routes approve: exactly the LAN; refused when not advertised" {
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("GET /device/nRouter/routes", "{\"advertisedRoutes\":[\"10.0.0.0/8\",\"0.0.0.0/0\"],\"enabledRoutes\":[]}"),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_body),
        route("GET /device/nRouter/routes", "{\"advertisedRoutes\":[\"192.168.1.0/24\",\"0.0.0.0/0\"],\"enabledRoutes\":[\"0.0.0.0/0\"]}"),
        route("POST /device/nRouter/routes", "{\"advertisedRoutes\":[\"192.168.1.0/24\"],\"enabledRoutes\":[\"192.168.1.0/24\"]}"),
        route("GET /device/nRouter/routes", "{\"advertisedRoutes\":[\"192.168.1.0/24\",\"0.0.0.0/0\"],\"enabledRoutes\":[\"192.168.1.0/24\"]}"),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts routes approve dagobah -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "does not advertise 192.168.1.0/24") != null);
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts routes approve dagobah -y"));
    try expectHas(f.h.stdout(), &.{ "approved routes  0.0.0.0/0 → 192.168.1.0/24", "0.0.0.0/0 was approved and is withdrawn", "✓ route approved and verified" });
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "POST /device/nRouter/routes")) try testing.expect(std.mem.endsWith(u8, q, "{\"routes\":[\"192.168.1.0/24\"]}"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
}

test "ts dns split set: lab domains to the gateway only; PATCH with that domain alone" {
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/dns/split-dns", "{\"corp.example.net\":[\"10.0.0.53\"]}"),
        route("PATCH /tailnet/-/dns/split-dns", "{\"corp.example.net\":[\"10.0.0.53\"],\"lab.example.com\":[\"192.168.1.1\"]}"),
        route("GET /tailnet/-/dns/split-dns", "{\"corp.example.net\":[\"10.0.0.53\"],\"lab.example.com\":[\"192.168.1.1\"]}"),
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/dns/split-dns", "{\"lab.example.com\":[\"192.168.1.1\"]}"),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts dns split set example.org 192.168.1.1 -y"));
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts dns split set home.arpa 1.1.1.1 -y"));
    try testing.expectEqual(@as(usize, 0), f.sent());
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts dns split set lab.example.com 192.168.1.1 -y"));
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "PATCH")) try testing.expect(std.mem.endsWith(u8, q, "{\"lab.example.com\":[\"192.168.1.1\"]}"));
    // Already so: a no-op, refused (exit 5).
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts dns split set lab.example.com 192.168.1.1 -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "nothing to change") != null);
}
