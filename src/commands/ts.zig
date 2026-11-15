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
const vm_cmd = @import("vm.zig");
const agent = @import("../pve/agent.zig");
const edge = @import("edge.zig");
const ui_diff = @import("../ui/diff.zig");

const Context = app.Context;
const Value = std.json.Value;

/// The tags artoo's join keys carry: its devices.
pub fn labTags(ctx: *Context) ![]const []const u8 {
    const cfg = try ctx.config();
    var out: std.ArrayList([]const u8) = .empty;
    try out.append(ctx.arena, tn.router_tag);
    try out.appendSlice(ctx.arena, try config.tsTags(ctx.arena, cfg.tailscale.guest_tags));
    return out.items;
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
fn labDevice(ctx: *Context, c: *ts.Client, word: []const u8) !struct { tn.Device, []const u8, tn.Ownership } {
    const d = try resolveDevice(ctx, try tn.devices(c), word);
    const own = try ownership(ctx, true);
    const why = own.reason(d) orelse return ctx.fail(error.Refused, "{s} is not a lab device (no tag {s}, no VM tagged artoo of that name); artoo changes lab devices only (SPEC §19)", .{ try clean(ctx, d.machine), tn.router_tag });
    return .{ d, why, own };
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
        op.dev, const why, const own = try labDevice(ctx, op.c, op.word);
        op.target = try clean(ctx, op.dev.machine);
        // A device that is a lab device by its VM name alone would leave
        // the lab under a name that is no artoo VM (and its recovery
        // rename would then be refused).
        if (std.mem.eql(u8, why, "vm")) {
            var kept = false;
            for (own.artoo_vms) |n| kept = kept or std.ascii.eqlIgnoreCase(n, op.new);
            if (!kept) return ctx.fail(error.Refused, "{s} is a lab device only by its VM name; {s} is no VM tagged artoo, so the renamed device would leave the lab — rename the guest with 'artoo vm rename' instead", .{ op.target, op.new });
        }
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
        op.dev, _, _ = try labDevice(ctx, op.c, op.word);
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
        op.dev, _, _ = try labDevice(ctx, op.c, op.word);
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

// ---------------------------------------------------------------- join

/// The guest's own view: `tailscale status --json` (`{}` when absent).
pub const GuestState = struct {
    backend: []const u8 = "unknown",
    hostname: []const u8 = "",
    dns_name: []const u8 = "",
    tags: []const []const u8 = &.{},
    /// `Self.ID`, the stable node ID the API calls `nodeId`.
    node_id: []const u8 = "",
    raw: []const u8 = "",

    pub fn running(s: GuestState) bool {
        return std.mem.eql(u8, s.backend, "Running");
    }
};

pub fn parseGuestState(a: std.mem.Allocator, out: []const u8) !GuestState {
    const v = std.json.parseFromSliceLeaky(Value, a, out, .{}) catch Value{ .null = {} };
    const self = ts.field(v, "Self");
    return .{
        .backend = ts.str(v, "BackendState") orelse "unknown",
        .hostname = ts.str(self, "HostName") orelse "",
        .dns_name = std.mem.trimEnd(u8, ts.str(self, "DNSName") orelse "", "."),
        .tags = try ts.strings(a, self, "Tags"),
        .node_id = ts.str(self, "ID") orelse "",
        .raw = out,
    };
}

pub fn guestState(c: *pve.Client, vmid: u32) !GuestState {
    const ctx = c.ctx;
    const r = try agent.sh(c, vmid, "tailscale status --json 2>/dev/null || echo '{}'", 60_000);
    if (!r.ok()) return ctx.fail(error.Protocol, "reading tailscale status on VM {d} failed", .{vmid});
    return parseGuestState(ctx.arena, r.out);
}

/// Enrolls with the key on stdin: written to a 0600 file under /run,
/// passed as `file:`, removed on exit. `$1` hostname, `$2` tag. A tagged
/// node that accepts no routes, advertises none, runs no Tailscale SSH and
/// keeps its own DNS (SPEC §9.6).
const join_script =
    \\set -eu
    \\umask 077
    \\key=$(mktemp /run/artoo-tskey.XXXXXX)
    \\trap 'rm -f "$key"' EXIT
    \\cat > "$key"
    \\tailscale up --auth-key="file:$key" --advertise-tags="$2" --hostname="$1" --accept-routes=false --advertise-routes= --accept-dns=false --ssh=false --timeout=60s
    \\
;

const join_timeout_ms = 2 * 60 * 1000;

const JoinOp = struct {
    c: *pve.Client,
    tsc: *ts.Client,
    word: []const u8,
    tag: []const u8,
    target: []const u8 = "",
    risk: ui.blocks.Risk = .normal,
    api: ui.json.Target = .tailscale,
    vm: vms.Vm = undefined,
    state: GuestState = .{},
    ledger: exec.Ledger = .{},
    key: ?tn.NewKey = null,
    key_used: bool = false,
    device: ?tn.Device = null,

    pub fn read(op: *JoinOp, ctx: *Context) !void {
        const v = try vms.resolve(op.c, op.word);
        op.vm = v;
        op.target = v.name;
        if (v.template) return ctx.fail(error.Refused, "{s} is a template", .{v.name});
        if (!template.taggedWith(v.tags, "artoo")) return ctx.fail(error.Refused, "{s} is not an artoo guest (no tag artoo)", .{v.name});
        if (vm_cmd.roleOf(v.tags)) |r| if (std.mem.eql(u8, r, "edge") or std.mem.eql(u8, r, "watch") or std.mem.eql(u8, r, "router"))
            return ctx.fail(error.Refused, "{s} carries role-{s}: {s}", .{ v.name, r, if (std.mem.eql(u8, r, "router")) "it joins with 'artoo router setup'" else "it never joins the tailnet (SPEC §9.6, §9.7, §9.9)" });
        if (!template.taggedWith(v.tags, "tailnet")) return ctx.fail(error.Refused, "{s} is not tagged tailnet; guests join the tailnet only when tagged (SPEC §9.6): 'artoo vm set {s} tags=…;tailnet' first", .{ v.name, v.name });
        if (!v.running()) return ctx.fail(error.Refused, "{s} is {s}; start it first", .{ v.name, v.status });
        if (!try agent.ping(op.c, v.vmid)) return ctx.fail(error.Refused, "the guest agent of {s} does not answer", .{v.name});
        op.state = try guestState(op.c, v.vmid);
        if (op.state.running()) return ctx.fail(error.NoChange, "{s} is already on the tailnet ({s}, tags {s}); nothing to join", .{ v.name, try clean(ctx, if (op.state.dns_name.len > 0) op.state.dns_name else op.state.hostname), try joinClean(ctx, op.state.tags) });
    }

    pub fn plan(op: *JoinOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        return .{
            .action = try std.fmt.allocPrint(a, "Join {s} ({d}) to the tailnet", .{ op.vm.name, op.vm.vmid }),
            .target = try deviceTarget(ctx, op.tsc),
            .changes = try a.dupe(ui.blocks.Change, &.{
                .{ .field = "join key", .from = null, .to = try std.fmt.allocPrint(a, "single-use, preauthorized, {s}, 10 min (created by artoo, never shown)", .{op.tag}) },
                .{ .field = "tailnet", .from = try clean(ctx, op.state.backend), .to = try std.fmt.allocPrint(a, "{s} as {s}: no routes accepted or advertised, no Tailscale SSH, its own DNS", .{ op.vm.name, op.tag }) },
            }),
            .impact = try a.dupe([]const u8, &.{try std.fmt.allocPrint(a, "Tailnet devices reach {s} as the policy allows {s}", .{ op.vm.name, op.tag })}),
            .recovery = try std.fmt.allocPrint(a, "artoo ts device rm {s}", .{op.vm.name}),
            .notes = try a.dupe([]const u8, &.{"The key goes over the guest agent's stdin into a 0600 file under /run, removed after use; a key left unused by a failed run is deleted."}),
        };
    }

    pub fn fingerprint(op: *JoinOp) []const u8 {
        return op.state.raw;
    }

    pub fn send(op: *JoinOp, ctx: *Context) !void {
        const a = ctx.arena;
        const l = &op.ledger;
        const s_key = try l.add(a, "create the join key");
        const s_join = try l.add(a, "join the tailnet");
        errdefer {
            op.dropKey(ctx);
            ctx.out.writeAll("\n") catch {};
            l.render(ctx.out, &ctx.ui) catch {};
        }
        l.set(s_key, .unknown, "");
        const nk = try tn.createJoinKey(op.tsc, &.{op.tag}, try tn.keyDescription(a, &.{ "artoo", "join", op.vm.name }));
        op.key = nk;
        l.set(s_key, .done, try std.fmt.allocPrint(a, "{s}, single-use, 10 min", .{try clean(ctx, nk.id)}));
        l.set(s_join, .unknown, "");
        const r = try agent.exec(op.c, op.vm.vmid, &.{ "sh", "-c", join_script, "sh", op.vm.name, op.tag }, nk.key, join_timeout_ms);
        if (!r.ok()) {
            l.set(s_join, .failed, "");
            const why = try tn.redact(a, edge.firstLine(if (r.err.len > 0) r.err else r.out), nk.key);
            return ctx.fail(error.Partial, "tailscale up failed on {s} (exit {?d}): {s}", .{ op.vm.name, r.code, try clean(ctx, why) });
        }
        op.key_used = true;
        l.set(s_join, .done, op.tag);
    }

    /// Delete the key artoo created when the guest did not use it; keeps
    /// the error being reported.
    fn dropKey(op: *JoinOp, ctx: *Context) void {
        const k = op.key orelse return;
        if (op.key_used) return;
        const diag = ctx.diag;
        defer ctx.diag = diag;
        tn.deleteKey(op.tsc, k.id) catch return;
        op.key = null;
    }

    /// The guest says Running with the tag, and the API lists its device
    /// with the tag (polled briefly).
    pub fn verify(op: *JoinOp, ctx: *Context) !bool {
        try ctx.out.writeAll("\n");
        try op.ledger.render(ctx.out, &ctx.ui);
        const st = try guestState(op.c, op.vm.vmid);
        if (!st.running() or !tn.contains(st.tags, op.tag) or st.node_id.len == 0) return false;
        // The node the guest says it is (`Self.ID`), never a device found
        // by name: an old device of the same name may still be listed.
        var tries: usize = 0;
        while (true) : (tries += 1) {
            if (try tn.getDevice(op.tsc, st.node_id)) |d| if (d.hasTag(op.tag)) {
                op.device = d;
                return true;
            };
            if (tries >= 10) return false;
            try ctx.io.sleep(.fromMilliseconds(@intCast(ctx.test_hooks.poll_ms orelse 2000)), .awake);
        }
    }

    pub fn done(op: *JoinOp) []const u8 {
        const d = op.device orelse return "joined";
        return std.fmt.allocPrint(op.c.ctx.arena, "{s} joined the tailnet as {s} ({s})", .{ op.vm.name, op.tag, clean(op.c.ctx, d.name) catch d.id }) catch "joined";
    }
};

pub const join = struct {
    pub const name = "join";
    pub const summary = "Join a guest tagged tailnet to the tailnet with a key artoo creates";
    pub const details =
        \\The guest becomes a tagged node with --tag, one of
        \\tailscale.guest_tags (default: the first): it accepts no
        \\routes, advertises none, runs no Tailscale SSH and keeps its own DNS
        \\(SPEC §9.6). artoo creates a single-use, preauthorized key (10 min),
        \\hands it to the guest over the agent's stdin and never shows it; a key
        \\left unused by a failed run is deleted. Refused for guests without the
        \\tailnet tag, role-edge, role-watch and role-router; a guest already
        \\on the tailnet is only reported.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "VM", .help = "A running guest tagged tailnet", .complete = .vm }};
    pub const flags = [_]cli.Flag{.{ .long = "tag", .kind = .string, .metavar = "TAG", .help = "One of tailscale.guest_tags (default: the first)" }};
    pub const examples = [_][]const u8{ "artoo ts join naboo -n", "artoo ts join naboo --tag tag:lab-guest" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const cfg = try ctx.config();
        const allowed = try config.tsTags(ctx.arena, cfg.tailscale.guest_tags);
        if (allowed.len == 0) return ctx.fail(error.ConfigInvalid, "tailscale.guest_tags is empty", .{});
        const tag = if (args.string("tag")) |want| blk: {
            for (allowed) |t| if (std.mem.eql(u8, t, want)) break :blk t;
            return ctx.fail(error.Refused, "--tag {s} is not in tailscale.guest_tags ({s}); add it there first", .{ try clean(ctx, want), try std.mem.join(ctx.arena, ", ", allowed) });
        } else allowed[0];
        var c = try pve.Client.open(ctx);
        defer c.deinit();
        var tsc = try ts.Client.open(ctx, .main);
        defer tsc.deinit();
        var op: JoinOp = .{ .c = &c, .tsc = &tsc, .word = args.pos("VM"), .tag = tag };
        try exec.run(ctx, &op, .{});
    }
};

// ---------------------------------------------------------------- policy apply

/// Refuses, before any request, a policy that is not HuJSON or that
/// grants Funnel (SPEC §9.6, §19): no override.
pub fn checkPolicyLocally(ctx: *Context, word: []const u8, text: []const u8) !void {
    const a = ctx.arena;
    const json = tn.hujsonToJson(a, text) catch return ctx.fail(error.Refused, "{s} is not valid HuJSON (an unterminated string or comment, or a stray '/')", .{word});
    const v = std.json.parseFromSliceLeaky(Value, a, json, .{}) catch return ctx.fail(error.Refused, "{s} is not valid HuJSON", .{word});
    if (v != .object) return ctx.fail(error.Refused, "{s} is not a policy (expected an object)", .{word});
    if (tn.nonAsciiKey(v)) |key| return ctx.fail(error.Refused, "{s} has the non-ASCII key \"{s}\"; Tailscale folds key case (Unicode included), so artoo refuses keys it cannot check (SPEC §19)", .{ word, try clean(ctx, key) });
    const funnel = try tn.funnelAttrs(a, v);
    if (funnel.len > 0) return ctx.fail(error.Refused, "{s} grants Funnel in nodeAttrs ({s}); artoo never applies a policy that opens tailnet devices to the internet (SPEC §9.6)", .{ word, try joinClean(ctx, funnel) });
}

/// The tailnet's DNS name for the typed confirmation: `tailscale.tailnet`
/// when it names one, else the suffix of a device's MagicDNS name.
fn tailnetName(ctx: *Context, c: *ts.Client) ![]const u8 {
    if (!std.mem.eql(u8, c.tailnet, "-")) return c.tailnet;
    for (try tn.devices(c)) |d| if (std.mem.findScalar(u8, d.name, '.')) |dot| {
        const rest = d.name[dot + 1 ..];
        if (rest.len > 0) return clean(ctx, rest);
    };
    return ctx.fail(error.Refused, "cannot tell the tailnet's name for the confirmation (no device lists one); set it with 'artoo config set tailscale.tailnet NAME'", .{});
}

fn writeDiff(ctx: *Context, w: *Io.Writer, u: *const ui.Ui, hs: []const ui_diff.Hunk) !void {
    const p = u.palette;
    try w.print("{s}--- live policy{s}\n{s}+++ file{s}\n", .{ p.on(.muted), p.off(.muted), p.on(.muted), p.off(.muted) });
    for (hs) |h| {
        try w.print("{s}@@ -{d},{d} +{d},{d} @@{s}\n", .{ p.on(.muted), h.old_start, h.old_len, h.new_start, h.new_len, p.off(.muted) });
        for (h.lines) |l| {
            const role: ui.style.Role, const mark: u8 = switch (l.kind) {
                .same => .{ .text, ' ' },
                .del => .{ .fail, '-' },
                .add => .{ .ok, '+' },
            };
            try w.print("{s}{c}{s}{s}\n", .{ p.on(role), mark, try clean(ctx, l.text), p.off(role) });
        }
    }
    try w.writeAll("\n");
}

const ApplyOp = struct {
    c: *ts.Client,
    word: []const u8,
    text: []const u8,
    target: []const u8 = "",
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .tailscale,
    live: tn.Policy = .{ .text = "", .etag = null },
    etag: []const u8 = "",
    validation: Validation = undefined,

    pub fn read(op: *ApplyOp, ctx: *Context) !void {
        op.target = try tailnetName(ctx, op.c);
        op.live = try tn.policy(op.c, false);
        op.etag = op.live.etag orelse return ctx.fail(error.Protocol, "Tailscale answered the policy without an ETag; artoo applies a policy only against the version it read (If-Match)", .{});
        op.validation = try validate(op.c, op.text);
        if (!op.validation.ok) {
            const p = ctx.ui.palette;
            for (op.validation.errors) |e| try ctx.err.print("{s}{s}{s} {s}\n", .{ p.on(.fail), ctx.ui.glyphs.fail, p.off(.fail), e });
            return ctx.fail(error.Refused, "{s} did not validate{s}{s}; nothing was applied", .{ op.word, if (op.validation.message.len > 0) ": " else "", op.validation.message });
        }
    }

    pub fn plan(op: *ApplyOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const d = try ui_diff.diff(a, op.live.text, op.text);
        const hs = try ui_diff.hunks(a, d, 3);
        if (hs.len == 0) return null;
        const st = ui_diff.stats(d);
        const w = if (ctx.json()) ctx.err else ctx.out;
        try writeDiff(ctx, w, if (ctx.json()) &ctx.err_ui else &ctx.ui, hs);
        var notes: std.ArrayList([]const u8) = .empty;
        try notes.append(a, "Tailscale validated the file and ran its tests; it is sent once, only if the live policy is still the version read (If-Match).");
        for (op.validation.warnings) |wn| try notes.append(a, try std.fmt.allocPrint(a, "warning: {s}", .{wn}));
        return .{
            .action = try std.fmt.allocPrint(a, "Replace the tailnet policy with {s}", .{try clean(ctx, op.word)}),
            .risk = .destructive,
            .target = try std.fmt.allocPrint(a, "Tailscale policy of {s}", .{op.target}),
            .changes = try a.dupe(ui.blocks.Change, &.{.{
                .field = "policy",
                .from = try std.fmt.allocPrint(a, "live, ETag {s}", .{try clean(ctx, op.etag)}),
                .to = try std.fmt.allocPrint(a, "{s}: +{d} -{d} lines", .{ try clean(ctx, op.word), st.added, st.removed }),
            }}),
            .impact = try a.dupe([]const u8, &.{"Who may reach what on the tailnet changes as the diff shows, for every device at once"}),
            .recovery = "keep the live policy first ('artoo ts policy show > before.hujson') and apply it again to revert",
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *ApplyOp) []const u8 {
        return op.etag;
    }

    pub fn send(op: *ApplyOp, _: *Context) !void {
        try tn.setPolicy(op.c, op.text, op.etag);
    }

    pub fn verify(op: *ApplyOp, ctx: *Context) !bool {
        const now = try tn.policy(op.c, false);
        return tn.samePolicy(ctx.arena, now.text, op.text);
    }

    pub fn done(_: *ApplyOp) []const u8 {
        return "policy applied and verified (a fresh read matches the file)";
    }
};

pub const policy_apply = struct {
    pub const name = "apply";
    pub const summary = "Replace the tailnet policy with a HuJSON file (high impact; the policy credential)";
    pub const details =
        \\Uses the separate tailscale-policy credential, never the main one:
        \\create it for the change and revoke it afterwards. Refused before any
        \\request when the file grants Funnel. Tailscale validates the file and
        \\runs its tests; the plan shows the diff live → file; the write is sent
        \\once with If-Match (the ETag read), so a policy changed meanwhile is
        \\refused; a fresh read verifies it. -n stops after validation and the
        \\diff. Interactive: type the tailnet's name to confirm.
        \\Non-interactive: --yes --confirm TAILNET.
    ;
    pub const positionals = [_]cli.Positional{.{ .name = "FILE", .help = "HuJSON policy file", .complete = .file }};
    pub const flags = [_]cli.Flag{.{ .long = "confirm", .kind = .string, .metavar = "TAILNET", .help = "Non-interactive confirmation (with --yes)" }};
    pub const examples = [_][]const u8{ "artoo ts policy apply policy.hujson -n", "artoo ts policy apply policy.hujson" };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const word = args.pos("FILE");
        const text = try readPolicyFile(ctx, word);
        try checkPolicyLocally(ctx, word, text);
        var c = try ts.Client.open(ctx, .policy);
        defer c.deinit();
        var op: ApplyOp = .{ .c = &c, .word = word, .text = text };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

pub const group = cli.group("ts", "Tailscale: the lab's devices, routes, split DNS and keys on the tailnet (SPEC §19)", &.{
    cli.leaf(join),
    cli.group("devices", "Devices on the tailnet", &.{cli.leaf(devices_ls)}),
    cli.group("device", "One device", &.{ cli.leaf(device_show), cli.leaf(device_rename), cli.leaf(device_rm) }),
    cli.group("routes", "Subnet routes", &.{cli.leaf(routes_approve)}),
    cli.group("dns", "Tailnet DNS", &.{ cli.leaf(dns_show), cli.group("split", "Split DNS for the lab's domains", &.{cli.leaf(dns_split_set)}) }),
    cli.group("keys", "Auth key metadata", &.{cli.leaf(keys_ls)}),
    cli.group("policy", "The tailnet policy", &.{ cli.leaf(policy_show), cli.leaf(policy_validate), cli.leaf(policy_preview), cli.leaf(policy_apply) }),
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

const vms_hoth = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;tailnet\"},{\"vmid\":203,\"name\":\"hoth\",\"status\":\"stopped\",\"tags\":\"artoo\"}]}";

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
        route("POST /oauth/token", token_ok),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("GET /tailnet/-/devices?fields=all", devices_body),
        route("/qemu", vms_hoth),
        route("POST /device/nNaboo/name", "{}"),
        route("GET /device/nNaboo?fields=all", "{\"nodeId\":\"nNaboo\",\"name\":\"hoth.example.ts.net\"}"),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    // The operator's phone is never renamed.
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts device rename phone hoth -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "not a lab device") != null);
    try testing.expectEqual(Exit.usage, f.h.run(&root, "ts device rename naboo Hoth_1 -y"));
    // naboo is a lab device by its VM name only: a name that is no artoo
    // VM would take it out of the lab.
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts device rename naboo hoth -y"));
    try testing.expect(std.mem.find(u8, f.h.stderr(), "only by its VM name") != null);
    try testing.expect(std.mem.find(u8, f.h.stderr(), "artoo vm rename") != null);
    // With an artoo VM hoth, the renamed device stays a lab device.
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

fn agentOut(a: std.mem.Allocator, code: i64, out: []const u8, err: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .data = .{ .exited = 1, .exitcode = code, .@"out-data" = out, .@"err-data" = err } }, .{});
}

const join_vms = "{\"data\":[{\"vmid\":201,\"name\":\"naboo\",\"status\":\"running\",\"tags\":\"artoo;tailnet\"},{\"vmid\":202,\"name\":\"dagobah\",\"status\":\"running\",\"tags\":\"artoo;role-router;tailnet\"},{\"vmid\":203,\"name\":\"hoth\",\"status\":\"running\",\"tags\":\"artoo\"},{\"vmid\":204,\"name\":\"bespin\",\"status\":\"running\",\"tags\":\"artoo;role-edge;tailnet\"},{\"vmid\":205,\"name\":\"scarif\",\"status\":\"running\",\"tags\":\"artoo;role-watch;tailnet\"},{\"vmid\":206,\"name\":\"kessel\",\"status\":\"stopped\",\"tags\":\"artoo;tailnet\"},{\"vmid\":207,\"name\":\"endor\",\"status\":\"running\",\"tags\":\"tailnet\"}]}";
const join_key = "{\"id\":\"kJoin\",\"key\":\"tskey-auth-JOINSECRET\",\"keyType\":\"auth\"}";
const agent_up = "{\"data\":{\"result\":{}}}";

test "ts join: artoo creates a single-use guest key, the guest joins as a tagged node, verified by guest and API" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /api2/json/nodes/pve/qemu HTTP", join_vms),
        route("agent/ping", agent_up),
        route("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        route("exec-status", try agentOut(a, 0, "{\"BackendState\":\"NeedsLogin\"}", "")),
        route("POST /tailnet/-/keys", join_key),
        route("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        route("exec-status", try agentOut(a, 0, "", "")),
        route("agent/exec HTTP", "{\"data\":{\"pid\":44}}"),
        route("exec-status", try agentOut(a, 0, "{\"BackendState\":\"Running\",\"Self\":{\"ID\":\"nNew\",\"HostName\":\"naboo\",\"DNSName\":\"naboo.example.ts.net.\",\"Tags\":[\"tag:lab-guest\"]}}", "")),
        route("GET /device/nNew?", "{\"nodeId\":\"nNew\",\"name\":\"naboo.example.ts.net\",\"tags\":[\"tag:lab-guest\"]}"),
        // A stale, offline device of the same name: never consulted.
        route("GET /tailnet/-/devices", "{\"devices\":[{\"nodeId\":\"nOld\",\"name\":\"naboo.example.ts.net\",\"tags\":[\"tag:lab-guest\"],\"connectedToControl\":false}]}"),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    const code = f.h.run(&root, "ts join naboo -y");
    const out = f.h.stdout();
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ out, f.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 1), f.srv.unused());
    for (f.srv.received) |req| if (req) |q| try testing.expect(std.mem.find(u8, q, "nOld") == null and !std.mem.startsWith(u8, q, "GET /tailnet/-/devices"));
    try expectHas(out, &.{
        "single-use, preauthorized, tag:lab-guest, 10 min (created by artoo, never shown)",
        "create the join key  done  kJoin, single-use, 10 min",
        "join the tailnet     done  tag:lab-guest",
        "naboo joined the tailnet as tag:lab-guest (naboo.example.ts.net)",
    });
    var joined = false;
    for (f.srv.received) |req| if (req) |q| {
        if (std.mem.startsWith(u8, q, "POST /tailnet/-/keys")) try testing.expect(std.mem.endsWith(u8, q,
            \\{"keyType":"auth","description":"artoo join naboo","expirySeconds":600,"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true,"tags":["tag:lab-guest"]}}}}
        ));
        // The key travels only as the agent's stdin, never in argv.
        if (std.mem.find(u8, q, "JOINSECRET") != null) {
            try testing.expect(std.mem.find(u8, q, "input-data=tskey-auth-JOINSECRET") != null);
            try testing.expect(std.mem.find(u8, q, "accept-routes%3Dfalse") != null or std.mem.find(u8, q, "accept-routes=false") != null);
            joined = true;
        }
    };
    try testing.expect(joined);
    try testing.expect(std.mem.find(u8, out, "JOINSECRET") == null);
    try testing.expect(std.mem.find(u8, f.h.stderr(), "JOINSECRET") == null);
}

test "ts join: refused for a guest without tailnet, edge, watch, router, stopped and foreign guests; no key is created" {
    for ([_][]const u8{ "hoth", "bespin", "scarif", "dagobah", "kessel", "endor" }) |vm| {
        var f: Fixture = undefined;
        try f.initRoutes(&.{
            route("POST /oauth/token", token_ok),
            route("GET /api2/json/nodes/pve/qemu HTTP", join_vms),
        });
        defer f.deinit();
        try f.tailscaleConfig("");
        const line = try std.fmt.allocPrint(f.h.arena.allocator(), "ts join {s} -y", .{vm});
        try testing.expectEqual(Exit.refused, f.h.run(&root, line));
        for (f.srv.received) |req| if (req) |q| try testing.expect(std.mem.find(u8, q, "/keys") == null);
    }
}

test "ts join: a guest already on the tailnet is only reported" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /api2/json/nodes/pve/qemu HTTP", join_vms),
        route("agent/ping", agent_up),
        route("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        route("exec-status", try agentOut(a, 0, "{\"BackendState\":\"Running\",\"Self\":{\"HostName\":\"naboo\",\"DNSName\":\"naboo.example.ts.net.\",\"Tags\":[\"tag:lab-guest\"]}}", "")),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts join naboo -y"));
    if (std.mem.find(u8, f.h.stderr(), "already on the tailnet (naboo.example.ts.net, tags tag:lab-guest)") == null) {
        std.debug.print("--- err:\n{s}\n", .{f.h.stderr()});
        return error.TestUnexpectedResult;
    }
    for (f.srv.received) |req| if (req) |q| try testing.expect(std.mem.find(u8, q, "/keys") == null);
}

test "ts join: a tag the client does not own is refused by Tailscale before anything reaches the guest" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /api2/json/nodes/pve/qemu HTTP", join_vms),
        route("agent/ping", agent_up),
        route("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        route("exec-status", try agentOut(a, 0, "{}", "")),
        .{ .match = "POST /tailnet/-/keys", .behavior = .{ .respond = .{ .status = 400, .body = "{\"message\":\"requested tags [tag:lab-guest] are invalid or not permitted\"}" } } },
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.refused, f.h.run(&root, "ts join naboo -y"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    if (std.mem.find(u8, f.h.stderr(), "not permitted") == null) {
        std.debug.print("--- err:\n{s}\n", .{f.h.stderr()});
        return error.TestUnexpectedResult;
    }
}

test "ts join: a failed join deletes the unused key and never shows it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /api2/json/nodes/pve/qemu HTTP", join_vms),
        route("agent/ping", agent_up),
        route("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        route("exec-status", try agentOut(a, 0, "{}", "")),
        route("POST /tailnet/-/keys", join_key),
        route("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        route("exec-status", try agentOut(a, 1, "", "backend error: invalid key tskey-auth-JOINSECRET")),
        route("DELETE /tailnet/-/keys/kJoin", ""),
    });
    defer f.deinit();
    try f.tailscaleConfig("");
    try testing.expectEqual(Exit.partial, f.h.run(&root, "ts join naboo -y"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    try testing.expect(std.mem.find(u8, f.h.stderr(), "invalid key [auth key]") != null);
    try testing.expect(std.mem.find(u8, f.h.stdout(), "JOINSECRET") == null);
    try testing.expect(std.mem.find(u8, f.h.stderr(), "JOINSECRET") == null);
}

test "ts join --tag: a tag outside tailscale.guest_tags is refused before any request; a listed one is used" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    {
        var f: Fixture = undefined;
        try f.initRoutes(&.{});
        defer f.deinit();
        try f.tmp.dir.createDirPath(testing.io, ".artoo");
        try f.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = "{\"schema_version\":1,\"tailscale\":{\"client_id\":\"kTEST1CNTRL\",\"guest_tags\":\"tag:lab-guest,tag:lab-app\"}}\n" });
        try testing.expectEqual(Exit.refused, f.h.run(&root, "ts join naboo --tag tag:lab-other -y"));
        try testing.expectEqual(@as(usize, 0), f.sent());
        try testing.expect(std.mem.find(u8, f.h.stderr(), "--tag tag:lab-other is not in tailscale.guest_tags (tag:lab-guest, tag:lab-app)") != null);
    }
    var f: Fixture = undefined;
    try f.initRoutes(&.{
        route("POST /oauth/token", token_ok),
        route("GET /api2/json/nodes/pve/qemu HTTP", join_vms),
        route("agent/ping", agent_up),
        route("agent/exec HTTP", "{\"data\":{\"pid\":42}}"),
        route("exec-status", try agentOut(a, 0, "{}", "")),
        route("POST /tailnet/-/keys", join_key),
        route("agent/exec HTTP", "{\"data\":{\"pid\":43}}"),
        route("exec-status", try agentOut(a, 0, "", "")),
        route("agent/exec HTTP", "{\"data\":{\"pid\":44}}"),
        route("exec-status", try agentOut(a, 0, "{\"BackendState\":\"Running\",\"Self\":{\"ID\":\"nNaboo\",\"HostName\":\"naboo\",\"Tags\":[\"tag:lab-app\"]}}", "")),
        route("GET /device/nNaboo?", "{\"nodeId\":\"nNaboo\",\"name\":\"naboo.example.ts.net\",\"tags\":[\"tag:lab-app\"]}"),
    });
    defer f.deinit();
    try f.tmp.dir.createDirPath(testing.io, ".artoo");
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = "{\"schema_version\":1,\"tailscale\":{\"client_id\":\"kTEST1CNTRL\",\"guest_tags\":\"tag:lab-guest,tag:lab-app\"}}\n" });
    try testing.expectEqual(Exit.ok, f.h.run(&root, "ts join naboo --tag tag:lab-app -y"));
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "POST /tailnet/-/keys"))
        try testing.expect(std.mem.find(u8, q, "\"tags\":[\"tag:lab-app\"]") != null);
}

const policy_cfg = "{\"schema_version\":1,\"tailscale\":{\"client_id\":\"kTEST1CNTRL\",\"policy_client_id\":\"kPOLICY\"}}\n";
const policy_token = "{\"access_token\":\"tskey-access-policy\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"policy_file devices:core:read devices:posture_attributes:read\"}";
const live_policy = "// lab\n{\n  \"grants\": [\n    {\"src\": [\"autogroup:member\"], \"dst\": [\"tag:lab-router\"], \"ip\": [\"*\"]},\n  ],\n}\n";
const new_policy = "// lab\n{\n  \"grants\": [\n    {\"src\": [\"autogroup:member\"], \"dst\": [\"tag:lab-router\"], \"ip\": [\"*\"]},\n    {\"src\": [\"autogroup:member\"], \"dst\": [\"tag:lab-guest\"], \"ip\": [\"443\"]},\n  ],\n}\n";

fn policyFixture(f: *Fixture, routes: []const Fixture.FakeServer.Route) !void {
    try f.initRoutes(routes);
    try f.tmp.dir.createDirPath(testing.io, ".artoo");
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = policy_cfg });
    try f.mem.map.put(f.h.arena.allocator(), "tailscale-policy", "tskey-client-policy-secret");
}

fn liveAcl(body: []const u8) Fixture.FakeServer.Route {
    return .{ .match = "GET /tailnet/-/acl HTTP", .behavior = .{ .respond = .{ .body = body, .extra = "etag: \"e0b2816b418\"\r\n" } } };
}

test "ts policy apply: a policy granting Funnel is refused before any request, without override" {
    var f: Fixture = undefined;
    try policyFixture(&f, &.{});
    defer f.deinit();
    const p = try f.file("funnel.hujson", "{\n  // open it up\n  \"nodeAttrs\": [{\"target\": [\"tag:lab-guest\"], \"attr\": [\"funnel\"]},],\n}\n");
    try testing.expectEqual(Exit.refused, f.h.run(&root, try std.fmt.allocPrint(f.h.arena.allocator(), "ts policy apply {s} -y --confirm example.ts.net", .{p})));
    try testing.expectEqual(@as(usize, 0), f.sent());
    try testing.expect(std.mem.find(u8, f.h.stderr(), "grants Funnel in nodeAttrs (funnel)") != null);
}

test "ts policy apply: Funnel under folded keys, and non-ASCII keys, are refused before any request" {
    for ([_][]const u8{
        "{\"NodeAttrs\": [{\"target\": [\"*\"], \"Attr\": [\"funnel\"]}]}",
        "{\"nodeattrs\": [{\"target\": [\"*\"], \"attr\": [\"funnel\"]}]}",
        "{\"nodeAttr\u{17F}\": [{\"target\": [\"*\"], \"attr\": [\"funnel\"]}]}",
        "{\"grants\": [], \"nodeAttrs\": [{\"target\": [\"*\"], \"\\u212Attr\": [\"x\"]}]}",
    }) |body| {
        var f: Fixture = undefined;
        try policyFixture(&f, &.{});
        defer f.deinit();
        const p = try f.file("p.hujson", body);
        try testing.expectEqual(Exit.refused, f.h.run(&root, try std.fmt.allocPrint(f.h.arena.allocator(), "ts policy apply {s} -y --confirm example.ts.net", .{p})));
        try testing.expectEqual(@as(usize, 0), f.sent());
    }
}

test "ts policy apply -n: validates and shows the diff, sends no write" {
    var f: Fixture = undefined;
    try policyFixture(&f, &.{
        route("POST /oauth/token", policy_token),
        route("GET /tailnet/-/devices", devices_body),
        liveAcl(live_policy),
        route("POST /tailnet/-/acl/validate", "{}"),
    });
    defer f.deinit();
    const p = try f.file("new.hujson", new_policy);
    try testing.expectEqual(Exit.ok, f.h.run(&root, try std.fmt.allocPrint(f.h.arena.allocator(), "ts policy apply {s} -n", .{p})));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    try expectHas(f.h.stdout(), &.{
        "@@ -2,5 +2,6 @@",
        "  \"grants\": [",
        "+    {\"src\": [\"autogroup:member\"], \"dst\": [\"tag:lab-guest\"], \"ip\": [\"443\"]},",
        "Tailscale policy of example.ts.net",
        "new.hujson: +1 -0 lines",
        "Dry run: nothing was sent.",
    });
    // Only the policy client was exchanged, never the main one.
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "POST /oauth/token"))
        try testing.expect(std.mem.endsWith(u8, q, "client_id=kPOLICY&client_secret=tskey-client-policy-secret"));
}

test "ts policy apply: sends once with If-Match as read, verified by a fresh read" {
    var f: Fixture = undefined;
    try policyFixture(&f, &.{
        route("POST /oauth/token", policy_token),
        route("GET /tailnet/-/devices", devices_body),
        liveAcl(live_policy),
        route("POST /tailnet/-/acl/validate", "{}"),
        route("POST /tailnet/-/acl HTTP", new_policy),
        liveAcl(new_policy),
    });
    defer f.deinit();
    const p = try f.file("new.hujson", new_policy);
    const code = f.h.run(&root, try std.fmt.allocPrint(f.h.arena.allocator(), "ts policy apply {s} -y --confirm example.ts.net", .{p}));
    if (code != .ok) std.debug.print("--- out:\n{s}\n--- err:\n{s}\n", .{ f.h.stdout(), f.h.stderr() });
    try testing.expectEqual(Exit.ok, code);
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    try expectHas(f.h.stdout(), &.{"policy applied and verified"});
    var posts: usize = 0;
    for (f.srv.received) |req| if (req) |q| if (std.mem.startsWith(u8, q, "POST /tailnet/-/acl HTTP")) {
        posts += 1;
        try testing.expect(std.ascii.findIgnoreCase(q, "if-match: \"e0b2816b418\"") != null);
        try testing.expect(std.ascii.findIgnoreCase(q, "content-type: application/hujson") != null);
        try testing.expect(std.mem.endsWith(u8, q, new_policy));
    };
    try testing.expectEqual(@as(usize, 1), posts);
}

test "ts policy apply: a policy changed since it was read (412) is refused, nothing applied" {
    var f: Fixture = undefined;
    try policyFixture(&f, &.{
        route("POST /oauth/token", policy_token),
        route("GET /tailnet/-/devices", devices_body),
        liveAcl(live_policy),
        route("POST /tailnet/-/acl/validate", "{}"),
        .{ .match = "POST /tailnet/-/acl HTTP", .behavior = .{ .respond = .{ .status = 412, .body = "{\"message\":\"precondition failed, invalid old hash\"}" } } },
    });
    defer f.deinit();
    const p = try f.file("new.hujson", new_policy);
    try testing.expectEqual(Exit.refused, f.h.run(&root, try std.fmt.allocPrint(f.h.arena.allocator(), "ts policy apply {s} -y --confirm example.ts.net", .{p})));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    try testing.expect(std.mem.find(u8, f.h.stderr(), "changed since it was read (412)") != null);
}

test "ts policy apply: a file Tailscale does not validate is refused before the plan" {
    var f: Fixture = undefined;
    try policyFixture(&f, &.{
        route("POST /oauth/token", policy_token),
        route("GET /tailnet/-/devices", devices_body),
        liveAcl(live_policy),
        route("POST /tailnet/-/acl/validate", "{\"message\":\"test(s) failed\",\"data\":[{\"user\":\"me@example.com\",\"errors\":[\"address \\\"tag:lab-guest:443\\\": want: Accept, got: Drop\"]}]}"),
    });
    defer f.deinit();
    const p = try f.file("new.hujson", new_policy);
    try testing.expectEqual(Exit.refused, f.h.run(&root, try std.fmt.allocPrint(f.h.arena.allocator(), "ts policy apply {s} -y --confirm example.ts.net", .{p})));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
    try testing.expect(std.mem.find(u8, f.h.stdout(), "Plan") == null);
}

test "the policy credential: only ts policy apply uses it; it needs its own secret" {
    // Only the policy client stored: other commands find no credential.
    {
        var f: Fixture = undefined;
        try policyFixture(&f, &.{});
        defer f.deinit();
        _ = f.mem.map.swapRemove("tailscale");
        try testing.expectEqual(Exit.auth, f.h.run(&root, "ts devices ls"));
        try testing.expectEqual(Exit.auth, f.h.run(&root, "ts policy show"));
        try testing.expectEqual(@as(usize, 0), f.sent());
    }
    // Only the main client stored: apply never falls back to it.
    var f: Fixture = undefined;
    try f.initRoutes(&.{});
    defer f.deinit();
    try f.tmp.dir.createDirPath(testing.io, ".artoo");
    try f.tmp.dir.writeFile(testing.io, .{ .sub_path = ".artoo/config.json", .data = policy_cfg });
    const p = try f.file("new.hujson", new_policy);
    try testing.expectEqual(Exit.auth, f.h.run(&root, try std.fmt.allocPrint(f.h.arena.allocator(), "ts policy apply {s} -y --confirm example.ts.net", .{p})));
    try testing.expectEqual(@as(usize, 0), f.sent());
}

test "ts policy apply: the confirmation must name the tailnet; a wrong one sends no write" {
    var f: Fixture = undefined;
    try policyFixture(&f, &.{
        route("POST /oauth/token", policy_token),
        route("GET /tailnet/-/devices", devices_body),
        liveAcl(live_policy),
        route("POST /tailnet/-/acl/validate", "{}"),
    });
    defer f.deinit();
    const p = try f.file("new.hujson", new_policy);
    try testing.expectEqual(Exit.refused, f.h.run(&root, try std.fmt.allocPrint(f.h.arena.allocator(), "ts policy apply {s} -y --confirm other.ts.net", .{p})));
    for (f.srv.received) |req| if (req) |q| try testing.expect(!std.mem.startsWith(u8, q, "POST /tailnet/-/acl HTTP"));
    try testing.expectEqual(@as(usize, 0), f.srv.unused());
}
