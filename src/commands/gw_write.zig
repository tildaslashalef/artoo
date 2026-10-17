//! Gateway writes (SPEC §10.2, §14.3): every catalog write becomes a verb
//! under `gw <resource>` (`add`, `set`, `patch`, `rm`, `restart`, …),
//! generated at compile time, plus the generic `gw api`. All of them run
//! the one mutation pipeline (`exec.zig`): local validation, a read of the
//! target, a plan with a field diff, confirmation (typed target for
//! destructive changes), one request, and a verifying read where the API
//! offers one. Actions the API cannot read back are reported as accepted,
//! never as verified.

const std = @import("std");
const app = @import("../app.zig");
const cli = @import("../cli.zig");
const exec = @import("../exec.zig");
const exposure = @import("../exposure.zig");
const http = @import("../http.zig");
const ui = @import("../ui.zig");
const catalog = @import("../unifi/catalog.zig");
const unifi = @import("../unifi/client.zig");
const view = @import("../unifi/view.zig");
const unibody = @import("../unifi/body.zig");
const gw = @import("gw.zig");

const Context = app.Context;
const Value = std.json.Value;
const Kind = catalog.Write.Kind;

const no_etags = "The UniFi API has no ETags; concurrent edits cannot be detected.";
/// Plan lines listed for a purge before summarizing the rest.
const purge_listed = 20;

fn targeted(k: Kind) bool {
    return switch (k) {
        .replace, .patch, .delete, .action, .port_action => true,
        else => false,
    };
}

const FileUse = enum { none, required, optional };

fn fileUse(w: catalog.Write) FileUse {
    return switch (w.kind) {
        .create, .replace, .patch, .ordering => .required,
        .action => if (w.fields.len > 0) .optional else .none,
        else => .none,
    };
}

/// `prefix a, b, c` wrapped at 76 columns with a hanging indent.
fn wrapList(comptime prefix: []const u8, comptime items: []const []const u8) []const u8 {
    comptime {
        var s: []const u8 = prefix;
        var col = prefix.len;
        for (items, 0..) |it, i| {
            const piece = it ++ (if (i + 1 < items.len) "," else ".");
            if (col + 1 + piece.len > 76) {
                s = s ++ "\n  ";
                col = 2;
            } else if (i > 0 or prefix.len > 0) {
                s = s ++ " ";
                col += 1;
            }
            s = s ++ piece;
            col += piece.len;
        }
        return s;
    }
}

fn detailsFor(comptime r: *const catalog.Resource, comptime w: catalog.Write) []const u8 {
    comptime {
        @setEvalBranchQuota(50_000);
        var s: []const u8 = @tagName(w.method) ++ " " ++ w.op.path ++ (if (w.kind == .purge) "?filter=EXPR" else "") ++ "\n" ++ switch (w.kind) {
            .create => "The body comes from --from FILE.",
            .replace => "Replaces the whole object: fields missing from the file revert to\nserver defaults (the preview lists them). Start from\n'artoo -o json gw " ++ r.name ++ " show ID > FILE' and edit it; read-only fields\n(id, metadata, …) are dropped and named in the plan. Secrets appear as\n<redacted> in that output: put the real value back.",
            .patch => "Only the fields in the file change.",
            .delete => "Deletes the object.",
            .action, .port_action => "Action " ++ w.action.? ++ ". The API offers no read-back: the result is\nreported as accepted, not verified.",
            .ordering => "The body is the complete order.",
            .adopt => "See 'artoo gw devices pending'.",
            .purge => "Deletes every matching voucher.",
        };
        if (w.fields.len > 0) s = s ++ "\n\n" ++ wrapList("Body fields:", w.fields);
        if (w.required.len > 0 and w.kind != .patch) s = s ++ "\n" ++ wrapList("Required:", w.required);
        if (w.destructive) s = s ++ "\n\nDestructive: type the target to confirm, or --yes --confirm TARGET.";
        return s;
    }
}

const from_flag: cli.Flag = .{ .long = "from", .short = 'f', .kind = .string, .metavar = "FILE", .help = "Request body as JSON (a 'show -o json' document works)" };
const confirm_flag: cli.Flag = .{ .long = "confirm", .kind = .string, .metavar = "TARGET", .help = "Non-interactive confirmation (with --yes)" };

pub fn Verb(comptime r: *const catalog.Resource, comptime w: catalog.Write) type {
    if ((w.kind == .replace or w.kind == .patch or w.kind == .delete or targeted(w.kind)) and r.show == null)
        @compileError(r.name ++ " " ++ w.verb ++ ": targeted writes need a show operation");
    const zones = w.kind == .ordering and std.mem.eql(u8, r.name, "fw-policies");
    return struct {
        const write = w;
        pub const name = w.verb;
        pub const summary = w.summary;
        pub const details = detailsFor(r, w);
        pub const positionals = blk: {
            var p: []const cli.Positional = &.{};
            if (targeted(w.kind)) p = p ++ .{cli.Positional{ .name = "ID|NAME", .help = gw.targetHelp(r) }};
            if (w.kind == .port_action) p = p ++ .{cli.Positional{ .name = "PORT", .help = "Port index (see 'gw devices show')" }};
            if (w.kind == .adopt) p = p ++ .{cli.Positional{ .name = "MAC", .help = "MAC address of the pending device" }};
            if (zones) p = p ++ gw.zone_positionals;
            break :blk p[0..p.len].*;
        };
        pub const flags = blk: {
            var f: []const cli.Flag = &.{};
            if (fileUse(w) != .none) f = f ++ .{from_flag};
            if (w.force) f = f ++ .{cli.Flag{ .long = "force", .help = "Delete even if other objects reference it (force=true)" }};
            if (w.kind == .purge) f = f ++ .{cli.Flag{ .long = "filter", .kind = .string, .metavar = "EXPR", .help = "Vouchers to delete (required; see 'gw vouchers ls -h')" }};
            if (w.kind == .adopt) f = f ++ .{cli.Flag{ .long = "ignore-limit", .help = "Adopt even beyond the device limit" }};
            if (w.destructive) f = f ++ .{confirm_flag};
            break :blk f[0..f.len].*;
        };
        pub const examples = [_][]const u8{"artoo gw " ++ r.name ++ " " ++ w.verb ++
            (if (targeted(w.kind)) " NAME" else "") ++
            (if (w.kind == .port_action) " 4" else "") ++
            (if (w.kind == .adopt) " aa:bb:cc:dd:ee:ff" else "") ++
            (if (zones) " Internal External" else "") ++
            (if (w.kind == .purge) " --filter \"expired.eq(true)\"" else "") ++
            (if (fileUse(w) == .required) " --from FILE" else "") ++ " --dry-run"};

        pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
            var op: WriteOp = .{ .r = r, .w = &write, .risk = if (w.destructive) .destructive else .normal };
            // Everything local is checked before the first request.
            if (comptime fileUse(w) != .none) {
                if (args.string("from")) |path| {
                    op.body = try loadBody(ctx, path, &write, r.read_only);
                } else if (comptime fileUse(w) == .required) {
                    return ctx.fail(error.Usage, "--from FILE is required (the request body as JSON)", .{});
                }
            }
            if (comptime targeted(w.kind)) op.word = args.pos("ID|NAME");
            if (comptime w.kind == .port_action) op.port = std.fmt.parseInt(u16, args.pos("PORT"), 10) catch
                return ctx.fail(error.Usage, "PORT must be a port index, got '{s}'", .{args.pos("PORT")});
            if (comptime w.kind == .adopt) {
                op.mac = try macAddress(ctx, args.pos("MAC"));
                op.ignore_limit = args.has("ignore-limit");
            }
            if (comptime w.kind == .purge) {
                const f = args.string("filter") orelse return ctx.fail(error.Usage, "--filter EXPR is required; purge never deletes every voucher implicitly", .{});
                if (std.mem.trim(u8, f, " ").len == 0) return ctx.fail(error.Usage, "--filter is empty", .{});
                op.filter = f;
            }
            if (comptime w.force) op.force = args.has("force");
            if (comptime zones) op.zones = .{ args.pos("SRC_ZONE"), args.pos("DST_ZONE") };
            if (op.body) |b| if (std.mem.eql(u8, r.name, "dns-policies")) try guardDns(ctx, b.body);

            var c = try unifi.Client.open(ctx);
            defer c.deinit();
            op.c = &c;
            const confirm: ?[]const u8 = if (comptime w.destructive) args.string("confirm") else null;
            try exec.run(ctx, &op, .{ .confirm = confirm });
        }
    };
}

fn loadBody(ctx: *Context, path: []const u8, w: *const catalog.Write, read_only: []const []const u8) !unibody.Prepared {
    const bytes = std.Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(4 << 20)) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return ctx.fail(error.Usage, "cannot read {s}: {t}", .{ try gw.sanitized(ctx, path), err }),
    };
    var problem: unibody.Problem = .not_json;
    return unibody.prepare(ctx.arena, bytes, w.*, read_only, &problem) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Invalid => ctx.fail(error.Usage, "{s}: {s}", .{ try gw.sanitized(ctx, path), try gw.sanitized(ctx, try unibody.describe(ctx.arena, problem, w.*)) }),
    };
}

fn macAddress(ctx: *Context, s: []const u8) ![]const u8 {
    var ok = s.len == 17;
    if (ok) for (s, 0..) |ch, i| {
        ok = ok and (if (i % 3 == 2) ch == ':' else std.ascii.isHex(ch));
    };
    if (!ok) return ctx.fail(error.Usage, "MAC must look like aa:bb:cc:dd:ee:ff, got '{s}'", .{s});
    return std.ascii.allocLowerString(ctx.arena, s);
}

/// SPEC §9.6 for DNS policies written through the catalog or `gw api`:
/// outside home.arpa, no name or target may point at Proxmox/UniFi.
fn guardDns(ctx: *Context, b: Value) !void {
    if (b != .object) return;
    const domain = view.string(b, "domain") orelse return;
    if (exposure.isPrivate(domain)) return;
    const why = exposure.protected(try ctx.config(), domain, view.string(b, "ipv4Address")) orelse
        exposure.protected(try ctx.config(), view.string(b, "targetDomain"), null);
    if (why) |w| return ctx.fail(error.Refused, "refused: {s}; Proxmox and UniFi keep home.arpa names only (SPEC §9.6)", .{w});
}

fn method(m: catalog.Method) http.Method {
    return switch (m) {
        .POST => .POST,
        .PUT => .PUT,
        .PATCH => .PATCH,
        .DELETE => .DELETE,
    };
}

fn parseRaw(ctx: *Context, raw: []const u8, what: []const u8) !Value {
    return std.json.parseFromSliceLeaky(Value, ctx.arena, raw, .{}) catch
        ctx.fail(error.Protocol, "UniFi sent invalid JSON for {s}", .{what});
}

/// One catalog write. `current` holds the raw (unredacted) object for
/// diffs and verification only; nothing renders it directly.
const WriteOp = struct {
    c: *unifi.Client = undefined,
    r: *const catalog.Resource,
    w: *const catalog.Write,
    risk: ui.blocks.Risk,
    api: ui.json.Target = .unifi,
    target: []const u8 = "",

    // Inputs.
    word: ?[]const u8 = null,
    body: ?unibody.Prepared = null,
    port: ?u16 = null,
    mac: ?[]const u8 = null,
    ignore_limit: bool = false,
    filter: ?[]const u8 = null,
    force: bool = false,
    zones: ?[2][]const u8 = null,

    // Read state.
    id: ?[]const u8 = null,
    current: ?Value = null,
    matches: []const Value = &.{},
    order_path: ?[]const u8 = null,
    state: []const u8 = "",

    // Outcome.
    verified: bool = false,

    pub fn read(op: *WriteOp, ctx: *Context) !void {
        const c = op.c;
        var raw: []const u8 = "";
        switch (op.w.kind) {
            .replace, .patch, .delete, .action, .port_action => {
                if (op.id == null) op.id = (try unifi.resolve(c, op.r, op.word.?)).id;
                raw = try c.getRaw(try unifi.expandPath(c, op.r.show.?.path, op.id.?));
                op.current = try parseRaw(ctx, raw, op.r.label);
                op.target = try objectName(ctx, op.r, op.current.?, op.id.?);
                if (op.port) |p| if (!hasPort(op.current.?, p)) {
                    return ctx.fail(error.Usage, "{s} has no port {d} (see 'artoo gw devices show {s}')", .{ op.target, p, op.target });
                };
            },
            .ordering => {
                if (op.order_path == null) op.order_path = if (op.zones) |z|
                    try gw.zonePairPath(c, op.w.op.path, z[0], z[1])
                else
                    try unifi.expandPath(c, op.w.op.path, null);
                raw = try c.getRaw(op.order_path.?);
                op.current = try parseRaw(ctx, raw, "the current order");
                op.target = op.r.name;
            },
            .purge => {
                const page = try unifi.list(c, op.r, .{ .filter = op.filter, .all = true });
                op.matches = page.items;
                var ids: std.ArrayList(u8) = .empty;
                for (page.items) |it| try ids.appendSlice(ctx.arena, view.string(it, "id") orelse "?");
                raw = ids.items;
                op.target = op.r.name;
            },
            .create => {
                const b = op.body.?.body;
                op.target = if (view.string(b, "name") orelse view.string(b, "domain")) |n|
                    try gw.sanitized(ctx, n)
                else
                    try std.fmt.allocPrint(ctx.arena, "new {s}", .{op.r.label});
            },
            .adopt => op.target = op.mac.?,
        }
        op.state = try std.fmt.allocPrint(ctx.arena, "{s}:{x}", .{ op.id orelse "-", std.hash.Wyhash.hash(0, raw) });
    }

    pub fn plan(op: *WriteOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        const label = op.r.label;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        var impact: std.ArrayList([]const u8) = .empty;
        var notes: std.ArrayList([]const u8) = .empty;
        var recovery: ?[]const u8 = null;
        const verb_text: []const u8 = switch (op.w.kind) {
            .create => "Add",
            .replace => "Replace",
            .patch => "Change",
            .delete => "Delete",
            .ordering => "Reorder",
            .purge => "Delete",
            .adopt => "Adopt",
            .action, .port_action => op.w.verb,
        };
        switch (op.w.kind) {
            .create => {
                for (try unibody.flatten(a, op.body.?.body)) |p| try changes.append(a, .{ .field = p.key, .from = null, .to = p.text });
                recovery = try std.fmt.allocPrint(a, "artoo gw {s} rm {s}", .{ op.r.name, op.target });
            },
            .replace, .ordering => {
                const ch = try unibody.diff(a, op.current.?, op.body.?.body, op.r.read_only);
                if (ch.len == 0) return null;
                for (ch) |x| try changes.append(a, .{ .field = x.key, .from = x.from, .to = x.to orelse "(reset: not in the file)" });
                if (op.w.kind == .replace) {
                    try notes.append(a, "PUT replaces the whole object; fields absent from the file revert to server defaults.");
                    recovery = try std.fmt.allocPrint(a, "artoo gw {s} set {s} --from FILE holding the previous values above", .{ op.r.name, op.target });
                }
            },
            .patch => {
                const old = try unibody.flatten(a, op.current.?);
                for (try unibody.flatten(a, op.body.?.body)) |p| {
                    const prev = for (old) |o| {
                        if (std.mem.eql(u8, o.key, p.key)) break o;
                    } else null;
                    if (prev != null and std.mem.eql(u8, prev.?.raw, p.raw)) continue;
                    try changes.append(a, .{ .field = p.key, .from = if (prev) |x| x.text else null, .to = p.text });
                }
                if (changes.items.len == 0) return null;
            },
            .delete => {
                for (op.r.columns) |col| {
                    const v = view.lookup(op.current.?, col.path) orelse continue;
                    const text = (try view.scalar(a, v)) orelse continue;
                    try changes.append(a, .{ .field = col.title, .from = text, .to = null });
                }
                if (changes.items.len == 0) try changes.append(a, .{ .field = label, .from = op.target, .to = null });
                try impact.append(a, if (std.mem.eql(u8, op.r.name, "devices"))
                    "UniFi forgets the device; it must be adopted again"
                else
                    try std.fmt.allocPrint(a, "UniFi deletes the {s}; anything using it stops working", .{label}));
                if (op.force) try notes.append(a, "--force: deleted even if other objects reference it.");
                recovery = try std.fmt.allocPrint(a, "artoo gw {s} add --from FILE (a new ID; references must be updated)", .{op.r.name});
            },
            .action, .port_action => {
                const what = if (op.port) |p| try std.fmt.allocPrint(a, "{s} on port {d}", .{ op.w.action.?, p }) else op.w.action.?;
                try changes.append(a, .{ .field = "action", .from = null, .to = what });
                if (op.body) |b| for (try unibody.flatten(a, b.body)) |p| try changes.append(a, .{ .field = p.key, .from = null, .to = p.text });
                const act = op.w.action.?;
                try impact.append(a, if (std.mem.eql(u8, act, "RESTART"))
                    try std.fmt.allocPrint(a, "{s} restarts; its clients lose service until it is back online", .{op.target})
                else if (std.mem.eql(u8, act, "POWER_CYCLE"))
                    try std.fmt.allocPrint(a, "PoE power on port {d} of {s} is cut and restored; the powered device reboots", .{ op.port.?, op.target })
                else if (std.mem.eql(u8, act, "AUTHORIZE_GUEST_ACCESS"))
                    try std.fmt.allocPrint(a, "{s} gets guest network access", .{op.target})
                else
                    try std.fmt.allocPrint(a, "{s} loses guest network access", .{op.target}));
                try notes.append(a, "The API offers no read-back for actions: the result will be 'accepted', not verified.");
            },
            .purge => {
                if (op.matches.len == 0) return null;
                for (op.matches[0..@min(op.matches.len, purge_listed)]) |m| {
                    const n = view.string(m, "name") orelse "--";
                    const code = view.string(m, "code") orelse view.string(m, "id") orelse "?";
                    try changes.append(a, .{ .field = try gw.sanitized(ctx, code), .from = try gw.sanitized(ctx, n), .to = null });
                }
                if (op.matches.len > purge_listed) try notes.append(a, try std.fmt.allocPrint(a, "… and {d} more", .{op.matches.len - purge_listed}));
                try impact.append(a, try std.fmt.allocPrint(a, "{d} voucher(s) matching {s} stop working", .{ op.matches.len, try gw.sanitized(ctx, op.filter.?) }));
            },
            .adopt => {
                try changes.append(a, .{ .field = "device", .from = "pending", .to = try std.fmt.allocPrint(a, "adopted ({s})", .{op.mac.?}) });
                if (op.ignore_limit) try notes.append(a, "--ignore-limit: adopted even beyond the device limit.");
                try notes.append(a, "Adoption completes asynchronously; follow it with 'artoo gw devices ls'.");
            },
        }
        if (op.w.destructive and op.w.kind != .delete and op.w.kind != .purge and op.w.kind != .action and op.w.kind != .port_action) {
            try impact.append(a, "Network-wide setting: LAN clients can be affected as soon as it applies");
        }
        if (op.body) |b| if (b.dropped.len > 0) {
            try notes.append(a, try std.fmt.allocPrint(a, "Ignored read-only fields from the file: {s}", .{try std.mem.join(a, ", ", b.dropped)}));
        };
        try notes.append(a, no_etags);
        return .{
            .action = try std.fmt.allocPrint(a, "{s} {s} {s}", .{ try gw.capitalized(ctx, verb_text), label, op.target }),
            .risk = op.risk,
            .target = try std.fmt.allocPrint(a, "UniFi (site {s})", .{try gw.sanitized(ctx, op.c.site_name orelse op.c.site)}),
            .changes = changes.items,
            .impact = impact.items,
            .recovery = recovery,
            .notes = notes.items,
        };
    }

    pub fn fingerprint(op: *WriteOp) []const u8 {
        return op.state;
    }

    fn requestPath(op: *WriteOp, ctx: *Context) ![]const u8 {
        const c = op.c;
        return switch (op.w.kind) {
            .create, .adopt => unifi.expandPath(c, op.w.op.path, null),
            .replace, .patch, .action => unifi.expandPath(c, op.w.op.path, op.id.?),
            .delete => blk: {
                const p = try unifi.expandPath(c, op.w.op.path, op.id.?);
                break :blk if (op.force) try std.fmt.allocPrint(ctx.arena, "{s}?force=true", .{p}) else p;
            },
            .port_action => blk: {
                const idx = try std.fmt.allocPrint(ctx.arena, "{d}", .{op.port.?});
                const template = try std.mem.replaceOwned(u8, ctx.arena, op.w.op.path, "{portIdx}", idx);
                break :blk unifi.expandPath(c, template, op.id.?);
            },
            .ordering => op.order_path.?,
            .purge => blk: {
                var p: std.ArrayList(u8) = .empty;
                try p.appendSlice(ctx.arena, try unifi.expandPath(c, op.w.op.path, null));
                try p.appendSlice(ctx.arena, "?filter=");
                try catalog.appendEscaped(ctx.arena, &p, op.filter.?);
                break :blk p.items;
            },
        };
    }

    fn requestBody(op: *WriteOp, ctx: *Context) !?[]const u8 {
        const a = ctx.arena;
        return switch (op.w.kind) {
            .create, .replace, .patch, .ordering => try std.json.Stringify.valueAlloc(a, op.body.?.body, .{}),
            .action, .port_action => blk: {
                var obj: std.json.ObjectMap = .empty;
                try obj.put(a, "action", .{ .string = op.w.action.? });
                if (op.body) |b| {
                    var it = b.body.object.iterator();
                    while (it.next()) |e| try obj.put(a, e.key_ptr.*, e.value_ptr.*);
                }
                break :blk try std.json.Stringify.valueAlloc(a, Value{ .object = obj }, .{});
            },
            .adopt => try std.json.Stringify.valueAlloc(a, .{ .macAddress = op.mac.?, .ignoreDeviceLimit = op.ignore_limit }, .{}),
            .delete, .purge => null,
        };
    }

    pub fn send(op: *WriteOp, ctx: *Context) !void {
        const path = try op.requestPath(ctx);
        const body = try op.requestBody(ctx);
        const resp = try op.c.request(method(op.w.method), path, body);
        if (op.w.kind == .create) op.id = createdId(ctx, resp.body);
    }

    pub fn verify(op: *WriteOp, ctx: *Context) !bool {
        const c = op.c;
        switch (op.w.kind) {
            .create => {
                const id = op.id orelse return true; // e.g. vouchers: no single object to read back
                const fresh = try parseRaw(ctx, try c.getRaw(try unifi.expandPath(c, op.r.show.?.path, id)), op.r.label);
                op.verified = true;
                return unibody.contains(op.body.?.body, fresh);
            },
            .replace, .patch => {
                const fresh = try parseRaw(ctx, try c.getRaw(try unifi.expandPath(c, op.r.show.?.path, op.id.?)), op.r.label);
                op.verified = true;
                return unibody.contains(op.body.?.body, fresh);
            },
            .ordering => {
                const fresh = try parseRaw(ctx, try c.getRaw(op.order_path.?), "the order");
                op.verified = true;
                return unibody.contains(op.body.?.body, fresh);
            },
            .delete => {
                _ = c.getRaw(try unifi.expandPath(c, op.r.show.?.path, op.id.?)) catch |err| switch (err) {
                    error.NotFound => {
                        ctx.diag = null;
                        op.verified = true;
                        return true;
                    },
                    else => |e| return e,
                };
                return false;
            },
            .purge => {
                const page = try unifi.list(c, op.r, .{ .filter = op.filter, .all = true });
                op.verified = true;
                return page.items.len == 0;
            },
            .action, .port_action, .adopt => return true,
        }
    }

    pub fn done(op: *WriteOp) []const u8 {
        return if (op.verified)
            "applied and verified by a fresh read"
        else
            "accepted by UniFi; the API offers no read-back for this, so it is not verified";
    }
};

fn createdId(ctx: *Context, body: []const u8) ?[]const u8 {
    const v = std.json.parseFromSliceLeaky(Value, ctx.arena, body, .{}) catch return null;
    return view.string(v, "id");
}

fn objectName(ctx: *Context, r: *const catalog.Resource, item: Value, id: []const u8) ![]const u8 {
    for (r.match) |m| {
        if (view.string(item, m)) |s| if (s.len > 0) return gw.sanitized(ctx, s);
    }
    return gw.sanitized(ctx, id);
}

fn hasPort(device: Value, idx: u16) bool {
    const ports = view.lookup(device, "interfaces.ports") orelse return false;
    if (ports != .array) return false;
    for (ports.array.items) |p| {
        const i = view.lookup(p, "idx") orelse continue;
        if (i == .integer and i.integer == idx) return true;
    }
    return false;
}

// ---------------------------------------------------------------- gw api

pub const api = struct {
    pub const name = "api";
    pub const summary = "Generic Integration API request (writes are destructive-confirmed)";
    pub const details =
        \\PATH starts with /v1/; {siteId} is replaced by the configured site. GET
        \\prints the response (secrets redacted). POST, PUT, PATCH and DELETE run
        \\the mutation pipeline with destructive confirmation — type PATH, or
        \\--yes --confirm PATH — and are reported as accepted: artoo cannot
        \\validate the body or verify the result of a generic request.
    ;
    pub const positionals = [_]cli.Positional{
        .{ .name = "METHOD", .help = "GET, POST, PUT, PATCH or DELETE" },
        .{ .name = "PATH", .help = "/v1/… (query string allowed)" },
    };
    pub const flags = [_]cli.Flag{ from_flag, confirm_flag };
    pub const examples = [_][]const u8{
        "artoo gw api GET /v1/info",
        "artoo gw api GET '/v1/sites/{siteId}/wans'",
        "artoo gw api POST '/v1/sites/{siteId}/traffic-matching-lists' --from list.json --dry-run",
    };

    pub fn run(ctx: *Context, args: cli.Args(@This())) !void {
        const m_word = args.pos("METHOD");
        const m = std.meta.stringToEnum(http.Method, try std.ascii.allocUpperString(ctx.arena, m_word)) orelse
            return ctx.fail(error.Usage, "unknown METHOD '{s}' (GET, POST, PUT, PATCH, DELETE)", .{m_word});
        const path = args.pos("PATH");
        if (!std.mem.startsWith(u8, path, "/v1/") or std.mem.find(u8, path, "..") != null) {
            return ctx.fail(error.Usage, "PATH must start with /v1/ and contain no '..', got '{s}'", .{path});
        }
        for (path) |ch| if (ch <= ' ' or ch == 0x7f) return ctx.fail(error.Usage, "PATH contains spaces or control characters", .{});

        var body: ?Value = null;
        if (args.string("from")) |file| {
            if (m == .GET or m == .DELETE) return ctx.fail(error.Usage, "--from is only for POST, PUT and PATCH", .{});
            const bytes = std.Io.Dir.cwd().readFileAlloc(ctx.io, file, ctx.arena, .limited(4 << 20)) catch |err| switch (err) {
                error.OutOfMemory, error.Canceled => |e| return e,
                else => return ctx.fail(error.Usage, "cannot read {s}: {t}", .{ try gw.sanitized(ctx, file), err }),
            };
            body = std.json.parseFromSliceLeaky(Value, ctx.arena, bytes, .{}) catch
                return ctx.fail(error.Usage, "{s} is not valid JSON", .{try gw.sanitized(ctx, file)});
            if (try redactedPath(ctx, body.?)) |p| return ctx.fail(error.Usage, "{s} holds '{s}' copied from artoo output; put the real value in the file", .{ p, view.redacted });
            if (std.mem.find(u8, path, "/dns/policies") != null) try guardDns(ctx, body.?);
        } else if (m == .POST or m == .PUT or m == .PATCH) {
            return ctx.fail(error.Usage, "--from FILE is required for {t}", .{m});
        }

        var c = try unifi.Client.open(ctx);
        defer c.deinit();
        const resolved = if (std.mem.find(u8, path, "{siteId}") != null)
            try std.mem.replaceOwned(u8, ctx.arena, path, "{siteId}", try unifi.siteId(&c))
        else
            path;

        if (m == .GET) {
            const v = try unifi.getJson(&c, resolved);
            if (ctx.json()) return ui.json.envelope(ctx.out, .unifi, v, .{ .collected_at = ctx.ui.now, .path = resolved });
            try gw.header(ctx, &c);
            if (v == .object) if (v.object.get("data")) |d| if (d == .array) {
                try view.objectTable(ctx.out, ctx.arena, &ctx.ui, d.array.items, 0);
                return;
            };
            return view.detail(ctx.out, ctx.arena, &ctx.ui, try gw.sanitized(ctx, resolved), v);
        }
        var op: ApiOp = .{ .c = &c, .method = m, .target = path, .resolved = resolved, .body = body };
        try exec.run(ctx, &op, .{ .confirm = args.string("confirm") });
    }
};

fn redactedPath(ctx: *Context, v: Value) !?[]const u8 {
    for (try unibody.flatten(ctx.arena, v)) |p| {
        if (std.mem.eql(u8, p.raw, "\"" ++ view.redacted ++ "\"")) return p.key;
    }
    return null;
}

const ApiOp = struct {
    c: *unifi.Client,
    method: http.Method,
    target: []const u8,
    resolved: []const u8,
    body: ?Value,
    risk: ui.blocks.Risk = .destructive,
    api: ui.json.Target = .unifi,
    status: u16 = 0,
    created: ?[]const u8 = null,
    done_text: []const u8 = "",

    pub fn read(_: *ApiOp, _: *Context) !void {}

    pub fn plan(op: *ApiOp, ctx: *Context) !?exec.Plan {
        const a = ctx.arena;
        var changes: std.ArrayList(ui.blocks.Change) = .empty;
        if (op.body) |b| for (try unibody.flatten(a, b)) |p| try changes.append(a, .{ .field = if (p.key.len > 0) p.key else "(body)", .from = null, .to = p.text });
        const notes = try a.dupe([]const u8, &.{ "Generic request: artoo does not validate the body or verify the result.", no_etags });
        return .{
            .action = try std.fmt.allocPrint(a, "{t} {s}", .{ op.method, try gw.sanitized(ctx, op.resolved) }),
            .risk = .destructive,
            .target = try std.fmt.allocPrint(a, "UniFi (site {s})", .{try gw.sanitized(ctx, op.c.site_name orelse op.c.site)}),
            .changes = changes.items,
            .notes = notes,
        };
    }

    pub fn fingerprint(_: *ApiOp) []const u8 {
        return "";
    }

    pub fn send(op: *ApiOp, ctx: *Context) !void {
        const body = if (op.body) |b| try std.json.Stringify.valueAlloc(ctx.arena, b, .{}) else null;
        const resp = try op.c.request(op.method, op.resolved, body);
        op.status = resp.status;
        op.created = createdId(ctx, resp.body);
    }

    pub fn verify(op: *ApiOp, ctx: *Context) !bool {
        op.done_text = if (op.created) |id|
            try std.fmt.allocPrint(ctx.arena, "accepted by UniFi (HTTP {d}, id {s}); not verified", .{ op.status, try gw.sanitized(ctx, id) })
        else
            try std.fmt.allocPrint(ctx.arena, "accepted by UniFi (HTTP {d}); not verified", .{op.status});
        return true;
    }

    pub fn done(op: *ApiOp) []const u8 {
        return op.done_text;
    }
};

// ---------------------------------------------------------------- tests

const testing = std.testing;
const testkit = @import("../testkit.zig");
const Exit = testkit.Exit;
const Gateway = testkit.Gateway;
const root = cli.group("artoo", "test", &.{gw.group});

const sites =
    \\{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"S1","internalReference":"default","name":"Default"}]}
;
const networks =
    \\{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"N1","name":"Default","vlanId":1}]}
;
const network =
    \\{"management":"GATEWAY","id":"N1","name":"Default","enabled":true,"vlanId":1,"metadata":{"origin":"SYSTEM_DEFINED"},"default":true,
    \\ "ipv4Configuration":{"hostIpAddress":"192.168.1.1","prefixLength":24,"dhcpConfiguration":{"mode":"SERVER","dnsServerIpAddressesOverride":["1.1.1.1","1.0.0.1"],"domainName":"local"}}}
;
/// `show -o json`-style document with the DNS override changed and
/// `domainName` left out.
const network_edit =
    \\{"schema_version":1,"target":"unifi","data":
    \\{"management":"GATEWAY","id":"N1","name":"Default","enabled":true,"vlanId":1,"metadata":{"origin":"SYSTEM_DEFINED"},"default":true,
    \\ "ipv4Configuration":{"hostIpAddress":"192.168.1.1","prefixLength":24,"dhcpConfiguration":{"mode":"SERVER","dnsServerIpAddressesOverride":["192.168.1.1"]}}}}
;
const network_after =
    \\{"management":"GATEWAY","id":"N1","name":"Default","enabled":true,"vlanId":1,"metadata":{"origin":"SYSTEM_DEFINED"},"default":true,
    \\ "ipv4Configuration":{"hostIpAddress":"192.168.1.1","prefixLength":24,"dhcpConfiguration":{"mode":"SERVER","dnsServerIpAddressesOverride":["192.168.1.1"],"leaseTimeSeconds":86400}}}
;
const devices =
    \\{"offset":0,"limit":200,"count":1,"totalCount":1,"data":[{"id":"D1","name":"Beacon","state":"ONLINE"}]}
;
const beacon =
    \\{"id":"D1","name":"Beacon","model":"U6+","state":"ONLINE","interfaces":{"ports":[{"idx":1,"state":"UP"}]}}
;

test "gw networks set: dry run diffs current vs file, names dropped and reset fields" {
    var g: Gateway = undefined;
    try g.init(&.{ .{ .respond = .{ .body = sites } }, .{ .respond = .{ .body = networks } }, .{ .respond = .{ .body = network } } });
    defer g.deinit();
    const path = try g.file("net.json", network_edit);
    try testing.expectEqual(Exit.ok, g.h.run(&root, try std.fmt.allocPrint(g.h.arena.allocator(), "gw networks set Default --from {s} -n", .{path})));
    try testing.expectEqual(@as(usize, 3), g.sent());
    try testing.expectEqualStrings("GET /v1/sites/S1/networks/N1 HTTP/1.1", g.request(2));
    try testing.expectEqualStrings(
        \\Plan · Replace network Default  ▲ destructive
        \\  Target    UniFi (site Default)
        \\  Change    ipv4Configuration.dhcpConfiguration.dnsServerIpAddressesOverride  ["1.1.1.1","1.0.0.1"] → ["192.168.1.1"]
        \\            ipv4Configuration.dhcpConfiguration.domainName                    local → (reset: not in the file)
        \\  Impact    Network-wide setting: LAN clients can be affected as soon as it applies
        \\  Recovery  artoo gw networks set Default --from FILE holding the previous values above
        \\  Note      PUT replaces the whole object; fields absent from the file revert to server defaults.
        \\            Ignored read-only fields from the file: default, id, metadata
        \\            The UniFi API has no ETags; concurrent edits cannot be detected.
        \\
        \\Dry run: nothing was sent.
        \\
    , g.h.stdout());
}

test "gw networks set: destructive confirmation, one PUT without read-only fields, verified" {
    var g: Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = sites } }, .{ .respond = .{ .body = networks } },      .{ .respond = .{ .body = network } },
        .{ .respond = .{ .body = sites } }, .{ .respond = .{ .body = networks } },      .{ .respond = .{ .body = network } },
        .{ .respond = .{ .body = "{}" } },  .{ .respond = .{ .body = network_after } },
    });
    defer g.deinit();
    const ar = g.h.arena.allocator();
    const path = try g.file("net.json", network_edit);
    try testing.expectEqual(Exit.refused, g.h.run(&root, try std.fmt.allocPrint(ar, "gw networks set Default --from {s} -y", .{path})));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "--confirm Default") != null);
    try testing.expectEqual(Exit.ok, g.h.run(&root, try std.fmt.allocPrint(ar, "gw networks set Default --from {s} -y --confirm Default", .{path})));
    try testing.expectEqualStrings("PUT /v1/sites/S1/networks/N1 HTTP/1.1", g.request(6));
    const sent = try std.json.parseFromSliceLeaky(Value, ar, g.body(6), .{});
    try testing.expect(sent.object.get("id") == null and sent.object.get("metadata") == null and sent.object.get("default") == null);
    try testing.expectEqualStrings("Default", sent.object.get("name").?.string);
    try testing.expect(std.mem.endsWith(u8, g.h.stdout(), "✓ applied and verified by a fresh read\n"));
}

test "gw networks set: no difference is refused; a fresh read without the change is partial" {
    var g: Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = sites } }, .{ .respond = .{ .body = networks } }, .{ .respond = .{ .body = network_after } },
        .{ .respond = .{ .body = sites } }, .{ .respond = .{ .body = networks } }, .{ .respond = .{ .body = network } },
        .{ .respond = .{ .body = "{}" } },  .{ .respond = .{ .body = network } },
    });
    defer g.deinit();
    const ar = g.h.arena.allocator();
    const same = try g.file("same.json",
        \\{"management":"GATEWAY","name":"Default","enabled":true,"vlanId":1,
        \\ "ipv4Configuration":{"hostIpAddress":"192.168.1.1","prefixLength":24,"dhcpConfiguration":{"mode":"SERVER","dnsServerIpAddressesOverride":["192.168.1.1"],"leaseTimeSeconds":86400}}}
    );
    try testing.expectEqual(Exit.refused, g.h.run(&root, try std.fmt.allocPrint(ar, "gw networks set Default --from {s} -y --confirm Default", .{same})));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "nothing to change") != null);
    const edit = try g.file("net.json", network_edit);
    try testing.expectEqual(Exit.partial, g.h.run(&root, try std.fmt.allocPrint(ar, "gw networks set Default --from {s} -y --confirm Default", .{edit})));
    try testing.expectEqual(@as(usize, 8), g.sent());
}

test "gw writes: bad files are usage errors before any request" {
    var g: Gateway = undefined;
    try g.init(&.{});
    defer g.deinit();
    const ar = g.h.arena.allocator();
    const redacted = try g.file("wifi.json",
        \\{"name":"LabNet","enabled":true,"type":"STANDARD","hideName":false,"clientIsolationEnabled":false,"multicastToUnicastConversionEnabled":false,
        \\ "uapsdEnabled":false,"channel2gLockedTo6":false,"dtimPeriod2gLockedTo3":false,"securityConfiguration":{"type":"WPA2_PERSONAL","passphrase":"<redacted>"}}
    );
    try testing.expectEqual(Exit.usage, g.h.run(&root, try std.fmt.allocPrint(ar, "gw wifi set x --from {s}", .{redacted})));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "securityConfiguration.passphrase holds '<redacted>'") != null);
    const unknown = try g.file("zone.json", "{\"name\":\"z\",\"networkIds\":[],\"color\":\"red\"}");
    try testing.expectEqual(Exit.usage, g.h.run(&root, try std.fmt.allocPrint(ar, "gw fw-zones add --from {s}", .{unknown})));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "field 'color' is not accepted by createFirewallZone") != null);
    try testing.expectEqual(Exit.usage, g.h.run(&root, "gw fw-zones add"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "gw vouchers purge -y"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "gw devices adopt nope"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "gw devices port-cycle Beacon x"));
    // SPEC §9.6 through the catalog.
    const dns = try g.file("dns.json", "{\"type\":\"A_RECORD\",\"enabled\":true,\"domain\":\"pve.lab.example.com\",\"ipv4Address\":\"192.168.1.10\",\"ttlSeconds\":0}");
    try testing.expectEqual(Exit.refused, g.h.run(&root, try std.fmt.allocPrint(ar, "gw dns-policies add --from {s} -y", .{dns})));
    try testing.expectEqual(@as(usize, 0), g.sent());
}

test "gw dns-policies add: POST, then the created object is read back" {
    var g: Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = sites } },
        .{ .respond = .{ .status = 201, .body = "{\"id\":\"P9\",\"type\":\"A_RECORD\"}" } },
        .{ .respond = .{ .body = "{\"id\":\"P9\",\"type\":\"A_RECORD\",\"enabled\":true,\"domain\":\"web.lab.example.com\",\"ipv4Address\":\"192.168.1.201\",\"ttlSeconds\":300,\"metadata\":{}}" } },
    });
    defer g.deinit();
    const f = try g.file("dns.json", "{\"type\":\"A_RECORD\",\"enabled\":true,\"domain\":\"web.lab.example.com\",\"ipv4Address\":\"192.168.1.201\",\"ttlSeconds\":300}");
    try testing.expectEqual(Exit.ok, g.h.run(&root, try std.fmt.allocPrint(g.h.arena.allocator(), "gw dns-policies add --from {s} -y", .{f})));
    try testing.expectEqualStrings("POST /v1/sites/S1/dns/policies HTTP/1.1", g.request(1));
    try testing.expectEqualStrings("GET /v1/sites/S1/dns/policies/P9 HTTP/1.1", g.request(2));
    try testing.expect(std.mem.find(u8, g.h.stdout(), "Plan · Add DNS policy web.lab.example.com\n") != null);
}

test "gw networks rm --force: DELETE with force, verified by a 404" {
    var g: Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = sites } }, .{ .respond = .{ .body = networks } },                                     .{ .respond = .{ .body = network } },
        .{ .respond = .{ .body = "" } },    .{ .respond = .{ .status = 404, .body = "{\"message\":\"not found\"}" } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "gw networks rm Default --force -y --confirm Default"));
    try testing.expectEqualStrings("DELETE /v1/sites/S1/networks/N1?force=true HTTP/1.1", g.request(3));
    const out = g.h.stdout();
    try testing.expect(std.mem.find(u8, out, "Change    NAME        Default → (removed)") != null);
    try testing.expect(std.mem.find(u8, out, "--force: deleted even if other objects reference it.") != null);
    try testing.expect(std.mem.endsWith(u8, out, "✓ applied and verified by a fresh read\n"));
}

test "gw devices restart / port-cycle: fixed action body, reported as accepted" {
    var g: Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = sites } },  .{ .respond = .{ .body = devices } }, .{ .respond = .{ .body = beacon } },
        .{ .respond = .{ .body = "{}" } },   .{ .respond = .{ .body = sites } },   .{ .respond = .{ .body = devices } },
        .{ .respond = .{ .body = beacon } },
    });
    defer g.deinit();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "gw devices restart Beacon -y --confirm Beacon"));
    try testing.expectEqualStrings("POST /v1/sites/S1/devices/D1/actions HTTP/1.1", g.request(3));
    try testing.expectEqualStrings("{\"action\":\"RESTART\"}", g.body(3));
    try testing.expect(std.mem.endsWith(u8, g.h.stdout(), "✓ accepted by UniFi; the API offers no read-back for this, so it is not verified\n"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "gw devices port-cycle Beacon 9 -y --confirm Beacon"));
    try testing.expect(std.mem.find(u8, g.h.stderr(), "Beacon has no port 9") != null);
    try testing.expectEqual(@as(usize, 7), g.sent());
}

test "gw vouchers purge: nothing matching is a no-op" {
    var g: Gateway = undefined;
    try g.init(&.{ .{ .respond = .{ .body = sites } }, .{ .respond = .{ .body = "{\"offset\":0,\"limit\":200,\"count\":0,\"totalCount\":0,\"data\":[]}" } } });
    defer g.deinit();
    try testing.expectEqual(Exit.refused, g.h.run(&root, "gw vouchers purge --filter expired.eq(true) -y --confirm vouchers"));
    try testing.expectEqualStrings("GET /v1/sites/S1/hotspot/vouchers?offset=0&limit=200&filter=expired.eq%28true%29 HTTP/1.1", g.request(1));
}

test "gw api: GET prints redacted JSON; writes need the typed path" {
    var g: Gateway = undefined;
    try g.init(&.{
        .{ .respond = .{ .body = sites } },
        .{ .respond = .{ .body = "{\"name\":\"x\",\"passphrase\":\"hunter2\"}" } },
        .{ .respond = .{ .body = sites } },
        .{ .respond = .{ .body = sites } },
        .{ .respond = .{ .status = 201, .body = "{\"id\":\"T1\"}" } },
    });
    defer g.deinit();
    const ar = g.h.arena.allocator();
    try testing.expectEqual(Exit.ok, g.h.run(&root, "-o json gw api get /v1/sites/{siteId}/wifi/broadcasts/W1"));
    try testing.expectEqualStrings("GET /v1/sites/S1/wifi/broadcasts/W1 HTTP/1.1", g.request(1));
    try testing.expect(std.mem.find(u8, g.h.stdout(), "hunter2") == null);
    try testing.expectEqual(Exit.usage, g.h.run(&root, "gw api GET /v2/x"));
    try testing.expectEqual(Exit.usage, g.h.run(&root, "gw api POST /v1/x"));
    const f = try g.file("list.json", "{\"type\":\"PORTS\",\"name\":\"web\",\"items\":[]}");
    const p = "/v1/sites/{siteId}/traffic-matching-lists";
    try testing.expectEqual(Exit.refused, g.h.run(&root, try std.fmt.allocPrint(ar, "gw api POST {s} --from {s} -y", .{ p, f })));
    try testing.expectEqual(Exit.ok, g.h.run(&root, try std.fmt.allocPrint(ar, "gw api POST {s} --from {s} -y --confirm {s}", .{ p, f, p })));
    try testing.expectEqualStrings("POST /v1/sites/S1/traffic-matching-lists HTTP/1.1", g.request(4));
    try testing.expect(std.mem.endsWith(u8, g.h.stdout(), "✓ accepted by UniFi (HTTP 201, id T1); not verified\n"));
}
