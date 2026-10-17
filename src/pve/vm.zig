//! Virtual machines on the configured node (SPEC §3.2): listing, VM
//! target resolution (VMID or exact name; ambiguity lists candidates),
//! config and status reads, and guest-agent addresses. Resource modules
//! never print.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const pve = @import("client.zig");

pub const Vm = struct {
    vmid: u32,
    name: []const u8,
    /// `running`, `stopped`, `paused`, … (PVE's word).
    status: []const u8,
    template: bool,
    cpus: ?f64,
    /// Fraction of the VM's vCPUs (0..1).
    cpu: ?f64,
    mem: ?u64,
    maxmem: ?u64,
    maxdisk: ?u64,
    uptime: ?u64,
    tags: []const u8,
    lock: ?[]const u8,

    pub fn running(v: Vm) bool {
        return std.mem.eql(u8, v.status, "running");
    }
};

/// VMs (and templates) on the configured node, sorted by VMID. Read from
/// `/nodes/<node>/qemu` (configs + live status): `/cluster/resources` is
/// refreshed by pvestatd and lists a just-created VM without name or
/// status for several seconds (live-proven 2026-10-10).
pub fn list(c: *pve.Client) ![]Vm {
    const data = try c.get(try c.nodePath("/qemu", .{}));
    var out: std.ArrayList(Vm) = .empty;
    for (pve.items(data)) |it| {
        try out.append(c.ctx.arena, fromResource(it) orelse continue);
    }
    std.mem.sort(Vm, out.items, {}, struct {
        fn lt(_: void, a: Vm, b: Vm) bool {
            return a.vmid < b.vmid;
        }
    }.lt);
    return out.items;
}

pub fn fromResource(it: Value) ?Vm {
    const id = pve.uint(it, "vmid") orelse return null;
    if (id > std.math.maxInt(u32)) return null;
    return .{
        .vmid = @intCast(id),
        .name = pve.str(it, "name") orelse "",
        .status = pve.str(it, "status") orelse "unknown",
        .template = pve.flag(it, "template"),
        .cpus = pve.num(it, "maxcpu") orelse pve.num(it, "cpus"),
        .cpu = pve.num(it, "cpu"),
        .mem = pve.uint(it, "mem"),
        .maxmem = pve.uint(it, "maxmem"),
        .maxdisk = pve.uint(it, "maxdisk"),
        .uptime = pve.uint(it, "uptime"),
        .tags = pve.str(it, "tags") orelse "",
        .lock = pve.str(it, "lock"),
    };
}

pub const ResolveError = error{ NotFound, Ambiguous };

pub const Resolution = union(enum) {
    vm: Vm,
    /// Several VMs carry the name.
    ambiguous: []const Vm,
    missing,
};

/// `word` is a VMID or an exact (then case-insensitive) VM name.
pub fn find(vms: []const Vm, arena: Allocator, word: []const u8) !Resolution {
    if (std.fmt.parseInt(u32, word, 10)) |id| {
        for (vms) |v| {
            if (v.vmid == id) return .{ .vm = v };
        }
        return .missing;
    } else |_| {}
    for ([_]bool{ false, true }) |loose| {
        var hits: std.ArrayList(Vm) = .empty;
        for (vms) |v| {
            const same = if (loose) std.ascii.eqlIgnoreCase(v.name, word) else std.mem.eql(u8, v.name, word);
            if (same) try hits.append(arena, v);
        }
        if (hits.items.len == 1) return .{ .vm = hits.items[0] };
        if (hits.items.len > 1) return .{ .ambiguous = hits.items };
    }
    return .missing;
}

/// Resolve a VM target or fail with a message naming the candidates.
pub fn resolve(c: *pve.Client, word: []const u8) !Vm {
    const ctx = c.ctx;
    const vms = try list(c);
    return switch (try find(vms, ctx.arena, word)) {
        .vm => |v| v,
        .missing => ctx.fail(error.NotFound, "no VM '{s}' on {s} (see 'artoo vm ls --all')", .{ word, c.node }),
        .ambiguous => |hits| blk: {
            var ids: std.ArrayList(u8) = .empty;
            for (hits, 0..) |h, i| try ids.print(ctx.arena, "{s}{d}", .{ if (i > 0) ", " else "", h.vmid });
            break :blk ctx.fail(error.Usage, "{d} VMs are named '{s}'; use a VMID: {s}", .{ hits.len, word, ids.items });
        },
    };
}

/// Lowest VMID ≥ `first` not used anywhere in the cluster.
pub fn freeVmid(c: *pve.Client, first: u32) !u32 {
    const all = pve.items(try c.get("/cluster/resources?type=vm"));
    var id: u32 = first;
    while (id < 1_000_000) : (id += 1) {
        for (all) |v| {
            if (pve.uint(v, "vmid") == id) break;
        } else return id;
    }
    return c.ctx.fail(error.Refused, "no free VMID", .{});
}

pub fn config(c: *pve.Client, vmid: u32) !Value {
    return c.get(try c.nodePath("/qemu/{d}/config", .{vmid}));
}

pub fn status(c: *pve.Client, vmid: u32) !Value {
    return c.get(try c.nodePath("/qemu/{d}/status/current", .{vmid}));
}

pub fn snapshots(c: *pve.Client, vmid: u32) ![]const Value {
    return pve.items(try c.get(try c.nodePath("/qemu/{d}/snapshot", .{vmid})));
}

/// `agent: 1` / `agent: enabled=1,…`.
pub fn agentEnabled(cfg: Value) bool {
    const a = pve.str(cfg, "agent") orelse return pve.flag(cfg, "agent");
    return std.mem.startsWith(u8, a, "1") or std.mem.find(u8, a, "enabled=1") != null;
}

pub const Address = struct {
    interface: []const u8,
    address: []const u8,
    prefix: ?i64,
    ipv6: bool,
};

/// Non-loopback addresses reported by the guest agent.
pub fn agentAddresses(c: *pve.Client, vmid: u32) ![]const Address {
    const data = try c.get(try c.nodePath("/qemu/{d}/agent/network-get-interfaces", .{vmid}));
    var out: std.ArrayList(Address) = .empty;
    for (pve.items(pve.obj(data, "result"))) |iface| {
        const name = pve.str(iface, "name") orelse continue;
        if (std.mem.eql(u8, name, "lo")) continue;
        for (pve.items(pve.obj(iface, "ip-addresses"))) |ip| {
            const addr = pve.str(ip, "ip-address") orelse continue;
            const v6 = std.mem.eql(u8, pve.str(ip, "ip-address-type") orelse "", "ipv6");
            if (v6 and std.mem.startsWith(u8, addr, "fe80")) continue;
            try out.append(c.ctx.arena, .{ .interface = name, .address = addr, .prefix = pve.int(ip, "prefix"), .ipv6 = v6 });
        }
    }
    return out.items;
}

/// `*` and `?` glob, case-insensitive.
pub fn globMatch(pattern: []const u8, s: []const u8) bool {
    if (pattern.len == 0) return s.len == 0;
    return switch (pattern[0]) {
        '*' => globMatch(pattern[1..], s) or (s.len > 0 and globMatch(pattern, s[1..])),
        '?' => s.len > 0 and globMatch(pattern[1..], s[1..]),
        else => s.len > 0 and std.ascii.toLower(pattern[0]) == std.ascii.toLower(s[0]) and globMatch(pattern[1..], s[1..]),
    };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn vmFixture(id: u32, name: []const u8) Vm {
    return .{ .vmid = id, .name = name, .status = "stopped", .template = false, .cpus = 1, .cpu = null, .mem = null, .maxmem = null, .maxdisk = null, .uptime = null, .tags = "", .lock = null };
}

test "find: VMID, exact name, case-insensitive name, ambiguity" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const vms = [_]Vm{ vmFixture(100, "web-01"), vmFixture(101, "Web-02"), vmFixture(102, "dup"), vmFixture(103, "dup") };
    try testing.expectEqual(@as(u32, 101), (try find(&vms, ar, "101")).vm.vmid);
    try testing.expectEqual(@as(u32, 100), (try find(&vms, ar, "web-01")).vm.vmid);
    try testing.expectEqual(@as(u32, 101), (try find(&vms, ar, "web-02")).vm.vmid);
    try testing.expectEqual(@as(usize, 2), (try find(&vms, ar, "dup")).ambiguous.len);
    try testing.expect((try find(&vms, ar, "nope")) == .missing);
    try testing.expect((try find(&vms, ar, "999")) == .missing);
}

test "globMatch" {
    try testing.expect(globMatch("web-*", "web-01"));
    try testing.expect(globMatch("*01", "WEB-01"));
    try testing.expect(globMatch("w?b*", "web-01"));
    try testing.expect(!globMatch("db-*", "web-01"));
}

test "agentEnabled" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expect(agentEnabled(try std.json.parseFromSliceLeaky(Value, ar, "{\"agent\":\"1\"}", .{})));
    try testing.expect(agentEnabled(try std.json.parseFromSliceLeaky(Value, ar, "{\"agent\":\"enabled=1,fstrim_cloned_disks=1\"}", .{})));
    try testing.expect(!agentEnabled(try std.json.parseFromSliceLeaky(Value, ar, "{\"agent\":\"0\"}", .{})));
    try testing.expect(!agentEnabled(try std.json.parseFromSliceLeaky(Value, ar, "{}", .{})));
}
