//! Grafana's provisioned content on the watchdog (SPEC §9.9): the alert
//! rules, generated from a table so queries live in one place and are
//! tested, and the lab board. Rules use the plain three-step form (query,
//! reduce, threshold) with `bool` comparisons, so every series is 0 or 1
//! and an alert resolves when its condition clears.

const std = @import("std");
const Allocator = std.mem.Allocator;
const files = @import("files.zig");

pub const Severity = enum { warning, critical };

pub const Rule = struct {
    uid: []const u8,
    title: []const u8,
    /// MetricsQL returning 1 (firing) or 0 per series.
    expr: []const u8,
    @"for": []const u8 = "5m",
    severity: Severity = .warning,
    summary: []const u8,
};

/// The initial rules (SPEC §9.9).
pub const rules = [_]Rule{
    .{ .uid = "artoo-guest-silent", .title = "Guest silent", .expr = "time() - max by (host) (tlast_over_time(node_boot_time_seconds[1d])) > bool 300", .@"for" = "0s", .summary = "{{ $labels.host }} sent no metrics for 5 minutes" },
    .{ .uid = "artoo-pve-silent", .title = "Proxmox silent", .expr = "time() - max(tlast_over_time(system_uptime{object=\"nodes\"}[1d])) > bool 300", .@"for" = "0s", .severity = .critical, .summary = "Proxmox's metric export sent nothing for 5 minutes" },
    .{ .uid = "artoo-rootfs", .title = "Root filesystem above 85 %", .expr = "1 - node_filesystem_avail_bytes{mountpoint=\"/\"} / node_filesystem_size_bytes{mountpoint=\"/\"} > bool 0.85", .summary = "{{ $labels.host }}: / is above 85 %" },
    .{ .uid = "artoo-memory", .title = "Memory above 90 %", .expr = "1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes > bool 0.9", .summary = "{{ $labels.host }}: memory above 90 %" },
    .{ .uid = "artoo-pve-memory", .title = "Proxmox memory above 90 %", .expr = "memory_memused{object=\"nodes\"} / memory_memtotal{object=\"nodes\"} > bool 0.9", .summary = "Proxmox: memory above 90 %" },
    .{ .uid = "artoo-cpu", .title = "CPU above 90 %", .expr = "1 - avg by (host) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) > bool 0.9", .@"for" = "15m", .summary = "{{ $labels.host }}: CPU above 90 % for 15 minutes" },
    .{ .uid = "artoo-pve-cpu", .title = "Proxmox CPU above 90 %", .expr = "avg_over_time(cpustat_cpu{object=\"nodes\"}[5m]) > bool 0.9", .@"for" = "15m", .summary = "Proxmox: CPU above 90 % for 15 minutes" },
    .{ .uid = "artoo-pve-storage", .title = "Proxmox storage above 85 %", .expr = "system_used{object=\"storages\"} / system_total{object=\"storages\"} > bool 0.85", .summary = "Proxmox: storage {{ $labels.host }} above 85 %" },
    .{ .uid = "artoo-units", .title = "Failed systemd unit", .expr = "node_systemd_unit_state{state=\"failed\"} > bool 0", .summary = "{{ $labels.host }}: {{ $labels.name }} failed" },
    .{ .uid = "artoo-edge-drops", .title = "Edge reached for Proxmox or UniFi", .expr = "increase(artoo_drop_packets{table=\"artoo_edge\",counter=~\"to_pve|to_gateway\"}[10m]) > bool 0", .@"for" = "0s", .severity = .critical, .summary = "{{ $labels.host }} tried {{ $labels.counter }} — sign of compromise (SPEC §9.7)" },
    .{ .uid = "artoo-telemetry", .title = "Telemetry attempt blocked", .expr = "increase(artoo_drop_packets{table=\"artoo_watch\",counter=\"telemetry\"}[10m]) > bool 0", .@"for" = "0s", .summary = "A service on {{ $labels.host }} tried the internet (SPEC §9.9)" },
    .{ .uid = "artoo-tunnel", .title = "Tunnel not connected", .expr = "max by (host) (cloudflared_tunnel_ha_connections) < bool 1", .summary = "cloudflared on {{ $labels.host }} has no connection" },
    .{ .uid = "artoo-router", .title = "Router route not primary", .expr = "artoo_tailscale_routes_primary < bool 1 or artoo_tailscale_running < bool 1", .summary = "{{ $labels.host }}: Tailscale not running or its route not primary" },
    .{ .uid = "artoo-cert", .title = "Certificate expires within 14 days", .expr = "probe_ssl_earliest_cert_expiry - time() < bool 1209600", .severity = .critical, .summary = "{{ $labels.job }}: certificate expires within 14 days" },
    .{ .uid = "artoo-probe", .title = "HTTPS probe failing", .expr = "probe_success < bool 1", .summary = "{{ $labels.job }} does not answer over HTTPS" },
    .{ .uid = "artoo-reboot", .title = "Reboot pending for 7 days", .expr = "artoo_reboot_required_seconds > bool 604800", .@"for" = "0s", .summary = "{{ $labels.host }} waits for a reboot" },
};

/// The rule group file for `provisioning/alerting`.
pub fn rulesYaml(a: Allocator) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a,
        \\# Managed by artoo (SPEC §9.9); 'artoo watch setup' overwrites edits.
        \\apiVersion: 1
        \\groups:
        \\  - orgId: 1
        \\    name: lab
        \\    folder: Lab
        \\    interval: 1m
        \\    rules:
        \\
    );
    for (rules) |r| {
        try out.print(a,
            \\      - uid: {s}
            \\        title: "{s}"
            \\        condition: C
            \\        data:
            \\          - refId: A
            \\            relativeTimeRange: {{ from: 600, to: 0 }}
            \\            datasourceUid: victoriametrics
            \\            model: {{ refId: A, instant: true, expr: {f} }}
            \\          - refId: B
            \\            datasourceUid: __expr__
            \\            model: {{ refId: B, type: reduce, expression: A, reducer: last }}
            \\          - refId: C
            \\            datasourceUid: __expr__
            \\            model:
            \\              refId: C
            \\              type: threshold
            \\              expression: B
            \\              conditions: [{{ evaluator: {{ type: gt, params: [0] }} }}]
            \\        noDataState: OK
            \\        execErrState: Error
            \\        for: {s}
            \\        labels: {{ severity: {s} }}
            \\        annotations: {{ summary: {f} }}
            \\
        , .{ r.uid, r.title, std.json.fmt(r.expr, .{}), r.@"for", @tagName(r.severity), std.json.fmt(r.summary, .{}) });
    }
    return out.items;
}

// ---------------------------------------------------------------- dashboards

/// The one lab board, Grafana's home page (`grafana.ini`). Grafana's own
/// JSON, kept as a file so it stays readable and can be exported from the
/// UI after a trial edit; data sources by their provisioned UIDs.
pub const lab_board = @embedFile("dashboards/lab.json");
pub const lab_board_path = "/etc/grafana/dashboards/artoo-lab.json";

/// The dashboard files for `/etc/grafana/dashboards`; `watch setup`
/// removes any other `.json` there.
pub fn dashboardFiles(a: Allocator) ![]const files.File {
    return a.dupe(files.File, &.{.{ .path = lab_board_path, .mode = "0640", .owner = "root:grafana", .content = lab_board }});
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

test "rules: unique uids, bool comparisons, the critical ones" {
    for (rules, 0..) |r, i| {
        try testing.expect(std.mem.find(u8, r.expr, " bool ") != null);
        for (rules[i + 1 ..]) |o| try testing.expect(!std.mem.eql(u8, r.uid, o.uid));
    }
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const y = try rulesYaml(arena.allocator());
    for ([_][]const u8{
        "      - uid: artoo-edge-drops\n",
        "model: { refId: A, instant: true, expr: \"increase(artoo_drop_packets{table=\\\"artoo_edge\\\",counter=~\\\"to_pve|to_gateway\\\"}[10m]) > bool 0\" }\n",
        "        labels: { severity: critical }\n",
        "model: { refId: A, instant: true, expr: \"1 - avg by (host) (rate(node_cpu_seconds_total{mode=\\\"idle\\\"}[5m])) > bool 0.9\" }\n",
        "model: { refId: A, instant: true, expr: \"avg_over_time(cpustat_cpu{object=\\\"nodes\\\"}[5m]) > bool 0.9\" }\n",
        "        for: 15m\n",
        "datasourceUid: victoriametrics\n",
        "conditions: [{ evaluator: { type: gt, params: [0] } }]\n",
    }) |want| {
        if (std.mem.find(u8, y, want) == null) {
            std.debug.print("missing: {s}\n", .{want});
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(rules.len, std.mem.count(u8, y, "condition: C\n"));
}

test "lab board: valid JSON, the provisioned data sources, nothing dangling" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try std.json.parseFromSliceLeaky(std.json.Value, a, lab_board, .{});
    try testing.expectEqualStrings("artoo-lab", v.object.get("uid").?.string);
    try testing.expectEqualStrings("Proxmox · Homelab", v.object.get("title").?.string);
    var ids: std.AutoHashMapUnmanaged(i64, void) = .empty;
    var n: usize = 0;
    var stack: std.ArrayList(std.json.Value) = .empty;
    for (v.object.get("panels").?.array.items) |p| try stack.append(a, p);
    while (stack.pop()) |p| {
        n += 1;
        const id = p.object.get("id").?.integer;
        try testing.expect(!ids.contains(id));
        try ids.put(a, id, {});
        if (p.object.get("panels")) |inner| for (inner.array.items) |q| try stack.append(a, q);
        if (p.object.get("datasource")) |ds| {
            const uid = ds.object.get("uid").?.string;
            try testing.expect(std.mem.eql(u8, uid, "victoriametrics") or std.mem.eql(u8, uid, "loki"));
        }
    }
    try testing.expect(n > 20);
    const fs = try dashboardFiles(a);
    try testing.expectEqualStrings(lab_board_path, fs[0].path);
}
