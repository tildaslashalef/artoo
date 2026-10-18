//! Grafana's provisioned content on the watchdog (SPEC §9.9): the alert
//! rules, generated from a table so queries live in one place and are
//! tested, and the lab board. Rules use the plain three-step form: the
//! query returns the raw value, B reduces it (`last`) and C compares it
//! with the threshold, so every series is judged 0 or 1 (an alert
//! resolves when its condition clears) and the value is `$values.B` in
//! the annotations.

const std = @import("std");
const Allocator = std.mem.Allocator;
const files = @import("files.zig");

pub const Severity = enum { warning, critical };

pub const Rule = struct {
    uid: []const u8,
    title: []const u8,
    /// MetricsQL returning the raw value per series.
    expr: []const u8,
    /// Fires when the value is greater (`gt`) or less (`lt`) than `threshold`.
    op: enum { gt, lt } = .gt,
    threshold: []const u8,
    @"for": []const u8 = "5m",
    severity: Severity = .warning,
    /// One line: what fails, on which guest, host, storage or service,
    /// and the value in its unit (Grafana's annotation template).
    summary: []const u8,
    /// What it means and the artoo commands to run next.
    description: []const u8,
};

/// The initial rules (SPEC §9.9). Guests' and Alloy's series name the
/// guest in `host`; Proxmox's name the node (`object="nodes"`) or the
/// storage (`object="storages"`) there; probes carry `service`, `url`
/// and `vm` from the watchdog's relabelling (`files.alloyConfig`).
pub const rules = [_]Rule{
    .{
        .uid = "artoo-guest-silent",
        .title = "Guest silent",
        .expr = "time() - max by (host) (tlast_over_time(node_boot_time_seconds[1d]))",
        .threshold = "300",
        .@"for" = "0s",
        .summary = "{{ $labels.host }} is silent: no metrics for {{ humanizeDuration $values.B.Value }}",
        .description = "The guest {{ $labels.host }} sends nothing to the watchdog: it is stopped or unreachable, or its Alloy stopped. Check: artoo vm show {{ $labels.host }}, artoo vm verify {{ $labels.host }}. Removed for good: artoo watch forget {{ $labels.host }}.",
    },
    .{
        .uid = "artoo-pve-silent",
        .title = "Proxmox silent",
        .expr = "time() - max(tlast_over_time(system_uptime{object=\"nodes\"}[1d]))",
        .threshold = "300",
        .@"for" = "0s",
        .severity = .critical,
        .summary = "Proxmox is silent: no metrics for {{ humanizeDuration $values.B.Value }}",
        .description = "Proxmox's metric export (External Metric Server) sends nothing to the watchdog: the host is down or the export stopped. Check: artoo host show, artoo watch status.",
    },
    .{
        .uid = "artoo-rootfs",
        .title = "Root filesystem above 85 %",
        .expr = "1 - node_filesystem_avail_bytes{mountpoint=\"/\"} / node_filesystem_size_bytes{mountpoint=\"/\"}",
        .threshold = "0.85",
        .summary = "{{ $labels.host }}: root filesystem {{ humanizePercentage $values.B.Value }} full",
        .description = "The disk of {{ $labels.host }} is above 85 %. Check: artoo vm ssh {{ $labels.host }} -- df -h /",
    },
    .{
        .uid = "artoo-memory",
        .title = "Memory above 90 %",
        .expr = "1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes",
        .threshold = "0.9",
        .summary = "{{ $labels.host }}: memory {{ humanizePercentage $values.B.Value }} used",
        .description = "{{ $labels.host }} is short of memory (guests have no swap). Check: artoo vm show {{ $labels.host }}; more: artoo vm set {{ $labels.host }} memory=…",
    },
    .{
        .uid = "artoo-pve-memory",
        .title = "Proxmox memory above 90 %",
        .expr = "memory_memused{object=\"nodes\"} / memory_memtotal{object=\"nodes\"}",
        .threshold = "0.9",
        .summary = "Proxmox {{ $labels.host }}: memory {{ humanizePercentage $values.B.Value }} used",
        .description = "The Proxmox host is short of memory; its guests' RAM is what fills it. Check: artoo status (the guests and their memory).",
    },
    .{
        .uid = "artoo-cpu",
        .title = "CPU above 90 %",
        .expr = "1 - avg by (host) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m]))",
        .threshold = "0.9",
        .@"for" = "15m",
        .summary = "{{ $labels.host }}: CPU {{ humanizePercentage $values.B.Value }} busy for 15 minutes",
        .description = "All of {{ $labels.host }}'s cores are busy, likely a runaway process. Check: artoo vm ssh {{ $labels.host }}, then top.",
    },
    .{
        .uid = "artoo-pve-cpu",
        .title = "Proxmox CPU above 90 %",
        .expr = "avg_over_time(cpustat_cpu{object=\"nodes\"}[5m])",
        .threshold = "0.9",
        .@"for" = "15m",
        .summary = "Proxmox {{ $labels.host }}: CPU {{ humanizePercentage $values.B.Value }} busy for 15 minutes",
        .description = "The Proxmox host's CPU is saturated. Check: artoo status (CPU per guest).",
    },
    .{
        .uid = "artoo-pve-storage",
        .title = "Proxmox storage above 85 %",
        .expr = "system_used{object=\"storages\"} / system_total{object=\"storages\"}",
        .threshold = "0.85",
        .summary = "Proxmox storage {{ $labels.host }}: {{ humanizePercentage $values.B.Value }} full",
        .description = "The storage {{ $labels.host }} on Proxmox is above 85 %. Check: artoo storage show {{ $labels.host }}",
    },
    .{
        .uid = "artoo-units",
        .title = "Failed systemd unit",
        .expr = "node_systemd_unit_state{state=\"failed\"}",
        .threshold = "0",
        .summary = "{{ $labels.host }}: unit {{ $labels.name }} failed",
        .description = "A systemd unit on {{ $labels.host }} failed. Check: artoo vm ssh {{ $labels.host }} -- systemctl status {{ $labels.name }}",
    },
    .{
        .uid = "artoo-edge-drops",
        .title = "Edge reached for Proxmox or UniFi",
        .expr = "increase(artoo_drop_packets{table=\"artoo_edge\",counter=~\"to_pve|to_gateway\"}[10m])",
        .threshold = "0",
        .@"for" = "0s",
        .severity = .critical,
        .summary = "{{ $labels.host }} (edge) tried to reach {{ if eq $labels.counter \"to_pve\" }}Proxmox{{ else }}UniFi{{ end }}: possible compromise",
        .description = "{{ printf \"%.0f\" $values.B.Value }} packets from the edge VM towards {{ if eq $labels.counter \"to_pve\" }}Proxmox{{ else }}UniFi{{ end }} dropped in 10 minutes; nothing on the edge should try (SPEC §9.7). Check now: artoo edge status",
    },
    .{
        .uid = "artoo-telemetry",
        .title = "Telemetry attempt blocked",
        .expr = "increase(artoo_drop_packets{table=\"artoo_watch\",counter=\"telemetry\"}[10m])",
        .threshold = "0",
        .@"for" = "0s",
        .summary = "{{ $labels.host }}: a service tried to reach the internet",
        .description = "{{ printf \"%.0f\" $values.B.Value }} packets from Grafana, Loki, VictoriaMetrics, Alloy or ntfy dropped in 10 minutes: a telemetry or update attempt (SPEC §9.9). Check: artoo watch status",
    },
    .{
        .uid = "artoo-tunnel",
        .title = "Tunnel not connected",
        .expr = "max by (host) (cloudflared_tunnel_ha_connections)",
        .op = .lt,
        .threshold = "1",
        .summary = "Cloudflare Tunnel down: cloudflared on {{ $labels.host }} has no connection",
        .description = "Public routes do not answer. Check: artoo edge status, artoo cf tunnel ls",
    },
    .{
        .uid = "artoo-router",
        .title = "Router route not primary",
        .expr = "min by (host) ({__name__=~\"artoo_tailscale_running|artoo_tailscale_routes_primary\"})",
        .op = .lt,
        .threshold = "1",
        .summary = "{{ $labels.host }} (router): remote access down",
        .description = "Tailscale on {{ $labels.host }} is not running or its LAN route is not primary: the tailnet cannot reach the lab. Check: artoo router status",
    },
    .{
        .uid = "artoo-cert",
        .title = "Certificate expires within 14 days",
        .expr = "probe_ssl_earliest_cert_expiry - time()",
        .op = .lt,
        .threshold = "1209600",
        .severity = .critical,
        .summary = "{{ or $labels.service $labels.job }}: HTTPS certificate expires in {{ humanizeDuration $values.B.Value }}",
        .description = "The edge's wildcard certificate{{ with $labels.url }} served for {{ . }}{{ end }} is close to expiry: Caddy renews it well before, so renewal failed. Check: artoo edge status",
    },
    .{
        .uid = "artoo-probe",
        .title = "HTTPS probe failing",
        .expr = "probe_success",
        .op = .lt,
        .threshold = "1",
        .summary = "{{ or $labels.service $labels.job }}{{ with $labels.url }} ({{ . }}){{ end }} is down, probed from {{ $labels.host }}",
        .description = "The service {{ or $labels.service $labels.job }}{{ with $labels.vm }} on {{ . }}{{ end }} does not answer through the edge: no 2xx, a TLS error, or its health reports it down. Check: {{ with $labels.vm }}artoo vm verify {{ . }}, {{ end }}artoo svc ls, artoo edge status",
    },
    .{
        .uid = "artoo-reboot",
        .title = "Reboot pending for 7 days",
        .expr = "artoo_reboot_required_seconds",
        .threshold = "604800",
        .@"for" = "0s",
        .summary = "{{ $labels.host }} has waited {{ humanizeDuration $values.B.Value }} for a reboot",
        .description = "An update on {{ $labels.host }} needs a reboot, never done automatically. Reboot: artoo vm reboot {{ $labels.host }} (the packages: artoo vm verify {{ $labels.host }})",
    },
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
            \\              conditions: [{{ evaluator: {{ type: {s}, params: [{s}] }} }}]
            \\        noDataState: OK
            \\        execErrState: Error
            \\        for: {s}
            \\        labels: {{ severity: {s} }}
            \\        annotations:
            \\          summary: {f}
            \\          description: {f}
            \\
        , .{ r.uid, r.title, std.json.fmt(r.expr, .{}), @tagName(r.op), r.threshold, r.@"for", @tagName(r.severity), std.json.fmt(r.summary, .{}), std.json.fmt(r.description, .{}) });
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

test "rules: unique uids, raw values judged by the threshold, the critical ones" {
    for (rules, 0..) |r, i| {
        // The value reaches the annotations only when the query keeps it.
        try testing.expect(std.mem.find(u8, r.expr, " bool ") == null);
        try testing.expect(r.summary.len > 0 and r.description.len > 0);
        try testing.expect(std.mem.find(u8, r.description, "artoo ") != null);
        for (rules[i + 1 ..]) |o| try testing.expect(!std.mem.eql(u8, r.uid, o.uid));
    }
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const y = try rulesYaml(arena.allocator());
    for ([_][]const u8{
        "      - uid: artoo-edge-drops\n",
        "model: { refId: A, instant: true, expr: \"increase(artoo_drop_packets{table=\\\"artoo_edge\\\",counter=~\\\"to_pve|to_gateway\\\"}[10m])\" }\n",
        "        labels: { severity: critical }\n",
        "model: { refId: A, instant: true, expr: \"1 - avg by (host) (rate(node_cpu_seconds_total{mode=\\\"idle\\\"}[5m]))\" }\n",
        "model: { refId: A, instant: true, expr: \"avg_over_time(cpustat_cpu{object=\\\"nodes\\\"}[5m])\" }\n",
        "conditions: [{ evaluator: { type: gt, params: [0.9] } }]\n",
        "conditions: [{ evaluator: { type: lt, params: [1209600] } }]\n",
        "        for: 15m\n",
        "datasourceUid: victoriametrics\n",
    }) |want| {
        if (std.mem.find(u8, y, want) == null) {
            std.debug.print("missing: {s}\n", .{want});
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(rules.len, std.mem.count(u8, y, "condition: C\n"));
    try testing.expectEqual(rules.len, std.mem.count(u8, y, "          description: \""));
}

test "rules: the probe alert names the service, its URL and guest (golden)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const y = try rulesYaml(arena.allocator());
    const start = std.mem.find(u8, y, "      - uid: artoo-probe\n").?;
    const end = start + std.mem.find(u8, y[start + 1 ..], "      - uid: ").? + 1;
    try testing.expectEqualStrings(
        \\      - uid: artoo-probe
        \\        title: "HTTPS probe failing"
        \\        condition: C
        \\        data:
        \\          - refId: A
        \\            relativeTimeRange: { from: 600, to: 0 }
        \\            datasourceUid: victoriametrics
        \\            model: { refId: A, instant: true, expr: "probe_success" }
        \\          - refId: B
        \\            datasourceUid: __expr__
        \\            model: { refId: B, type: reduce, expression: A, reducer: last }
        \\          - refId: C
        \\            datasourceUid: __expr__
        \\            model:
        \\              refId: C
        \\              type: threshold
        \\              expression: B
        \\              conditions: [{ evaluator: { type: lt, params: [1] } }]
        \\        noDataState: OK
        \\        execErrState: Error
        \\        for: 5m
        \\        labels: { severity: warning }
        \\        annotations:
        \\          summary: "{{ or $labels.service $labels.job }}{{ with $labels.url }} ({{ . }}){{ end }} is down, probed from {{ $labels.host }}"
        \\          description: "The service {{ or $labels.service $labels.job }}{{ with $labels.vm }} on {{ . }}{{ end }} does not answer through the edge: no 2xx, a TLS error, or its health reports it down. Check: {{ with $labels.vm }}artoo vm verify {{ . }}, {{ end }}artoo svc ls, artoo edge status"
        \\
    , y[start..end]);
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
