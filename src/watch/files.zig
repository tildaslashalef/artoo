//! What `artoo watch setup|enroll` puts on the watchdog VM and the guests
//! (SPEC §9.9): every file is rendered here from config and the lab's
//! observed state, so nothing drifts from SPEC. Each carries a header
//! naming artoo as its owner.

const std = @import("std");
const Allocator = std.mem.Allocator;
const edge_files = @import("../edge/files.zig");

pub const File = edge_files.File;
pub const sha256Hex = edge_files.sha256Hex;
pub const write_file = edge_files.write_file;

// ---------------------------------------------------------------- pins

/// Pinned stack (SPEC §9.9). Bumping one is a deliberate SPEC edit.
pub const vm_version = "v1.153.0";
pub const vm_url = "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/" ++ vm_version ++ "/victoria-metrics-linux-amd64-" ++ vm_version ++ ".tar.gz";
/// From the release's `victoria-metrics-linux-amd64-v1.153.0_checksums.txt`.
pub const vm_sha256 = "1b495bde563825cf83dc7c0425a9d8fa03e7214858e0949f9177efc6bb1f8bfc";
pub const grafana_version = "13.2.3";
pub const loki_version = "3.7.8";
/// Debian revision included: the repository's version string.
pub const alloy_version = "1.20.1-1";
pub const ntfy_version = "2.29.0";

/// Grafana's apt signing key (`https://apt.grafana.com/gpg.key`, the
/// current key only; SHA-256 3d402968…ff8c).
pub const grafana_key = @embedFile("grafana.asc");
pub const grafana_key_fingerprint = "B53AE77BADB630A683046005963FA27710458545";
/// ntfy's apt signing key (`https://archive.ntfy.sh/apt/keyring.gpg`,
/// SHA-256 9bf8ec8d…de58).
pub const ntfy_key = @embedFile("ntfy-keyring.gpg");
pub const ntfy_key_fingerprint = "55BA774A6F5EE67431E4B6B7CFDB962D4F1EC4AF";

pub const port_vm: u16 = 8428;
pub const port_loki: u16 = 3100;
pub const port_grafana: u16 = 3000;
pub const port_ntfy: u16 = 2586;

/// ntfy topic for the lab's alerts.
pub const topic = "lab";
/// Service names (SPEC §9.6) Grafana and ntfy are served under.
pub const grafana_service = "grafana";
pub const ntfy_service = "ntfy";
/// Service users whose internet traffic `scarif`'s firewall drops.
pub const quiet_users = [_][]const u8{ "grafana", "loki", "victoriametrics", "alloy", "ntfy" };

/// Retention: metrics 90 days, logs 31 days (744 h).
pub const retention_metrics = "90d";
pub const retention_logs = "744h";

const header = "# Managed by artoo (SPEC §9.9); 'artoo watch setup' overwrites edits.\n";
const header_guest = "# Managed by artoo (SPEC §9.9); 'artoo watch enroll' overwrites edits.\n";

// ---------------------------------------------------------------- the lab

pub const Lab = struct {
    pve: []const u8,
    gateway: []const u8,
    /// `192.168.1.0/24`.
    lan: []const u8,
    /// `192.168.1.200-192.168.1.254`.
    pool: []const u8,
    /// The edge VM's address (Caddy reaches Grafana and ntfy).
    edge: []const u8,
    /// `lab.example.com`.
    domain: []const u8,
    /// HTTPS probes through the edge: the service names (SPEC §9.6).
    services: []const Service = &.{},

    pub fn appsUrl(l: Lab, a: Allocator, service: []const u8) ![]const u8 {
        return std.fmt.allocPrint(a, "https://{s}.apps.{s}", .{ service, l.domain });
    }
};

/// A service the watchdog probes: its name and health (SPEC §9.6, the
/// route file's health lines, already validated there).
pub const Service = struct {
    name: []const u8,
    /// Starts with `/`.
    path: []const u8 = "/",
    /// Literal text that fails the probe when the answer holds it.
    down: ?[]const u8 = null,
    /// The route's upstream guest, named in the probe's alerts.
    vm: []const u8 = "",
};

/// Alloy names a probe's series `job="integrations/blackbox/<target>"`
/// and the scrape gives them the watchdog as `host` (seen live), so the
/// probe relabelling adds `service`, `url` and `vm` for the alerts
/// (SPEC §9.9, probe labels). `$` is the replacement's group marker.
fn probeLabels(a: Allocator, out: *std.ArrayList(u8), l: Lab) !void {
    try out.appendSlice(a,
        \\
        \\prometheus.relabel "probes" {
        \\  forward_to = [prometheus.relabel.host.receiver]
        \\
    );
    for (l.services) |s| {
        var url: std.ArrayList(u8) = .empty;
        for (try std.mem.concat(a, u8, &.{ try l.appsUrl(a, s.name), s.path })) |ch| {
            if (ch == '$') try url.append(a, '$');
            try url.append(a, ch);
        }
        const labels = [_][2][]const u8{ .{ "service", s.name }, .{ "url", url.items }, .{ "vm", s.vm } };
        for (labels) |kv| if (kv[1].len > 0) try out.print(a,
            \\  rule {{
            \\    source_labels = ["job"]
            \\    regex         = "integrations/blackbox/{s}"
            \\    target_label  = "{s}"
            \\    replacement   = "{s}"
            \\  }}
            \\
        , .{ s.name, kv[0], kv[1] });
    }
    try out.appendSlice(a, "}\n");
}

/// The blackbox modules as YAML flow, inside an Alloy string: `https`,
/// plus `https-<name>` for each service with a down text, which fails on
/// the text (regex-escaped, then quoted for YAML and for Alloy).
fn blackboxModules(a: Allocator, services: []const Service) ![]const u8 {
    const base = "prober: http, timeout: 8s, http: { fail_if_not_ssl: true, preferred_ip_protocol: ip4";
    var out: std.ArrayList(u8) = .empty;
    try out.print(a, "{{ modules: {{ https: {{ {s} }} }}", .{base});
    for (services) |s| {
        const t = s.down orelse continue;
        var re: std.ArrayList(u8) = .empty;
        for (t) |ch| {
            if (std.mem.findScalar(u8, "\\.+*?()|[]{}^$", ch) != null) try re.append(a, '\\');
            try re.append(a, ch);
        }
        var q: std.ArrayList(u8) = .empty;
        for (re.items) |ch| switch (ch) {
            '\'' => try q.appendSlice(a, "''"),
            '\\' => try q.appendSlice(a, "\\\\"),
            '"' => try q.appendSlice(a, "\\\""),
            else => try q.append(a, ch),
        };
        try out.print(a, ", https-{s}: {{ {s}, fail_if_body_matches_regexp: ['{s}'] }} }}", .{ s.name, base, q.items });
    }
    try out.appendSlice(a, " } }");
    return out.items;
}

// ---------------------------------------------------------------- scarif

/// nftables: ingest from the pool and Proxmox, Grafana and ntfy only from
/// the edge (Caddy), SSH only from Proxmox. Egress: UniFi's DNS, the
/// edge's HTTPS (probes), the internet for apt only — never for the
/// service users (`telemetry` counts their attempts).
pub fn nftables(a: Allocator, l: Lab) ![]const u8 {
    var users: std.ArrayList(u8) = .empty;
    for (quiet_users, 0..) |u, i| try users.print(a, "{s}\"{s}\"", .{ if (i == 0) "" else ", ", u });
    return std.fmt.allocPrint(a,
        \\#!/usr/sbin/nft -f
        \\{[header]s}
        \\flush ruleset
        \\
        \\define pve = {[pve]s}
        \\define gateway = {[gateway]s}
        \\define lan = {[lan]s}
        \\define pool = {[pool]s}
        \\define edge = {[edge]s}
        \\define private4 = {{ 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 169.254.0.0/16 }}
        \\
        \\table inet artoo_watch {{
        \\    counter to_pve {{ }}
        \\    counter to_gateway {{ }}
        \\    counter to_lan {{ }}
        \\    counter telemetry {{ }}
        \\    counter out_other {{ }}
        \\    counter in_dropped {{ }}
        \\
        \\    chain input {{
        \\        type filter hook input priority filter; policy drop;
        \\        iif "lo" accept
        \\        ct state established,related accept
        \\        ct state invalid drop
        \\        icmp type {{ echo-request, destination-unreachable, time-exceeded }} accept
        \\        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, echo-request, destination-unreachable, packet-too-big, time-exceeded }} accept
        \\        ip saddr $pve tcp dport 22 accept
        \\        ip saddr $pve tcp dport {{ {[vm]d}, {[loki]d} }} accept
        \\        ip saddr $pool tcp dport {{ {[vm]d}, {[loki]d} }} accept
        \\        ip saddr $edge tcp dport {{ {[grafana]d}, {[ntfy]d} }} accept
        \\        counter name in_dropped drop
        \\    }}
        \\
        \\    chain forward {{
        \\        type filter hook forward priority filter; policy drop;
        \\    }}
        \\
        \\    chain output {{
        \\        type filter hook output priority filter; policy drop;
        \\        oif "lo" accept
        \\        ct state established,related accept
        \\        ip daddr $pve counter name to_pve drop
        \\        ip daddr $gateway meta l4proto {{ tcp, udp }} th dport 53 accept
        \\        ip daddr $gateway counter name to_gateway drop
        \\        ip daddr $edge tcp dport 443 accept
        \\        ip daddr $lan counter name to_lan drop
        \\        ip daddr $private4 counter name to_lan drop
        \\        icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, mld-listener-report, mld2-listener-report }} accept
        \\        ip6 daddr != 2000::/3 counter name to_lan drop
        \\        meta skuid {{ {[users]s} }} counter name telemetry drop
        \\        icmp type echo-request accept
        \\        tcp dport {{ 80, 443 }} accept
        \\        udp dport 123 accept
        \\        counter name out_other drop
        \\    }}
        \\}}
        \\
    , .{
        .header = std.mem.trimEnd(u8, header, "\n"),
        .pve = l.pve,
        .gateway = l.gateway,
        .lan = l.lan,
        .pool = l.pool,
        .edge = l.edge,
        .vm = port_vm,
        .loki = port_loki,
        .grafana = port_grafana,
        .ntfy = port_ntfy,
        .users = users.items,
    });
}

pub const grafana_list = header ++
    \\deb [signed-by=/usr/share/keyrings/grafana.asc] https://apt.grafana.com stable main
    \\
;

pub const ntfy_list = header ++
    \\deb [arch=amd64 signed-by=/usr/share/keyrings/ntfy.gpg] https://archive.ntfy.sh/apt stable main
    \\
;

/// apt holds the stack at its pins (priority > 1000 also allows a
/// deliberate downgrade to the pin); unattended upgrades never touch these
/// origins.
pub fn aptPins(a: Allocator, packages: []const [2][]const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, header);
    for (packages, 0..) |p, i| {
        try out.print(a, "{s}Package: {s}\nPin: version {s}\nPin-Priority: 1001\n", .{ if (i == 0) "" else "\n", p[0], p[1] });
    }
    return out.items;
}

pub const watch_packages = [_][2][]const u8{
    .{ "grafana", grafana_version },
    .{ "loki", loki_version },
    .{ "alloy", alloy_version },
    .{ "ntfy", ntfy_version },
};
pub const guest_packages = [_][2][]const u8{.{ "alloy", alloy_version }};

/// VictoriaMetrics single-node under artoo's sandboxed unit (the
/// documented one, tightened); `MemoryMax` because its memory flags size
/// caches only.
pub const vm_unit = std.fmt.comptimePrint(header ++
    \\[Unit]
    \\Description=VictoriaMetrics, artoo watch (SPEC 9.9)
    \\After=network-online.target nftables.service
    \\Wants=network-online.target
    \\
    \\[Service]
    \\Type=simple
    \\User=victoriametrics
    \\Group=victoriametrics
    \\ExecStart=/usr/local/bin/victoria-metrics-prod -storageDataPath=/var/lib/victoria-metrics -retentionPeriod={[retention]s} -httpListenAddr=:{[port]d} -selfScrapeInterval=30s
    \\Restart=always
    \\LimitNOFILE=1048576
    \\MemoryMax=1536M
    \\NoNewPrivileges=true
    \\ProtectSystem=strict
    \\ProtectHome=true
    \\ReadWritePaths=/var/lib/victoria-metrics
    \\PrivateTmp=true
    \\PrivateDevices=true
    \\ProtectKernelTunables=true
    \\ProtectKernelModules=true
    \\ProtectControlGroups=true
    \\RestrictNamespaces=true
    \\RestrictSUIDSGID=true
    \\LockPersonality=true
    \\RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
    \\SystemCallArchitectures=native
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\
, .{ .retention = retention_metrics, .port = port_vm });

/// Single-node Loki: filesystem/TSDB under /var/lib/loki, retention by the
/// compactor, gRPC on localhost, no usage reporting.
pub const loki_config = std.fmt.comptimePrint(header ++
    \\auth_enabled: false
    \\
    \\server:
    \\  http_listen_port: {[port]d}
    \\  grpc_listen_address: 127.0.0.1
    \\  grpc_listen_port: 9096
    \\  log_level: warn
    \\
    \\common:
    \\  instance_addr: 127.0.0.1
    \\  path_prefix: /var/lib/loki
    \\  storage:
    \\    filesystem:
    \\      chunks_directory: /var/lib/loki/chunks
    \\      rules_directory: /var/lib/loki/rules
    \\  replication_factor: 1
    \\  ring:
    \\    kvstore:
    \\      store: inmemory
    \\
    \\schema_config:
    \\  configs:
    \\    - from: 2026-01-01
    \\      store: tsdb
    \\      object_store: filesystem
    \\      schema: v13
    \\      index:
    \\        prefix: index_
    \\        period: 24h
    \\
    \\compactor:
    \\  working_directory: /var/lib/loki/compactor
    \\  compaction_interval: 10m
    \\  retention_enabled: true
    \\  retention_delete_delay: 2h
    \\  delete_request_store: filesystem
    \\
    \\limits_config:
    \\  retention_period: {[retention]s}
    \\
    \\pattern_ingester:
    \\  enabled: false
    \\
    \\analytics:
    \\  reporting_enabled: false
    \\
, .{ .port = port_loki, .retention = retention_logs });

/// Every Grafana switch that contacts grafana.com or another outside
/// service, off (SPEC §9.9); `watch status` reads these lines back.
pub const grafana_telemetry = [_][3][]const u8{
    .{ "analytics", "reporting_enabled", "false" },
    .{ "analytics", "check_for_updates", "false" },
    .{ "analytics", "check_for_plugin_updates", "false" },
    .{ "analytics", "feedback_links_enabled", "false" },
    .{ "news", "news_feed_enabled", "false" },
    .{ "security", "disable_gravatar", "true" },
    .{ "snapshots", "external_enabled", "false" },
    .{ "plugins", "preinstall_disabled", "true" },
    .{ "plugins", "preinstall_auto_update", "false" },
    .{ "plugins", "plugin_admin_enabled", "false" },
    .{ "plugins", "public_key_retrieval_disabled", "true" },
};

pub fn grafanaIni(a: Allocator, l: Lab) ![]const u8 {
    const url = try l.appsUrl(a, grafana_service);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, std.mem.trimEnd(u8, header, "\n"));
    try out.print(a,
        \\
        \\; The admin password: random at setup, 'artoo watch secret grafana' sets yours.
        \\
        \\[paths]
        \\data = /var/lib/grafana
        \\logs = /var/log/grafana
        \\plugins = /var/lib/grafana/plugins
        \\provisioning = /etc/grafana/provisioning
        \\
        \\[server]
        \\http_port = {d}
        \\domain = {s}.apps.{s}
        \\root_url = {s}/
        \\
        \\[security]
        \\admin_user = admin
        \\admin_password = $__file{{/etc/grafana/admin_password}}
        \\cookie_secure = true
        \\disable_gravatar = true
        \\
        \\[users]
        \\allow_sign_up = false
        \\
        \\[auth.anonymous]
        \\enabled = false
        \\
        \\[unified_alerting]
        \\enabled = true
        \\
        \\[dashboards]
        \\default_home_dashboard_path = /etc/grafana/dashboards/artoo-lab.json
        \\
    , .{ port_grafana, grafana_service, l.domain, url });
    var section: []const u8 = "";
    for (grafana_telemetry) |t| {
        // [security] is written above, with the login settings.
        if (std.mem.eql(u8, t[0], "security")) continue;
        if (!std.mem.eql(u8, section, t[0])) {
            section = t[0];
            try out.print(a, "\n[{s}]\n", .{section});
        }
        try out.print(a, "{s} = {s}\n", .{ t[1], t[2] });
    }
    return out.items;
}

pub const datasources = header ++
    \\apiVersion: 1
    \\prune: true
    \\datasources:
    \\  - name: VictoriaMetrics
    \\    uid: victoriametrics
    \\    type: prometheus
    \\    access: proxy
    \\    url: http://localhost:8428
    \\    isDefault: true
    \\    editable: false
    \\    jsonData:
    \\      timeInterval: 30s
    \\  - name: Loki
    \\    uid: loki
    \\    type: loki
    \\    access: proxy
    \\    url: http://localhost:3100
    \\    editable: false
    \\
;

pub const dashboard_provider = header ++
    \\apiVersion: 1
    \\providers:
    \\  - name: artoo
    \\    folder: Lab
    \\    type: file
    \\    # Files are the truth: a dashboard whose file is gone is deleted.
    \\    disableDeletion: false
    \\    allowUiUpdates: false
    \\    options:
    \\      path: /etc/grafana/dashboards
    \\
;

/// The notification's title and message (SPEC §9.9, readable
/// notifications), from the rules' `summary` and `description`
/// annotations: ntfy's built-in Grafana template shows only these two.
/// One alert → its summary as the title; several → the rule's title
/// and the counts. Grafana's notification template language (Go
/// templates); notifications are grouped by rule (`alertname`).
pub const notification_template =
    \\{{ define "artoo.title" -}}
    \\{{ if eq (len .Alerts.Firing) 0 -}}
    \\Resolved: {{ if eq (len .Alerts.Resolved) 1 }}{{ (index .Alerts.Resolved 0).Annotations.summary }}{{ else }}{{ .GroupLabels.alertname }} ({{ len .Alerts.Resolved }}){{ end }}
    \\{{- else if eq (len .Alerts) 1 -}}
    \\{{ (index .Alerts.Firing 0).Annotations.summary }}
    \\{{- else -}}
    \\{{ .GroupLabels.alertname }}: {{ len .Alerts.Firing }} firing{{ with .Alerts.Resolved }}, {{ len . }} resolved{{ end }}
    \\{{- end }}
    \\{{- end }}
    \\
    \\{{ define "artoo.message" -}}
    \\{{ if eq (len .Alerts) 1 -}}
    \\{{ with index .Alerts 0 -}}
    \\{{ if eq .Status "firing" }}{{ .Annotations.description }}
    \\Since {{ .StartsAt.UTC.Format "Jan 2 15:04 UTC" }}.
    \\{{- else }}Fired since {{ .StartsAt.UTC.Format "Jan 2 15:04 UTC" }}.{{ end }}
    \\{{- end }}
    \\{{- else -}}
    \\{{ range .Alerts.Firing -}}
    \\{{ .Annotations.summary }}
    \\{{ .Annotations.description }}
    \\Since {{ .StartsAt.UTC.Format "Jan 2 15:04 UTC" }}.
    \\
    \\{{ end -}}
    \\{{ with .Alerts.Resolved -}}
    \\Resolved:
    \\{{ range . }}- {{ .Annotations.summary }}
    \\{{ end -}}
    \\{{ end -}}
    \\{{ end -}}
    \\{{ end }}
    \\
;

/// `text` as a YAML block scalar's lines, indented by six spaces.
fn indented(comptime text: []const u8) []const u8 {
    comptime {
        var out: []const u8 = "";
        var it = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
        while (it.next()) |line| out = out ++ (if (line.len == 0) "" else "      " ++ line) ++ "\n";
        return out;
    }
}

/// The webhook to ntfy on `localhost` with ntfy's built-in Grafana
/// template, its title and message from `notification_template`; the
/// token comes from Grafana's environment (`/etc/grafana/ntfy.env`, made
/// on the VM by `watch setup`).
pub const contact_point = std.fmt.comptimePrint(header ++
    \\apiVersion: 1
    \\contactPoints:
    \\  - orgId: 1
    \\    name: ntfy
    \\    receivers:
    \\      - uid: artoo-ntfy
    \\        type: webhook
    \\        disableResolveMessage: false
    \\        settings:
    \\          url: http://localhost:{[port]d}/{[topic]s}?template=grafana
    \\          httpMethod: POST
    \\          authorization_scheme: Bearer
    \\          authorization_credentials: $NTFY_TOKEN
    \\          title: '{{{{ template "artoo.title" . }}}}'
    \\          message: '{{{{ template "artoo.message" . }}}}'
    \\policies:
    \\  - orgId: 1
    \\    receiver: ntfy
    \\    group_by: ["grafana_folder", "alertname"]
    \\    group_wait: 30s
    \\    group_interval: 5m
    \\    repeat_interval: 4h
    \\templates:
    \\  - orgId: 1
    \\    name: artoo
    \\    template: |
    \\
, .{ .port = port_ntfy, .topic = topic }) ++ indented(notification_template);

pub const grafana_dropin = header ++
    \\[Service]
    \\EnvironmentFile=/etc/grafana/ntfy.env
    \\
;

pub fn ntfyServer(a: Allocator, l: Lab) ![]const u8 {
    return std.fmt.allocPrint(a,
        \\{s}
        \\# Users, their access and Grafana's token come from /etc/ntfy/auth.env.
        \\base-url: "{s}"
        \\listen-http: ":{d}"
        \\behind-proxy: true
        \\cache-file: "/var/cache/ntfy/cache.db"
        \\auth-file: "/var/lib/ntfy/user.db"
        \\auth-default-access: "deny-all"
        \\enable-signup: false
        \\enable-login: true
        \\# No relay: the Android app keeps its own connection (ntfy's default is ntfy.sh).
        \\upstream-base-url: ""
        \\log-level: warn
        \\
    , .{ std.mem.trimEnd(u8, header, "\n"), try l.appsUrl(a, ntfy_service), port_ntfy });
}

/// The package unit plus artoo's environment (users, ACL, token) and the
/// sandboxing the package leaves for "a future update".
pub const ntfy_dropin = header ++
    \\[Unit]
    \\ConditionPathExists=/etc/ntfy/auth.env
    \\
    \\[Service]
    \\EnvironmentFile=/etc/ntfy/auth.env
    \\NoNewPrivileges=true
    \\ProtectSystem=strict
    \\ProtectHome=true
    \\ReadWritePaths=/var/cache/ntfy /var/lib/ntfy
    \\PrivateTmp=true
    \\
;

/// `NTFY_AUTH_*` for ntfy's declarative users (SPEC §9.9): bcrypt hashes
/// only (the phone's is made on the Mac), Grafana's token generated on the
/// VM. `token` may be the shell expansion that the setup script fills.
pub fn ntfyAuthEnv(a: Allocator, grafana_hash: []const u8, phone_hash: ?[]const u8, token: []const u8) ![]const u8 {
    var users: std.ArrayList(u8) = .empty;
    try users.print(a, "grafana:{s}:user", .{grafana_hash});
    if (phone_hash) |h| try users.print(a, ",phone:{s}:user", .{h});
    const access = if (phone_hash != null)
        "grafana:" ++ topic ++ ":wo,phone:" ++ topic ++ ":ro"
    else
        "grafana:" ++ topic ++ ":wo";
    return std.fmt.allocPrint(a,
        \\# Managed by artoo (SPEC §9.9): hashes and a token that never leaves this VM.
        \\NTFY_AUTH_USERS='{s}'
        \\NTFY_AUTH_ACCESS='{s}'
        \\NTFY_AUTH_TOKENS='grafana:{s}:grafana'
        \\
    , .{ users.items, access, token });
}

/// Accounts and directories, before any package: the firewall names the
/// service users, and Loki's package starts its service on install.
pub const prepare =
    \\set -eu
    \\for u in grafana loki victoriametrics alloy ntfy; do
    \\  getent group "$u" >/dev/null || groupadd --system "$u"
    \\  getent passwd "$u" >/dev/null || useradd --system --gid "$u" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "$u"
    \\done
    \\getent group systemd-journal >/dev/null && usermod -a -G systemd-journal alloy
    \\getent group adm >/dev/null && usermod -a -G adm alloy
    \\install -d -m 0750 -o victoriametrics -g victoriametrics /var/lib/victoria-metrics
    \\install -d -m 0750 -o loki -g loki /var/lib/loki
    \\install -d -m 0755 /etc/loki /etc/ntfy /etc/alloy /etc/grafana/dashboards
    \\install -d -m 0755 /etc/grafana /etc/grafana/provisioning /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /etc/grafana/provisioning/alerting
    \\install -d -m 0700 -o ntfy -g ntfy /var/cache/ntfy /var/lib/ntfy
    \\install -d -m 0770 -o alloy -g alloy /var/lib/alloy
    \\install -d -m 0755 /var/lib/artoo-facts
    \\
;

/// Packages at their pins; configs written before are kept (`confold`).
pub const install_packages = std.fmt.comptimePrint(
    \\set -eu
    \\export DEBIAN_FRONTEND=noninteractive
    \\apt-get update -qq
    \\apt-get install -y -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef grafana={[grafana]s} loki={[loki]s} alloy={[alloy]s} ntfy={[ntfy]s} >/dev/null
    \\
, .{ .grafana = grafana_version, .loki = loki_version, .alloy = alloy_version, .ntfy = ntfy_version });

/// VictoriaMetrics from its release tarball, checked against the pinned
/// SHA-256 before anything is unpacked.
pub const install_vm = std.fmt.comptimePrint(
    \\set -eu
    \\W=$(mktemp -d /var/tmp/artoo-vm.XXXXXX)
    \\trap 'rm -rf "$W"' EXIT
    \\curl -fsSL --proto '=https' -o "$W/vm.tar.gz" '{[url]s}'
    \\echo '{[sha]s}  '"$W/vm.tar.gz" | sha256sum -c --quiet -
    \\tar -xzf "$W/vm.tar.gz" -C "$W" victoria-metrics-prod
    \\"$W/victoria-metrics-prod" -version | grep -q -- '-{[version]s}-'
    \\install -m 0755 "$W/victoria-metrics-prod" /usr/local/bin/victoria-metrics-prod
    \\
, .{ .url = vm_url, .sha = vm_sha256, .version = vm_version });

/// Sets Grafana's admin password from stdin (base64), as user `grafana` so
/// the database keeps its owner.
pub const reset_admin =
    \\set -eu
    \\base64 -d | runuser -u grafana -- /usr/sbin/grafana cli --homepath /usr/share/grafana --config /etc/grafana/grafana.ini admin reset-admin-password --password-from-stdin >/dev/null
    \\
;

/// A random initial admin password and Grafana's ntfy token, made on the
/// VM once; neither ever leaves it.
pub const make_secrets = std.fmt.comptimePrint(
    \\set -eu
    \\umask 077
    \\if ! test -s /etc/grafana/admin_password; then
    \\  head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' > /etc/grafana/admin_password
    \\  chown root:grafana /etc/grafana/admin_password; chmod 0640 /etc/grafana/admin_password
    \\fi
    \\if ! test -s /etc/grafana/ntfy.env; then
    \\  t="tk_$(tr -dc 'a-z0-9' </dev/urandom | head -c 29)"
    \\  printf 'NTFY_TOKEN=%s\n' "$t" > /etc/grafana/ntfy.env
    \\  chown root:grafana /etc/grafana/ntfy.env; chmod 0640 /etc/grafana/ntfy.env
    \\fi
    \\
, .{});

/// Writes /etc/ntfy/auth.env from the template on stdin (base64), filling
/// `@TOKEN@` with Grafana's token from /etc/grafana/ntfy.env — so the token
/// is never sent from the Mac — and `@GRAFANA_HASH@` with the Grafana
/// user's hash already there.
pub const write_auth_env =
    \\set -eu
    \\umask 077
    \\t=$(sed -n 's/^NTFY_TOKEN=//p' /etc/grafana/ntfy.env)
    \\test -n "$t"
    \\g=$(sed -n "s/^NTFY_AUTH_USERS='grafana:\\([^:]*\\):user.*/\\1/p" /etc/ntfy/auth.env 2>/dev/null || true)
    \\f=$(mktemp /etc/ntfy/auth.env.artoo.XXXXXX)
    \\base64 -d | sed -e "s|@TOKEN@|$t|" -e "s|@GRAFANA_HASH@|$g|" > "$f"
    \\if grep -q "grafana::" "$f"; then rm -f "$f"; echo "no Grafana user hash to keep; run 'artoo watch setup'" >&2; exit 3; fi
    \\chown root:ntfy "$f"; chmod 0640 "$f"
    \\mv -f "$f" /etc/ntfy/auth.env
    \\
;

pub const token_placeholder = "@TOKEN@";
/// Keeps the Grafana user's hash already in /etc/ntfy/auth.env.
pub const grafana_hash_placeholder = "@GRAFANA_HASH@";

// ---------------------------------------------------------------- guests

/// Alloy's systemd drop-in, on every guest (also from the template's
/// vendor-data): no start before enrollment, and no traffic beyond the
/// private networks — telemetry cannot leave even if a switch is missed.
pub const alloy_dropin =
    \\# Managed by artoo (SPEC §9.9): starts only once enrolled; private networks only.
    \\[Unit]
    \\ConditionPathExists=/etc/alloy/artoo.alloy
    \\
    \\[Service]
    \\IPAddressDeny=any
    \\IPAddressAllow=localhost link-local 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7
    \\
;
pub const alloy_dropin_path = "/etc/systemd/system/alloy.service.d/10-artoo.conf";

pub const alloy_default = header_guest ++
    \\CONFIG_FILE="/etc/alloy/artoo.alloy"
    \\CUSTOM_ARGS="--disable-reporting --server.http.disable-support-bundle"
    \\RESTART_ON_UPGRADE=true
    \\
;

pub const Role = enum { plain, edge, router, watch, search };

pub const Guest = struct {
    /// The guest's VM name (the `host` label).
    name: []const u8,
    role: Role = .plain,
    /// `scarif.lab.example.com`.
    watch_host: []const u8,
};

/// The guest's Alloy pipeline: journald → Loki, node metrics (with the
/// systemd collector and artoo's fact files) → VictoriaMetrics, plus the
/// role's local scrapes and, on the watchdog, the HTTPS probes.
pub fn alloyConfig(a: Allocator, g: Guest, l: Lab) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.print(a,
        \\// Managed by artoo (SPEC §9.9); 'artoo watch enroll' overwrites edits.
        \\
        \\loki.relabel "journal" {{
        \\  forward_to = []
        \\  rule {{
        \\    source_labels = ["__journal__systemd_unit"]
        \\    target_label  = "unit"
        \\  }}
        \\  rule {{
        \\    source_labels = ["__journal_priority_keyword"]
        \\    target_label  = "level"
        \\  }}
        \\}}
        \\
        \\loki.source.journal "journal" {{
        \\  forward_to    = [loki.write.watch.receiver]
        \\  relabel_rules = loki.relabel.journal.rules
        \\  labels        = {{ host = "{[name]s}" }}
        \\}}
        \\
        \\loki.write "watch" {{
        \\  endpoint {{
        \\    url = "http://{[watch]s}:{[loki]d}/loki/api/v1/push"
        \\  }}
        \\}}
        \\
        \\prometheus.exporter.unix "node" {{
        \\  enable_collectors = ["systemd"]
        \\  textfile {{
        \\    directory = "/var/lib/artoo-facts"
        \\  }}
        \\}}
        \\
        \\prometheus.scrape "node" {{
        \\  targets         = prometheus.exporter.unix.node.targets
        \\  forward_to      = [prometheus.relabel.host.receiver]
        \\  scrape_interval = "30s"
        \\}}
        \\
        \\prometheus.relabel "host" {{
        \\  forward_to = [prometheus.remote_write.watch.receiver]
        \\  rule {{
        \\    target_label = "host"
        \\    replacement  = "{[name]s}"
        \\  }}
        \\}}
        \\
        \\prometheus.remote_write "watch" {{
        \\  endpoint {{
        \\    url = "http://{[watch]s}:{[vm]d}/api/v1/write"
        \\  }}
        \\}}
        \\
    , .{ .name = g.name, .watch = g.watch_host, .loki = port_loki, .vm = port_vm });
    switch (g.role) {
        .edge => try out.appendSlice(a,
            \\
            \\prometheus.scrape "edge" {
            \\  targets = [
            \\    {"__address__" = "localhost:2019", "job" = "caddy"},
            \\    {"__address__" = "localhost:20241", "job" = "cloudflared"},
            \\  ]
            \\  forward_to      = [prometheus.relabel.host.receiver]
            \\  scrape_interval = "30s"
            \\}
            \\
        ),
        .watch => {
            try out.print(a,
                \\
                \\prometheus.exporter.blackbox "https" {{
                \\  config = "{s}"
                \\
            , .{try blackboxModules(a, l.services)});
            for (l.services) |s| try out.print(a,
                \\  target {{
                \\    name    = "{s}"
                \\    address = "{s}{s}"
                \\    module  = "https{s}{s}"
                \\  }}
                \\
            , .{ s.name, try l.appsUrl(a, s.name), s.path, if (s.down != null) "-" else "", if (s.down != null) s.name else "" });
            try out.appendSlice(a,
                \\}
                \\
                \\prometheus.scrape "probes" {
                \\  targets         = prometheus.exporter.blackbox.https.targets
                \\  forward_to      = [prometheus.relabel.probes.receiver]
                \\  scrape_interval = "60s"
                \\}
                \\
            );
            try probeLabels(a, &out, l);
        },
        .search => try out.appendSlice(a,
            \\
            \\prometheus.scrape "search" {
            \\  targets         = [{"__address__" = "localhost:8080", "job" = "holocron"}]
            \\  metrics_path    = "/v1/metrics"
            \\  forward_to      = [prometheus.relabel.host.receiver]
            \\  scrape_interval = "30s"
            \\}
            \\
        ),
        .plain, .router => {},
    }
    return out.items;
}

/// Facts as metrics, every minute, for Alloy's textfile collector: pending
/// reboot, the last unattended upgrade, and per role the edge's drop
/// counters, the router's Tailscale route, the watchdog's telemetry drops.
pub const facts_script =
    \\#!/bin/sh
    \\# Managed by artoo (SPEC §9.9): facts for Alloy's textfile collector.
    \\set -u
    \\out=/var/lib/artoo-facts/artoo.prom
    \\t=$(mktemp /var/lib/artoo-facts/.artoo.XXXXXX)
    \\now=$(date +%s)
    \\{
    \\if [ -e /var/run/reboot-required ]; then
    \\  echo "artoo_reboot_required 1"
    \\  echo "artoo_reboot_required_seconds $((now - $(stat -c %Y /var/run/reboot-required)))"
    \\else
    \\  echo "artoo_reboot_required 0"
    \\  echo "artoo_reboot_required_seconds 0"
    \\fi
    \\s=/var/lib/apt/periodic/unattended-upgrades-stamp
    \\[ -e "$s" ] && echo "artoo_upgrades_last_run_timestamp_seconds $(stat -c %Y "$s")"
    \\for tb in artoo_edge artoo_watch; do
    \\  nft -j list counters table inet "$tb" 2>/dev/null | jq -r --arg tb "$tb" '.nftables[] | select(.counter) | .counter | "artoo_drop_packets{table=\"\($tb)\",counter=\"\(.name)\"} \(.packets)"'
    \\done
    \\if command -v tailscale >/dev/null 2>&1 && systemctl is-active -q tailscaled &&
    \\   tailscale debug prefs 2>/dev/null | jq -e '(.AdvertiseRoutes // []) | length > 0' >/dev/null; then
    \\  tailscale status --json 2>/dev/null | jq -r '
    \\    "artoo_tailscale_running \(if .BackendState == "Running" then 1 else 0 end)",
    \\    "artoo_tailscale_routes_primary \((.Self.PrimaryRoutes // []) | length)"'
    \\fi
    \\} > "$t"
    \\chmod 0644 "$t"
    \\mv -f "$t" "$out"
    \\
;

pub const facts_service = header_guest ++
    \\[Unit]
    \\Description=artoo facts for Alloy (SPEC 9.9)
    \\
    \\[Service]
    \\Type=oneshot
    \\ExecStart=/usr/local/libexec/artoo-facts
    \\
;

pub const facts_timer = header_guest ++
    \\[Unit]
    \\Description=artoo facts every minute (SPEC 9.9)
    \\
    \\[Timer]
    \\OnBootSec=30s
    \\OnUnitActiveSec=60s
    \\AccuracySec=5s
    \\
    \\[Install]
    \\WantedBy=timers.target
    \\
;

/// Installs Alloy at its pin when missing (guests built before the
/// template carried it); needs the repository files, and creates the
/// `alloy` group the config file belongs to.
pub const enroll_install = std.fmt.comptimePrint(
    \\set -eu
    \\export DEBIAN_FRONTEND=noninteractive
    \\if ! dpkg-query -W -f='${{Version}}' alloy 2>/dev/null | grep -qx '{[alloy]s}'; then
    \\  apt-get update -qq
    \\  apt-get install -y -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef alloy={[alloy]s} >/dev/null
    \\fi
    \\
, .{ .alloy = alloy_version });

/// (Re)starts Alloy and the facts timer.
pub const enroll_start =
    \\set -eu
    \\getent group systemd-journal >/dev/null && usermod -a -G systemd-journal alloy
    \\install -d -m 0755 /var/lib/artoo-facts
    \\systemctl daemon-reload
    \\systemctl enable --now artoo-facts.timer >/dev/null 2>&1
    \\systemctl start artoo-facts.service
    \\systemctl enable alloy >/dev/null 2>&1
    \\systemctl restart alloy
    \\
;

pub const enroll_script = enroll_install ++ enroll_start;

/// Files that need the `alloy` group (written after the install).
pub fn needsAlloy(f: File) bool {
    return std.mem.endsWith(u8, f.owner, ":alloy");
}

/// The files `watch enroll` keeps on a guest.
pub fn guestFiles(a: Allocator, g: Guest, l: Lab) ![]const File {
    return a.dupe(File, &.{
        .{ .path = "/usr/share/keyrings/grafana.asc", .mode = "0644", .owner = "root:root", .content = grafana_key },
        .{ .path = "/etc/apt/sources.list.d/grafana.list", .mode = "0644", .owner = "root:root", .content = grafana_list },
        .{ .path = "/etc/apt/preferences.d/artoo-alloy", .mode = "0644", .owner = "root:root", .content = try aptPins(a, &guest_packages) },
        .{ .path = alloy_dropin_path, .mode = "0644", .owner = "root:root", .content = alloy_dropin },
        .{ .path = "/etc/default/alloy", .mode = "0644", .owner = "root:root", .content = alloy_default },
        .{ .path = "/etc/alloy/artoo.alloy", .mode = "0640", .owner = "root:alloy", .content = try alloyConfig(a, g, l) },
        .{ .path = "/usr/local/libexec/artoo-facts", .mode = "0755", .owner = "root:root", .content = facts_script },
        .{ .path = "/etc/systemd/system/artoo-facts.service", .mode = "0644", .owner = "root:root", .content = facts_service },
        .{ .path = "/etc/systemd/system/artoo-facts.timer", .mode = "0644", .owner = "root:root", .content = facts_timer },
    });
}

/// The watchdog's own files, in the order they are applied (its Alloy
/// files come from `guestFiles` with role `watch`).
pub fn watchFiles(a: Allocator, l: Lab, dashboards: []const File, rules: []const u8) ![]const File {
    var out: std.ArrayList(File) = .empty;
    try out.appendSlice(a, &.{
        .{ .path = "/etc/nftables.conf", .mode = "0644", .owner = "root:root", .content = try nftables(a, l) },
        .{ .path = "/usr/share/keyrings/grafana.asc", .mode = "0644", .owner = "root:root", .content = grafana_key },
        .{ .path = "/usr/share/keyrings/ntfy.gpg", .mode = "0644", .owner = "root:root", .content = ntfy_key },
        .{ .path = "/etc/apt/sources.list.d/grafana.list", .mode = "0644", .owner = "root:root", .content = grafana_list },
        .{ .path = "/etc/apt/sources.list.d/ntfy.list", .mode = "0644", .owner = "root:root", .content = ntfy_list },
        .{ .path = "/etc/apt/preferences.d/artoo-watch", .mode = "0644", .owner = "root:root", .content = try aptPins(a, &watch_packages) },
        .{ .path = "/etc/systemd/system/victoriametrics.service", .mode = "0644", .owner = "root:root", .content = vm_unit },
        .{ .path = "/etc/loki/config.yml", .mode = "0644", .owner = "root:root", .content = loki_config },
        .{ .path = "/etc/grafana/grafana.ini", .mode = "0640", .owner = "root:grafana", .content = try grafanaIni(a, l) },
        .{ .path = "/etc/grafana/provisioning/datasources/artoo.yaml", .mode = "0640", .owner = "root:grafana", .content = datasources },
        .{ .path = "/etc/grafana/provisioning/dashboards/artoo.yaml", .mode = "0640", .owner = "root:grafana", .content = dashboard_provider },
        .{ .path = "/etc/grafana/provisioning/alerting/artoo-contact.yaml", .mode = "0640", .owner = "root:grafana", .content = contact_point },
        .{ .path = "/etc/grafana/provisioning/alerting/artoo-rules.yaml", .mode = "0640", .owner = "root:grafana", .content = rules },
        .{ .path = "/etc/systemd/system/grafana-server.service.d/10-artoo.conf", .mode = "0644", .owner = "root:root", .content = grafana_dropin },
        .{ .path = "/etc/ntfy/server.yml", .mode = "0644", .owner = "root:root", .content = try ntfyServer(a, l) },
        .{ .path = "/etc/systemd/system/ntfy.service.d/10-artoo.conf", .mode = "0644", .owner = "root:root", .content = ntfy_dropin },
    });
    try out.appendSlice(a, dashboards);
    return out.items;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

const test_lab: Lab = .{
    .pve = "192.168.1.10",
    .gateway = "192.168.1.1",
    .lan = "192.168.1.0/24",
    .pool = "192.168.1.200-192.168.1.254",
    .edge = "192.168.1.200",
    .domain = "lab.example.com",
    .services = &.{ .{ .name = "grafana" }, .{ .name = "ntfy" } },
};

fn expectAll(hay: []const u8, needles: []const []const u8) !void {
    for (needles) |n| {
        if (std.mem.find(u8, hay, n) == null) {
            std.debug.print("missing: {s}\n--- in:\n{s}\n", .{ n, hay });
            return error.TestUnexpectedResult;
        }
    }
}

test "nftables: Proxmox and UniFi dropped first, service users never reach the internet" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const nft = try nftables(arena.allocator(), test_lab);
    try expectAll(nft, &.{
        "table inet artoo_watch {\n",
        "ip saddr $edge tcp dport { 3000, 2586 } accept\n",
        "ip saddr $pool tcp dport { 8428, 3100 } accept\n",
        "ip saddr $pve tcp dport 22 accept\n",
        "meta skuid { \"grafana\", \"loki\", \"victoriametrics\", \"alloy\", \"ntfy\" } counter name telemetry drop\n",
    });
    const pve = std.mem.find(u8, nft, "ip daddr $pve counter name to_pve drop").?;
    const telemetry = std.mem.find(u8, nft, "counter name telemetry drop").?;
    const web = std.mem.find(u8, nft, "tcp dport { 80, 443 } accept").?;
    try testing.expect(pve < web and telemetry < web);
}

test "grafanaIni: every telemetry switch off, root URL is the service name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const ini = try grafanaIni(arena.allocator(), test_lab);
    try expectAll(ini, &.{
        "root_url = https://grafana.apps.lab.example.com/\n",
        "admin_password = $__file{/etc/grafana/admin_password}\n",
        "[analytics]\nreporting_enabled = false\ncheck_for_updates = false\ncheck_for_plugin_updates = false\nfeedback_links_enabled = false\n",
        "[news]\nnews_feed_enabled = false\n",
        "disable_gravatar = true\n",
        "[snapshots]\nexternal_enabled = false\n",
        "[plugins]\npreinstall_disabled = true\npreinstall_auto_update = false\nplugin_admin_enabled = false\npublic_key_retrieval_disabled = true\n",
    });
}

test "loki: no usage reporting, retention on" {
    try expectAll(loki_config, &.{ "analytics:\n  reporting_enabled: false\n", "retention_enabled: true\n", "retention_period: 744h\n", "grpc_listen_address: 127.0.0.1\n" });
}

test "alloy: reporting off, LAN only, pushes to the watchdog by name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectAll(alloy_default, &.{"CUSTOM_ARGS=\"--disable-reporting --server.http.disable-support-bundle\"\n"});
    try expectAll(alloy_dropin, &.{ "IPAddressDeny=any\n", "ConditionPathExists=/etc/alloy/artoo.alloy\n" });
    const plain = try alloyConfig(a, .{ .name = "naboo", .watch_host = "scarif.lab.example.com" }, test_lab);
    try expectAll(plain, &.{
        "url = \"http://scarif.lab.example.com:3100/loki/api/v1/push\"",
        "url = \"http://scarif.lab.example.com:8428/api/v1/write\"",
        "labels        = { host = \"naboo\" }",
        "directory = \"/var/lib/artoo-facts\"",
    });
    try testing.expect(std.mem.find(u8, plain, "localhost:2019") == null);
    try testing.expect(std.mem.find(u8, plain, "blackbox") == null);
    const edge = try alloyConfig(a, .{ .name = "bespin", .role = .edge, .watch_host = "scarif.lab.example.com" }, test_lab);
    try expectAll(edge, &.{ "\"localhost:2019\", \"job\" = \"caddy\"", "\"localhost:20241\", \"job\" = \"cloudflared\"" });
    try testing.expect(std.mem.find(u8, edge, "/v1/metrics") == null);
    const search = try alloyConfig(a, .{ .name = "holocron", .role = .search, .watch_host = "scarif.lab.example.com" }, test_lab);
    try expectAll(search, &.{ "{\"__address__\" = \"localhost:8080\", \"job\" = \"holocron\"}", "metrics_path    = \"/v1/metrics\"" });
    try testing.expect(std.mem.find(u8, plain, "/v1/metrics") == null);
    const watch = try alloyConfig(a, .{ .name = "scarif", .role = .watch, .watch_host = "scarif.lab.example.com" }, test_lab);
    try expectAll(watch, &.{
        "  config = \"{ modules: { https: { prober: http, timeout: 8s, http: { fail_if_not_ssl: true, preferred_ip_protocol: ip4 } } } }\"\n",
        "address = \"https://grafana.apps.lab.example.com/\"\n    module  = \"https\"\n",
        "address = \"https://ntfy.apps.lab.example.com/\"\n    module  = \"https\"\n",
    });
}

test "alloy: a service's health path and down text (SPEC §9.9)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var l = test_lab;
    l.services = &.{
        .{ .name = "grafana" },
        .{ .name = "search", .path = "/v1/health", .down = "\"down\"" },
        .{ .name = "odd", .path = "/h?x=1", .down = "it's (a.b)\\" },
    };
    const watch = try alloyConfig(a, .{ .name = "scarif", .role = .watch, .watch_host = "scarif.lab.example.com" }, l);
    try expectAll(watch, &.{
        "  config = \"{ modules: { https: { prober: http, timeout: 8s, http: { fail_if_not_ssl: true, preferred_ip_protocol: ip4 } }" ++
            ", https-search: { prober: http, timeout: 8s, http: { fail_if_not_ssl: true, preferred_ip_protocol: ip4, fail_if_body_matches_regexp: ['\\\"down\\\"'] } }" ++
            ", https-odd: { prober: http, timeout: 8s, http: { fail_if_not_ssl: true, preferred_ip_protocol: ip4, fail_if_body_matches_regexp: ['it''s \\\\(a\\\\.b\\\\)\\\\\\\\'] } } } }\"\n",
        "address = \"https://grafana.apps.lab.example.com/\"\n    module  = \"https\"\n",
        "name    = \"search\"\n    address = \"https://search.apps.lab.example.com/v1/health\"\n    module  = \"https-search\"\n",
        "address = \"https://odd.apps.lab.example.com/h?x=1\"\n    module  = \"https-odd\"\n",
    });
}

test "alloy: probes named by service, URL and guest for the alerts (golden, SPEC §9.9)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var l = test_lab;
    l.services = &.{
        .{ .name = "grafana", .vm = "scarif" },
        .{ .name = "search", .path = "/v1/health?p=$1", .down = "\"down\"", .vm = "hoth" },
        .{ .name = "orphan" },
    };
    const watch = try alloyConfig(a, .{ .name = "scarif", .role = .watch, .watch_host = "scarif.lab.example.com" }, l);
    try expectAll(watch, &.{"  forward_to      = [prometheus.relabel.probes.receiver]\n"});
    const start = std.mem.find(u8, watch, "prometheus.relabel \"probes\"").?;
    try testing.expectEqualStrings(
        \\prometheus.relabel "probes" {
        \\  forward_to = [prometheus.relabel.host.receiver]
        \\  rule {
        \\    source_labels = ["job"]
        \\    regex         = "integrations/blackbox/grafana"
        \\    target_label  = "service"
        \\    replacement   = "grafana"
        \\  }
        \\  rule {
        \\    source_labels = ["job"]
        \\    regex         = "integrations/blackbox/grafana"
        \\    target_label  = "url"
        \\    replacement   = "https://grafana.apps.lab.example.com/"
        \\  }
        \\  rule {
        \\    source_labels = ["job"]
        \\    regex         = "integrations/blackbox/grafana"
        \\    target_label  = "vm"
        \\    replacement   = "scarif"
        \\  }
        \\  rule {
        \\    source_labels = ["job"]
        \\    regex         = "integrations/blackbox/search"
        \\    target_label  = "service"
        \\    replacement   = "search"
        \\  }
        \\  rule {
        \\    source_labels = ["job"]
        \\    regex         = "integrations/blackbox/search"
        \\    target_label  = "url"
        \\    replacement   = "https://search.apps.lab.example.com/v1/health?p=$$1"
        \\  }
        \\  rule {
        \\    source_labels = ["job"]
        \\    regex         = "integrations/blackbox/search"
        \\    target_label  = "vm"
        \\    replacement   = "hoth"
        \\  }
        \\  rule {
        \\    source_labels = ["job"]
        \\    regex         = "integrations/blackbox/orphan"
        \\    target_label  = "service"
        \\    replacement   = "orphan"
        \\  }
        \\  rule {
        \\    source_labels = ["job"]
        \\    regex         = "integrations/blackbox/orphan"
        \\    target_label  = "url"
        \\    replacement   = "https://orphan.apps.lab.example.com/"
        \\  }
        \\}
        \\
    , watch[start..]);
    // Other guests keep their series as they are.
    const plain = try alloyConfig(a, .{ .name = "naboo", .role = .plain, .watch_host = "scarif.lab.example.com" }, l);
    try testing.expect(std.mem.find(u8, plain, "relabel \"probes\"") == null);
}

test "contact point: ntfy's template shows the artoo title and message (golden, SPEC §9.9)" {
    try expectAll(contact_point, &.{
        "          url: http://localhost:2586/lab?template=grafana\n",
        "          title: '{{ template \"artoo.title\" . }}'\n          message: '{{ template \"artoo.message\" . }}'\n",
        "templates:\n  - orgId: 1\n    name: artoo\n    template: |\n      {{ define \"artoo.title\" -}}\n",
    });
    // Grafana interpolates `$VAR` in contact point settings (not in
    // templates or rule annotations): the only `$` there is the token.
    const settings = contact_point[0..std.mem.find(u8, contact_point, "policies:").?];
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, settings, "$"));
    const tmpl = contact_point[std.mem.find(u8, contact_point, "    template: |\n").? + 16 ..];
    var it = std.mem.splitScalar(u8, tmpl[0 .. tmpl.len - 1], '\n');
    var n: usize = 0;
    while (it.next()) |line| : (n += 1) try testing.expect(line.len == 0 or std.mem.startsWith(u8, line, "      "));
    try testing.expectEqual(std.mem.count(u8, notification_template, "\n"), n);
}

test "ntfy: deny-all, no relay, users from the environment" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try expectAll(try ntfyServer(a, test_lab), &.{ "base-url: \"https://ntfy.apps.lab.example.com\"\n", "auth-default-access: \"deny-all\"\n", "upstream-base-url: \"\"\n", "behind-proxy: true\n" });
    const env = try ntfyAuthEnv(a, "$2b$10$g", "$2b$10$p", token_placeholder);
    try expectAll(env, &.{ "NTFY_AUTH_USERS='grafana:$2b$10$g:user,phone:$2b$10$p:user'\n", "NTFY_AUTH_ACCESS='grafana:lab:wo,phone:lab:ro'\n", "NTFY_AUTH_TOKENS='grafana:@TOKEN@:grafana'\n" });
    const no_phone = try ntfyAuthEnv(a, "$2b$10$g", null, token_placeholder);
    try testing.expect(std.mem.find(u8, no_phone, "phone") == null);
}

test "apt pins and installs name the same versions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const pins = try aptPins(arena.allocator(), &watch_packages);
    try expectAll(pins, &.{ "Package: grafana\nPin: version 13.2.3\n", "Package: alloy\nPin: version 1.20.1-1\n", "Package: ntfy\nPin: version 2.29.0\n" });
    try expectAll(install_packages, &.{ "grafana=13.2.3", "loki=3.7.8", "alloy=1.20.1-1", "ntfy=2.29.0", "--force-confold" });
    try expectAll(install_vm, &.{ vm_sha256, "sha256sum -c", vm_url });
}

test "guestFiles: only Alloy's config needs the alloy group (written after the install)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var n: usize = 0;
    for (try guestFiles(arena.allocator(), .{ .name = "naboo", .watch_host = "scarif.lab.example.com" }, test_lab)) |f| {
        if (needsAlloy(f)) {
            n += 1;
            try testing.expectEqualStrings("/etc/alloy/artoo.alloy", f.path);
        }
    }
    try testing.expectEqual(@as(usize, 1), n);
}
