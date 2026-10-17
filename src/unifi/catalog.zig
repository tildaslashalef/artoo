//! Comptime catalog of the UniFi Network Integration API read surface
//! (SPEC §10.2), built from the official v10.6.106 export
//! (`../homelab/api/unifi/network_v10.6.106_openapi.json`). Every GET
//! operation appears exactly once; paths and operationIds are copied
//! verbatim so the export test and `gw spec` can diff them.
//!
//! Each resource declares its list/show operations, extra read verbs,
//! table columns (dotted JSON paths into live items), the fields used for
//! name resolution, and the server-side filterable properties.

const std = @import("std");

pub const Op = struct {
    path: []const u8,
    id: []const u8,
};

pub const Fmt = enum {
    text,
    /// true → yes, false → no.
    bool,
    /// Device/port state: ONLINE → ● online.
    state,
    /// ISO timestamp → relative time.
    time,
    /// Array of scalars → comma list.
    list,
    /// Array → element count.
    count,
};

pub const Column = struct {
    title: []const u8,
    /// Dotted path; `a|b|c` = first present of several paths.
    path: []const u8,
    fmt: Fmt = .text,
    /// Table drop priority (0 = always shown).
    drop: u8 = 0,
    right: bool = false,
    /// Identifiers are never truncated.
    id: bool = false,
};

pub const Filterable = struct {
    name: []const u8,
    type: []const u8,
    functions: []const u8,
};

pub const Extra = struct {
    verb: []const u8,
    summary: []const u8,
    op: Op,
    /// Takes the resource ID/name as its positional.
    targeted: bool = true,
    shape: Shape = .object,
    /// For `.page`: table columns and server-side filterable properties.
    columns: []const Column = &.{},
    filterable: []const Filterable = &.{},

    pub const Shape = enum {
        /// One JSON object, shown as a detail view.
        object,
        /// A paginated list, like `ls`.
        page,
        /// Needs `--from ZONE --to ZONE` (firewall zone IDs as query).
        zone_pair,
    };
};

pub const Method = enum { POST, PUT, PATCH, DELETE };

/// One write operation (SPEC §10.2), generated from the export's request
/// schemas. `fields`/`required` are top-level body keys (union over
/// discriminator variants; deeper validation is the server's).
pub const Write = struct {
    verb: []const u8,
    summary: []const u8,
    kind: Kind,
    method: Method,
    op: Op,
    /// SPEC §3.4: typed-name confirmation, `--yes --confirm` otherwise.
    destructive: bool = false,
    /// Fixed `action` value for action endpoints.
    action: ?[]const u8 = null,
    /// The endpoint accepts `?force=true`.
    force: bool = false,
    fields: []const []const u8 = &.{},
    required: []const []const u8 = &.{},

    pub const Kind = enum {
        /// POST to the collection, body from `--from FILE`.
        create,
        /// PUT a complete body (`--from FILE`) to one object.
        replace,
        /// PATCH selected fields (`--from FILE`).
        patch,
        delete,
        /// POST `{"action": …}` (+ optional fields) to one object.
        action,
        /// Like `action`, on one port of a device (`PORT` argument).
        port_action,
        /// PUT an ordering body (`--from FILE`).
        ordering,
        /// POST `{macAddress, ignoreDeviceLimit}`.
        adopt,
        /// DELETE the collection with a required `--filter`.
        purge,
    };
};

pub const Resource = struct {
    /// CLI noun, `artoo gw <name>`.
    name: []const u8,
    /// Singular label used in messages ("device").
    label: []const u8,
    summary: []const u8,
    /// OpenAPI tag, for `gw spec`.
    tag: []const u8,
    site: bool = true,
    list: Op,
    paginated: bool = true,
    filter: bool = true,
    show: ?Op = null,
    extras: []const Extra = &.{},
    columns: []const Column,
    /// Fields matched exactly when a name is given instead of an ID.
    match: []const []const u8 = &.{"name"},
    filterable: []const Filterable = &.{},
    writes: []const Write = &.{},
    /// Fields in a read object that writes do not accept (`id`,
    /// `metadata`, …): dropped, and named in the plan, when a `show -o
    /// json` document is used as a body.
    read_only: []const []const u8 = &.{},
};

const id_col: Column = .{ .title = "ID", .path = "id", .drop = 3, .id = true };
const origin_col: Column = .{ .title = "ORIGIN", .path = "metadata.origin", .drop = 2 };
const eq4 = "eq ne in notIn";
const eq4like = "eq ne in notIn like";
const eqne = "eq ne";
const cmp = "eq ne gt ge lt le in notIn";
const set_fns = "isEmpty contains containsAny containsAll containsExactly";
const ts = "isNull isNotNull eq ne gt ge lt le";

pub const info: Op = .{ .path = "/v1/info", .id = "getInfo" };

pub const resources = [_]Resource{
    .{
        .name = "sites",
        .label = "site",
        .summary = "Local sites",
        .tag = "Sites",
        .site = false,
        .list = .{ .path = "/v1/sites", .id = "getSiteOverviewPage" },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "REFERENCE", .path = "internalReference", .id = true },
            id_col,
        },
        .match = &.{ "name", "internalReference" },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "internalReference", .type = "STRING", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "devices",
        .label = "device",
        .summary = "Adopted UniFi devices",
        .tag = "UniFi Devices",
        .list = .{ .path = "/v1/sites/{siteId}/devices", .id = "getAdoptedDeviceOverviewPage" },
        .show = .{ .path = "/v1/sites/{siteId}/devices/{deviceId}", .id = "getAdoptedDeviceDetails" },
        .extras = &.{
            .{ .verb = "stats", .summary = "Latest statistics (CPU, memory, load, uptime, radios)", .op = .{ .path = "/v1/sites/{siteId}/devices/{deviceId}/statistics/latest", .id = "getAdoptedDeviceLatestStatistics" } },
            .{
                .verb = "pending",
                .summary = "Devices pending adoption",
                .targeted = false,
                .shape = .page,
                .op = .{ .path = "/v1/pending-devices", .id = "getPendingDevicePage" },
                .columns = &.{
                    .{ .title = "MODEL", .path = "model" },
                    .{ .title = "STATE", .path = "state", .fmt = .state },
                    .{ .title = "IP", .path = "ipAddress", .id = true },
                    .{ .title = "MAC", .path = "macAddress", .id = true },
                    .{ .title = "FIRMWARE", .path = "firmwareVersion", .drop = 1 },
                    .{ .title = "SUPPORTED", .path = "supported", .fmt = .bool, .drop = 2 },
                },
                .filterable = &.{
                    .{ .name = "macAddress", .type = "STRING", .functions = eq4 },
                    .{ .name = "ipAddress", .type = "STRING", .functions = eq4 },
                    .{ .name = "model", .type = "STRING", .functions = eq4 },
                    .{ .name = "state", .type = "STRING", .functions = eq4 },
                    .{ .name = "supported", .type = "BOOLEAN", .functions = eqne },
                    .{ .name = "firmwareVersion", .type = "STRING", .functions = "isNull isNotNull eq ne gt ge lt le like in notIn" },
                    .{ .name = "firmwareUpdatable", .type = "BOOLEAN", .functions = eqne },
                    .{ .name = "features", .type = "SET(STRING)", .functions = set_fns },
                },
            },
        },
        .writes = &.{
            .{ .verb = "adopt", .summary = "Adopt a pending device by MAC address", .kind = .adopt, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/devices", .id = "adoptDevice" }, .fields = &.{ "ignoreDeviceLimit", "macAddress" }, .required = &.{ "ignoreDeviceLimit", "macAddress" } },
            .{ .verb = "restart", .summary = "Restart a device", .kind = .action, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/devices/{deviceId}/actions", .id = "executeAdoptedDeviceAction" }, .destructive = true, .action = "RESTART" },
            .{ .verb = "port-cycle", .summary = "Power-cycle PoE on a device port", .kind = .port_action, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/devices/{deviceId}/interfaces/ports/{portIdx}/actions", .id = "executePortAction" }, .destructive = true, .action = "POWER_CYCLE" },
            .{ .verb = "rm", .summary = "Remove (forget) an adopted device", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/devices/{deviceId}", .id = "removeDevice" }, .destructive = true },
        },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "MODEL", .path = "model" },
            .{ .title = "STATE", .path = "state", .fmt = .state },
            .{ .title = "IP", .path = "ipAddress", .id = true },
            .{ .title = "FIRMWARE", .path = "firmwareVersion", .drop = 1 },
            .{ .title = "UPDATE", .path = "firmwareUpdatable", .fmt = .bool, .drop = 2 },
            .{ .title = "FEATURES", .path = "features", .fmt = .list, .drop = 2 },
            id_col,
        },
        .match = &.{ "name", "macAddress", "ipAddress" },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "macAddress", .type = "STRING", .functions = eq4 },
            .{ .name = "ipAddress", .type = "STRING", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "model", .type = "STRING", .functions = eq4 },
            .{ .name = "state", .type = "STRING", .functions = eq4 },
            .{ .name = "supported", .type = "BOOLEAN", .functions = eqne },
            .{ .name = "firmwareVersion", .type = "STRING", .functions = "isNull isNotNull eq ne gt ge lt le like in notIn" },
            .{ .name = "firmwareUpdatable", .type = "BOOLEAN", .functions = eqne },
            .{ .name = "features", .type = "SET(STRING)", .functions = set_fns },
            .{ .name = "interfaces", .type = "SET(STRING)", .functions = set_fns },
        },
    },
    .{
        .name = "clients",
        .label = "client",
        .summary = "Connected clients",
        .tag = "Clients",
        .list = .{ .path = "/v1/sites/{siteId}/clients", .id = "getConnectedClientOverviewPage" },
        .show = .{ .path = "/v1/sites/{siteId}/clients/{clientId}", .id = "getConnectedClientDetails" },
        .writes = &.{
            .{ .verb = "authorize", .summary = "Authorize guest access for a client", .kind = .action, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/clients/{clientId}/actions", .id = "executeConnectedClientAction" }, .action = "AUTHORIZE_GUEST_ACCESS", .fields = &.{ "dataUsageLimitMBytes", "rxRateLimitKbps", "timeLimitMinutes", "txRateLimitKbps" } },
            .{ .verb = "unauthorize", .summary = "Revoke guest access for a client", .kind = .action, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/clients/{clientId}/actions", .id = "executeConnectedClientAction" }, .action = "UNAUTHORIZE_GUEST_ACCESS", .fields = &.{ "dataUsageLimitMBytes", "rxRateLimitKbps", "timeLimitMinutes", "txRateLimitKbps" } },
        },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "TYPE", .path = "type" },
            .{ .title = "IP", .path = "ipAddress", .id = true },
            .{ .title = "CONNECTED", .path = "connectedAt", .fmt = .time, .drop = 1 },
            .{ .title = "MAC", .path = "macAddress", .drop = 2, .id = true },
            .{ .title = "ACCESS", .path = "access.type", .drop = 2 },
            id_col,
        },
        .match = &.{ "name", "macAddress", "ipAddress" },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "type", .type = "STRING", .functions = eq4 },
            .{ .name = "macAddress", .type = "STRING", .functions = "isNull isNotNull eq ne in notIn" },
            .{ .name = "ipAddress", .type = "STRING", .functions = "isNull isNotNull eq ne in notIn" },
            .{ .name = "connectedAt", .type = "TIMESTAMP", .functions = ts },
            .{ .name = "access.type", .type = "STRING", .functions = eq4 },
            .{ .name = "access.authorized", .type = "BOOLEAN", .functions = "isNull isNotNull eq ne" },
        },
    },
    .{
        .name = "networks",
        .label = "network",
        .summary = "Networks (VLANs, DHCP)",
        .tag = "Networks",
        .list = .{ .path = "/v1/sites/{siteId}/networks", .id = "getNetworksOverviewPage" },
        .show = .{ .path = "/v1/sites/{siteId}/networks/{networkId}", .id = "getNetworkDetails" },
        .extras = &.{
            .{ .verb = "refs", .summary = "Resources that reference the network", .op = .{ .path = "/v1/sites/{siteId}/networks/{networkId}/references", .id = "getNetworkReferences" } },
        },
        .writes = &.{
            .{ .verb = "add", .summary = "Create a network", .kind = .create, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/networks", .id = "createNetwork" }, .destructive = true, .fields = &.{ "cellularBackupEnabled", "deviceId", "dhcpGuarding", "enabled", "internetAccessEnabled", "ipv4Configuration", "ipv6Configuration", "isolationEnabled", "management", "mdnsForwardingEnabled", "name", "vlanId", "zoneId" }, .required = &.{ "enabled", "management", "name", "vlanId" } },
            .{ .verb = "set", .summary = "Replace a network (complete body)", .kind = .replace, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/networks/{networkId}", .id = "updateNetwork" }, .destructive = true, .fields = &.{ "cellularBackupEnabled", "deviceId", "dhcpGuarding", "enabled", "internetAccessEnabled", "ipv4Configuration", "ipv6Configuration", "isolationEnabled", "management", "mdnsForwardingEnabled", "name", "vlanId", "zoneId" }, .required = &.{ "enabled", "management", "name", "vlanId" } },
            .{ .verb = "rm", .summary = "Delete a network", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/networks/{networkId}", .id = "deleteNetwork" }, .destructive = true, .force = true },
        },
        .read_only = &.{ "default", "id", "metadata" },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "VLAN", .path = "vlanId", .right = true },
            .{ .title = "MANAGEMENT", .path = "management" },
            .{ .title = "ENABLED", .path = "enabled", .fmt = .bool },
            .{ .title = "DEFAULT", .path = "default", .fmt = .bool, .drop = 1 },
            origin_col,
            id_col,
        },
        .filterable = &.{
            .{ .name = "management", .type = "STRING", .functions = eq4 },
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "enabled", .type = "BOOLEAN", .functions = eqne },
            .{ .name = "vlanId", .type = "INTEGER", .functions = cmp },
            .{ .name = "deviceId", .type = "UUID", .functions = "eq ne in notIn isNull isNotNull" },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "wifi",
        .label = "Wi-Fi broadcast",
        .summary = "Wi-Fi broadcasts (SSIDs)",
        .tag = "WiFi Broadcasts",
        .list = .{ .path = "/v1/sites/{siteId}/wifi/broadcasts", .id = "getWifiBroadcastPage" },
        .show = .{ .path = "/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}", .id = "getWifiBroadcastDetails" },
        .writes = &.{
            .{ .verb = "add", .summary = "Create a Wi-Fi broadcast", .kind = .create, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/wifi/broadcasts", .id = "createWifiBroadcast" }, .destructive = true, .fields = &.{ "advertiseDeviceName", "arpProxyEnabled", "bandSteeringEnabled", "basicDataRateKbpsByFrequencyGHz", "blackoutScheduleConfiguration", "broadcastingDeviceFilter", "broadcastingFrequenciesGHz", "bssTransitionEnabled", "channel2gLockedTo6", "clientFilteringPolicy", "clientIsolationEnabled", "dnsAssistanceConfiguration", "dtimPeriod2gLockedTo3", "dtimPeriodByFrequencyGHzOverride", "enabled", "handoffSuggestionsConfiguration", "hideName", "hotspotConfiguration", "mdnsProxyConfiguration", "mloEnabled", "multicastFilteringPolicy", "multicastToUnicastConversionEnabled", "name", "network", "securityConfiguration", "type", "uapsdEnabled" }, .required = &.{ "channel2gLockedTo6", "clientIsolationEnabled", "dtimPeriod2gLockedTo3", "enabled", "hideName", "multicastToUnicastConversionEnabled", "name", "securityConfiguration", "type", "uapsdEnabled" } },
            .{ .verb = "set", .summary = "Replace a Wi-Fi broadcast (complete body)", .kind = .replace, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}", .id = "updateWifiBroadcast" }, .destructive = true, .fields = &.{ "advertiseDeviceName", "arpProxyEnabled", "bandSteeringEnabled", "basicDataRateKbpsByFrequencyGHz", "blackoutScheduleConfiguration", "broadcastingDeviceFilter", "broadcastingFrequenciesGHz", "bssTransitionEnabled", "channel2gLockedTo6", "clientFilteringPolicy", "clientIsolationEnabled", "dnsAssistanceConfiguration", "dtimPeriod2gLockedTo3", "dtimPeriodByFrequencyGHzOverride", "enabled", "handoffSuggestionsConfiguration", "hideName", "hotspotConfiguration", "mdnsProxyConfiguration", "mloEnabled", "multicastFilteringPolicy", "multicastToUnicastConversionEnabled", "name", "network", "securityConfiguration", "type", "uapsdEnabled" }, .required = &.{ "channel2gLockedTo6", "clientIsolationEnabled", "dtimPeriod2gLockedTo3", "enabled", "hideName", "multicastToUnicastConversionEnabled", "name", "securityConfiguration", "type", "uapsdEnabled" } },
            .{ .verb = "rm", .summary = "Delete a Wi-Fi broadcast", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/wifi/broadcasts/{wifiBroadcastId}", .id = "deleteWifiBroadcast" }, .destructive = true, .force = true },
        },
        .read_only = &.{ "id", "metadata" },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "ENABLED", .path = "enabled", .fmt = .bool },
            .{ .title = "SECURITY", .path = "securityConfiguration.type" },
            .{ .title = "NETWORK", .path = "network.type", .drop = 1 },
            .{ .title = "BANDS (GHz)", .path = "broadcastingFrequenciesGHz", .fmt = .list, .drop = 1 },
            id_col,
        },
        .filterable = &.{
            .{ .name = "type", .type = "STRING", .functions = eq4 },
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "enabled", .type = "BOOLEAN", .functions = eqne },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "broadcastingFrequenciesGHz", .type = "SET(DECIMAL)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
            .{ .name = "network.type", .type = "STRING", .functions = "eq ne in notIn isNull isNotNull" },
            .{ .name = "network.networkId", .type = "UUID", .functions = eq4 },
            .{ .name = "securityConfiguration.type", .type = "STRING", .functions = eq4 },
            .{ .name = "broadcastingDeviceFilter.type", .type = "STRING", .functions = "eq ne in notIn isNull isNotNull" },
            .{ .name = "broadcastingDeviceFilter.deviceIds", .type = "SET(UUID)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "broadcastingDeviceFilter.deviceTagIds", .type = "SET(UUID)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "hotspotConfiguration.type", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "fw-policies",
        .label = "firewall policy",
        .summary = "Firewall policies (zone-based firewall)",
        .tag = "Firewall",
        .list = .{ .path = "/v1/sites/{siteId}/firewall/policies", .id = "getFirewallPolicies" },
        .show = .{ .path = "/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}", .id = "getFirewallPolicy" },
        .extras = &.{
            .{ .verb = "order", .summary = "User-defined policy order between two zones", .targeted = false, .shape = .zone_pair, .op = .{ .path = "/v1/sites/{siteId}/firewall/policies/ordering", .id = "getFirewallPolicyOrdering" } },
        },
        .writes = &.{
            .{ .verb = "add", .summary = "Create a firewall policy", .kind = .create, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/firewall/policies", .id = "createFirewallPolicy" }, .destructive = true, .fields = &.{ "action", "connectionStateFilter", "description", "destination", "enabled", "ipProtocolScope", "ipsecFilter", "loggingEnabled", "name", "schedule", "source" }, .required = &.{ "action", "destination", "enabled", "ipProtocolScope", "loggingEnabled", "name", "source" } },
            .{ .verb = "set", .summary = "Replace a firewall policy (complete body)", .kind = .replace, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}", .id = "updateFirewallPolicy" }, .destructive = true, .fields = &.{ "action", "connectionStateFilter", "description", "destination", "enabled", "ipProtocolScope", "ipsecFilter", "loggingEnabled", "name", "schedule", "source" }, .required = &.{ "action", "destination", "enabled", "ipProtocolScope", "loggingEnabled", "name", "source" } },
            .{ .verb = "patch", .summary = "Change selected firewall policy fields", .kind = .patch, .method = .PATCH, .op = .{ .path = "/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}", .id = "patchFirewallPolicy" }, .destructive = true, .fields = &.{"loggingEnabled"} },
            .{ .verb = "rm", .summary = "Delete a firewall policy", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/firewall/policies/{firewallPolicyId}", .id = "deleteFirewallPolicy" }, .destructive = true },
            .{ .verb = "reorder", .summary = "Replace the policy order between two zones", .kind = .ordering, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/firewall/policies/ordering", .id = "updateFirewallPolicyOrdering" }, .destructive = true, .fields = &.{"orderedFirewallPolicyIds"}, .required = &.{"orderedFirewallPolicyIds"} },
        },
        .read_only = &.{ "id", "index", "metadata" },
        .columns = &.{
            .{ .title = "INDEX", .path = "index", .right = true },
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "ENABLED", .path = "enabled", .fmt = .bool },
            .{ .title = "ACTION", .path = "action.type" },
            .{ .title = "SOURCE ZONE", .path = "source.zoneId", .drop = 1, .id = true },
            .{ .title = "DEST ZONE", .path = "destination.zoneId", .drop = 1, .id = true },
            origin_col,
            id_col,
        },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "source.zoneId", .type = "UUID", .functions = eq4 },
            .{ .name = "destination.zoneId", .type = "UUID", .functions = eq4 },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "fw-zones",
        .label = "firewall zone",
        .summary = "Firewall zones (zone-based firewall)",
        .tag = "Firewall",
        .list = .{ .path = "/v1/sites/{siteId}/firewall/zones", .id = "getFirewallZones" },
        .show = .{ .path = "/v1/sites/{siteId}/firewall/zones/{firewallZoneId}", .id = "getFirewallZone" },
        .writes = &.{
            .{ .verb = "add", .summary = "Create a firewall zone", .kind = .create, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/firewall/zones", .id = "createFirewallZone" }, .destructive = true, .fields = &.{ "name", "networkIds" }, .required = &.{ "name", "networkIds" } },
            .{ .verb = "set", .summary = "Replace a firewall zone (complete body)", .kind = .replace, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/firewall/zones/{firewallZoneId}", .id = "updateFirewallZone" }, .destructive = true, .fields = &.{ "name", "networkIds" }, .required = &.{ "name", "networkIds" } },
            .{ .verb = "rm", .summary = "Delete a firewall zone", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/firewall/zones/{firewallZoneId}", .id = "deleteFirewallZone" }, .destructive = true },
        },
        .read_only = &.{ "id", "metadata" },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "NETWORKS", .path = "networkIds", .fmt = .count, .right = true },
            origin_col,
            id_col,
        },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
            .{ .name = "metadata.configurable", .type = "BOOLEAN", .functions = "eq ne isNull isNotNull" },
        },
    },
    .{
        .name = "acl",
        .label = "ACL rule",
        .summary = "Access control (ACL) rules",
        .tag = "Access Control (ACL Rules)",
        .list = .{ .path = "/v1/sites/{siteId}/acl-rules", .id = "getAclRulePage" },
        .show = .{ .path = "/v1/sites/{siteId}/acl-rules/{aclRuleId}", .id = "getAclRule" },
        .extras = &.{
            .{ .verb = "order", .summary = "User-defined ACL rule order", .targeted = false, .op = .{ .path = "/v1/sites/{siteId}/acl-rules/ordering", .id = "getAclRuleOrdering" } },
        },
        .writes = &.{
            .{ .verb = "add", .summary = "Create an ACL rule", .kind = .create, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/acl-rules", .id = "createAclRule" }, .destructive = true, .fields = &.{ "action", "description", "destinationFilter", "enabled", "enforcingDeviceFilter", "index", "name", "networkIdFilter", "protocolFilter", "sourceFilter", "type" }, .required = &.{ "action", "enabled", "name", "type" } },
            .{ .verb = "set", .summary = "Replace an ACL rule (complete body)", .kind = .replace, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/acl-rules/{aclRuleId}", .id = "updateAclRule" }, .destructive = true, .fields = &.{ "action", "description", "destinationFilter", "enabled", "enforcingDeviceFilter", "index", "name", "networkIdFilter", "protocolFilter", "sourceFilter", "type" }, .required = &.{ "action", "enabled", "name", "type" } },
            .{ .verb = "rm", .summary = "Delete an ACL rule", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/acl-rules/{aclRuleId}", .id = "deleteAclRule" }, .destructive = true },
            .{ .verb = "reorder", .summary = "Replace the ACL rule order", .kind = .ordering, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/acl-rules/ordering", .id = "updateAclRuleOrdering" }, .destructive = true, .fields = &.{"orderedAclRuleIds"}, .required = &.{"orderedAclRuleIds"} },
        },
        .read_only = &.{ "id", "metadata" },
        .columns = &.{
            .{ .title = "INDEX", .path = "index", .right = true },
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "TYPE", .path = "type" },
            .{ .title = "ACTION", .path = "action" },
            .{ .title = "ENABLED", .path = "enabled", .fmt = .bool },
            origin_col,
            id_col,
        },
        .filterable = &.{
            .{ .name = "type", .type = "STRING", .functions = eq4 },
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "enabled", .type = "BOOLEAN", .functions = eqne },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "description", .type = "STRING", .functions = "isNull isNotNull eq ne in notIn like" },
            .{ .name = "action", .type = "STRING", .functions = eq4 },
            .{ .name = "index", .type = "INTEGER", .functions = cmp },
            .{ .name = "protocolFilter", .type = "SET(STRING)", .functions = "isNull isNotNull contains containsAny containsAll containsExactly" },
            .{ .name = "networkId", .type = "UUID", .functions = "isNull isNotNull eq ne in notIn" },
            .{ .name = "enforcingDeviceFilter.deviceIds", .type = "SET(UUID)", .functions = "isNull isNotNull contains containsAny containsAll containsExactly" },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
            .{ .name = "sourceFilter.type", .type = "STRING", .functions = "isNull isNotNull eq ne in notIn" },
            .{ .name = "sourceFilter.ipAddressesOrSubnets", .type = "SET(STRING)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "sourceFilter.portFilter", .type = "SET(INTEGER)", .functions = "isNull isNotNull contains containsAny containsAll containsExactly" },
            .{ .name = "sourceFilter.networkIds", .type = "SET(UUID)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "sourceFilter.macAddresses", .type = "SET(STRING)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "sourceFilter.prefixLength", .type = "INTEGER", .functions = "isNull isNotNull eq ne gt ge lt le in notIn" },
            .{ .name = "destinationFilter.type", .type = "STRING", .functions = "isNull isNotNull eq ne in notIn" },
            .{ .name = "destinationFilter.ipAddressesOrSubnets", .type = "SET(STRING)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "destinationFilter.portFilter", .type = "SET(INTEGER)", .functions = "isNull isNotNull contains containsAny containsAll containsExactly" },
            .{ .name = "destinationFilter.networkIds", .type = "SET(UUID)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "destinationFilter.macAddresses", .type = "SET(STRING)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "destinationFilter.prefixLength", .type = "INTEGER", .functions = "isNull isNotNull eq ne gt ge lt le in notIn" },
        },
    },
    .{
        .name = "dns-policies",
        .label = "DNS policy",
        .summary = "DNS policies (A/AAAA/CNAME/MX/SRV/TXT records, forwarding)",
        .tag = "DNS Policies",
        .list = .{ .path = "/v1/sites/{siteId}/dns/policies", .id = "getDnsPolicyPage" },
        .show = .{ .path = "/v1/sites/{siteId}/dns/policies/{dnsPolicyId}", .id = "getDnsPolicy" },
        .writes = &.{
            .{ .verb = "add", .summary = "Create a DNS policy", .kind = .create, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/dns/policies", .id = "createDnsPolicy" }, .fields = &.{ "domain", "enabled", "ipAddress", "ipv4Address", "ipv6Address", "mailServerDomain", "port", "priority", "protocol", "serverDomain", "service", "targetDomain", "text", "ttlSeconds", "type", "weight" }, .required = &.{ "enabled", "type" } },
            .{ .verb = "set", .summary = "Replace a DNS policy (complete body)", .kind = .replace, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/dns/policies/{dnsPolicyId}", .id = "updateDnsPolicy" }, .fields = &.{ "domain", "enabled", "ipAddress", "ipv4Address", "ipv6Address", "mailServerDomain", "port", "priority", "protocol", "serverDomain", "service", "targetDomain", "text", "ttlSeconds", "type", "weight" }, .required = &.{ "enabled", "type" } },
            .{ .verb = "rm", .summary = "Delete a DNS policy", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/dns/policies/{dnsPolicyId}", .id = "deleteDnsPolicy" }, .destructive = true },
        },
        .read_only = &.{ "id", "metadata" },
        .columns = &.{
            .{ .title = "DOMAIN", .path = "domain", .id = true },
            .{ .title = "TYPE", .path = "type" },
            .{ .title = "VALUE", .path = "ipv4Address|ipv6Address|targetDomain|mailServerDomain|serverDomain|ipAddress|text", .id = true },
            .{ .title = "TTL", .path = "ttlSeconds", .right = true, .drop = 1 },
            .{ .title = "ENABLED", .path = "enabled", .fmt = .bool },
            id_col,
        },
        .match = &.{"domain"},
        .filterable = &.{
            .{ .name = "type", .type = "STRING", .functions = eq4 },
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "enabled", .type = "BOOLEAN", .functions = eqne },
            .{ .name = "domain", .type = "STRING", .functions = eq4like },
            .{ .name = "ipv4Address", .type = "STRING", .functions = eq4like },
            .{ .name = "ipv6Address", .type = "STRING", .functions = eq4like },
            .{ .name = "targetDomain", .type = "STRING", .functions = eq4like },
            .{ .name = "mailServerDomain", .type = "STRING", .functions = eq4like },
            .{ .name = "text", .type = "STRING", .functions = eq4like },
            .{ .name = "serverDomain", .type = "STRING", .functions = eq4like },
            .{ .name = "ipAddress", .type = "STRING", .functions = eq4like },
            .{ .name = "ttlSeconds", .type = "INTEGER", .functions = cmp },
            .{ .name = "priority", .type = "INTEGER", .functions = cmp },
            .{ .name = "service", .type = "STRING", .functions = eq4 },
            .{ .name = "protocol", .type = "STRING", .functions = eq4 },
            .{ .name = "port", .type = "INTEGER", .functions = cmp },
            .{ .name = "weight", .type = "INTEGER", .functions = cmp },
        },
    },
    .{
        .name = "traffic-lists",
        .label = "traffic matching list",
        .summary = "Traffic matching lists (ports, IPs)",
        .tag = "Traffic Matching Lists",
        .list = .{ .path = "/v1/sites/{siteId}/traffic-matching-lists", .id = "getTrafficMatchingLists" },
        .show = .{ .path = "/v1/sites/{siteId}/traffic-matching-lists/{trafficMatchingListId}", .id = "getTrafficMatchingList" },
        .writes = &.{
            .{ .verb = "add", .summary = "Create a traffic matching list", .kind = .create, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/traffic-matching-lists", .id = "createTrafficMatchingList" }, .fields = &.{ "items", "name", "type" }, .required = &.{ "name", "type" } },
            .{ .verb = "set", .summary = "Replace a traffic matching list (complete body)", .kind = .replace, .method = .PUT, .op = .{ .path = "/v1/sites/{siteId}/traffic-matching-lists/{trafficMatchingListId}", .id = "updateTrafficMatchingList" }, .fields = &.{ "items", "name", "type" }, .required = &.{ "name", "type" } },
            .{ .verb = "rm", .summary = "Delete a traffic matching list", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/traffic-matching-lists/{trafficMatchingListId}", .id = "deleteTrafficMatchingList" }, .destructive = true },
        },
        .read_only = &.{"id"},
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "TYPE", .path = "type" },
            id_col,
        },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
        },
    },
    .{
        .name = "vouchers",
        .label = "voucher",
        .summary = "Hotspot vouchers",
        .tag = "Hotspot",
        .list = .{ .path = "/v1/sites/{siteId}/hotspot/vouchers", .id = "getVouchers" },
        .show = .{ .path = "/v1/sites/{siteId}/hotspot/vouchers/{voucherId}", .id = "getVoucher" },
        .writes = &.{
            .{ .verb = "add", .summary = "Create hotspot vouchers", .kind = .create, .method = .POST, .op = .{ .path = "/v1/sites/{siteId}/hotspot/vouchers", .id = "createVouchers" }, .fields = &.{ "authorizedGuestLimit", "count", "dataUsageLimitMBytes", "name", "rxRateLimitKbps", "timeLimitMinutes", "txRateLimitKbps" }, .required = &.{ "name", "timeLimitMinutes" } },
            .{ .verb = "rm", .summary = "Delete a voucher", .kind = .delete, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/hotspot/vouchers/{voucherId}", .id = "deleteVoucher" }, .destructive = true },
            .{ .verb = "purge", .summary = "Delete every voucher matching --filter", .kind = .purge, .method = .DELETE, .op = .{ .path = "/v1/sites/{siteId}/hotspot/vouchers", .id = "deleteVouchers" }, .destructive = true },
        },
        .read_only = &.{ "activatedAt", "authorizedGuestCount", "code", "createdAt", "expired", "expiresAt", "id" },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "CODE", .path = "code", .id = true },
            .{ .title = "GUESTS", .path = "authorizedGuestCount", .right = true },
            .{ .title = "EXPIRED", .path = "expired", .fmt = .bool },
            .{ .title = "EXPIRES", .path = "expiresAt", .fmt = .time, .drop = 1 },
            id_col,
        },
        .match = &.{ "name", "code" },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "createdAt", .type = "TIMESTAMP", .functions = "eq ne gt ge lt le" },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "code", .type = "STRING", .functions = eq4 },
            .{ .name = "authorizedGuestLimit", .type = "INTEGER", .functions = ts },
            .{ .name = "authorizedGuestCount", .type = "INTEGER", .functions = "eq ne gt ge lt le" },
            .{ .name = "activatedAt", .type = "TIMESTAMP", .functions = "eq ne gt ge lt le" },
            .{ .name = "expiresAt", .type = "TIMESTAMP", .functions = "eq ne gt ge lt le" },
            .{ .name = "expired", .type = "BOOLEAN", .functions = eqne },
            .{ .name = "timeLimitMinutes", .type = "INTEGER", .functions = "eq ne gt ge lt le" },
            .{ .name = "dataUsageLimitMBytes", .type = "INTEGER", .functions = ts },
            .{ .name = "rxRateLimitKbps", .type = "INTEGER", .functions = ts },
            .{ .name = "txRateLimitKbps", .type = "INTEGER", .functions = ts },
        },
    },
    .{
        .name = "wans",
        .label = "WAN interface",
        .summary = "WAN interfaces",
        .tag = "Supporting Resources",
        .list = .{ .path = "/v1/sites/{siteId}/wans", .id = "getWansOverviewPage" },
        .filter = false,
        .columns = &.{ .{ .title = "NAME", .path = "name", .id = true }, id_col },
    },
    .{
        .name = "vpn-servers",
        .label = "VPN server",
        .summary = "VPN servers",
        .tag = "Supporting Resources",
        .list = .{ .path = "/v1/sites/{siteId}/vpn/servers", .id = "getVpnServerPage" },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "TYPE", .path = "type" },
            .{ .title = "ENABLED", .path = "enabled", .fmt = .bool },
            origin_col,
            id_col,
        },
        .filterable = &.{
            .{ .name = "type", .type = "STRING", .functions = eq4 },
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "enabled", .type = "BOOLEAN", .functions = eqne },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "vpn-tunnels",
        .label = "site-to-site VPN tunnel",
        .summary = "Site-to-site VPN tunnels",
        .tag = "Supporting Resources",
        .list = .{ .path = "/v1/sites/{siteId}/vpn/site-to-site-tunnels", .id = "getSiteToSiteVpnTunnelPage" },
        .columns = &.{
            .{ .title = "NAME", .path = "name", .id = true },
            .{ .title = "TYPE", .path = "type" },
            origin_col,
            id_col,
        },
        .filterable = &.{
            .{ .name = "type", .type = "STRING", .functions = eq4 },
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
            .{ .name = "metadata.source", .type = "STRING", .functions = "eq ne in notIn isNull isNotNull" },
        },
    },
    .{
        .name = "radius",
        .label = "RADIUS profile",
        .summary = "RADIUS profiles",
        .tag = "Supporting Resources",
        .list = .{ .path = "/v1/sites/{siteId}/radius/profiles", .id = "getRadiusProfileOverviewPage" },
        .columns = &.{ .{ .title = "NAME", .path = "name", .id = true }, origin_col, id_col },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "lags",
        .label = "LAG",
        .summary = "Link aggregation groups",
        .tag = "Switching",
        .list = .{ .path = "/v1/sites/{siteId}/switching/lags", .id = "getLagPage" },
        .show = .{ .path = "/v1/sites/{siteId}/switching/lags/{lagId}", .id = "getLag" },
        .columns = &.{ .{ .title = "TYPE", .path = "type" }, origin_col, id_col },
        .match = &.{},
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "type", .type = "STRING", .functions = eq4 },
            .{ .name = "switchStackId", .type = "UUID", .functions = "eq ne in notIn isNull isNotNull" },
            .{ .name = "mcLagDomainId", .type = "UUID", .functions = "eq ne in notIn isNull isNotNull" },
            .{ .name = "members.deviceId", .type = "SET(UUID)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "members.portIdxs", .type = "SET(INTEGER)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "mc-lag",
        .label = "MC-LAG domain",
        .summary = "MC-LAG domains",
        .tag = "Switching",
        .list = .{ .path = "/v1/sites/{siteId}/switching/mc-lag-domains", .id = "getMcLagDomainPage" },
        .show = .{ .path = "/v1/sites/{siteId}/switching/mc-lag-domains/{mcLagDomainId}", .id = "getMcLagDomain" },
        .columns = &.{ .{ .title = "NAME", .path = "name", .id = true }, .{ .title = "LAGS", .path = "lags", .fmt = .count, .right = true }, origin_col, id_col },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "peers.deviceId", .type = "SET(UUID)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "stacks",
        .label = "switch stack",
        .summary = "Switch stacks",
        .tag = "Switching",
        .list = .{ .path = "/v1/sites/{siteId}/switching/switch-stacks", .id = "getSwitchStackPage" },
        .show = .{ .path = "/v1/sites/{siteId}/switching/switch-stacks/{switchStackId}", .id = "getSwitchStack" },
        .columns = &.{ .{ .title = "NAME", .path = "name", .id = true }, .{ .title = "UNITS", .path = "units", .fmt = .count, .right = true }, origin_col, id_col },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "units.id", .type = "SET(INTEGER)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "units.macAddress", .type = "SET(STRING)", .functions = "contains containsAny containsAll containsExactly" },
            .{ .name = "metadata.origin", .type = "STRING", .functions = eq4 },
        },
    },
    .{
        .name = "device-tags",
        .label = "device tag",
        .summary = "Device tags",
        .tag = "Supporting Resources",
        .list = .{ .path = "/v1/sites/{siteId}/device-tags", .id = "getDeviceTagPage" },
        .columns = &.{ .{ .title = "NAME", .path = "name", .id = true }, .{ .title = "DEVICES", .path = "deviceIds", .fmt = .count, .right = true }, origin_col, id_col },
        .filterable = &.{
            .{ .name = "id", .type = "UUID", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
            .{ .name = "deviceIds", .type = "SET(UUID)", .functions = "contains containsAny containsAll containsExactly" },
        },
    },
    .{
        .name = "dpi-apps",
        .label = "DPI application",
        .summary = "DPI applications",
        .tag = "Supporting Resources",
        .site = false,
        .list = .{ .path = "/v1/dpi/applications", .id = "getDpiApplications" },
        .columns = &.{ .{ .title = "ID", .path = "id", .right = true, .id = true }, .{ .title = "NAME", .path = "name", .id = true } },
        .filterable = &.{
            .{ .name = "id", .type = "INTEGER", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
        },
    },
    .{
        .name = "dpi-categories",
        .label = "DPI category",
        .summary = "DPI application categories",
        .tag = "Supporting Resources",
        .site = false,
        .list = .{ .path = "/v1/dpi/categories", .id = "getDpiApplicationCategories" },
        .columns = &.{ .{ .title = "ID", .path = "id", .right = true, .id = true }, .{ .title = "NAME", .path = "name", .id = true } },
        .filterable = &.{
            .{ .name = "id", .type = "INTEGER", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
        },
    },
    .{
        .name = "countries",
        .label = "country",
        .summary = "Country codes",
        .tag = "Supporting Resources",
        .site = false,
        .list = .{ .path = "/v1/countries", .id = "getCountries" },
        .columns = &.{ .{ .title = "CODE", .path = "code", .id = true }, .{ .title = "NAME", .path = "name", .id = true } },
        .match = &.{ "code", "name" },
        .filterable = &.{
            .{ .name = "code", .type = "STRING", .functions = eq4 },
            .{ .name = "name", .type = "STRING", .functions = eq4like },
        },
    },
};

/// Every GET operation in the catalog (info, lists, shows, extras).
pub const all_ops: []const Op = blk: {
    var ops: []const Op = &.{info};
    for (resources) |r| {
        ops = ops ++ .{r.list};
        if (r.show) |s| ops = ops ++ .{s};
        for (r.extras) |e| ops = ops ++ .{e.op};
    }
    break :blk ops;
};

pub fn find(name: []const u8) ?*const Resource {
    for (&resources) |*r| {
        if (std.mem.eql(u8, r.name, name)) return r;
    }
    return null;
}

pub const PathError = error{ OutOfMemory, MissingSite, MissingId };

/// Fill `{siteId}` and the one other `{…}` placeholder (the object ID).
pub fn expand(arena: std.mem.Allocator, template: []const u8, site: ?[]const u8, id: ?[]const u8) PathError![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var rest = template;
    while (std.mem.findScalar(u8, rest, '{')) |open| {
        const close = std.mem.findScalarPos(u8, rest, open, '}') orelse break;
        try out.appendSlice(arena, rest[0..open]);
        const name = rest[open + 1 .. close];
        const value = if (std.mem.eql(u8, name, "siteId")) site orelse return error.MissingSite else id orelse return error.MissingId;
        try appendEscaped(arena, &out, value);
        rest = rest[close + 1 ..];
    }
    try out.appendSlice(arena, rest);
    return out.items;
}

/// Percent-encode everything outside RFC 3986 unreserved characters.
pub fn appendEscaped(arena: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) error{OutOfMemory}!void {
    for (value) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~') {
            try out.append(arena, c);
        } else {
            try out.print(arena, "%{X:0>2}", .{c});
        }
    }
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

comptime {
    // Names unique; every resource has an identifier column.
    for (resources, 0..) |a, i| {
        for (resources[i + 1 ..]) |b| {
            if (std.mem.eql(u8, a.name, b.name)) @compileError("duplicate resource " ++ a.name);
        }
    }
}

test "catalog: 41 distinct GET operations" {
    const ops = all_ops;
    try testing.expectEqual(@as(usize, 41), ops.len);
    for (ops, 0..) |a, i| {
        for (ops[i + 1 ..]) |b| {
            try testing.expect(!std.mem.eql(u8, a.id, b.id));
            try testing.expect(!std.mem.eql(u8, a.path, b.path));
        }
    }
}

test "expand: site and id placeholders, escaping" {
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    try testing.expectEqualStrings("/v1/sites/S1/devices/D%2F1/statistics/latest", try expand(ar, "/v1/sites/{siteId}/devices/{deviceId}/statistics/latest", "S1", "D/1"));
    try testing.expectEqualStrings("/v1/countries", try expand(ar, "/v1/countries", null, null));
    try testing.expectError(error.MissingSite, expand(ar, "/v1/sites/{siteId}/wans", null, null));
}

// Checked against the official export when it is present locally
// (the private homelab checkout; clones without it skip this test).
test "catalog matches the v10.6.106 OpenAPI export" {
    const io = testing.io;
    var a = std.heap.ArenaAllocator.init(testing.allocator);
    defer a.deinit();
    const ar = a.allocator();
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, "../homelab/api/unifi/network_v10.6.106_openapi.json", ar, .limited(64 << 20)) catch
        return error.SkipZigTest;
    const doc = try std.json.parseFromSliceLeaky(std.json.Value, ar, bytes, .{});
    const paths = doc.object.get("paths").?.object;
    var gets: usize = 0;
    var it = paths.iterator();
    while (it.next()) |e| {
        const get = e.value_ptr.object.get("get") orelse continue;
        gets += 1;
        const op_id = get.object.get("operationId").?.string;
        var found = false;
        for (all_ops) |op| {
            if (std.mem.eql(u8, op.path, e.key_ptr.*)) {
                try testing.expectEqualStrings(op_id, op.id);
                found = true;
            }
        }
        if (!found) {
            std.debug.print("catalog lacks GET {s} ({s})\n", .{ e.key_ptr.*, op_id });
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(all_ops.len, gets);
}
