# API facts

The vendor API behaviour artoo depends on: the UniFi Network Integration
API (and the classic API it also uses), the Proxmox VE API, GitHub
releases, the Tailscale API, and Rex's packages and CLI. Each fact comes
from the vendor's official documents or from live reads (read-only, or
approved runs), and names the vendor version it was checked against
where one is known. Section references (`SPEC §9.5`) point into
[SPEC.md](SPEC.md). A lab's own state belongs in the operator's lab
record; operating procedures in [GUIDE.md](GUIDE.md).

## 1. UniFi Network Integration API

- **Reference documents:** the official Network API v10.6.106 export
  (`network_v10.6.106_openapi.json`, OpenAPI 3.1, plus the Postman
  collection), matching UniFi's firmware. It is authoritative for paths,
  parameters, schemas and each endpoint's filterable properties. It is
  expected at `../homelab/api/unifi/network_v10.6.106_openapi.json`
  relative to the artoo checkout; tests that need it skip without it.
  Sources: <https://developer.ui.com/network/v10.6.106/>, or the gateway's
  `GET /proxy/network/api-docs/integration.json` with the API key (what
  the UI's "Network API" page renders); `artoo gw spec --save PATH`
  fetches it without exposing the key. The download equals the gateway's
  document except `servers`. After a firmware update: fetch, run
  `gw spec`, update the catalog, then change behaviour.
- **Shape:** 44 paths, 73 operations (41 GET, 12 POST, 9 PUT, 1 PATCH,
  10 DELETE), 380 schemas. No security scheme is declared: auth is the
  `X-API-KEY` header, injected at request time and never logged. Base
  `https://unifi.home.arpa/proxy/network/integration`.
- **Pagination:** `offset` (default 0), `limit` (default 25, max 200). No
  stable sort: a set of pages is not a snapshot.
- **Errors:** `{statusCode, statusName, code, message, requestId,
  requestPath, timestamp}`. Operations declare no non-2xx responses, so
  error handling follows the live server.
- **Filter grammar** (verified live): `property.function(args)`, such as
  `name.eq('ap-office')`, `name.in('a','b')`, `firmwareVersion.gt('6.0.0')`,
  `features.contains('accessPoint')`, `supported.eq(true)`; combined with
  `and(…)`, `or(…)`, `not(…)`. Strings take **single quotes only**,
  booleans are bare, `like` uses `*`. A bad filter answers 400
  `api.request.invalid-filter` with a positioned message (artoo: exit 2).
  Each list's filterable properties come from its description table; the
  catalog's tables are generated from the export and tested against it.
- **Secrets in responses:** Wi-Fi broadcast details return the passphrase
  in clear (`securityConfiguration.passphrase`); RADIUS and VPN fields may
  carry secrets. artoo redacts secret-bearing keys before any output.
- **Schemas:** polymorphism hostile to code generation (77 discriminator
  nodes, 190 `allOf`, schema names with spaces). No generated client:
  handwritten models, tolerant on responses, strict on requests; write
  bodies are checked against generated top-level field lists (the union
  over discriminator variants).
- **`/v1/info`** exposes only `applicationVersion`. Version-specific
  behaviour is gated centrally; versions are never compared lexically.
- **No ETags, idempotency keys or rate-limit documentation:** plans state
  that concurrent edits cannot be detected; writes are never retried.
- **Coverage:** CRUD for networks, Wi-Fi broadcasts, firewall policies and
  zones, ACL rules, DNS policies, traffic matching lists, hotspot vouchers
  (plus filtered bulk delete); device actions (restart, PoE port
  power-cycle, adopt, remove) and client guest authorization. Read-only:
  sites, switching, WANs, VPN, RADIUS, DPI, countries, device tags. Only
  firewall policy has PATCH. **Not in the API:** DHCP reservations,
  client renames, port forwarding, static routes, QoS, NAT, firmware and
  UniFi OS.
- **DNS policies:** A, AAAA, CNAME, MX, SRV, TXT and forward-domain. An A
  record answers on the gateway a few seconds after creation, also for a
  name inside the public `example.com` domain; public resolvers never see
  it (verified live: add, `dig @192.168.1.1`, remove, NXDOMAIN). A
  network's DHCP DNS servers, domain name and range are set with
  `PUT …/networks/{id}`.
- **Live quirks:** firewall zones and policies answer 400 "Zone Based
  Firewall is not configured"; the device list
  reports the gateway's WAN address as its `ipAddress`; device-to-port
  mapping is not exposed.

### Classic API (undocumented)

Not covered by `gw spec`; firmware may change it. The same `X-API-KEY`
authenticates `/proxy/network/api/s/default/…` (verified live with
`GET self`: the key is site admin, super; and `GET rest/user`: every
known client, offline ones included).

- **Client records** carry `name` (the UI alias), `hostname` (from DHCP),
  `use_fixedip` + `fixed_ip` (the UI's Fixed IP, a DHCP reservation) and
  `local_dns_record_enabled` + `local_dns_record`.
- **Create:** `POST group/user {"objects":[{"data":{mac, name,
  use_fixedip, network_id, fixed_ip}}]}` creates the record for a MAC
  never seen, name and Fixed IP applied in one request. `network_id` is
  the classic `rest/networkconf` `_id` (verified live by
  `scripts/live/unifi-reservation-probe.sh`).
- **Fixed IP in use:** while another MAC is connected on an address,
  `group/user` with that `fixed_ip` answers 400 `api.err.Invalid`
  (Network 11.0.103). The Integration API has no action that drops a
  connected client (only guest authorize/unauthorize), and deleting the
  gateway's ARP entry does not drop it either: the client drops when the
  switch ages its MAC out.
- **Forget:** `POST cmd/stamgr {"cmd":"forget-sta","macs":[…]}` works with
  the key: an offline client's record is gone; a client the gateway still
  counts as connected is re-created at once.
- **Client names:** UniFi names a client from its DHCP hostname; a static
  client inherits the hostname of the last lease on its IP (verified live:
  a static guest showed under the name of the device that last leased its
  address). Hence the client record, SPEC §9.5.

### WAN sources

Verified read-only on Network 11.0.99, gateway firmware 6.0.17 (SPEC
SPEC §10.4). The Integration API's `GET …/wans` answers `{id, name}` only; the
rest comes from the classic and v2 APIs with the same key.

Under `/proxy/network/api/s/default/`:

- **`GET stat/health`:** the `wan` subsystem has `status`, `wan_ip`,
  `gateways[]`, `netmask`, `isp_name`, `isp_organization`, `asn`,
  `gw_name` and `uptime_stats.WAN{availability, latency_average,
  time_period, uptime, monitors[], alerting_monitors[]}` (a monitor has
  `id`, `target`, `type` `icmp`|`dns`, `availability`, `latency_average`;
  an alerting one also `health`). The `www` subsystem has `status`,
  `latency`, `uptime`, `drops`.
- **`GET stat/device`:** the gateway (the device with `wan1`) has
  `wan1{up, ip, netmask, speed, full_duplex, media, port_idx, ifname,
  rx_errors, tx_errors, rx_dropped, tx_dropped, mac_table[{ip, mac,
  lastReachable}]}`, `last_wan_status{WAN}`, `last_wan_interfaces{WAN{ip,
  alive}}`, `last_downtime_stats{WAN}` (seconds), `uptime_stats` as
  above, `port_table[{port_idx, ifname, media, up, speed, full_duplex}]`
  and `ethernet_overrides[{ifname, networkgroup}]`.
- **Port assignment:** `ethernet_overrides` says which interface carries
  which WAN group (`eth4` → `WAN`). A WAN group without an entry has no
  port: a second WAN with Port "Unassigned" in the UI has no entry, its
  `wan2` is `null`, and it is `BACKUP` in the load-balancing status.
- **Not usable:** `stat/event` and `stat/alarm` answer 404 ("NotFound"),
  `rest/alarm` 400.

Under `/proxy/network/v2/api/site/default/`:

- **`GET wan/load-balancing/status`** →
  `{wan_interfaces:[{name, state (ACTIVE|BACKUP), wan_networkgroup
  (WAN|WAN2)}]}`.
- **`GET wan/enriched-configuration`** answers 200 (per WAN
  `configuration{name, wan_networkgroup, …}`, `details.service_provider`,
  `statistics`) but carries no port; artoo does not use it.
- **`POST system-log/all`** with `{timestampFrom, timestampTo (ms),
  pageSize, pageNumber, categories:["INTERNET_AND_WAN"]}` →
  `{data[], page_number, total_element_count, total_page_count}`, newest
  first. An event has `event`, `severity` (`MEDIUM`, `VERY_HIGH`, …),
  `timestamp` (ms), `title_raw`, `message_raw` with `{PLACEHOLDERS}` and
  `parameters{NAME:{id?, name}}`: `WAN_ID` `{id: WAN, name: WAN1}`,
  `WAN_NAME` `{id: <group>, name: <WAN name>}`, `ISP_NAME`, `PORT`,
  `DURATION` `{id: seconds, name: "2m 35s"}`, `COUNT`.
- **Events seen:** `NETWORK_WAN_FAILED`, `NETWORK_WAN_RESTORED`,
  `NETWORK_WAN_FAILED_MULTIPLE_TIMES`, `ISP_PACKET_LOSS`, and
  `NETWORK_WAN_FAILED_TEMPORARY` ("restored after a temporary
  disconnection", `DURATION` in seconds, no preceding failure event).
- **`POST system-log/critical`** with the same body answers `[]`.

## 2. Proxmox VE API

- **Access:** user `artoo@pve`, token `artoo@pve!cli`, privilege
  separation off. ACLs on `/` and `/nodes/<node>` grant `PVEAuditor`,
  `PVEVMAdmin`, `PVEDatastoreAdmin`, `PVESDNUser`, plus `ArtooFetch`
  (`Sys.AccessNetwork`) on `/nodes/<node>`. Verified live: 32 of 33
  privileges, none of `Sys.Modify`, `Sys.PowerMgmt`, `Sys.Console`,
  `User.Modify`, `Permissions.Modify`.
- **ACLs replace, not merge, along the path:** the most specific path
  with an entry for a user replaces inherited roles, so node-level entries
  repeat the full role set. A privsep token without its own ACL answers
  200 with empty data, so permission checks assert on content.
  `pveum acl list` silently omits entries naming a deleted token; verify
  cleanups by grepping `/etc/pve/user.cfg`.
- **Privileges per operation** (`PVE/API2/Qemu.pm`, `QemuServer.pm`):

  | Operation | Privileges |
  | --- | --- |
  | power | `VM.PowerMgmt` |
  | clone | `VM.Clone` + `VM.Allocate` + `Datastore.AllocateSpace` + `SDN.Use` on `/sdn/zones/localnetwork/vmbr0`, even for untagged `vmbr0` |
  | destroy | `VM.Allocate` |
  | config | per key: `cores` → `VM.Config.CPU`, `memory` → `VM.Config.Memory`, `name`/`description` → `VM.Config.Options`, cloud-init keys → `VM.Config.Cloudinit` or `VM.Config.Network` |
  | resize | `VM.Config.Disk` |
  | snapshots | `VM.Snapshot` (rollback also `VM.Snapshot.Rollback`) |
  | delete a storage volume | `Datastore.Allocate` |

- **Errors:** pveproxy puts the message in the status line's reason
  phrase (sometimes also in JSON `message`/`errors`). A missing VM
  answers **500** "Configuration file … does not exist", not 404. A token
  secret with the wrong token ID answers 401.
- **Requests:** writes are form-encoded. GET and DELETE carry parameters
  in the query string and must not have a body (the Zig stdlib asserts).
  Most writes return a UPID.
- **Config:** `PUT …/config` is synchronous and accepts `digest` for
  optimistic locking. `GET …/config` shows pending values as if live;
  `GET …/pending` lists each key with `value` (current), `pending` and
  `delete` (1, or 2 for a forced delete), SPEC §9.13. `status/reboot`
  applies pending changes. Which `vm set` key waits for the next start on
  a running VM is read from `/pending` afterwards (SPEC §9.13), never
  assumed. Memory hotplug needs `numa=1`; Proxmox refuses the start
  otherwise.
- **Resize:** `PUT …/resize` takes `disk`, `size`
  (`\+?\d+(\.\d+)?[KMGT]?`: absolute without `+`, bytes without a unit)
  and `digest`, returns a UPID and refuses to shrink; the drive's `size=`
  in the config shows the result.
- **Unverified live:** `PUT …/resize` (`vm disk grow`), the `vm set`
  keys `startup`, `protection`, `numa`, `vcpus`, `cpulimit`, `cpuunits`
  and `hotplug` (SPEC §9.15's table), and
  `vm set --reboot`.
- **Memory figures** (PVE 9.2): `/nodes/{node}/qemu` `mem` equals
  `memhost` (the QEMU process on the host). `status/current` `mem` is
  `ballooninfo.total_mem − free_mem`, and `ballooninfo` has no
  available-memory figure. `agent/file-read` (`file`, `decode=1`) returns
  `/proc/meminfo` as `content` (SPEC §9.14).
- **Guest agent requests are ASCII only** (pve-manager 9.2.27, seen
  live 2026-11-25): a non-ASCII character anywhere in an
  `agent/exec` argument (one em dash in a script comment was enough)
  makes that request time out (`got timeout`), and the agent then
  answers nothing, ping included, until the VM restarts. On the guest,
  `qemu-ga` keeps running but never logs the request. A probable cause:
  `PVE::QMPClient` writes the request built by `to_json` as a character
  string, so it arrives short and the agent waits for the rest. artoo
  refuses such a request before sending it (SPEC §7).
- **Tasks:** `stopped` with `OK` or `WARNINGS: n` is success. The
  `errors=1` filter also returns tasks with warnings.
- **Listing:** `/cluster/resources` is refreshed by pvestatd: a VM created
  seconds ago appears with its VMID but no name or status. Per-node
  `/nodes/{node}/qemu` reads configs and live status directly.
- **Guests:** a guest without an OS ignores ACPI shutdown (the task times
  out). Rolling back a RAM-less snapshot leaves the VM stopped unless the
  rollback sends `start=1`.
- **Snapshots** (`apidoc.js`, pve-manager 9.2.21): `snapname` is a
  `pve-configid` of at most 40 characters. The listing
  (`GET …/snapshot`) returns `name` (`current` is the live VM), `parent`,
  `snaptime`, `vmstate` and `description`; no endpoint returns a size.
  `DELETE` has `force` (drops the config entry even when removing the
  disk snapshots fails; artoo never sends it); `POST …/rollback` has
  `start`. On ZFS, `volume_rollback_is_possible` (`ZFSPoolPlugin.pm`)
  lists every snapshot created after the target as a blocker: only the
  newest snapshot can be rolled back to.
- **Storage status:** `GET /nodes/{node}/storage/{storage}/status`
  returns `total`, `used`, `avail` (bytes), `type`, `active`, `enabled`,
  `shared`.
- **Provisioning constraints:** no API endpoint uploads snippets
  (`download-url` allows only `iso|vztmpl|import`), hence SPEC §9.2's SSH
  placement. `local` is the directory `/var/lib/vz` (import, snippets,
  backup, vztmpl, iso); `local-zfs` holds images and rootdir only. The
  cloud-init ISO is generated at VM start from the config and the
  `cicustom` snippet, so a missing snippet breaks the next start.
- **Template build** (verified live, approved): the token's roles suffice
  for `download-url` (`content=import`, SHA-256 checked; 825 MiB in under
  a minute), `POST /qemu` with
  `scsi0=local-zfs:0,import-from=local:import/…` and `cicustom` (the
  snippet must exist first), and `POST /qemu/{id}/template` (UPID
  `qmtemplate`). The imported disk becomes `base-<id>-disk-0` at the
  image's virtual size (3.5 GiB for Ubuntu 26.04). The API lists snippets
  (`content=snippets`, with size) though it cannot upload them.
- **Ubuntu 26.04 guests** (observed live):
  - sudo is `sudo-rs` ("interactive authentication is required");
  - sshd is socket-activated, so `/run/sshd` is missing until the first
    connection and `sshd -T` fails; `sshd -G` (OpenSSH 10) works;
  - Proxmox's generated user-data uses the deprecated `user:` key, so
    `cloud-init status` is always "degraded done" (exit 2); artoo judges
    the JSON status instead;
  - the first-boot upgrade installs a newer kernel (and its initramfs);
  - `qmreboot` finishes once the guest has shut down, and the restart
    follows, so `vm reboot` polls for `running`;
  - 1 GiB RAM is about 99% used right after cloud-init.

## 3. GitHub releases

Checked against the public repository, read-only and without a token
(REST API version `2022-11-28`).

- **Release:** `GET https://api.github.com/repos/<owner>/<repo>/releases/latest`
  is the newest release that is neither a draft nor a pre-release;
  `…/releases/tags/vX.Y.Z` names one (404 when absent). Fields used:
  `tag_name`, `prerelease`, `draft`, `published_at`, and per asset
  `name`, `size`, `state` (`uploaded`) and `digest` (`sha256:<hex>`,
  GitHub's own hash of the upload).
- **Headers sent:** `Accept: application/vnd.github+json`,
  `X-GitHub-Api-Version: 2022-11-28`, a `User-Agent` (required).
- **Download:** an asset's URL
  `https://github.com/<owner>/<repo>/releases/download/<tag>/<name>`
  answers **302** to a signed, short-lived URL on
  `release-assets.githubusercontent.com` (GitHub's older host
  `objects.githubusercontent.com` is also accepted), which serves the
  bytes.
- **Rate limit:** without a token, 60 requests an hour per address; a
  used-up limit answers 403 or 429 with a JSON `message`.
- **Client:** Zig 0.17's `std.http` reaches both hosts with the system
  roots; its `std.compress.flate` (gzip) and `std.tar` read the release
  archives that `scripts/release-binaries.sh` makes on the macOS runner
  (a directory, `LICENSE`, `artoo` mode 755, `README.md`; no PAX entries).

## 4. Tailscale API

Read from the official OpenAPI document (`version: v2`; SPEC §17);
unverified live.

- **Reference document:** `https://api.tailscale.com/api/v2?outputOpenapiSchema=true`
  (OpenAPI 3.1), copied to `../homelab/api/tailscale/openapi.yaml`. It
  states the endpoints are stable but the schema "may change or break
  without notice".
- **Auth:** `Authorization: Bearer <token>` (or the token as a Basic
  username). OAuth client secrets start `tskey-client-`, API access
  tokens `tskey-api-`.
- **Token exchange** (not in the OpenAPI document; from Tailscale's OAuth
  documentation): `POST /api/v2/oauth/token` with `client_id`,
  `client_secret` (and optional `scope`, `tags`) answers `access_token`,
  `token_type`, `expires_in` (3600) and `scope`. artoo sends
  `grant_type=client_credentials`, the ID and the secret form-encoded, and
  reads `tags` from the answer only if one appears.
- **Tailnet path:** `/tailnet/{tailnet}/…`; `-` means the credential's
  own tailnet.
- **Devices:** `GET /tailnet/{tailnet}/devices`, `GET|DELETE
  /device/{deviceId}`, and under `/device/{deviceId}`: `POST /name`
  (`{"name"}`), `/tags` (`{"tags"}`), `/key` (key expiry), `/authorized`;
  `GET|POST /routes` (`advertisedRoutes`, `enabledRoutes`; a POST sets
  `{"routes": […]}`, the enabled list).
- **Keys:** `GET|POST /tailnet/{tailnet}/keys`, `GET|DELETE
  /tailnet/{tailnet}/keys/{keyId}`. Creating an auth key sends
  `capabilities.devices.create` (`reusable`, `ephemeral`,
  `preauthorized`, `tags`), `expirySeconds` and `description`; the answer
  carries the key once. A list made with an OAuth-derived token covers
  the tailnet's keys.
- **Key descriptions:** at most 50 letters, digits, hyphens and spaces,
  so `artoo router <vm>` and `artoo join <vm>`, without a colon.
- **DNS:** `GET|PATCH|PUT /tailnet/{tailnet}/dns/split-dns` is a map of
  domain → nameserver list; PATCH changes only the domains sent, `null`
  clears one, PUT replaces the whole map. Also `dns/nameservers`,
  `dns/preferences`, `dns/searchpaths`.
- **Policy:** `GET /tailnet/{tailnet}/acl` (HuJSON, or JSON on request)
  answers an `ETag`. `POST` takes `application/hujson` or
  `application/json`, honours `If-Match` (the ETag as the GET returned
  it, quoted as in the document's example `"e0b2816b418"`, or
  `"ts-default"`), and answers `412` ("precondition failed, invalid old
  hash") on a mismatch and `400` on a validation or test error.
  `POST …/acl/validate` answers `{}` or `{message, data: [{user, errors,
  warnings}]}`; `POST …/acl/preview?type=user|ipport&previewFor=…`.
- **Errors and lists:** HTTP status plus `{"message": …}`; some endpoints
  document `429`. The API "does not currently support pagination".

## 5. Rex

Checked against Rex Server & CLI preview.23 and Rex for Mac preview.34,
from Superlogical's documentation and the packages themselves (SPEC §18).

- **apt:** `https://pkgs.superlogical.com/rex/apt`, suites `stable`,
  `preview`, `snapshot`, component `main`. Keyring
  `https://pkgs.superlogical.com/rex/keys/rex-archive-keyring.gpg`
  (binary, 2854 bytes, SHA-256
  `07a92e758ac2fc189efa17c24bf3df70d75e4216f6c262283a5c812377deb83e`; the
  armored `rex.asc` dearmors to the same bytes); primary key
  `E28636AC71905C6DDE40C1EDFAA6B80F641307A7` ("Superlogical Package
  Signing", expires 2036), signing subkey
  `E032B88AE0C279B9EA9BDF27C00363666EE29BCE` (expires 2028-09: artoo's
  embedded keyring, `src/guest/rex-archive-keyring.gpg`, must be
  refreshed before then).
- **Upstream's installer** writes `/etc/apt/sources.list.d/rex.sources`
  (`Types: deb`, `URIs`, `Suites: CHANNEL`, `Components: main`,
  `Architectures: ARCH`, `Signed-By:
  /etc/apt/keyrings/rex-archive-keyring.gpg`) and
  `/etc/apt/preferences.d/rex` (`Package: rex` / `Pin: origin
  pkgs.superlogical.com` / `Pin-Priority: 1001`, then `Package: rex` /
  `Pin: release *` / `Pin-Priority: -1`; the package's maintainer script
  adds the second record to a file that lacks it), then runs `apt-get
  install -y --allow-downgrades -o Dpkg::Options::=--force-confdef -o
  Dpkg::Options::=--force-confold rex`. Rex's packages name Superlogical
  as Maintainer; Ubuntu's `rex` (Perl) does not.
- **Versions:** a snapshot deb is `0.1.0~alpha.N`; the same build's `rex
  version` prints `0.1.0-snapshot.N`.
- **Package files:** `/usr/bin/rex`, the system units `rex.service`,
  `rex.socket` and `rex-login-server` (none enabled by the package), the
  `xterm-rex` terminfo, `/etc/ssh/ssh_config.d/50-rex.conf`.
- **Personal server:** socket `$XDG_RUNTIME_DIR/rex/server.sock`. Any
  `rex` command starts a missing one unless `REX_AUTOSTART=0` (or
  `--autostart=false`); an autostarted server stops about 10 s after its
  last session and client go. Without linger, logging out ends it. `rex
  server status --json` names the running `rex_version`.
- **Program status:** programs report it with OSC 7501 (`ESC ] 7501 ;
  state=working:app=NAME:msg=BASE64 ESC \`). `rex block call -b BLOCK
  program_status` answers `{records: [{state
  (idle|working|done|blocked|error), app, effective_app, msg, title,
  updated_at, owner{pid,name}}]}` (a subagent's record also has `id`).
  `rex ls --json` lists `sessions [{session_id, label}]`; `rex block ls
  -s SESSION --json` lists that session's `blocks [{block_id, label,
  flavor}]` (one session per call). Claude Code reports
  `app=claude-code` itself.
- **Skill:** `rex skill status --json` → `{scope, harnesses: [{id,
  detected, session_naming, items: [{kind (skill|hook), path, state
  (current|outdated|missing|foreign|unreadable|unsupported)}]}]}`; `rex
  skill setup [--agent ID]… [--session-naming] [--json]`; harness ids
  `claude`, `codex`, `opencode`, `pi`.
- **Terminfo:** `rex terminfo status --json` → `{term, reason, entry,
  system_guard_state, conclusion ("Ready: …" when ready), fix}`; `rex
  terminfo setup --system`.
- **Hosts:** `rex hosts list --json` → `{home: {label, endpoint,
  this_machine, reached}, hosts: [{host: {id, label, endpoints[], icon,
  updated_at}, from, held}], warnings}`; `rex hosts add LABEL ENDPOINT…
  [--icon]`, `edit LABEL [--label NEW] [--endpoint E]…`, `remove LABEL`;
  labels compare without case. An SSH endpoint is
  `ssh://[USER@]HOST[:PORT][/SOCKET]` and needs `rex` on the remote PATH.
  Rex for Mac carries the CLI at `/Applications/Rex.app/Contents/Helpers/Rex
  Server.rex/Contents/MacOS/rex`.
  Rex for Mac (app 0.1.0-snapshot.2145, server 0.1.0-preview.24, seen
  2026-11-26) lists only the hosts saved in the app: a host added with
  `rex hosts add` (its record carries `added_from`) is listed by the CLI
  and reachable with `rex -S LABEL`, but the app never shows it, with or
  without `--icon`, even after a restart. The app's Add Remote Host…
  saves `{label, endpoints, icon}` without `added_from`, and the CLI lists
  that one too.
- **Antigravity (`agy`) hooks:** `hooks.json` in the customization root
  (`~/.gemini/config/`), top-level keys naming hooks (`enabled`
  optional). The events `SessionStart`, `PreInvocation`,
  `PostInvocation` and `Stop` take `[{type: "command", command,
  timeout}]`, the tool events `[{matcher, hooks}]`. A command runs with
  `sh -c` in that directory, reads JSON on stdin and prints JSON
  (`SessionStart`: `{"injectSteps": [{"systemMessage": {"systemMessage":
  TEXT}}]}`; `Stop`'s input has `terminationReason`).
- **Claude Code settings:** `permissions.defaultMode` (`default`,
  `acceptEdits`, `plan`, `auto`, `dontAsk`, `bypassPermissions`); `auto`
  and `bypassPermissions` take effect from user settings, not a
  project's; `permissions.disableBypassPermissionsMode: "disable"` works
  from any scope.
