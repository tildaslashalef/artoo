# Operating a Lab with artoo — Agent Guide

How an agent (or a person) inspects and changes a lab with `artoo` (and,
for the Proxmox host itself, SSH), organised by what you set out to do.
Why artoo behaves as it does is in [SPEC.md](SPEC.md); each section below
names its SPEC owner instead of repeating it. `artoo help <noun> [verb]`
is the exact reference for flags and examples; with completion installed,
Tab completes commands, flags and VM names.

The names and addresses below describe an **example lab** (§2); read
your own from `artoo config show` and `artoo status`.

## 1. Ground rules

- **Read freely, write only with approval.** Every live change — a VM, a
  DNS record, a public route, a gateway setting, a host change, a physical
  change — needs the operator's explicit approval of a concrete plan
  (target, current state, change, impact, rollback, validation). The
  current boundary lives in the operator's own instructions: if the
  checkout has an `AGENTS.local.md` (gitignored), read it — it points to
  the operator's private lab record. No task, checkbox or command
  authorizes a change by itself.
- **Preview first.** Every write takes `-n/--dry-run`: it reads, plans and
  prints the preview and sends nothing. Show it before asking.
- **Never handle secrets.** Never print, paste, log or put a secret on a
  command line, and never ask the operator to paste one into the session.
  Secrets enter through hidden prompts in the operator's own terminal
  (`artoo auth set …`, `artoo edge secret dns`, `artoo router setup`) or
  travel API → VM without being shown (`artoo edge tunnel`).
- **The Proxmox host and the gateway are never public** — no public
  record, tunnel route or edge route to them, by name or address. artoo
  derives them from config (`pve.node`, the endpoint and SSH hosts, the
  guests' gateway address, `guests.reserved_names`) and refuses such
  targets with no override (SPEC §9.6). Services on the `role-watch` and
  `role-search` VMs are never public either.
- **Report honestly.** "Accepted" is not "verified"; exit 7 means the
  outcome is unknown and must be checked, never assumed.

## 2. The lab at a glance

The example lab used throughout this guide:

| System | What | Address | Reached by |
| --- | --- | --- | --- |
| `pve` | Proxmox VE host (Proxmox VE 9) | `192.168.1.10`, `https://pve.home.arpa:8006` | artoo (API token), SSH as root |
| UniFi | UniFi gateway (UniFi Network 10.6+) | `192.168.1.1`, `https://unifi.home.arpa` | artoo (API key), UniFi UI (operator) |
| `bespin` | Edge guest (`role-edge`), `.200` | `bespin.lab.example.com` | the guest agent; SSH only via Proxmox |
| `dagobah` | Subnet-router guest (`role-router`), `.201` | `dagobah.lab.example.com` | the guest agent, SSH |
| `scarif` | Watchdog guest (`role-watch`) | `scarif.lab.example.com` | the guest agent; SSH only via Proxmox |
| Workstation | The operator's machine (macOS or Linux) | — | where artoo, the secret store, the SSH key and the mkcert CA live |

Guests are created with one account, the **guest user** (`guests.user`,
default `artoo`); `<user>` below stands for it.

### Names — four kinds (SPEC §9.6)

| Name | Resolves to | Answered by | Example |
| --- | --- | --- | --- |
| `<host>.home.arpa` | infrastructure | UniFi | `pve.home.arpa` |
| `<vm>.lab.example.com` — machine name | the guest itself | UniFi (made by `vm new`) | `naboo.lab.example.com` |
| `<svc>.apps.lab.example.com` — service name | the edge `.200`, which proxies to the guest | UniFi (made by `svc add`) | `grafana.apps.lab.example.com` |
| `<host>.example.com` — public name | Cloudflare | Cloudflare (made by `cf tunnel route add`) | `blog.example.com` |

Private names never enter public DNS; away from home they resolve through
Tailscale split DNS. The lab's own hosts and equipment are listed in
`guests.reserved_names` (comma-separated): guests never take those names
and they are never published.

### Request paths

```text
LAN client ──https──▶ grafana.apps.lab.example.com = bespin:443 (Caddy, *.apps wildcard)
                       └─ route file /etc/caddy/services/grafana.caddy ──http──▶ naboo:3000

Internet ──https──▶ blog.example.com (Cloudflare) ══tunnel══▶ cloudflared on bespin
                       └─ https://localhost (Caddy, TLS checked as grafana.apps…) ──▶ same route ──▶ naboo:3000

Away (Tailscale) ──▶ dagobah (subnet router, tag:lab-router) ──▶ 192.168.1.0/24, as the tailnet policy allows
                       names: split DNS lab.example.com + home.arpa → 192.168.1.1
```

`bespin` can reach the guest pool and the internet only: its two
firewalls (inside the VM and on Proxmox) drop anything towards Proxmox,
UniFi's other ports and the rest of the LAN (SPEC §9.7).

### Where each secret lives

| Secret | Lives in | Used for | Rotated by |
| --- | --- | --- | --- |
| `pve` — token `artoo@pve!cli` | the secret store (macOS Keychain, Linux Secret Service, or a 0600 file), service `artoo` | the Proxmox API | operator-approved host change (§15) |
| `unifi` — API key `artoo` | the secret store | UniFi's API | operator, UniFi UI |
| `cloudflare` — account token `artoo` | the secret store | zone records, the tunnel's routes | operator, Cloudflare dashboard |
| `guest/<vm>` — the guest user's sudo password | the secret store | `artoo vm password` | `vm new` makes it, `vm rm` deletes it |
| `bespin-acme` — DNS-01 token | `bespin` only (`/etc/caddy/cloudflare.env`) | the `*.apps` wildcard | `artoo edge secret dns` |
| tunnel token | `bespin` only (`/etc/cloudflared/tunnel.env`) | cloudflared | `artoo edge tunnel` (API → VM) |
| Tailscale auth key | nowhere — single-use, spent when the router joins | `artoo router setup` | a new key per router rebuild |
| Grafana admin password | `scarif` only (Grafana's database) | signing in to Grafana | `artoo watch secret grafana` |
| ntfy `phone` password | the operator's phone; `scarif` keeps a bcrypt hash | the ntfy app's login | `artoo watch secret phone` |
| Grafana's ntfy token | `scarif` only (`/etc/grafana/ntfy.env`) | alerts → ntfy | made by `watch setup`, never leaves the VM |
| mkcert CA private key | the workstation only | Proxmox's and UniFi's certificates | manual (§15) |

## 3. Start of every session

```console
artoo doctor --connect     # binary, config, secrets, CA bundles, all three APIs, token expiry
artoo auth status          # which secrets are stored (values are never read)
                           # auth set|rm pve|unifi|cloudflare: operator, own terminal (§15)
artoo status               # one screen: Proxmox, guests, storage, tasks, UniFi, edge, router, tunnel, services (exit 8 on a failed check)
```

- Use the **installed** binary `~/.local/bin/artoo`. After code changes the
  developer runs `make install` (it also installs the fish completion;
  `COMPLETION=zsh|bash|none`; `artoo completion SHELL` prints the script).
  A release install is brought current with `artoo update` (SPEC §18):
  `artoo update --check` is read-only (exit 0 = a newer release exists);
  replacing the binary is a write — the operator's go-ahead first.
- Config: `~/.artoo/config.json`, non-secret (`artoo config show|get|set|
  unset|edit|init`; `config set -h` lists the keys).
- Another machine: `artoo config export FILE` seals the config, the CA
  bundle and the three API credentials under a passphrase; `artoo config
  import FILE` installs them there (SPEC §6.1). The operator runs both in
  their own terminal and types the passphrase; an agent never asks for
  it. The new machine still needs its own SSH key on Proxmox and in
  `guests.extra_ssh_keys`.
- TLS to Proxmox and UniFi is verified against the mkcert root
  `~/.artoo/tls/rootCA.pem`; Cloudflare against the system roots. There is
  no insecure mode.

## 4. How artoo behaves (SPEC §3, §4, §8)

- Grammar: `artoo <noun> <verb> [TARGET…] [flags]`. A VM is a VMID or its
  exact name; gateway objects take their ID or unique name; a task takes a
  UPID, the printed handle (`qmstart:100@14:32`) or a unique fragment.
- Global flags anywhere: `-o json` (one JSON document on stdout; its
  target is `pve`, `unifi`, `cloudflare` or `local`), `-n/--dry-run`,
  `-y/--yes` (skips the prompt, never validation), `--no-wait`,
  `--timeout SECONDS`, `-v` (sanitized diagnostics on stderr), `--ascii`,
  `--color`, `--config PATH`.
- Writes: preview → confirm → one request → track → verify by a fresh
  read. Multi-step writes print a step ledger; re-running an interrupted
  workflow continues it. Non-interactive runs need `--yes`; **destructive**
  changes (VM stop/rm, snapshot rm/rollback, template/image rm, record and
  route removals, gateway deletes, network/Wi-Fi/firewall changes, `gw api`
  writes) also need `--confirm TARGET` — the exact name shown in the
  preview (`naboo`, `naboo@pre-upgrade`, `blog.example.com`, the API path).
- Nothing to change → exit 5, nothing sent.

| Exit | Meaning | What to do |
| --- | --- | --- |
| 0 | Success (or dry run) | — |
| 2 | Usage or config error, or the named target does not exist | Fix the command |
| 3 | Credentials or permission | `artoo auth status`; tell the operator |
| 4 | Network/TLS/protocol | Read the message |
| 5 | Refused by a safety gate (declined, no `--yes`/`--confirm`, no-op, drift, a guard such as "a service points at this VM") | Nothing was sent |
| 6 | A Proxmox task (or a guest-side step) ran and failed | `artoo task log TASK`; read the ledger |
| 7 | Outcome unknown, or a wait deadline passed | Inspect before retrying |
| 8 | Partial: a check failed or a write was not verified | Read the report |

## 5. Look around (read-only)

```console
artoo status
artoo host show; artoo host health [zfs services …]    # SPEC §11
artoo storage ls; artoo storage show local-zfs
artoo task ls [--failed|--running] [-l N]; artoo task show|log|wait TASK
artoo vm ls [--all] [-s running] [--name 'web-*']; artoo vm show VM; artoo vm config VM
artoo vm snap ls VM
artoo image ls; artoo template ls; artoo template show T
artoo svc ls                 # service names: upstream, record + route, drift
artoo vm urls VM             # the services a VM runs and their public hosts
artoo edge status            # drops towards Proxmox/UniFi first, Caddy, certificate, tunnel
artoo router status          # tailnet state, tag, route advertised + approved
artoo dns ls                 # UniFi A records
artoo cf dns ls; artoo cf tunnel ls      # public zone; tunnels and public routes
artoo gw info                # gateway summary; more in §12
```

## 6. Run a guest (SPEC §9.1–9.5)

```console
artoo vm new -n                          # plan; picks a free Star Wars / Middle-earth name
artoo vm new naboo --role web -n         # your name; the role shows in 'vm ls'
artoo vm new naboo --size medium -y      # waits for cloud-init (minutes)
artoo vm new hoth --ip 192.168.1.230 --no-dns -y
artoo vm verify naboo                    # read-only checks; exit 8 on any failure
artoo vm verify --all                    # every artoo guest at once (updates, pending reboots, …)
artoo vm ssh naboo [-- CMD]              # host key pinned through the guest agent
artoo vm password naboo                  # the guest user's sudo/console password (terminal only)
artoo vm ssh-config                      # ~/.artoo/ssh_config: plain ssh/scp/rsync as strict as vm ssh
artoo vm cp ./bin/tool naboo:bin/        # copy as the guest user; SHA-256 checked on the far side
artoo vm cp -r bespin:site naboo:        # guest to guest, relayed through the workstation (scp -3)
artoo vm cp -n naboo:notes.txt .         # target and scp command only
```

- `vm cp` copies as the guest user only: no sudo, no root destinations
  (root placement is the role setup commands' job, through the guest
  agent). An existing target needs `--force`; a checksum mismatch exits 8.
  Proxmox and UniFi are refused.
- After `vm ssh-config`, the operator adds `Include ~/.artoo/ssh_config`
  to `~/.ssh/config` once, above the first `Host` line. artoo never
  edits `~/.ssh/config`. From then on, `ssh bespin` jumps through
  Proxmox on its own.

- `vm new` also writes to UniFi — a client record for the VM's MAC
  (its name, Fixed IP = its address) and, unless `--no-dns`, the machine
  name — so it needs approval like any gateway write. Addresses come from
  the pool (`guests.address_pool`, here `.200–.254`, outside DHCP); a
  Fixed IP held by an offline client is skipped. Names in
  `guests.reserved_names` are never picked or accepted.
- **Never assume a guest's address** — in a plan, a proposal, a firewall
  rule or a command. Read it from `artoo vm ls` at the time; for a new
  guest, run `artoo vm ls` and then `vm new -n`, whose plan names the
  address it will take (the lowest free pool address, SPEC §9.5).
- Guests run **fish** as the guest user's shell: for `vm ssh … -- CMD`
  with shell syntax, wrap it: `artoo vm ssh naboo -- sh -c "'…'"`.
- Guests tagged `ssh-jump` (the edge) accept SSH only from Proxmox;
  `vm ssh` jumps automatically, by hand it is `ssh -J root@192.168.1.10
  <user>@bespin.lab.example.com`.

Lifecycle:

```console
artoo vm start VM -y
artoo vm shutdown VM -y                  # ACPI; Proxmox gives up after 180 s (exit 6)
artoo vm reboot VM -y
artoo vm upgrade VM -n                   # what apt would install ('vm verify': pending updates)
artoo vm upgrade VM -y                   # install it (SPEC §9.12); never reboots: then 'vm reboot VM'
artoo vm stop VM --yes --confirm NAME    # power cut
artoo vm set VM memory=4G cores=2 onboot=1 tags=artoo,web -y   # allowlisted keys, digest-guarded
                                         # running VM: CPU/memory may stay pending (SPEC §9.13);
                                         # 'vm config VM' marks them, 'vm reboot VM' applies them
artoo vm snap add VM pre-upgrade -y
artoo vm snap rollback VM pre-upgrade --yes --confirm NAME@pre-upgrade
artoo vm snap rm VM pre-upgrade --yes --confirm NAME@pre-upgrade
artoo vm clone SOURCE NEWNAME [--id N] -y
artoo vm rm VM --yes --confirm NAME      # stops, destroys disks, forgets its client and DNS records,
                                         # stored password and pinned host key
```

`vm rm` **refuses** while a service name points at the VM: move it
(`svc set`) or remove it (`svc rm`) first.

### Fence a guest (SPEC §9.11)

```console
artoo vm fence naboo -n                    # the derived rules, as a diff against what is on Proxmox
artoo vm fence naboo --yes --confirm naboo # high-impact: an approved plan first
artoo vm fence naboo --off --yes --confirm naboo   # rollback
artoo config set guests.fence_allow_out 'naboo hoth tcp 5432'   # an outbound exception, kept
```

- The fence is the Proxmox VE firewall on the guest's NIC: services in
  only from the edge, SSH and ping from the LAN (from Proxmox only for
  `ssh-jump`), out only DNS, the watchdog, the exceptions, web and NTP.
  Nothing inside the guest changes. The edge, the watchdog and the router
  are refused (their setup owns their fence).
- It is a firewall change on Proxmox: every live run needs its own
  approved plan — also taking over a hand-written
  `/etc/pve/firewall/<vmid>.fw`, whose rules the plan shows as replaced.
- `svc add|set|rm` keep a fenced guest's inbound rules in step in the same
  plan; `vm verify`, `vm show` and `status` report drift.

### Images and templates (SPEC §9.2)

```console
artoo image ls                           # pins vs files on Proxmox
artoo image fetch ubuntu-2604 -n         # Proxmox downloads and checks SHA-256 (never the workstation)
artoo image rm ubuntu-2604 --yes --confirm ubuntu-2604
artoo template vendor                    # the exact vendor-data snippet (local, read-only)
artoo template build ubuntu-2604 -n      # image, snippet (root SSH), VM, convert
artoo template rm ubuntu-2604 --yes --confirm ubuntu-2604
```

`template build` places `artoo-vendor-<hash>.yaml` in
`/var/lib/vz/snippets` over root SSH — a persistent host file, so builds
need an approved plan. It never replaces an existing snippet.

## 7. Give a guest's service a LAN name (SPEC §9.6)

```console
artoo svc add grafana naboo:3000 -n   # plan: edge route to naboo.lab.example.com:3000 + UniFi record
artoo svc add grafana naboo:3000 -y   # → https://grafana.apps.lab.example.com/
artoo svc set grafana hoth:3000 -y    # move it: route only, name and record stay
artoo svc rm grafana --yes --confirm grafana
```

- The upstream is an artoo guest in the pool serving **plain HTTP**; HTTPS
  is the edge's `*.apps` wildcard, trusted everywhere (Let's Encrypt).
- `add` ends with a probe from the edge: `HTTP 200` (or any answer) means
  done; a 502 means the service is not up yet — not a failure.
- A service is a route file on `bespin` plus a UniFi record; `svc
  ls` reports a half that is missing and `svc add` repairs it.
- `svc rm` refuses while a public name points at the service.
- **Health:** a service that does not answer 2xx at `/` names its health
  path, and optionally a literal text that means down in that answer:
  `svc add search naboo:8080 --health /v1/health --health-down
  '"down"'`. Both are kept in the route file (`svc ls` shows them); the
  edge probe and the watchdog's probe request that path. Then run `watch
  setup` so the watchdog's probe changes. Without `--health`, `svc add`
  and `svc set` keep a route's health; `--health /` resets it.

## 8. Publish a service on the internet (SPEC §15, §9.7)

```console
artoo cf tunnel route add blog grafana -n   # blog.example.com → service grafana
artoo cf tunnel route add blog grafana -y
artoo cf tunnel route rm blog --yes --confirm blog.example.com
```

- A public name always reaches an **existing service** (`svc add` first):
  Cloudflare → tunnel → cloudflared on `bespin` → Caddy on localhost
  (TLS checked as `grafana.apps.lab.example.com`) → the same route → guest.
  One path; the edge's firewalls apply to public traffic too.
- Each route is an ingress rule of the tunnel plus a proxied CNAME
  `blog.example.com → <tunnel-id>.cfargotunnel.com`, comment
  `artoo: tunnel grafana`. The app sees `grafana.apps.lab.example.com` as
  Host; an app that builds absolute links needs its public URL in its own
  settings.
- Check the public name **by hand a minute later**, ideally through a
  public resolver (`dig blog.example.com @1.1.1.1`) or a phone on mobile
  data — an early lookup through UniFi can cache "not found".
- Refused: Proxmox/UniFi names and addresses, `guests.reserved_names`,
  services on `role-watch`/`role-search` guests, names under
  `lab.example.com`, the zone apex, a host that already has a record or
  another route.
- Teardown order: `cf tunnel route rm` → `svc rm` → `vm rm` (each refuses
  while the next layer still depends on it).

## 9. Reach the lab from away (SPEC §9.8)

The subnet router `dagobah` advertises `192.168.1.0/24` to the tailnet;
split DNS sends `lab.example.com` and `home.arpa` to UniFi. A typical
tailnet policy lets the operator's devices reach Proxmox (22, 8006),
UniFi (443, DNS) and the guest pool, nothing else on the LAN.

```console
artoo router status        # Running, tag:lab-router, route advertised and approved, forwarding
artoo router setup -n      # what a (re)built router still needs
```

- Only the router joins the tailnet; guests are reached through it and
  need no key.
- Rebuilding the router: `vm new NAME --role router --size small --cores
  1`, `vm set NAME onboot=1`, remove the old machine in the Tailscale
  console, then the operator generates a **single-use auth key** tagged
  `tag:lab-router` and runs `artoo router setup` in their own terminal (the
  key is asked after the plan is confirmed, hidden).
- Devices other than the workstation warn about Proxmox's and UniFi's
  certificates until they trust the mkcert **public** root
  (`~/.artoo/tls/rootCA.pem`; on iOS: install it as a profile, then
  enable full trust under Certificate Trust Settings).

## 10. Operate the edge `bespin` (SPEC §9.7) and the watchdog (§9.9)

```console
artoo edge status          # read-only; first look after anything unusual
artoo edge setup -n        # plan: only the steps the VM's state needs (idempotent)
artoo edge setup -y        # hardening, both firewalls, cloudflared unit, Caddy build (minutes)
artoo edge secret dns      # the edge's own DNS-01 token — operator's terminal, hidden prompt
artoo edge tunnel -y       # create/connect the Cloudflare Tunnel; token API → VM, never shown
```

- The edge is the VM tagged `role-edge`; everything runs as root through
  the guest agent. **Any hit on the "drops to Proxmox/UniFi" counters is
  a sign of compromise:** shut it down (`artoo vm shutdown bespin`) and
  look before anything else.
- Caddy is built from pinned sources on the VM; a version bump is a SPEC
  edit, then `edge setup`. Ubuntu and cloudflared update themselves;
  `edge status` reports pending reboots — rebooting is an approved action.
- **Rebuild** (it is never backed up): `vm new bespin --role edge
  --size small --cores 1 --ssh-jump --ip 192.168.1.200`, `vm set bespin
  onboot=1`, `edge setup`, `edge secret dns` (a new DNS-01 token from the
  operator), `edge tunnel` (delivers a fresh token for the existing
  tunnel). Route files are lost with the VM: `svc ls` shows each service as
  "no route" and `svc add NAME VM:PORT` restores it; public routes live in
  Cloudflare and keep working once the services are back.

### The watchdog `scarif` (SPEC §9.9)

Metrics (VictoriaMetrics), logs (Loki), dashboards and alert rules
(Grafana) and notifications (ntfy) on the VM tagged `role-watch`; Grafana
Alloy on every guest pushes to it, Proxmox pushes through Proxmox's own
metric export. Nothing phones home; nothing of it is public.

```console
artoo watch status          # read-only: blocked telemetry first, then pins, services, every guest's freshness
artoo watch setup -n|-y     # converge the VM (idempotent); re-run after 'svc add' or a health change to probe services
artoo watch enroll --all    # Alloy on existing guests (new ones: 'vm new' does it)
artoo watch forget HOST     # a guest removed without 'vm rm' keeps alerting: delete its metrics
artoo watch secret grafana  # Grafana's admin password — operator's terminal, hidden prompt
artoo watch secret phone    # the phone's ntfy login (bcrypt made on the workstation)
```

- **First build** (each step under the approved plan): `vm new scarif
  --role watch --size medium --ssh-jump --ip <pool address>`, `vm set
  scarif onboot=1`, `watch setup`, `svc add grafana scarif:3000`, `svc add
  ntfy scarif:2586`, `watch setup` again (probes the two names), both
  `watch secret`s, `watch enroll --all`, then the operator runs
  `PVE_SSH=root@<host address> scripts/pve-metrics.sh <address>` (a host
  change, it needs `Sys.Modify`). `cf tunnel route add` refuses Grafana
  and ntfy.
- **Phone** (on the tailnet): ntfy app → subscribe → topic `lab`, *Use
  another server* `https://ntfy.apps.lab.example.com`, *Instant
  delivery*; log in as `phone`. No relay: the app keeps its own
  connection to `scarif`.
- **Web:** Grafana at `https://grafana.apps.lab.example.com` (user
  `admin`). The machine name `scarif.lab.example.com` serves nothing on
  443, and there is no `scarif.apps…`: service names say what runs.
- **Any "telemetry blocked" count** means a component tried the internet:
  `journalctl` on `scarif` around the time, then fix the switch in SPEC
  §9.9. "Edge reached for Proxmox or UniFi" is the edge's compromise
  signal (above).
- **Rebuild** (never backed up; history is lost): the first-build steps
  again; the Proxmox metric server stays if the address is the same.

## 11. DNS records by hand

```console
artoo dns add naboo 192.168.1.201 -n          # UniFi; short names get lab.example.com
artoo dns rm naboo --yes --confirm naboo.lab.example.com
artoo cf dns add _artoo-test TXT hello -n     # Cloudflare; short names get example.com
artoo cf dns add www CNAME example.pages.dev --proxied --note blog -y
artoo cf dns rm www --yes --confirm www.example.com
```

Prefer the workflows (`vm new`, `svc add`, `cf tunnel route add`), which
keep records consistent. UniFi records answer on `192.168.1.1` within
seconds (`dig @192.168.1.1 NAME`); in the example lab DHCP hands every
client that resolver and the domain `home.arpa`. Public records are
outward-facing; artoo marks what it creates (`artoo: …`) and touches
nothing else; Proxmox/UniFi, `guests.reserved_names`, LAN/Tailscale
addresses and names under `lab.example.com` are refused (SPEC §10.3, §15).

## 12. Gateway settings and the full UniFi API (SPEC §10)

Every Integration API area is a `gw` resource with `ls`/`show` and, where
the API allows, `add`/`set`/`rm`: `sites`, `devices` (`stats`, `pending`,
`adopt`, `restart`, `port-cycle`, `rm`), `clients` (`authorize`,
`unauthorize`), `networks` (`refs`), `wifi`, `fw-policies` and `acl`
(`order`, `reorder`; `fw-policies patch`), `fw-zones`, `dns-policies`,
`traffic-lists`, `vouchers` (`purge`), and read-only `wans`,
`vpn-servers`, `vpn-tunnels`, `radius`, `lags`, `mc-lag`, `stacks`,
`device-tags`, `dpi-apps`, `dpi-categories`, `countries`.

```console
artoo gw clients ls --filter "type.eq('WIRED')"   # 'ls -h' shows the filter grammar per resource
artoo -o json gw networks show Default > net.json  # edit net.json, then:
artoo gw networks set Default --from net.json -n   # preview: field diff, reset fields
artoo gw networks set Default --from net.json --yes --confirm Default
artoo gw api GET '/v1/sites/{siteId}/devices'      # escape hatch (quote the path); writes need --confirm PATH
artoo gw spec                                      # after a firmware update: drift vs the catalog
```

Read-only fields are dropped and named in the plan; secrets show as
`<redacted>` and a file still holding `<redacted>` is refused. `PUT`
replaces the whole object. Actions (`restart`, `port-cycle`, `authorize`)
are reported as *accepted*, not verified. Network, Wi-Fi and firewall
changes are destructive-class (typed confirmation).

## 13. Recipes

**A new web app on the LAN and the internet**

```console
artoo vm new naboo --role web -y                    # 1. the guest
artoo vm ssh naboo                                  # 2. install the app, listening on :3000
artoo svc add grafana naboo:3000 -y                 # 3. https://grafana.apps.lab.example.com
artoo cf tunnel route add grafana grafana -y        # 4. https://grafana.example.com (check by hand later)
```

**Take it down** — reverse order; each step refuses while the next layer
depends on it:

```console
artoo cf tunnel route rm grafana --yes --confirm grafana.example.com
artoo svc rm grafana --yes --confirm grafana
artoo vm rm naboo --yes --confirm naboo
```

**Move a service to a rebuilt guest** — the names stay:
`artoo svc set grafana hoth:3000 -y`.

## 14. Direct SSH to Proxmox

For host work artoo does not cover (inspection, logs, host configuration
under an approved plan):

```console
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o ConnectTimeout=10 root@192.168.1.10
```

- Root key login is installed; the host key is in the workstation's
  `known_hosts`. Never disable host-key checking, replace a changed host
  key, create a new identity, or ask for the root password.
- Non-interactive SSH runs **Bash** (interactive TTYs may switch to
  fish): write explicit `bash` scripts.
- First read-only check: `hostname -f; pveversion; zpool status -x;
  systemctl --failed --no-legend`.
- Prefer the IP to the name unless the workstation resolves the host
  name reliably.
- Before changing a file, back it up under
  `/root/pve-setup-backups/<topic>-<UTC timestamp>/`.
- Development workloads belong in guests, never on the host. Prefer artoo
  for VM operations; `qm` over SSH is for bootstrap and emergencies.
- Host updates (an approved host change): `pveupd` in root's fish — `apt
  update`, summary, `apt full-upgrade`, reboot-needed check; never plain
  `apt upgrade`. Root's shell config comes from `hosts/pve/`
  (`scripts/pve-shell.sh`, backs up first).
- The host scripts `scripts/pve-*.sh` and the live tests in
  `scripts/live/` need `PVE_SSH=root@<host address>` (there is no
  default). Live tests record the resources they own in
  `~/.artoo/live-ledger.txt` (or `$ARTOO_LEDGER`).

## 15. Credentials and certificates (SPEC §6, §7, §15)

- **Proxmox token** `artoo@pve!cli` (user `artoo@pve`, privilege separation
  off): ACL on `/` and on `/nodes/<node>` with `PVEAuditor`,
  `PVEVMAdmin`, `PVEDatastoreAdmin`, `PVESDNUser`; `/nodes/<node>`
  additionally `ArtooFetch` (`Sys.AccessNetwork`). No host, user or
  permission administration. Proxmox ACLs replace (not merge) along a
  path — a node-level entry must repeat the full role set. Rotation (an
  approved host change):

  ```console
  ssh … root@192.168.1.10 'pveum user token remove artoo@pve cli'
  ssh … root@192.168.1.10 'pveum user token add artoo@pve cli --privsep 0 --output-format json' \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["value"])' \
    | artoo auth set pve --stdin --yes
  ```

- **UniFi API key** `artoo`: the operator creates it in the UniFi UI
  (Settings → Integrations) and enters it with `artoo auth set unifi`.
- **Cloudflare token** `artoo`: an *account* API token with *the zone* →
  Zone Read, DNS Read + Edit, and *the account* → Cloudflare One
  Connector: cloudflared Edit (not "Argo Tunnel (Legacy)"). Editing a
  token's permissions keeps its value. Entered with `artoo auth set
  cloudflare`; `doctor --connect` shows it active and its expiry.
- **The edge's tokens** (`bespin-acme`, the tunnel token) exist only on
  `bespin` (§2).
- **Certificates**: mkcert leaves signed by the workstation's root CA —
  Proxmox (`pvenode cert set`) and UniFi (uploaded in the UniFi UI;
  UniFi presents it, it does not distribute the root). The CA private
  key never leaves the workstation: losing it means a new mkcert CA, new
  leaves for Proxmox and UniFi, and the new public root installed on
  every client (`~/.artoo/tls/rootCA.pem` too); renewal is manual;
  `doctor` warns 30 days before the CA bundle expires. Service names use
  the edge's Let's Encrypt wildcard instead (renewed by Caddy).

## 16. Outside artoo: the operator's consoles

- **UniFi UI:** client renames, port forwarding, static routes, QoS, NAT,
  DHCP reservations, firmware/UniFi OS, radio power, per-client signal and
  roaming; the API key.
- **Cloudflare dashboard:** the `artoo` token and its permissions; deleting
  the tunnel; Cloudflare Access in front of a public route (not artoo yet).
- **Tailscale console:** the tailnet policy, split DNS, auth keys, removing
  a machine; new personal devices join by logging in.
- **Physical work** (cabling, installing equipment) is always the
  operator's, with its own approval.

## 17. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Exit 3, "rejected the API token/key" | Secret missing or rotated — `artoo auth status`, ask the operator |
| Exit 3, Cloudflare 403 on a tunnel call | The token lacks *Cloudflare One Connector: cloudflared Edit* (§15) |
| Exit 4, TLS handshake failed | Wrong host name, or a certificate not signed by the mkcert root |
| Exit 2, "no VM 'x'" / "not found" | Name typo; `artoo vm ls --all` (exact, then case-insensitive) |
| Exit 2, "'x' matches 2 …" | Ambiguous name — use the ID shown |
| Exit 2, "invalid --filter" | Filter grammar: single quotes for strings, see `-h` |
| Exit 5, "service(s) … point at" / "public host(s) … reach" | Remove the dependent layer first (§13) |
| Exit 7 after a write | Outcome unknown — check with a fresh read before anything else |
| `svc add` ends with HTTP 502 | The app on the guest is not listening (yet) on that port |
| A service name answers "no such service" (404) | No route file for it on the edge — `svc ls`, then `svc add` |
| A public name gives Cloudflare error 1033/530 | cloudflared not connected — `edge status`, `cf tunnel ls` |
| A new public name does not resolve at home | UniFi cached "not found" from an early lookup; wait, or test via `@1.1.1.1` |
| Certificate warning on another device for `*.home.arpa` | It does not trust the mkcert root yet (§9) |
| `router status`: route not approved | The policy's `autoApprovers` or the device's tag (`tag:lab-router`) |
| `vm ssh … -- CMD` fails with a fish error | Guests' login shell is fish — wrap in `sh -c "'…'"` |
| A VM just created is missing from lists | It appears within seconds; artoo reads the node's own VM list |
| A removed VM's client reappears on UniFi | UniFi re-creates a client it still counts as connected; wait until it shows **offline**, then remove — that sticks. `vm rm` forgets its guest's record after the VM is gone |
