# Operating a Lab with artoo — Agent Guide

How an agent (or a person) inspects and changes a lab with `artoo` and,
for the Proxmox host itself, SSH, by task. The rules behind each command
are in [SPEC.md](SPEC.md); each section names its SPEC owner.
`artoo help <noun> [verb]` is the exact reference for flags and
examples. First-time setup is [QUICKSTART.md](QUICKSTART.md).

The names and addresses below describe an **example lab** (§2). Read
your own from `artoo config show` and `artoo status`.

## 1. Ground rules

- **Read freely, write only with approval.** Every live change (a VM, a
  DNS record, a public route, a gateway setting, a tailnet change, a
  host change, physical work) needs the operator's explicit approval of
  a concrete plan: target, current state, change, impact, rollback,
  validation. If the checkout has an `AGENTS.local.md` (gitignored),
  read it: it points to the operator's private lab record and the
  current approval boundary. No task, checkbox or command authorizes a
  change by itself.
- **Preview first.** Reads and `-n/--dry-run` previews need no approval:
  `-n` reads, plans, prints the plan and sends nothing. Show it when you
  ask.
- **Never handle secrets.** Never print, paste, log or put a secret on a
  command line, and never ask the operator to paste one into the
  session. Secrets go into hidden prompts in the operator's own terminal
  (`auth set …`, `edge secret dns`, `watch secret …`, `router setup`
  without the Tailscale credential), or travel API → VM unseen
  (`edge tunnel`, `ts join`).
- **The Proxmox host and the gateway are never public:** no public
  record, tunnel route or edge route to them, by name or address. artoo
  derives them from the config (`pve.node`, the endpoint and SSH hosts,
  the guests' gateway, `guests.reserved_names`) and refuses them with no
  override (SPEC §9.6). Services on `role-watch` and `role-search` guests
  are never public either.
- **Report honestly.** "Accepted" is not "verified". Exit 7 means the
  outcome is unknown: check it, never assume it.

## 2. The lab at a glance

| System | What | Address | Reached by |
| --- | --- | --- | --- |
| `pve` | Proxmox VE 9 host | `192.168.1.10`, `https://pve.home.arpa:8006` | artoo (API token); SSH as root |
| UniFi | gateway, UniFi Network 10.6+ | `192.168.1.1`, `https://unifi.home.arpa` | artoo (API key); the UniFi UI (operator) |
| `bespin` | edge guest (`role-edge`), `.200` | `bespin.lab.example.com` | the guest agent; SSH only through Proxmox |
| `dagobah` | subnet-router guest (`role-router`), `.201` | `dagobah.lab.example.com` | the guest agent; SSH |
| `scarif` | watchdog guest (`role-watch`) | `scarif.lab.example.com` | the guest agent; SSH only through Proxmox |
| Workstation | the operator's Mac or Linux machine | — | where artoo, the secret store, the SSH key and the mkcert CA live |

Every guest has one account, the **guest user** (`guests.user`, default
`artoo`); `<user>` below stands for it.

### Names (SPEC §9.6)

| Name | Resolves to | Answered by | Example |
| --- | --- | --- | --- |
| `<host>.home.arpa` | infrastructure | UniFi | `pve.home.arpa` |
| `<vm>.lab.example.com`, machine name | the guest | UniFi (made by `vm new`) | `naboo.lab.example.com` |
| `<svc>.apps.lab.example.com`, service name | the edge, which proxies to the guest | UniFi (made by `svc add`) | `grafana.apps.lab.example.com` |
| `<host>.example.com`, public name | Cloudflare | Cloudflare (made by `cf tunnel route add`) | `blog.example.com` |

Private names never enter public DNS; away from home they resolve
through Tailscale split DNS. `guests.reserved_names` lists the lab's own
hosts and equipment: no guest takes those names and none is published.

### Request paths

```text
LAN client ──https──▶ grafana.apps.lab.example.com = bespin:443 (Caddy, *.apps wildcard)
                       └─ route file /etc/caddy/services/grafana.caddy ──http──▶ naboo:3000

Internet ──https──▶ blog.example.com (Cloudflare) ══tunnel══▶ cloudflared on bespin
                       └─ https://localhost (Caddy, TLS checked as grafana.apps…) ──▶ same route ──▶ naboo:3000

Away (Tailscale) ──▶ dagobah (subnet router, tag:lab-router) ──▶ 192.168.1.0/24, as the tailnet policy allows
                       names: split DNS lab.example.com + home.arpa → 192.168.1.1
```

`bespin` reaches only the guest pool and the internet: its two
firewalls (in the VM and on Proxmox) drop everything towards Proxmox,
UniFi's other ports and the rest of the LAN (SPEC §9.7).

### Where each secret lives

| Secret | Lives in | Used for | Made or rotated by |
| --- | --- | --- | --- |
| `pve`: token `artoo@pve!cli` | the secret store (macOS Keychain, Linux Secret Service or a 0600 file), service `artoo` | the Proxmox API | an approved host change (§15) |
| `unifi`: API key | the secret store | the UniFi API | the operator, UniFi UI |
| `cloudflare`: account API token | the secret store | zone records, the tunnel's routes | the operator, Cloudflare dashboard |
| `tailscale`: OAuth client secret | the secret store | devices, keys, routes, split DNS | the operator, Tailscale console |
| `tailscale-policy`: OAuth client secret | the secret store, for one policy change | `ts policy apply` | the operator; revoked afterwards |
| `guest/<vm>`: the guest user's sudo password | the store of the machine that made or last reset it | `vm password` | `vm new` makes it, `vm password --reset` replaces it, `vm rm` deletes it |
| the edge's DNS-01 token | `bespin` only (`/etc/caddy/cloudflare.env`) | the `*.apps` wildcard | `edge secret dns` |
| the tunnel token | `bespin` only (`/etc/cloudflared/tunnel.env`) | cloudflared | `edge tunnel` (API → VM) |
| Tailscale join keys | nowhere: single-use, spent on joining | `router setup`, `ts join` | artoo, per run (10 minutes); without the credential, the operator |
| Grafana admin password | `scarif` only | signing in to Grafana | `watch secret grafana` |
| ntfy `phone` password | the operator's phone; `scarif` keeps a bcrypt hash | the ntfy app's login | `watch secret phone` |
| Grafana's ntfy token | `scarif` only (`/etc/grafana/ntfy.env`) | alerts → ntfy | `watch setup`; never leaves the VM |
| mkcert CA private key | the workstation only | Proxmox's and UniFi's certificates | by hand (§15) |

## 3. Start of every session

```console
artoo doctor --connect     # install, config, secrets, CA bundles, SSH keys; each API read-only, token expiry
artoo auth status          # which secrets are stored (none is read)
artoo status               # one screen: Proxmox, guests, storage, tasks, UniFi, edge, router, tunnel, services
```

- Use the **installed** binary `~/.local/bin/artoo`; after code changes,
  `make install` first. `artoo update --check` is read-only (exit 0: a
  newer release exists; 5: none). `artoo update` replaces the binary:
  the operator's go-ahead first (SPEC §16).
- Config: `~/.artoo/config.json`, never a secret (`config
  show|get|set|unset|edit|init`; `config set -h` lists the keys).
- TLS to Proxmox and UniFi is verified against `pve.ca_bundle` and
  `unifi.ca_bundle` (default `~/.artoo/tls/rootCA.pem`); Cloudflare,
  GitHub and Tailscale against the system roots. There is no insecure
  mode.

**Another machine** (SPEC §6.1). `artoo config export FILE` seals the
config, the CA bundles and the API credentials under a passphrase;
`artoo config import FILE` installs them there. The operator runs both
and types the passphrase; an agent never asks for it. SSH keys stay per
machine: on the new one, set `pve.ssh_identity` and
`guests.ssh_public_key` to its own key and add that to root's
`authorized_keys` on Proxmox. Guests take keys only when made: list the
new key in `guests.extra_ssh_keys` where `vm new` runs.

**Guest passwords** live on the machine that made or last reset them.
`config export --guest-passwords` carries them; `artoo vm password VM
--reset` sets a new one (a live change; other machines' copies stop
working).

## 4. How artoo behaves (SPEC §3, §4, §8)

- Grammar: `artoo <noun> <verb> [TARGET…] [flags]`. A VM is a VMID or
  its exact name; a gateway object takes its ID or unique name; a task
  takes a UPID, the printed handle (`qmstart:100@14:32`) or a unique
  fragment.
- Global flags, anywhere: `-o json` (one JSON document on stdout, its
  `target` one of `pve`, `unifi`, `cloudflare`, `tailscale`, `github`,
  `local`), `-n/--dry-run`, `-y/--yes` (skips the prompt, never
  validation), `--no-wait` (return once accepted; then `task wait
  TASK`), `--timeout SECONDS`, `-v` (sanitized diagnostics on stderr),
  `--ascii`, `--color`, `--config PATH`.
- Writes: read → plan → confirm → send once → track → verify with a
  fresh read. A write is never retried. Multi-step workflows print a
  step ledger and stop at the first failure without undoing anything;
  re-running the same command continues. Nothing to change → exit 5,
  nothing sent.
- Without a terminal, every write needs `--yes`. Destructive and
  high-impact writes (removals, rollbacks, forced stops, fences,
  renames, the tailnet policy, gateway network, Wi-Fi and firewall
  changes, `gw api` writes; the list is SPEC §3.4) need the typed
  target: `--yes --confirm TARGET` non-interactively, TARGET as the plan
  names it (`naboo`, `naboo@pre-upgrade`, `blog.example.com`, `all`).

| Exit | Meaning | What to do |
| --- | --- | --- |
| 0 | Success (or dry run) | — |
| 2 | Usage or config error, or the named target does not exist | Fix the command |
| 3 | Credentials or permission | `artoo auth status`; tell the operator |
| 4 | Network, TLS or protocol; nothing was written | Read the message |
| 5 | Refused by a safety gate: declined, no `--yes`/`--confirm`, nothing to change, changed since read, a guard ("a service points at this VM") | Nothing was sent |
| 6 | A Proxmox task (or a guest-side step) ran and failed | `artoo task log TASK`; read the ledger |
| 7 | Outcome unknown, or a wait ran out | Inspect before anything else |
| 8 | Partial: a section, check or step failed or was not verified | Read the report |

## 5. Look around (read-only)

```console
artoo status
artoo host show; artoo host health [zfs services …]   # SPEC §11
artoo storage ls; artoo storage show local-zfs
artoo task ls [--failed|--running] [-l N]; artoo task show|log|wait TASK
artoo vm ls [--all] [-s running] [--name 'web-*']; artoo vm show VM; artoo vm config VM
artoo vm snap ls VM
artoo image ls; artoo template ls; artoo template show T
artoo svc ls                 # service names: upstream, record and route, drift
artoo vm urls VM             # the services a VM runs and their public hosts
artoo edge status; artoo router status; artoo watch status
artoo dns ls                 # UniFi A records
artoo cf dns ls; artoo cf tunnel ls       # public zone; tunnels and public routes
artoo ts devices ls; artoo ts dns show    # the tailnet
artoo gw info                # the gateway (§12)
```

## 6. Run guests (SPEC §9.1–9.5)

```console
artoo vm new -n                          # plan; picks a free curated name
artoo vm new naboo --role web -n         # your name; the role shows in 'vm ls'
artoo vm new naboo --size medium -y      # waits for cloud-init (minutes)
artoo vm new hoth --ip 192.168.1.230 --no-dns -y
artoo vm new hoth --no-watch -y          # a test guest: no metrics, logs or alerts; 'vm rm hoth' after the test
artoo vm verify naboo                    # read-only checks; exit 8 on any failure
artoo vm verify --all [--full]           # every guest; --full: every check
artoo vm ssh naboo [-- CMD]              # host key pinned through the guest agent
artoo vm password naboo [--show]         # sudo/console password to the clipboard (terminal only)
artoo vm password naboo --reset -n       # a new password through the guest agent (SPEC §9.17)
artoo vm ssh-config                      # ~/.artoo/ssh_config: plain ssh/scp/rsync, as strict as vm ssh
artoo vm cp ./bin/tool naboo:bin/        # as the guest user; SHA-256 checked on the far side
artoo vm cp -r bespin:site naboo:        # guest to guest, relayed through the workstation
artoo vm cp -n naboo:notes.txt .         # target and scp command only
```

- `vm new` also writes to UniFi: a client record for the VM's MAC (its
  name, Fixed IP = its address) and, unless `--no-dns`, the machine
  name. It needs approval like any gateway write.
- **Never assume a guest's address** in a plan, a firewall rule or a
  command. Read it from `artoo vm ls`; for a new guest, `vm new -n`
  names the address it will take (the lowest free one in
  `guests.address_pool`, SPEC §9.5).
- The guest user's login shell is **fish**. For `vm ssh … -- CMD` with
  shell syntax, wrap it: `artoo vm ssh naboo -- sh -c "'…'"`.
- Guests tagged `ssh-jump` (the edge, the watchdog) accept SSH only from
  Proxmox; `vm ssh` jumps by itself, by hand it is `ssh -J
  root@192.168.1.10 <user>@bespin.lab.example.com`.
- `vm ssh-config` needs `Include ~/.artoo/ssh_config` once in
  `~/.ssh/config`, above the first `Host` line. The operator adds it;
  artoo never edits that file.
- `vm cp` writes only as the guest user (no sudo, no root-only
  destinations), refuses an existing target without `--force`, and
  exits 8 on a checksum mismatch. Proxmox and UniFi are refused.

### Lifecycle

```console
artoo vm start VM -y
artoo vm shutdown VM -y                  # ACPI; Proxmox gives up after 180 s (exit 6)
artoo vm reboot VM -y                    # also applies changes waiting for a restart
artoo vm stop VM --yes --confirm NAME    # power cut
artoo vm upgrade VM -n                   # what apt would install, security updates marked
artoo vm upgrade VM --snapshot -y        # a snapshot first; never reboots (SPEC §9.12)
artoo vm upgrade --all -n                # every ordinary guest in one plan; edge, router and watchdog get their own runs
artoo vm reboot --pending -n             # the guests that want a reboot, one by one; stops at the first that does not return
artoo vm set VM memory=4G cores=2 -y     # allowlisted keys, digest-guarded (SPEC §9.13, §9.15)
artoo vm set VM cores=4 --reboot -y      # reboot through Proxmox if the change waits for it
artoo vm set VM onboot=yes startup=order=1,up=30 protection=yes -y
artoo vm disk grow VM +20G -n            # final: Proxmox cannot shrink a disk
artoo vm clone SOURCE NEWNAME [--id N] -y   # a plain Proxmox copy: no records, password or pinned key
artoo vm rm VM --yes --confirm NAME
```

- A running VM's CPU or memory change may stay pending: `vm config VM`
  marks it, `vm reboot VM` (or `--reboot`) applies it. A reboot inside
  the guest does not.
- `vm disk grow` on the boot disk of a running guest whose agent answers
  grows `/` at once; otherwise at the next boot.
- `vm rm` stops and destroys the VM and its disks, then forgets its
  UniFi client record, DNS record, stored password, pinned host key,
  `ssh_config` block, watchdog metrics and tailnet device. It **refuses**
  while a service name points at the VM (`svc set` or `svc rm` first)
  and for a protected VM (`vm set VM protection=no` first).

### Snapshots (SPEC §9.16)

```console
artoo vm snap add VM pre-upgrade -y      # your own name; 'artoo-' is reserved
artoo vm snap rollback VM pre-upgrade --yes --confirm NAME@pre-upgrade
artoo vm snap rm VM pre-upgrade --yes --confirm NAME@pre-upgrade
artoo vm snap prune VM -n                # artoo's own beyond guests.snapshot_keep or older than guests.snapshot_max_age_days
artoo vm snap prune --all -n             # every guest (--confirm all)
```

Snapshots are rollback points, not backups: they live on the guest's
own storage. `--snapshot` (on `vm upgrade`, `edge setup`, `router
setup`, `watch setup`) refuses at the cap (`guests.snapshot_keep`,
default 2) or above 80 % storage use, and never deletes one to make
room; `vm snap prune` does. Proxmox (on ZFS) rolls back only to the
newest snapshot: `vm snap rollback` names the newer ones to remove
first. A guest that was running starts again after a rollback without
RAM.

### Rename (SPEC §9.18)

```console
artoo vm rename naboo hoth -n
artoo vm rename naboo hoth --yes --confirm naboo   # rollback: vm rename hoth naboo
```

- One step per place the name lives: Proxmox, DNS records, services,
  the pinned key and `ssh_config`, the stored password, fence
  exceptions, the tailnet name, the watchdog's series, the hostname and
  the UniFi client record. After a failure, the same command continues.
- Refused for the edge and the watchdog (rebuild those), stopped guests
  and VMs artoo did not create. `vm set name=` refuses on artoo guests.
- The guest's next boot runs cloud-init as a new instance, with new SSH
  host keys: `artoo vm ssh-config --repin hoth` pins the new key (it
  shows both fingerprints). Other machines keep the old name until they
  run `vm ssh-config` and get the password again.

### Fence a guest (SPEC §9.11)

```console
artoo vm fence naboo -n                            # the derived rules, as a diff against Proxmox
artoo vm fence naboo --yes --confirm naboo         # high-impact: an approved plan first
artoo vm fence naboo --off --yes --confirm naboo   # rollback
artoo config set guests.fence_allow_out 'naboo hoth tcp 5432'   # a kept outbound exception
```

- The fence is the Proxmox VE firewall on the guest's NIC. In: services
  from the edge only, SSH and ping from the LAN (from Proxmox only for
  `ssh-jump`). Out: DNS, the watchdog, the exceptions, then no private
  address but web, NTP and ping. Nothing inside the guest changes. The
  edge, the watchdog and the router are refused (their setup owns their
  firewall).
- It needs the datacenter firewall on (§10). It is a firewall change:
  every live run needs its own approved plan, and so does taking over a
  hand-written `/etc/pve/firewall/<vmid>.fw`, whose rules the plan shows
  as replaced.
- `svc add|set|rm` keep a fenced guest's inbound rules in step within
  the same plan; `vm verify`, `vm show` and `status` report drift.

### Rex and coding agents on a guest (SPEC §18)

```console
artoo config set agents.profile ~/dotfiles   # optional: rules, skills and settings for the agents
artoo rex setup naboo -n                     # the plan: package, pins, linger, skill, profile, permissions
artoo rex setup naboo                        # a live change: an approved plan first
artoo rex status                             # every guest tagged rex, with the agents working there
artoo rex hosts sync -n                      # the workstation's Rex hosts for those guests
artoo vm new hoth --rex                      # a new guest with Rex (or rex.default true)
```

- Ordinary guests only; the edge, the router and the watchdog are
  refused. Install and sign in to the agents yourself (`claude`,
  `agy`); artoo never copies an agent's login.
- The permission kind follows the fence: a fenced guest without private
  SSH keys runs agents without prompts (`sandboxed`); every other guest
  keeps prompts and has bypass mode disabled (`trusted-reach`). Fence
  the guest first (above) to get `sandboxed`.
- A profile file edited on the guest is left alone and reported by
  `rex status`; `rex setup VM --force-profile` puts the profile's back.
- `vm reboot --pending` skips a guest where an agent is working or
  waiting for you; `--force-agents` (typed confirmation) reboots it
  anyway. Rex updates come with `vm upgrade`; the running server keeps
  its sessions and takes the new version once it stops.

### Images and templates (SPEC §9.2)

```console
artoo image fetch ubuntu-2604 -n         # Proxmox downloads it and checks SHA-256
artoo image rm ubuntu-2604 --yes --confirm ubuntu-2604
artoo template vendor                    # the exact vendor-data snippet (local, read-only)
artoo template build ubuntu-2604 -n      # image, snippet (root SSH), VM, convert
artoo template rm ubuntu-2604 --yes --confirm ubuntu-2604
```

`template build` places `artoo-vendor-<hash>.yaml` in
`/var/lib/vz/snippets` over root SSH. It is a persistent host file, so
a build needs an approved plan. An existing snippet is never replaced.
Rebuild when `template ls` says `outdated`; existing guests never
change.

## 7. Give a service a LAN name (SPEC §9.6)

```console
artoo svc add grafana naboo:3000 -n   # plan: edge route to naboo.lab.example.com:3000 + UniFi record
artoo svc add grafana naboo:3000 -y   # → https://grafana.apps.lab.example.com/
artoo svc set grafana hoth:3000 -y    # move it: route only; name and record stay
artoo svc rm grafana --yes --confirm grafana
```

- The upstream is an artoo guest in the pool serving **plain HTTP**;
  HTTPS is the edge's `*.apps` Let's Encrypt wildcard.
- A service is a route file on `bespin` plus a UniFi record. `svc ls`
  reports a missing half; `svc add` repairs it.
- `add` ends with a probe from the edge; a 502 is a warning (the
  service is not up yet), not a failure.
- **Health:** a service that does not answer 2xx at `/` names its health
  path, and optionally a literal text that means down:
  `svc add search hoth:8080 --health /v1/health --health-down
  '"down"'`. Both live in the route file; the edge's and the watchdog's
  probes use them. Run `watch setup` afterwards so the watchdog probes
  the change. Without `--health`, `add` and `set` keep a route's health;
  `--health /` resets it.
- `svc rm` refuses while a public name points at the service.

## 8. Publish a service on the internet (SPEC §14)

```console
artoo cf tunnel route add blog grafana -n   # blog.example.com → service grafana
artoo cf tunnel route add blog grafana -y
artoo cf tunnel route rm blog --yes --confirm blog.example.com
```

- A public name always reaches an **existing service** (`svc add`
  first): Cloudflare → tunnel → cloudflared on `bespin` → Caddy on
  localhost (TLS checked as `grafana.apps.lab.example.com`) → the same
  route → guest. The edge's firewalls apply to public traffic too.
- Each route is an ingress rule plus a proxied CNAME `blog.example.com →
  <tunnel-id>.cfargotunnel.com`, commented `artoo: tunnel grafana`. The
  app sees `grafana.apps.lab.example.com` as Host; an app that builds
  absolute links needs its public URL in its own settings.
- Check the public name **by hand a minute later**, through a public
  resolver (`dig blog.example.com @1.1.1.1`) or a phone on mobile data:
  an early lookup through UniFi can cache "not found".
- Refused: Proxmox and UniFi names and addresses,
  `guests.reserved_names`, names under `lab.example.com`, the zone apex,
  a host that already has a record or another route, and services on
  `role-watch` or `role-search` guests.
- Teardown order: `cf tunnel route rm` → `svc rm` → `vm rm`. `svc rm`
  refuses while a public route reaches the service, `vm rm` while a
  service points at the VM.

## 9. Reach the lab from away (SPEC §9.8, §17)

The subnet router `dagobah` advertises `192.168.1.0/24` to the tailnet;
split DNS sends `lab.example.com` and `home.arpa` to UniFi. A typical
tailnet policy lets the operator's devices reach Proxmox (22, 8006),
UniFi (443, DNS) and the guest pool, nothing else on the LAN.

```console
artoo router status        # Running, tag:lab-router, route advertised and approved, forwarding
artoo router setup -n      # what a new or rebuilt router still needs
```

- **Build or rebuild:** `vm new dagobah --role router --size small
  --cores 1`, `vm set dagobah onboot=yes`, remove a previous router's
  device (`ts device rm OLD`), then `router setup`. With the `tailscale`
  credential, artoo makes the single-use join key and approves the
  route. Without it, the operator makes a single-use auth key tagged
  `tag:lab-router` and runs `router setup` in their own terminal (the key
  is asked after the plan is confirmed, hidden), and the policy's
  `autoApprovers` must approve the route.
- Guests are reached through the router. A guest joins the tailnet
  itself only when a program must see tailnet logins: tag it `tailnet`
  (`vm set VM tags=…,tailnet`), then `artoo ts join VM [--tag TAG]`.
  artoo makes the key; never run `tailscale up` by hand.
- Devices other than the workstation warn about Proxmox's and UniFi's
  certificates until they trust the mkcert **public** root
  (`~/.artoo/tls/rootCA.pem`; on iOS install it as a profile, then
  enable full trust under Certificate Trust Settings).

### The tailnet through the API

The `tailscale` OAuth client (§15) covers everyday work:

```console
artoo ts devices ls                    # every device; LAB says which are the lab's and why
artoo ts device show NAME
artoo ts keys ls                       # auth key metadata, never a key
artoo ts dns show
artoo ts dns split set lab.example.com 192.168.1.1 -n   # also home.arpa; only to the gateway
artoo ts policy show | validate FILE | preview WHO
artoo ts join VM [--tag TAG]           # a guest tagged tailnet joins (or moves to TAG)
artoo ts device rename NAME NEW        # an artoo guest: 'vm rename' instead
artoo ts device tag NAME TAGS          # devices whose tags came from the API or console
artoo ts device rm NAME                # typed confirmation
artoo ts routes approve dagobah
```

- **Tags.** Guest tags are `tailscale.guest_tags` (default
  `tag:lab-guest`; keep the `lab-` prefix). A tag must be in the
  policy's `tagOwners` and on the OAuth client (Devices Core and Auth
  Keys) before artoo can use it.
- **Moving a guest to another tag:** add the new tag to the policy (next
  to the old one), to the client and to `guest_tags`; `ts join VM --tag
  NEW` (the guest logs in again with a new key, a few seconds offline);
  then remove the old tag from the policy, the client and `guest_tags`.
- **Changing the policy:** the operator creates a second OAuth client
  with only Policy File write (the console adds Devices Core read and
  Posture Attributes read); the agent sets `tailscale.policy_client_id`;
  the operator runs `artoo auth set tailscale-policy`. Keep the lab's
  policy file in the lab record. Save the live one first (`ts policy
  show > before.hujson`), then `ts policy apply FILE -n` (Tailscale
  validates it and runs its tests; the plan shows the diff). After
  approval, the same without `-n` and with the tailnet's name as the
  typed confirmation. Afterwards the operator revokes that client and
  runs `artoo auth rm tailscale-policy`.

## 10. Operate the edge and the watchdog (SPEC §9.7, §9.9)

Both need the **datacenter firewall** on Proxmox, as does `vm fence`.
Enabling it is a one-time, approved host change:
`PVE_SSH=root@192.168.1.10 scripts/pve-firewall.sh` (it keeps SSH,
`:8006`, `:3128` and ping open from the LAN, and rolls itself back after
180 s unless a new SSH login and `:8006` still work).

### The edge `bespin`

```console
artoo edge status          # read-only; the first look after anything unusual
artoo edge setup -n        # only the steps the VM's state needs
artoo edge setup -y        # hardening, both firewalls, cloudflared, Caddy built from pinned sources (minutes)
artoo edge secret dns      # the edge's own DNS-01 token: operator's terminal, hidden prompt
artoo edge tunnel -y       # create and connect the Cloudflare Tunnel; its token goes API → VM, never shown
```

- The edge is the VM tagged `role-edge`; everything runs as root through
  the guest agent. **Any hit on the "drops towards Proxmox/UniFi"
  counters is a sign of compromise:** shut it down (`artoo vm shutdown
  bespin`) and look before anything else.
- Ubuntu and cloudflared update themselves; `edge status` compares Caddy
  with its latest release and reports a pending reboot. A Caddy bump is
  a SPEC edit, then `edge setup`. Rebooting is an approved action.
- **Build or rebuild** (it is never backed up): `vm new bespin --role
  edge --size small --cores 1 --ssh-jump --ip 192.168.1.200`, `vm set
  bespin onboot=yes`, `edge setup`, `edge secret dns` (a DNS-01 token
  from the operator), `edge tunnel` (a fresh token for the existing
  tunnel). Route files are lost with the VM: `svc ls` shows each service
  as missing its route and `svc add NAME VM:PORT` restores it. Public
  routes live in Cloudflare and work again once the services are back.

### The watchdog `scarif`

Metrics (VictoriaMetrics), logs (Loki), dashboards and alert rules
(Grafana) and notifications (ntfy) on the VM tagged `role-watch`. Grafana
Alloy on every guest pushes to it; Proxmox pushes through its own metric
export. Nothing phones home, and nothing of it is public.

```console
artoo watch status          # blocked telemetry first, then pins, services, every guest's freshness
artoo watch setup -n|-y     # converge the VM; re-run after 'svc add' or a health change
artoo watch enroll --all    # Alloy on existing guests (vm new enrolls new ones; skips no-watch guests)
artoo watch forget HOST     # metrics of a guest removed without 'vm rm', so its alerts resolve
artoo watch secret grafana  # Grafana's admin password: operator's terminal, hidden prompt
artoo watch secret phone    # the phone's ntfy login (bcrypt made on the workstation)
```

- **Build** (each step under the approved plan): `vm new scarif --role
  watch --size medium --ssh-jump --ip <pool address>`, `vm set scarif
  onboot=yes`, `watch setup`, `svc add grafana scarif:3000`, `svc add
  ntfy scarif:2586`, `watch setup` again (to probe the two names), both
  `watch secret`s, `watch enroll --all`. Then the operator runs
  `PVE_SSH=root@192.168.1.10 scripts/pve-metrics.sh <scarif's address>`
  (a host change: it needs `Sys.Modify`, which artoo's token lacks).
- **Phone** (on the tailnet): ntfy app → subscribe to topic `lab` on
  *another server* `https://ntfy.apps.lab.example.com` with *instant
  delivery*; log in as `phone`. No relay: the app keeps its own
  connection to `scarif`.
- **Web:** Grafana at `https://grafana.apps.lab.example.com` (user
  `admin`). The machine name `scarif.lab.example.com` serves nothing on
  443; service names say what runs.
- **A "telemetry blocked" count** means a component tried the internet:
  read `journalctl` on `scarif` around that time and fix the switch
  (SPEC §9.9).
- **Rebuild** (never backed up; history is lost): the build steps again.
  The Proxmox metric server stays if the address is the same.

## 11. DNS records by hand (SPEC §10.3, §14)

```console
artoo dns add nas.home.arpa 192.168.1.90 -n   # UniFi; a short name gets lab.example.com
artoo dns rm nas.home.arpa --yes --confirm nas.home.arpa
artoo cf dns add _artoo-test TXT hello -n     # Cloudflare; a short name gets example.com
artoo cf dns add www CNAME example.pages.dev --proxied --note blog -y
artoo cf dns rm www --yes --confirm www.example.com
```

Prefer the workflows (`vm new`, `svc add`, `cf tunnel route add`): they
keep records consistent. UniFi records answer on `192.168.1.1` within
seconds (`dig @192.168.1.1 NAME`). Public records are outward-facing:
artoo marks what it creates (`artoo: …`), touches nothing else, and
refuses Proxmox and UniFi, LAN and Tailscale addresses and names under
`lab.example.com`.

## 12. The gateway through the full UniFi API (SPEC §10)

Every Integration API area is a `gw` resource with `ls`/`show` and,
where the API allows, `add`/`set`/`rm`: `sites`, `devices` (`stats`,
`pending`, `adopt`, `restart`, `port-cycle`), `clients` (`authorize`,
`unauthorize`), `networks` (`refs`), `wifi`, `fw-policies` and `acl`
(`order`, `reorder`; `fw-policies patch`), `fw-zones`, `dns-policies`,
`traffic-lists`, `vouchers` (`purge`); read-only: `wans`,
`vpn-servers`, `vpn-tunnels`, `radius`, `lags`, `mc-lag`, `stacks`,
`device-tags`, `dpi-apps`, `dpi-categories`, `countries`.

```console
artoo gw clients ls --filter "type.eq('WIRED')"   # 'ls -h' shows each resource's filter grammar
artoo -o json gw networks show Default > net.json  # edit net.json, then:
artoo gw networks set Default --from net.json -n   # field diff and reset fields
artoo gw networks set Default --from net.json --yes --confirm Default
artoo gw api GET '/v1/sites/{siteId}/devices'      # escape hatch (quote the path); writes need --confirm PATH
artoo gw spec                                      # after a UniFi Network update: drift from artoo's catalog
```

- Read-only fields are dropped and named in the plan; secrets show as
  `<redacted>`, and a file that still holds `<redacted>` is refused. A
  `set` replaces the whole object. Actions (`restart`, `port-cycle`,
  `authorize`) are reported as *accepted*, not verified.
- **When the internet drops** (SPEC §10.4, read-only): `gw wans ls`
  shows each WAN's role, status, address ("shared" = the ISP's
  carrier-grade NAT), link and health; a WAN no port carries is "no
  port", not offline. `gw wans show WAN` adds the next hop, monitors and
  the last 24 hours' outages. `gw wans log [WAN] --since 7d` lists
  outages with their lead-up and likely cause (from evidence only, else
  "unknown").

## 13. Recipes

**A new web app on the LAN and the internet:**

```console
artoo vm new naboo --role web -y                    # 1. the guest
artoo vm ssh naboo                                  # 2. install the app, listening on :3000
artoo svc add grafana naboo:3000 -y                 # 3. https://grafana.apps.lab.example.com
artoo cf tunnel route add grafana grafana -y        # 4. https://grafana.example.com (check by hand later)
```

**Take it down**, in reverse order (§8):

```console
artoo cf tunnel route rm grafana --yes --confirm grafana.example.com
artoo svc rm grafana --yes --confirm grafana
artoo vm rm naboo --yes --confirm naboo
```

**Move a service to a rebuilt guest** (the names stay): `artoo svc set
grafana hoth:3000 -y`.

## 14. Direct SSH to Proxmox

For host work artoo does not cover (inspection, logs, host configuration
under an approved plan):

```console
ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=yes -o ConnectTimeout=10 root@192.168.1.10
```

- Root key login is set up and the host key is in the workstation's
  `known_hosts`. Never disable host-key checking, replace a changed host
  key, create a new identity or ask for the root password.
- Non-interactive SSH runs **Bash** (interactive terminals switch to
  fish): write explicit `bash` scripts.
- First read-only check: `hostname -f; pveversion; zpool status -x;
  systemctl --failed --no-legend`.
- Prefer the IP unless the workstation resolves the host name reliably.
- Before changing a file, back it up under
  `/root/pve-setup-backups/<topic>-<UTC timestamp>/`.
- Workloads belong in guests, never on the host. Prefer artoo for VM
  operations; `qm` over SSH is for bootstrap and emergencies.
- **Host updates:** `pveupd -c` in root's fish is read-only (`apt
  update` and what a `full-upgrade` would change). `pveupd` installs it
  (an approved host change) and refuses when it would remove a Proxmox
  core package or the running kernel; never plain `apt upgrade`. It
  never reboots: a host `reboot` shuts every guest down cleanly and
  starts the `onboot` ones again, and `pveupd` names running guests that
  would not come back. Root's shell config comes from `hosts/pve/`
  (`scripts/pve-shell.sh`, which backs up first).
- The host scripts `scripts/pve-*.sh` and the live tests in
  `scripts/live/` need `PVE_SSH=root@<host address>` (no default) and
  the installed `artoo` on `PATH`, whose `pve.ssh_identity` they use.
  Live tests record the resources they own in `~/.artoo/live-ledger.txt`
  (or `$ARTOO_LEDGER`).

## 15. Credentials and certificates (SPEC §6, §7, §14, §17)

Each credential is entered by the operator with `artoo auth set NAME`
(hidden prompt, or `--stdin`); `doctor --connect` tests it.

- **Proxmox token** `artoo@pve!cli`: created as in
  [QUICKSTART.md](QUICKSTART.md) §2 (roles: SPEC §7). It has no host,
  user or permission administration. Rotation is an approved host
  change:

  ```console
  ssh … root@192.168.1.10 'pveum user token remove artoo@pve cli'
  ssh … root@192.168.1.10 'pveum user token add artoo@pve cli --privsep 0 --output-format json' \
    | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["value"])' \
    | artoo auth set pve --stdin --yes
  ```

- **UniFi API key:** made in the UniFi UI (Settings → Integrations).
- **Cloudflare token:** an *account* API token with Zone Read and DNS
  Edit on the zone, and *Cloudflare One Connector: cloudflared* Edit on
  the account (not "Argo Tunnel (Legacy)"). Editing a token's
  permissions keeps its value. `doctor --connect` shows its expiry.
- **The edge's DNS-01 token:** a second account API token, limited to
  the zone with DNS Edit and Zone Read, handed over with `edge secret
  dns`. It and the tunnel token exist only on `bespin`.
- **Tailscale OAuth client** (Settings → Trust credentials → OAuth, in
  the console): write scopes Devices Core, Devices Routes, Auth Keys and
  DNS, plus Policy File read, owning `tag:lab-router` and every
  `tailscale.guest_tags` tag (SPEC §17). Set `tailscale.client_id`, then
  `auth set tailscale`; `doctor --connect` lists the scopes it grants
  and fails if it may write the policy.
- **Certificates:** mkcert leaves signed by the workstation's root CA,
  on Proxmox (`pvenode cert set`) and UniFi (uploaded in the UniFi UI).
  Renewal is by hand; `doctor` warns 30 days before the CA bundle
  expires. Losing the CA's private key means a new CA, new leaves for
  Proxmox and UniFi, and the new public root on every client
  (`~/.artoo/tls/rootCA.pem` too). Service names use the edge's Let's
  Encrypt wildcard instead, renewed by Caddy.

## 16. Outside artoo: the operator's consoles

- **UniFi UI:** client renames, port forwarding, static routes, QoS,
  NAT, DHCP settings, firmware and UniFi OS, radio power, per-client
  signal and roaming; the API key.
- **Cloudflare dashboard:** the tokens and their permissions; deleting
  the tunnel; Cloudflare Access in front of a public route.
- **Tailscale console:** the OAuth clients (`tailscale`, and
  `tailscale-policy` for one policy change); personal devices join by
  logging in. The policy, split DNS, lab devices' names, tags and
  removal, and join keys go through artoo.
- **Physical work** (cabling, installing equipment) is always the
  operator's, with its own approval.

## 17. Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Exit 3, "rejected the API token" / "API key" | Secret missing or rotated: `artoo auth status`, ask the operator |
| Exit 3, Cloudflare 403 on a tunnel call | The token lacks *Cloudflare One Connector: cloudflared* Edit (§15) |
| Exit 4, TLS handshake failed | Wrong host name, or a certificate not signed by the configured CA |
| Exit 2, "no VM 'x'" | Name typo: `artoo vm ls --all` |
| Exit 2, "'x' matches 2 …" | Ambiguous name: use the ID shown |
| Exit 2, "invalid --filter" | Filter grammar: single quotes for strings, see `-h` |
| Exit 5, "service … points at" / "public host … reaches" | Remove the dependent layer first (§13) |
| Exit 7 after a write | Outcome unknown: check with a fresh read before anything else |
| `svc add` ends with HTTP 502 | The app on the guest is not listening (yet) on that port |
| A service name answers "no such service" (404) | No route file on the edge: `svc ls`, then `svc add` |
| A public name gives Cloudflare error 1033 or 530 | cloudflared not connected: `edge status`, `cf tunnel ls` |
| A new public name does not resolve at home | UniFi cached "not found" from an early lookup: wait, or test with `@1.1.1.1` |
| Certificate warning on another device for `*.home.arpa` | It does not trust the mkcert root yet (§9) |
| `router status`: route not approved | The device's tag (`tag:lab-router`), or the policy's `autoApprovers` without the credential |
| `vm ssh … -- CMD` fails with a fish error | The login shell is fish: wrap in `sh -c "'…'"` |
| `ssh NAME` refuses a changed host key after `vm rename` or a rebuild | `artoo vm ssh-config --repin NAME`, after checking the fingerprints |
| `vm fence` says the fence has no effect; `vm verify` warns on it | The datacenter firewall is off (§10) |
| A removed VM's client reappears on UniFi | UniFi re-creates a client it still counts as connected: wait until it shows **offline**, then remove it |
| Exit 5 (or 8 mid-run), `vm new` says the address "is still held by connected client …" | A VM removed minutes ago still counts as connected there; only time clears it (about 10 minutes). Re-run the same `vm new` once `gw clients ls` no longer lists the MAC: it continues |
