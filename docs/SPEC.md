# artoo — design specification

This document is the contract for what artoo does today: commands,
flags, output, refusals, exit codes, configuration, files, the mutation
pipeline and secrets. The vendor API facts the code relies on are in
[API.md](API.md). The SPEC changes in the same pull request as the code
it describes; it holds no plans.

## 1. Purpose

`artoo` is the operator's single CLI for a home lab:

- **Proxmox** — one host running Proxmox VE 9.2 (e.g. `https://pve.home.arpa:8006`).
- **UniFi** — a UniFi gateway (e.g. `https://unifi.home.arpa`, Integration API).
- **Cloudflare** — the public DNS zone `example.com` and Cloudflare Tunnel,
  only for services explicitly made public (§9.6, §14).
- **Tailscale** — the lab's side of a tailnet (§17).
- **Rex** — the terminal on guests that run coding agents (§18).

From the workstation, artoo inspects and operates these systems, creates
a ready Ubuntu guest in one command — guest user and shell environment
configured, reachable as `<name>.lab.example.com` through a DNS record on
UniFi (§9.6) — and removes it cleanly in one command. Infrastructure keeps
its private `home.arpa` names and is never publicly exposed (§9.6).

artoo is a native Zig 0.17.0 binary: standard library only, no runtime
dependencies. Clients are **macOS arm64** and **Linux arm64/amd64**, with
identical commands, config and behavior; only the credential store
backend differs (§6).

Out of scope: host package management, clustering/Ceph, LXC management
(reported, not managed), consoles/VNC, a TUI, backups, gateway
firmware/OS administration, and tailnet administration beyond the lab's
side (the policy, users and settings stay in the operator's console; the
subnet router, lab devices and split DNS are in scope, §9.8, §17).

## 2. Principles

1. **Efficient to type, obvious to read.** Noun–verb grammar, positional
   targets, names accepted wherever IDs are, short flags for common options,
   output for a human first and JSON on request.
2. **Honest.** Missing data is `--`/`null`, never zero. A check that did not
   run is "not checked", never "ok". An ambiguous write is "unknown", never
   success. Partial results are shown and exit non-zero.
3. **Safe mutations, one pipeline.** Every write: validate → plan → preview →
   confirm → send once → track → verify (§8).
4. **Proportionate security.** TLS verified against the mkcert root; secrets
   never printed, logged, or put in argv, env, config or Git. No ceremony
   beyond that (no custom code-signing, no in-process wiping rules, no
   multi-token role matrices).
5. **Typed, tested, small.** Typed API models, offline tests for every
   command's parsing, planning and rendering; live tests only as explicit runs.

## 3. Command interface

Grammar: `artoo <noun> <verb> [TARGET…] [flags]`. Global flags are accepted
anywhere after the program name. Unknown commands suggest the closest match.

`artoo help <noun> [verb]` and `-h` on any command print usage with every
flag, its type and default, and examples. Help, parsing and completion
(§3.5) come from one declarative command table, so they cannot diverge.
Help is written for the operator and never cites this document:

- `details` reflow to the terminal width (60–100 columns, 80 when piped).
  Blank lines separate paragraphs; indented lines (lists, tables) and the
  line ending in `:` that introduces them stay as written.
- Long flag and command descriptions wrap under their column.
- A command's page shows its own flags and a one-line pointer to the
  global flags, which `artoo --help` lists.

### 3.1 Global flags

| Flag | Meaning |
| --- | --- |
| `-o, --output table\|json` | Output format (default from config: `table`) |
| `--color auto\|always\|never` | Color policy; `NO_COLOR` honored; `auto` = color only on a TTY |
| `--ascii` | ASCII-only glyphs and borders |
| `-y, --yes` | Skip the interactive confirmation (never skips validation) |
| `-n, --dry-run` | Plan and preview only; send no write |
| `--no-wait` | Return after the write is accepted (exit 0 = accepted only) |
| `--timeout SECONDS` | Per-request deadline override |
| `-v, --verbose` | Request/step diagnostics on stderr (sanitized) |
| `--config PATH` | Alternate config file (default `~/.artoo/config.json`) |
| `-h, --help` | Show help |
| `--version` | Show the version |

### 3.2 Targets

- `VM` is a numeric VMID or a VM name. A name must match exactly one VM;
  ambiguity is an error listing the candidates. Templates are VMs too.
- `TASK` is a UPID, a short task handle as artoo prints it
  (`qmstart:9010@14:32`), or any unique fragment shown in `task ls`.
- Gateway objects accept their ID or their unique name (`dns rm web-01`).

### 3.3 Command tree

```text
artoo status                          one-screen overview of the lab (§11)
artoo doctor [-c|--connect]           local install/config/secret store/CA checks; --connect calls each API read-only
artoo update [VERSION] [--check]      replace this binary with a verified GitHub release (§16)
artoo completion fish|bash|zsh        print the shell completion script (§3.5)

artoo auth set SECRET [--stdin] | status | rm SECRET   SECRET: pve, unifi, cloudflare, tailscale, tailscale-policy (§6)
artoo config show | get KEY | set KEY VALUE | unset KEY | edit | init   (§5)
artoo config export FILE [--stdin] [--force] [--guest-passwords] | import FILE [--stdin] [--force]
                                      artoo's setup to another machine (§6.1)

artoo host show | health [CHECK…]     Proxmox node: versions, CPU/RAM/load, uptime; CHECK: api, node, storage, tasks, zfs, services
artoo storage ls | show STORAGE
artoo task ls [--running|--failed] [-l N] | show TASK | log TASK [-a|--all] | wait TASK [--max-wait SECONDS]

artoo vm ls [-a|--all] [-s|--status STATE] [--name GLOB]
artoo vm show VM | config VM          pending values marked (§9.13)
artoo vm urls VM                      service URLs and public hosts that reach the VM
artoo vm start|shutdown|reboot VM
artoo vm reboot --pending [--force-agents [--confirm every-guest]]
                                      reboot the guests that want it after updates, one by one (§9.12, §18.8)
artoo vm stop VM                      forced stop (destructive confirmation)
artoo vm set VM KEY=VALUE… [--reboot] allowlisted config keys, digest-guarded (§9.13); name= only on foreign VMs
artoo vm rename OLD NEW               rename an artoo guest everywhere its name lives (§9.18; typed confirmation)
artoo vm disk grow VM SIZE [--disk SLOT]  grow a disk and the guest's root filesystem (§9.15)
artoo vm clone VM NEWNAME [--id VMID]
artoo vm rm VM [--keep-dns]           destroy VM + disks and every record artoo keeps of it (§9.3)
artoo vm snap ls VM | add VM NAME [-d TEXT] [--ram] | rm VM NAME | rollback VM NAME
artoo vm snap prune VM|--all [--keep N] [--older-than DAYS]
                                      delete artoo-owned snapshots beyond the cap or age (§9.16)
artoo vm new [NAME] [-s SIZE] [--cores N] [--memory SIZE] [--disk GIB] [--ip ADDR] [--id VMID]
                    [--template T] [--role ROLE] [--ssh-jump] [--no-dns] [--no-watch] [--rex|--no-rex]   (§9.3)
artoo vm verify VM|--all [--full] [--no-dns]   read-only readiness checks (§9.4)
artoo vm upgrade VM [--snapshot]      install the guest's pending package updates (§9.12, §9.16)
artoo vm upgrade --all                every ordinary guest in one plan; not edge, router, watchdog (§9.12)
artoo vm ssh VM [-- CMD…]             exec ssh <user>@<address> (convenience)
artoo vm ssh-config [--repin VM]      write ~/.artoo/ssh_config: strict plain ssh/scp/rsync; re-pin a changed host key (§9.10)
artoo vm cp SRC DST [-r] [--force]    copy as <user> to, from or between guests, SHA-256 checked (§9.10)
artoo vm password VM [--show|--reset] copy the guest user's password to the clipboard; --show prints it (TTY only, §7); --reset sets a new one (§9.17)
artoo vm fence VM [--off]             Proxmox NIC firewall around a guest (§9.11)

artoo template ls | show T | build T [--id VMID] | rm T | vendor [T]
artoo image ls | fetch IMAGE | rm IMAGE    pinned images on Proxmox (never the workstation)

artoo gw info                         UniFi: version, site, device/client/network/Wi-Fi/WAN/DNS counts
artoo gw <resource> ls|show|…         full Integration API surface (§10)
artoo gw api METHOD PATH [-f FILE]    any Integration API request; writes need a typed path (§3.4)
artoo gw spec [-f PATH] [--save PATH] live (or local) OpenAPI vs built-in catalog drift report
artoo gw wans ls | show WAN | log [WAN] [--since 24h|7d|30d]
                                      WAN health, port assignment and outages (§10.4)
artoo dns ls | add NAME IP [--ttl SECONDS] | rm NAME   shortcut for gw dns-policies A records (§10.3)
artoo cf dns ls [--type T] [--name NAME] | add NAME TYPE CONTENT [--proxied] [--ttl SECONDS] [--note TEXT] | rm NAME [--type T]
artoo cf tunnel ls | route add HOST SERVICE | route rm HOST   Cloudflare zone records + tunnel routes (§14)
artoo ts devices ls | device show NAME   the tailnet's devices, lab devices marked (§17)
artoo ts dns show | keys ls           tailnet DNS; auth key metadata (never a key's value)
artoo ts policy show [--json] | validate FILE | preview USER|IP:PORT   the policy, read-only
artoo ts policy apply FILE            replace the policy (credential tailscale-policy; diff, typed confirmation)
artoo ts device rename NAME NEW | device tag NAME TAGS | device rm NAME   lab devices only (rm: typed confirmation)
artoo ts routes approve ROUTER        approve exactly the LAN route a lab router advertises
artoo ts dns split set DOMAIN NAMESERVER…   guests.domain or home.arpa → the gateway only
artoo ts join VM [--tag TAG]          enroll a guest tagged tailnet with a key artoo creates (never shown)

artoo edge setup [--snapshot] | secret dns [--stdin] | tunnel | status
                                      the edge VM `bespin`: hardened HTTPS and the tunnel's endpoint (§9.7)
artoo svc ls | add NAME VM:PORT [--health PATH [--health-down TEXT]] | set NAME VM:PORT [--health …] | rm NAME
                                      service names on the edge VM (§9.6)
artoo router setup [--stdin] [--snapshot] | status
                                      the Tailscale subnet router (§9.8)
artoo watch setup [--snapshot] | status | enroll VM…|--all | secret grafana|phone [--stdin] | forget HOST
                                      the watchdog VM `scarif` (§9.9)
artoo rex setup VM… [--force-profile] Rex, its agent skill, the agent profile and permissions on guests (§18.3)
artoo rex status [VM…]                Rex and the agents on guests tagged rex (§18.7)
artoo rex hosts sync                  the workstation's Rex hosts for guests tagged rex (§18.9)
```

### 3.4 Confirmation

- Normal mutations: preview, then `Proceed? [y/N]`. Non-interactive without
  `--yes` refuses (exit 5).
- **Destructive** mutations need the typed target: interactively the
  operator types the target's name; non-interactively `--yes --confirm
  TARGET` is required, where `TARGET` equals the resolved name or ID (or
  what the command's help names: `VM@SNAPSHOT`, a record's FQDN, `all`
  with `--all`, `gw api`'s PATH as typed, the tailnet). They are `vm rm`,
  `vm stop`, `vm snap rollback|rm|prune`, `vm fence`, `vm rename`,
  `template rm`, `image rm`, `dns rm`, `cf dns rm`, `cf tunnel route rm`,
  `svc rm`, `ts device rm`, `ts policy apply`, `watch forget`, gateway
  deletes, device restarts and port cycles, firewall/ACL/network/Wi-Fi
  changes, voucher purges and generic `gw api` writes.

### 3.5 Shell completion

`artoo completion fish|bash|zsh` prints a thin script. On every Tab it
runs the hidden `artoo __complete -- WORDS…` (the words after `artoo`, the
last one being completed, maybe empty), which prints
`candidate<TAB>description` lines or the directive `:file` (the shell's own
path completion).

- Candidates come from the command table (§3): nouns, verbs,
  `help <noun> [verb]`, flags (global ones included) and their choices,
  so a new command completes without regenerating the script.
- A positional may declare live candidates: **VM names** (`VM`) and
  **template names** (`TEMPLATE`), read from Proxmox with a 1 s deadline;
  any error, timeout or missing secret completes nothing.
- `vm new NAME` offers the **curated guest names** (§9.1) that no VM or
  template carries; without Proxmox it offers all of them.
- Nothing else touches the network or prompts, and stdout never carries
  an error message.

## 4. Output

### 4.1 Human output

One shared rendering kit (`ui/`) serves every command:

- **Header line**, all on the left: artoo's mark `◓` (`artoo` with
  `--ascii`); for a view about one guest (`vm verify`, `edge status`, …)
  its name; then the context `<service> · <scope> · <time>` (`pve/<node>`,
  `unifi · <site>`, `tailscale · <tailnet>`, `cloudflare · <zone>`) or, for
  local commands, the local source (config file, secret store, version).
  The command is not echoed.
- **Tables**: column specs (title, alignment, min width, priority). Numbers
  right-aligned; width-aware (low-priority columns drop on narrow
  terminals; identifiers are never truncated); UTF-8-safe truncation with `…`.
- **Values**: IEC sizes (`1.8 TiB`), percentages with one decimal, `used /
  total (pct)` plus an optional 10-cell bar, relative times (`2m ago`,
  `in 3d`) with absolute time in `show`/JSON, durations (`3h 12m`).
- **Status**: a word plus color and glyph (`● running`, `○ stopped`,
  `✓ ok`, `▲ warning`, `✗ failed`, `– not checked`); ASCII fallbacks.
- **Counts**: `1 file`, `3 files` (`ui.values.count`), never `file(s)`.
- **API enum values** in tables read as words (`system defined`,
  `WPA2/WPA3 personal`, `A` for `A_RECORD`); JSON keeps them as sent.
- **Detail views** (`show`): aligned key/value sections; a value longer
  than the terminal wraps under its column.
- **Plans**: the preview block (target, current → intended, impact,
  recovery) shown before every confirmation.
- **Progress**: live step lines for multi-step writes (§4.4); an activity
  line while a command reads before printing (§4.5).
- **Palette**: Gruvbox dark (truecolor, 256-color fallback, none):

| Role | Color |
| --- | --- |
| text / muted / border | `#ebdbb2` / `#a89984` / `#504945` |
| titles, IDs | `#83a598` |
| ok / warning / failure | `#b8bb26` / `#fabd2f` / `#fb4934` |
| changed / emphasis / high-impact | `#8ec07c` / `#d3869b` / `#fe8019` |

All server- and user-supplied strings are sanitized for terminal controls
before rendering: C0, DEL **and** C1 (including UTF-8-encoded C1), the
bidi controls (U+202A–U+202E, U+2066–U+2069) and invalid UTF-8 each
become `?`.

### 4.2 JSON

`-o json` prints exactly one document on stdout:
`{"schema_version":1,"target":"pve|unifi|cloudflare|tailscale|github|local","data":…,"meta":{…}}`,
where `meta` carries collection times, pagination and per-section errors.
No ANSI and no prose on stdout; errors are a JSON object on stderr. Values
are raw units (bytes, seconds, fractions → documented), missing values
`null`. JSON and tables are rendered from the same view model.

Workflows with a step ledger (§4.4, §8.2) add it to their result as
`data.steps` (with `data.result` `applied`/`accepted`) and, when they fail
after steps ran, to the error object beside `error`. Each step is
`{"name", "state" (done|failed|not_run|unknown|skipped), "detail",
"seconds"}`; `seconds` is null for a step that never ran. A failure before
any step (validation, a gate, a declined prompt) carries no `steps`.

### 4.3 Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (or dry-run completed) |
| 1 | Internal error |
| 2 | Usage / config error, or a named target that does not exist (`vm show nope`) |
| 3 | Credential, authentication or permission failure |
| 4 | Network, TLS or protocol failure (nothing was written, or a read failed) |
| 5 | Refused by a safety gate (declined, non-interactive without `--yes`, target mismatch, no-op) |
| 6 | Remote task completed with failure |
| 7 | Outcome unknown (write sent, result not observed) or wait deadline exceeded |
| 8 | Partial result: some sections/checks/steps failed or were not verified |
| 130 | Interrupted |

### 4.4 Live step progress

Every workflow that keeps a step ledger (§8.2: `vm new`, `vm rm`,
`template build`, `edge setup|tunnel`, `svc add|set|rm`,
`cf tunnel route add|rm`, `router setup`, `watch setup|enroll`, …) shows
its steps **while they run**, on **stderr**; stdout keeps results.

The ledger drives the display: a step is shown when it starts and
finalized when it ends. Steps run in the order they are added: the first
added step, and the step after each finished one, start automatically, so
nothing may prompt once steps are added. Prompts (confirmation, a hidden
key) happen only outside a running step; the redraw stops while one is
open.

Long waits update the running step's detail through a `Note` (ledger +
step) they are handed; a note never starts or ends a step:

- **Proxmox tasks** (`template build`'s fetch, create and convert): the
  task log's newest non-empty line, read incrementally (`log?start=N`) on
  each poll — download progress, disk import.
- **cloud-init** (`vm new`): `cloud-init status --format json` polled every
  3 s instead of one `--wait`. While `running`/`not started` its `stage` is
  the note (`stage modules-final`), else its `detail` (the datasource,
  e.g. `DataSourceNoCloud [seed=/dev/sr0]`). The final status is judged as
  `vm verify`'s cloud-init check (§9.4); `vm new` records a failure and
  goes on (§9.3).
- **The Caddy build** (`edge setup`): the script writes its stage
  ("installing Go", "building xcaddy …", "building Caddy … (modules, then
  compile)", "checking the binary", "removing Go") to
  `/run/artoo-caddy-build.stage` (removed on exit); artoo reads it through
  the guest agent about every 2 s while the script runs. A missing file or
  a failed read reports nothing.

Display:

- **Terminal** (stderr is a TTY, no `-v`): finished steps stay as lines;
  the running step is one line redrawn about ten times a second — a
  spinner (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`; `|/-\` with `--ascii`), its name, elapsed time
  and the latest detail, cut to the terminal width (never wraps). When the
  step ends it becomes its final line (`✓ wait for cloud-init  2m 05s  …`,
  `✗ …`). A total time follows the last step. The redraw runs as one
  concurrent task (`io.concurrent`); without concurrency the line is
  redrawn only on step and detail changes (no animation, same result).
  The cursor is not hidden, so an interrupt leaves a normal terminal; the
  pipeline ends any open line before printing an error.
- **Not a terminal**, or `-v` (whose trace lines would collide with the
  redraw): one plain line per step start and end with a local timestamp —
  `14:32:01 ▸ wait for cloud-init` / `14:34:06 ✓ wait for cloud-init
  (2m 05s) done, …`. A changed detail of the running step is one more
  line, printed only when it changes:
  `14:33:10 · wait for cloud-init  stage modules-final`.
- **Results:** when stdout and stderr are both the terminal, the live
  lines are the ledger and the end-of-run ledger is not printed again on
  stdout. Otherwise stdout keeps it unchanged (a captured result). With
  `-o json`, stdout carries only its one document (no text summary);
  progress stays on stderr.

Offline tests assert the non-TTY lines and the final lines exactly; the
redraw is a pure function of (steps, now, width, frame), tested without a
terminal.

### 4.5 Activity line

A command that reads before it prints (`vm verify --all`, `status`,
`doctor --connect`, listings, the read and plan phase of a write) shows
that it is working: one line on **stderr**, erased before anything else is
printed, so the output is the same as without it.

- **When:** stderr is a terminal, no `-v`, no `-o json`, and the command
  is not hidden (`__complete` runs inside the shell's prompt). Nothing
  appears for the first 400 ms, so quick commands never flicker. Then the
  line is redrawn about ten times a second, as in §4.4: spinner, command
  path, elapsed time and the latest detail
  (`⠹ vm verify  12s  4/7 done, waiting on naboo, hoth`), cut to the
  terminal width. Without concurrency there is no ticker and nothing is
  drawn. Without a terminal (pipes, logs, agents), with `-v` or with
  `-o json`, nothing is written and output is unchanged byte for byte.
- **Central:** dispatch starts it for every command; commands only add
  details. The line ends for good at the first output — the first bytes
  that reach stdout or stderr, or any flush (a plan before its question, a
  prompt, §4.4's step lines, an error) — and is erased (`\r` plus clear
  line) before that output; nothing stays in scrollback. A command that
  gives the terminal to a child process (`vm ssh`'s `exec`, `vm cp`'s scp)
  ends it first.
- **Details:** `vm verify --all` and `status` count finished guests or
  sections and name the ones still running (`3/5 done, waiting on edge,
  tunnel`); `doctor --connect` names the API being probed; other commands
  show only the path and elapsed time. Details from concurrent tasks are
  serialized.

Offline tests: the drawn line is a pure function of (path, detail,
seconds, frame, width); the end-on-output writers are asserted exactly
(erase before the first bytes, nothing when never drawn); the counter's
detail text is checked.

## 5. Configuration

`~/.artoo/config.json` (dir 0700, file 0600) holds non-secret settings
only: `"schema_version": 1` and one object per section. Absent keys take
their defaults; unknown keys are refused. `config init` writes every key
with its default:

| Key | Default | Meaning |
| --- | --- | --- |
| `output.format` | `table` | default output format (`table`, `json`) |
| `output.color` | `auto` | color policy (§3.1) |
| `credentials.store` | `auto` | secret store backend (§6) |
| `pve.endpoint` | `https://pve.home.arpa:8006` | Proxmox API base URL |
| `pve.node` | `pve` | Proxmox node name |
| `pve.token_id` | `artoo@pve!cli` | API token ID (§7) |
| `pve.ca_bundle` | `~/.artoo/tls/rootCA.pem` | CA bundle (PEM) for TLS verification |
| `pve.timeout_seconds` | `15` | per-request deadline |
| `pve.ssh_host` | `192.168.1.10` | Proxmox address for root SSH |
| `pve.ssh_identity` | `~/.ssh/id_ed25519` | SSH private key for root on Proxmox |
| `unifi.endpoint` | `https://unifi.home.arpa/proxy/network/integration` | Integration API base URL |
| `unifi.site` | `default` | site (internal reference) |
| `unifi.ca_bundle` | `~/.artoo/tls/rootCA.pem` | CA bundle (PEM) for TLS verification |
| `unifi.timeout_seconds` | `10` | per-request deadline |
| `cloudflare.zone` | `example.com` | the zone artoo manages (§14) |
| `cloudflare.tunnel` | `lab` | the lab's Cloudflare Tunnel |
| `cloudflare.timeout_seconds` | `10` | per-request deadline |
| `tailscale.client_id` | empty | the OAuth client's ID (§17); while empty, the Tailscale integrations are off, whatever the store holds |
| `tailscale.tailnet` | `-` | `-` (the client's own tailnet) or a tailnet ID: one URL path segment of letters, digits, `.`, `_`, `-`, `@` |
| `tailscale.timeout_seconds` | `10` | per-request deadline |
| `tailscale.guest_tags` | `tag:lab-guest` | the tags `ts join` may give guests, comma-separated, the first the default (never `tag:lab-router`) |
| `tailscale.policy_client_id` | empty | the separate policy-writing client's ID, used by `ts policy apply` alone (§17) |
| `guests.domain` | `lab.example.com` | DNS domain for guest names |
| `guests.template` | `ubuntu-2604` | default template |
| `guests.ssh_public_key` | `~/.ssh/id_ed25519.pub` | public key installed for the guest user; artoo logs in with it |
| `guests.extra_ssh_keys` | empty | more public key files for the guest user, comma-separated (below) |
| `guests.address_pool` | `192.168.1.200-192.168.1.254` | static guest addresses (§9.5) |
| `guests.gateway` | `192.168.1.1/24` | guests' gateway and DNS server, with prefix |
| `guests.user` | `artoo` | the account on every guest (below) |
| `guests.reserved_names` | empty | comma-separated DNS labels: the lab's own host and equipment names, never a guest name and never published (§9.1, §9.6) |
| `guests.fence_allow_out` | empty | fenced guests' outbound exceptions, `VM PEER PROTO PORTS` entries separated by `;` (§9.11) |
| `guests.snapshot_keep` | `2` | 1–10: artoo-owned snapshots (`artoo-…`) a guest may hold; `--snapshot` refuses at the cap, `vm snap prune` keeps this many (§9.16) |
| `guests.snapshot_max_age_days` | `14` | 1–365: an older artoo-owned snapshot is a warning in `status`, `vm verify` and `vm snap ls`, and `vm snap prune` selects it (§9.16) |
| `rex.channel` | `preview` | Rex's apt suite: `preview`, `snapshot` or `stable` (§18.2) |
| `rex.default` | `false` | `vm new` sets up Rex on ordinary guests (§18.2) |
| `agents.profile` | empty | the agent profile's directory on the workstation; empty: none (§18.5) |

- `guests.user` is the account `vm new` creates on every guest: SSH key
  login, `sudo` with a generated password kept in the secret store as
  `guest/<name>` (§6, §9.1); `vm ssh` and `vm cp` log in as it. It is a
  Linux user name: lowercase letter first, then lowercase letters, digits,
  `_` or `-`, at most 32 characters, never `root`.
- `guests.extra_ssh_keys` names the other machines that log in (a second
  device, the Proxmox host); `vm new` installs them beside
  `guests.ssh_public_key`. Each file holds one OpenSSH public key line; a
  private key is refused without echoing it. The `vm new` plan lists them
  by comment ("more SSH keys"); `doctor` checks they are readable.
  Existing guests are unchanged (cloud-init applies keys once).

`config show` prints an empty value as `--`.

There are no profiles: the lab has one Proxmox host and one gateway.
`config set` validates keys and types against the schema. Writes are
atomic (unique temp file in the same directory, fsync, rename; lock file)
and refuse symlinked destinations. `config edit` opens a private copy
of the file in `$VISUAL` or `$EDITOR` (default `vi`); the file is
replaced only when the edited copy is a valid config. An unchanged copy
is deleted ("No changes."); an invalid one, or one left by a failed
editor, is kept and its path printed (exit 2), so no edit is lost. There is no migration: a file with another
`schema_version` is refused, and `config init` writes a fresh file and
refuses to overwrite an existing one.

## 6. Credentials

Secret kinds:

| Name | Holds |
| --- | --- |
| `pve` | Proxmox API token secret |
| `unifi` | UniFi API key |
| `cloudflare` | Cloudflare API token: `example.com` DNS + the account's tunnels (§14) |
| `tailscale` | the tailnet's OAuth client secret, `tskey-client-…` (§17) |
| `tailscale-policy` | optional: a second OAuth client that may write the policy, used only by `ts policy apply` (§17) |
| `guest/<name>` | the guest user's password on one guest |

One small `SecretStore` interface (`get`, `set`, `delete`, `exists`) has
backends chosen by `credentials.store` (default `auto`):

| Backend | Used by `auto` when | Storage |
| --- | --- | --- |
| `keychain` | macOS | login Keychain, service `artoo`, account = secret name, via `/usr/bin/security` |
| `secret-service` | Linux with a running Secret Service (desktop session; `secret-tool` present and answering) | GNOME Keyring / KWallet, attributes `service=artoo account=<name>` |
| `file` | Linux otherwise (headless/SSH) — or explicitly chosen anywhere | `$XDG_CONFIG_HOME/artoo/secrets.json` (default `~/.config/artoo/`), dir 0700 + file 0600 |

Rules for every backend:

- Secrets travel only over pipes/stdin to helper processes, never argv or
  environment variables. macOS reads with `security find-generic-password -w`
  (secret on stdout) and writes by feeding `add-generic-password -U … -T
  /usr/bin/security` to `security -i` on stdin. The item is owned by
  Apple's stable `security` binary, so rebuilding artoo never causes
  Keychain prompts and no code-signing identity is needed. Linux
  `secret-tool store` reads the secret from stdin.
- The `file` backend refuses to read a secrets file that is a symlink, not
  owned by the user, or group/world-accessible (as `ssh` does with keys),
  and writes it atomically with 0600.
- `auth set pve|unifi|cloudflare|tailscale|tailscale-policy` reads a
  hidden TTY prompt or `--stdin`. `tailscale` and `tailscale-policy` must
  be OAuth client secrets (`tskey-client-…`); a personal `tskey-api-…`
  token is refused. `auth status` shows the backend and which secrets are
  present without reading them; `auth rm` confirms.
- Secrets are fetched only when a request is about to be sent; never
  printed, logged, cached elsewhere, or put in error text, flags or env
  vars. The one exception is `config export`'s passphrase-sealed setup
  file (§6.1).
- Protection model: every backend protects against other user accounts,
  accidental commits/dotfile sync and (Keychain / encrypted disk) offline
  disk access; none protects against malware already running as the same
  user. The real limit is therefore **what each credential can do**: the
  Proxmox token has VM/storage administration but no host, user or
  permission administration (§7), and can be given an expiry; the
  Cloudflare token is limited to the `example.com` zone's DNS and the
  account's tunnels, ideally with an expiry and an IP filter (§14).

### 6.1 Setup transfer (`config export` / `config import`)

One file carries artoo's setup to another Mac or Linux machine — the only
exception to "secrets never leave the store" (§6).

- **Contents:** the config file as it is, the CA bundles it names
  (`pve.ca_bundle`, `unifi.ca_bundle`, once each) and the stored `pve`,
  `unifi`, `cloudflare` and `tailscale` credentials — never
  `tailscale-policy`, which is created for one policy change and revoked
  afterwards (§17). Never SSH keys, `known_hosts` or `ssh_config`: each
  machine has its own SSH key (added to Proxmox root and to
  `guests.extra_ssh_keys`).
- **`--guest-passwords`** also seals the stored `guest/<name>` password of
  every VM on Proxmox (templates skipped). The VMs are read from the API
  because the store cannot be listed on every backend, so a password left
  from a destroyed VM stays behind. VMs without a password here, or with a
  name the store does not accept, are named in the plan; duplicate names
  count once. Guest passwords add no power the file lacks without them:
  its Proxmox token already sets any guest user's password (§9.17).
- **Sealing** (`setup_file.zig`, stdlib only): Argon2id (64 MiB, 3 passes,
  one lane; tested against the reference implementation's test vector,
  because Zig 0.17 skips its own Argon2 tests) derives the key from the
  passphrase and a random 16-byte salt; XChaCha20-Poly1305 with a random
  24-byte nonce encrypts a JSON payload; the header (magic, version,
  parameters, salt, nonce) is the associated data. The file is
  ASCII-armored (`BEGIN/END ARTOO SETUP`). Reading bounds the parameters
  (1–10 passes, at most 1 GiB) before any work. A wrong passphrase and a
  changed file give the same refusal. An entry import does not know is
  refused ("unexpected entry").
- **Passphrase:** a hidden prompt (asked twice on export) or the first
  line of `--stdin`; never an argument or variable. Export requires at
  least 12 characters.
- **Export:** a plan of names only (config, CA bundles, which credentials
  are stored), confirmation, then FILE written atomically with mode 0600
  (an existing FILE needs `--force`), opened again and compared before
  success is reported. `--dry-run` writes nothing.
- **Import:** a plan per item — new, same (skipped) or different; anything
  different is replaced only with `--force`. Paths under the exporting
  machine's home become `~/…`; a `credentials.store` this system lacks
  (`keychain` off macOS, `secret-service` on macOS) becomes `auto`; both
  show in the plan. Credentials and guest passwords go to the store the
  imported config selects; a guest password reset on this machine is
  "different" and stays unless `--force`. Missing directories are created
  0700. Values are never shown or compared in the output. Import ends with
  the machine's own next steps (SSH key, `doctor --connect`).
- **Protection model:** the file is an offline copy of the lab's API
  credentials; its strength is the passphrase's. Delete it after use; for
  a machine kept long-term, a fresh Proxmox token is better still.

## 7. Proxmox access

One token, built-in roles:

- User `artoo@pve`, token `artoo@pve!cli`, **privilege separation off**.
- ACL on `/` for the user: `PVEAuditor`, `PVEVMAdmin`, `PVEDatastoreAdmin`,
  `PVESDNUser` (all built-in; present on Proxmox VE 9.2.21).
- One single-privilege custom role `ArtooFetch = Sys.AccessNetwork` on
  `/nodes/<node>`, required by `download-url` so Proxmox fetches images
  itself; among built-in roles only `Administrator` carries it. PVE ACLs
  replace rather than merge along the path, so the `/nodes/<node>` entry
  repeats the four built-in roles.
- Setup and verification: [API.md](API.md) §2 and GUIDE.md. Rotation is an
  operator-approved host change over the root SSH key, fed to
  `artoo auth set pve --stdin`.

`vm password VM` reveals a guest password only on an interactive TTY,
never in JSON. By default it copies the password to the clipboard through
the platform's helper on stdin (`pbcopy`; `wl-copy`, `xclip` or `xsel`
with a display) and refuses when none works; `--show` prints it after
confirmation. `--reset` sets a new one through the guest agent and stores
it on this machine (§9.17).

A guest agent request (`agent/exec` arguments and input, an
`agent/file-read` path) holding a non-ASCII byte is refused before it is
sent (exit 5, "nothing was sent"): Proxmox would leave the agent stuck
until the VM restarts (API.md §2). Every script artoo runs in a guest is
plain ASCII.

## 8. Transport and mutation pipeline

### 8.1 HTTP

One transport for every API (`std.http.Client`):

- **TLS:** hostname always verified. An API with a CA bundle in config
  (`pve.ca_bundle`, `unifi.ca_bundle`) is verified against that bundle
  only (`now` pinned so the stdlib never replaces it with the system
  roots). The APIs without one — Cloudflare (§14), GitHub (§16) and
  Tailscale (§17), the public endpoints — are verified against the
  operating system's root store (`std.crypto.Certificate.Bundle.rescan`),
  never the mkcert root.
- **Redirects** are refused (exit 4), except that `artoo update` takes
  GitHub's download redirects back and follows them under its own policy
  (§16). Requests send `accept-encoding: identity`.
- **No connection reuse.** The pool is disabled (`free_size = 0`) and
  requests are not keep-alive; every request opens a fresh connection. pveproxy closes idle connections after
  5 s, and the stdlib would reuse the dead socket and lose the response.
  Cost: one LAN TLS handshake per request.
- **Every request has a deadline** covering connect, send and receive. The
  attempt runs as a concurrent task raced against a sleep in an
  `Io.Select`; on expiry the attempt is canceled and `Io.Threaded`
  interrupts the blocked syscall with `SIG.IO`. Zig 0.17's `Io.Threaded`
  panics on a timed `connect`, so connect options carry no timeout. Bodies
  are size-capped while streaming, not after.
- **Retries:** GETs retry transport failures and 5xx with bounded backoff.
  Writes are sent **once**: a failure before any byte is sent → exit 4;
  any failure after sending (no head, body read error, timeout, malformed
  2xx) → exit 7 "unknown", with the UPID if one was parsed and the
  inspection command to run.
- **Typed decoding:** API responses parse into Zig structs
  (`ignore_unknown_fields`), tolerating PVE's number-as-string fields;
  outbound bodies are built from typed values and form/URL-encoded.

### 8.2 Pipeline

Every mutation of a lab API (Proxmox, UniFi, Cloudflare, Tailscale) runs
the same executor; `artoo update` follows the same steps on its own
(§16):

1. Parse and validate locally.
2. Resolve and **read** the target (identity, state, config digest).
3. Build a typed plan; refuse no-ops (exit 5).
4. Render the preview; `--dry-run` stops here (exit 0).
5. Confirm (§3.4).
6. **Re-read** the target when the prompt took 3 s or more; abort
   (exit 5, nothing sent) if identity or digest changed.
7. Send once (config PUTs carry the `digest`).
8. Track: PVE UPIDs are polled with a deadline; `stopped` with `OK` or
   `WARNINGS: n` is success (warnings shown); anything else is failure (6).
   A poll error after submission reports "submitted, outcome unknown" with
   the task handle (7).
9. Verify the intended state with a fresh read; failure to confirm → 8.

Multi-step workflows (`vm new`, `vm rm`, `template build`, … §4.4) print a
step ledger (done / failed / not run / unknown) and never auto-destroy to
compensate; re-running a workflow continues safely from observed state
where that is defined (§9.3).

## 9. Guests and provisioning

### 9.1 Guest baseline

- **Image:** Ubuntu Server LTS cloud image (26.04), pinned build and
  SHA-256 (§9.2). Existing guests never change when the pin or the
  payload advances.
- **User** `guests.user` (default `artoo`, §5): SSH key login only
  (`guests.ssh_public_key`, `~/.ssh/id_ed25519.pub`, plus
  `guests.extra_ssh_keys`), `PasswordAuthentication no`, root login
  disabled.
- **sudo asks for a password.** The vendor drop-in
  `/etc/sudoers.d/99-artoo-sudo-password` overrides cloud-init's
  `NOPASSWD` rule (sudoers applies the last match). The password is
  unique per guest, generated by artoo, stored in the secret store
  (`guest/<name>`), and sent to Proxmox only as a SHA-512 crypt hash in
  the native `cipassword` field (PVE 9.2 keeps a pre-hashed value
  unchanged and masks it on every read, `PVE/API2/Qemu.pm`). The
  plaintext never leaves the workstation.
- **Shell and tools:** the embedded payload in `src/guest/payload/` (fish
  as default shell with helper functions, tmux, Vim, starship) and the
  package list in its README; `qemu-guest-agent`; Tailscale installed but
  **not enrolled**, from its apt repository for the image's release, with
  the signing key embedded (`src/guest/tailscale.asc`, fingerprint
  `2596A99EAAB33821893C0A79458CA832957F5868`), not fetched at boot;
  Grafana Alloy at its pin from Grafana's repository (key embedded,
  §9.9), held off by its drop-in until `watch enroll`.
- **Ghostty terminfo, system-wide.** Ubuntu/Debian `ncurses-term` 6.5
  names the entry only `ghostty`, so with Ghostty's `TERM=xterm-ghostty`
  every curses program fails ("unknown terminal"). The payload's
  `terminfo/xterm-ghostty.terminfo` (Ghostty's `infocmp -x`) is written
  to `/usr/local/share/artoo/xterm-ghostty.terminfo` and compiled **as
  root** with `tic -x -o /etc/terminfo`, searched by every user including
  root (`sudo`, `sudo -i`, pagers); never per-user `~/.terminfo`. It runs
  from vendor-data `bootcmd` (once per instance via `cloud-init-per`),
  before package installs; the source stays for rebuilds. Ghostty's
  client-side `ssh-terminfo`/`ssh-env` are not relied on (interactive
  shells only).
- **Static address on 26.04.** The image's dracut initramfs DHCPs every
  NIC, and an up NIC cannot be renamed to Proxmox's `eth0`, so the static
  configuration would never apply. Vendor-data drops networking from the
  initramfs (`/etc/dracut.conf.d/90-artoo-no-initrd-network.conf`;
  `dracut -f` in `runcmd`, running kernel only, because a cloud-init run
  as a new instance (§9.18) finds older kernels' boot directories gone
  and `--regenerate-all` fails on them) and runs `netplan apply` once on
  the first boot. That boot pays cloud-init's 2-minute wait-online
  timeout; `vm verify` counts the rename/wait-online messages cloud-init
  records as handled.
- **Security updates, never a reboot.** The image's
  `unattended-upgrades` (on by default, daily timers, the release and
  `-security` pockets) is made explicit by
  `/etc/apt/apt.conf.d/52artoo-unattended-upgrades`: periodic update and
  upgrade on; Tailscale's repository added
  (`origin=Tailscale,codename=${distro_codename}`; its `Release` has no
  suite); `Automatic-Reboot "false"`; unused kernels removed. Pinned
  packages stay pinned (Alloy, the watchdog's stack: apt preferences,
  §9.9). Bug fixes from `-updates` are not installed unattended:
  `vm verify` counts them, `vm upgrade VM` installs them (§9.12). A
  reboot is the operator's: `vm verify` and `status` show a pending one
  (`/run/reboot-required`, with `.pkgs`), `vm reboot VM` does it. Every
  fresh guest has one pending (first boot's upgrade installs a newer
  kernel), which `vm new` handles (§9.3).
- **First-boot unit failure cleared.** The wait-online timeout leaves
  `systemd-networkd-wait-online` failed, which would fire the watchdog's
  failed-unit alert; the final `runcmd` resets it (`systemctl
  reset-failed`, tolerant of a unit that did not fail).
- **No firmware refresh.** A guest's firmware is QEMU's, updated on the
  host (`pve-qemu-kvm`, `pve-edk2-firmware`, microcode); fwupd in a VM
  finds nothing, yet `fwupd-refresh.timer` fetches LVFS metadata hourly
  and fails whenever the CDN stalls. `runcmd` stops the timer, then masks
  it so an upgrade cannot re-enable it (`mask --now` on a running timer
  leaves it failed, "Unit to trigger vanished"). The package stays:
  `ubuntu-server` depends on it.
- **Unique per guest:** machine-id, SSH host keys, password. Templates
  and payload hold nothing secret or identity-bearing.
- **Sizes** (vCPU / RAM GiB / disk GiB): `tiny` 1/1/20, `small` 2/2/20
  (default), `medium` 2/4/40, `large` 4/8/80, `xlarge` 8/16/160;
  `--cores`, `--memory`, `--disk` override (§9.3). The presets start at
  20 GiB (about 4 GiB used after first boot); a `--disk` no larger than
  the template's disk leaves it as it is (disks only grow). RAM, not vCPUs, bounds
  how many guests Proxmox holds.
- **Names:** one lowercase DNS label: letter first; letters, digits and
  single hyphens, none at the end; 2–40 characters. Without NAME,
  `vm new` picks a random free name from artoo's curated list (Star Wars
  planets and moons, Lord of the Rings places; `src/guest/names.zig`):
  no VM, DNS record or UniFi client record uses it, and it is never
  protected. Any other valid label may be given; protected names (§9.6,
  including `guests.reserved_names`) are always refused. `vm rm` frees a
  name (it clears the DNS record, client record and pinned host key).
  Purpose is not in the name: `vm new --role ROLE` tags the VM
  `role-ROLE`, and service names (§9.6) say what a service is. FQDN
  `<name>.lab.example.com` (§9.6). The hostname is the VM name; a static
  guest sends no DHCP hostname, so artoo gives it a UniFi client record
  under that name (§9.5).

### 9.2 Templates

A template is named after its image pin (`ubuntu-2604`; pins in
`src/guest/image.zig`: release, build, URL, SHA-256 and size from the
release's `SHA256SUMS`, whose signature is checked against Ubuntu's
cloud-image key when pinning). `template build ubuntu-2604` is
API-driven except for the snippet, runs only the steps the observed
state needs, and prints a step ledger:

1. **Image on Proxmox:** `image fetch` has Proxmox download it
   (`POST /nodes/{node}/storage/local/download-url`, `content=import`,
   `checksum-algorithm=sha256` + pinned checksum), so Proxmox verifies
   the SHA-256 before keeping it; no image is stored on the workstation.
   Target: storage `local` (`/var/lib/vz`, dataset `rpool/var-lib-vz`,
   content type *Import* enabled) → `/var/lib/vz/import/`. PVE 9.2
   accepts only `.qcow2|.raw|.vmdk|.ova` there (`PVE/Storage.pm`), so
   Ubuntu's `.img` (qcow2) is saved as
   `ubuntu-<release>-<build>-amd64.qcow2`. A file with the pinned name
   and size is reused; another size is refused (`image rm` first).
2. **Vendor-data snippet**, shared by all guests (`src/guest/vendor.zig`:
   payload, packages, Tailscale repository, sudo/sshd drop-ins; secret-
   and identity-free). Its name is content-addressed
   (`local:snippets/artoo-vendor-<first 12 hex of SHA-256>.yaml`), so a
   changed payload is a new file and existing guests never see a
   changed one; `template vendor` prints the exact
   document. Proxmox's upload API does not accept snippets, so this one
   file goes over root SSH (`pve.ssh_host`, `pve.ssh_identity`;
   BatchMode, strict host keys, fixed remote script, content on stdin).
   Written only if absent, never replaced; a present file is checked by
   its SHA-256.
3. **Create the VM** (lowest free VMID ≥ 9000, or `--id`) from the
   imported disk: `scsi0: local-zfs:0,import-from=local:import/<file>`
   (virtio-scsi single, iothread, discard, ssd), `ide2:
   local-zfs:cloudinit`, `q35`, `cpu: host`, 1 core, 1 GiB,
   `agent: enabled=1,fstrim_cloned_disks=1`, `serial0: socket` +
   `vga: serial0`, `net0: virtio,bridge=vmbr0`, `cicustom:
   vendor=<snippet>`, tag `artoo-template`; the description records
   image file, SHA-256 and snippet name.
4. **Convert to template.**

A template already built from the same image only gets the current
snippet (`cicustom` + description, digest-guarded); an unconverted VM
left by an interrupted build is converted; a template from another image
or a VM without the tag is refused (`template rm` first). `template rm`
removes the template and its disks; image and snippet stay (guests
reference the snippet). Templates are found by name and tag at run time;
no server IDs are stored in the repository.

### 9.3 `vm new [NAME]`

1. **Validate** locally: NAME (or pick one, §9.1), the size and its
   overrides (`--cores` 1–64, `--memory` at least 512 MiB, `--disk`
   4–4096 GiB), `--id` 100–999999999, `--role` one DNS label.
2. **Read:** the template (tagged `artoo-template`, with its vendor
   snippet present on Proxmox), a free VMID (lowest free ≥ 200, or `--id`,
   refused when taken), free space on `local-zfs`, the address (§9.5),
   the guests' network on UniFi, no other VM and no DNS record with that
   name, and the watchdog (a VM tagged `role-watch`) to enroll with.
3. **Plan + confirm**, one confirmation for the whole workflow.
4. **Steps**, in this order, each only when the observed state needs it:

   | Step | Does |
   | --- | --- |
   | generate password | a new password stored as `guest/<name>` (§6); only its SHA-512 crypt hash goes on |
   | clone template | full clone of the template to the VMID, task tracked |
   | configure cloud-init | one digest-guarded PUT: `cores`, `memory`, `ciuser=<guests.user>`, `cipassword=<hash>`, `sshkeys`, `ipconfig0` (static address, gateway), `nameserver` (the gateway), `searchdomain=<guests.domain>`, the template's `cicustom` (`vendor=local:snippets/artoo-vendor-<rev>.yaml`), tags `artoo` (+ `role-ROLE`, `ssh-jump`, `no-watch`) |
   | reserve address | the UniFi client record for the clone's `net0` MAC: name and Fixed IP (§9.5) |
   | resize disk | `scsi0` to the size, when larger than the template's |
   | start VM | task tracked |
   | wait for guest agent | always |
   | wait for cloud-init | always; `cloud-init status` polled through the guest agent (§4.4), bounded |
   | reboot for updates | always checked: when `/run/reboot-required` exists (§9.1), the guest, not in service yet, is rebooted through Proxmox (`status/reboot`, task tracked); after the agent answers again the request must be gone (`/run` is a tmpfs), else the step fails. Without a request it is skipped, "not needed". The second boot also proves the static address without the initramfs network (§9.1) |
   | pin SSH host key | always: `/etc/ssh/ssh_host_ed25519_key.pub` read through the guest agent (an authenticated channel) into `~/.artoo/known_hosts` under the VM name (`HostKeyAlias`), so SSH is strict from the first connection |
   | update ssh config | when `~/.artoo/ssh_config` exists: the guest's block (§9.10) |
   | add DNS record | `<name>.<guests.domain>` → address on UniFi (§10.3), unless `--no-dns` or the record already points there |
   | enroll in watch | when a watchdog exists and the guest is not tagged `no-watch` or the watchdog itself (§9.9) |
   | set up Rex | with `--rex`, or `rex.default` true and no `--no-rex`: `rex setup`'s steps (§18.3) in one step; its checks join step 5's |

   The address is reserved after the clone (the MAC exists only then)
   and always before the first start. `--rex` with `--role` or with
   `--no-rex` is a usage error (exit 2); with `rex.default` true a
   `--role` guest gets no Rex (§18.1). With Rex, the agent profile is
   loaded and checked in step 2, so a refused profile (§18.5) refuses
   before anything is created.
5. **Verify** with `vm verify`'s checks (§9.4) and print the ledger,
   the checks and the result: name, VMID, address, FQDN, the SSH command,
   and the pinned host key as one known_hosts line
   (`NAME,FQDN,ADDRESS ssh-ed25519 …`) for the other machines in
   `guests.extra_ssh_keys`.

Public exposure is never part of `vm new`: it is per service (§9.6).
Steps stop at the first failure and nothing is undone, with two
exceptions that are recorded and let the workflow go on, so the guest
can be inspected: a failed or degraded cloud-init, and a failed ssh
config update (`vm ssh-config` repairs it). A failed step or check
exits 8. Re-running `vm new NAME` on a VM artoo created (tag `artoo` and
a stored `guest/<name>`) continues: it configures again when `ciuser`,
`cipassword` or the static address is missing, resizes a smaller disk,
starts a stopped VM, reserves a missing client record (refused while
another client holds the address, §9.5; a record with another name or
Fixed IP is refused), adds a missing DNS record (one pointing elsewhere
is refused), and always runs the agent, cloud-init, reboot and host key
steps. Any other VM of that name is refused.

`vm rm VM` (destructive, typed confirmation) runs these steps, each only
when there is something to remove, stopping at the first failure:

| Step | Does |
| --- | --- |
| stop VM | forced stop, when running |
| destroy VM and disks | `DELETE …?purge=1&destroy-unreferenced-disks=1`, snapshots included |
| forget client record | UniFi's record for the VM's MAC, only when it carries the VM's name (§9.5) |
| remove DNS record | `<name>.<guests.domain>`, only when it points at the VM's static address; never with `--keep-dns` |
| delete Keychain password | the stored `guest/<name>` |
| forget SSH host key | its entry in `~/.artoo/known_hosts` |
| remove from ssh config | its block in `~/.artoo/ssh_config` |
| remove Rex host | its Rex host on the workstation, when `~/.artoo/rex-hosts.json` records it (§18.9); skipped with a note without a running Rex; its failure fails only this step |
| forget in watch | its metrics on a running watchdog, so alerts about it resolve (§9.9) |
| remove from the tailnet | its device, when it is a lab device (§17) |

Refused before planning: a template (`template rm`), a VM with
`protection` set (`vm set VM protection=no` first; checked before the
forced stop, since Proxmox would refuse only the destroy), and a VM that
service routes (§9.6) point at, listing them (`svc set` or `svc rm`
first). A record that is not the VM's (another name, another address, a
device that is not a lab device) is kept and named in the plan, as is a
part that could not be read (UniFi, the edge VM, a stopped watchdog, the
tailnet), with the command to finish by hand where there is one
(`watch forget`, `ts device rm`). Verify: the VMID is gone,
and so are the forgotten client record and tailnet device.

### 9.4 `vm verify VM`

Read-only; commands through the guest agent need
`VM.GuestAgent.Unrestricted` (in `PVEVMAdmin`). Each check reports ok,
warning, failed or not checked; a check that does not hold fails unless
the last column says otherwise. Any failure → exit 8.

| Check | Holds when | Warning or not checked |
| --- | --- | --- |
| VM, agent | VM running; guest agent responding | |
| cloud-init | done, not degraded | |
| hostname | hostname and FQDN are the VM's | |
| user account | the guest user's shell is fish; its home and the payload files are owned by it | |
| sudo, sshd | `sudo -n` refused for the guest user; `sshd -T` shows no root and no password login | |
| Ghostty terminfo | `infocmp -x xterm-ghostty` succeeds as the guest user **and** as root, from `/etc/terminfo`; `tput -T xterm-ghostty colors` prints 256 | |
| tools | baseline tools present | |
| Tailscale | installed, not enrolled. Tagged `tailnet` (§9.6): a tagged node, no accepted or advertised routes, no exit node, no Tailscale SSH (the tag on the edge or watchdog fails). Edge and watchdog: absent (§9.7, §9.9). Router: §9.8 | warning: a `tailnet` guest not enrolled yet |
| unattended updates | periodic upgrade on, `-security` allowed, daily timer enabled, no automatic reboot; the detail gives the last run | warning: no Tailscale origin where Tailscale is installed (an older baseline); a last run older than 2 days (the timer fires daily and catches up after downtime, so apt's daily job quits before it upgrades, as it does silently while `apt-get check` fails) |
| pending updates | §9.12's simulation on the current package lists, nothing refreshed or installed; other updates counted in the detail, phased ones not. Fails on packages an interrupted dpkg left unfinished, naming them and `sudo dpkg --configure -a` (they stop apt's daily refresh and unattended upgrades) | warning: security updates waiting, naming them and `vm upgrade VM` (the unattended run installs them within a day, so one that stays is the updater falling behind); lists older than 2 days (apt's daily refresh is not getting through), naming `sudo systemctl start apt-daily.service` on the guest |
| reboot pending | none | warning, with the packages that want it |
| config pending | no Proxmox keys waiting for a restart (§9.13) | warning |
| Rex | on a guest tagged `rex`: `rex status`'s checks (§18.7), the agent rows excepted | not checked without an answering agent |
| Alloy | enrolled and running (§9.9) | not checked without a `role-watch` VM, on the watchdog itself, or on a guest tagged `no-watch` |
| fence | §9.11, on a guest tagged `fenced` | warning: the datacenter firewall is off; not checked on a guest that is not fenced |
| snapshots | the VM's snapshots can be read; the detail counts them (and artoo's) | warning: an artoo-owned snapshot older than `guests.snapshot_max_age_days`, naming `vm snap prune VM` (§9.16) |
| SSH key login | from the workstation, strict host key keyed by VM name | |
| client record | UniFi record for the VM's MAC, with the VM's name and its address as Fixed IP | |
| DNS record, answer | record on UniFi; `dig @<gateway>` from the workstation resolves it | not checked: the answer without `dig`, both with `--no-dns` |

`vm verify --all` checks every artoo guest (tag `artoo`, not templates)
concurrently, one task per guest with its own `Context` copy, as
`status` does (§11). It prints only what needs attention: one table
(GUEST, CHECK, STATUS, DETAIL) with a row per warning or failure, the
guest named on its first row only (a guest that could not be checked is
one failed row, CHECK `verify`); then the guests with nothing to report
on one line (`✓ Nothing to report: …`, or `✓ All checks ok: …` when that
is every guest); then the summary line. `--full` (only with `--all`)
prints one block per guest with every check instead; one guest always
shows every check. Any failure in any guest → exit 8. `-o json` is a
list of `{vm, vmid, checks}` with every check, whatever `--full`.

### 9.5 Addressing

Guests get **static addresses from a dedicated pool**
(`guests.address_pool`, e.g. `.200–.254`, outside the gateway's DHCP
range) through `ipconfig0`, **and a matching UniFi client record**.
After the clone and before the first start, artoo reads the MAC Proxmox
assigned to `net0` (stable for the VM's life) and creates the record
(`POST group/user`, [API.md](API.md) §1): name = VM name, Fixed IP = the address,
network = the classic network whose subnet is `guests.gateway`. UniFi
matches clients by MAC, so the guest appears under its name and the
address stays reserved for the next `vm new` even while the guest is
off. The address is the lowest pool address with no Fixed IP on any
client record (offline ones included), no connected client, no DNS
record and no VM config claiming it.

`vm rm` forgets the record (`forget-sta`) after the VM is destroyed,
only when the record carries the VM's MAC and name. UniFi keeps a
destroyed guest's MAC as a connected client on its address for several
minutes (about 10 on Network 11.0.103), and meanwhile refuses a Fixed IP
on that address for another MAC with a bare `api.err.Invalid`;
forgetting the record does not end it. So a rebuild on the same address
waits: `vm rm`'s plan says so when the record has a Fixed IP, and
`vm new` (when it continues a guest whose record is missing, and when
the reservation is refused) names the other client holding the address
(another record's Fixed IP, or a connected client) and refuses until it
is gone.

`--no-dns` skips only the DNS record. The guest stays static: no DHCP,
no change to the first-boot network handling (§9.1). The Integration API
offers no reservations; the classic calls live only in
`src/unifi/classic.zig`.

### 9.6 Names, HTTPS and exposure

- **Two kinds of names**, one label each, no overlap:
  **machine names** `<vm>.lab.example.com` → the guest (UniFi A record
  made by `vm new`, §9.3), for SSH and anything addressed to the
  machine; **service names** `<service>.apps.lab.example.com` → the edge
  VM, which proxies HTTPS to the guest running the service, so a service
  can move without renaming. Public names for public services: §14.
  Infrastructure keeps `home.arpa` (`pve.home.arpa`, `unifi.home.arpa`).
- **LAN resolution:** UniFi DNS-policy A records answer LAN lookups for
  both kinds (§10.3). Private names never enter public DNS.
- **HTTPS:** the always-on **Caddy edge VM** (§9.7) holds the Let's
  Encrypt DNS-01 wildcard `*.apps.lab.example.com` with its own DNS-edit
  token (not artoo's) and routes service names to guests. Only the
  wildcard is ever requested: certificates land in public CT logs, so no
  service or machine name is published. The transient
  `_acme-challenge.apps.lab.example.com` TXT record (made and removed by
  Caddy) is the only public record under `lab.example.com`. Machine
  names get no public certificate.
- **Remote access is Tailscale only:** remote SSH and private access
  through a subnet router (§9.8) plus split DNS for `lab.example.com`.
  Tailnet ACL, subnet-router and enrollment changes are separate
  approvals. A guest joins the tailnet itself only when the operator tags
  it `tailnet` (`vm set NAME tags=…,tailnet`), for a program that
  identifies callers by their tailnet login: a tagged node,
  `--accept-routes=false`, no advertised routes, no Tailscale SSH,
  reachable only on the ports the tailnet policy grants. `ts join VM`
  enrolls it with a single-use key artoo creates and never shows (§17).
  Every other guest stays installed but not enrolled (§9.1); `vm verify`
  holds both (§9.4). Never the edge or the watchdog (§9.7, §9.9).
- **Public access is per service:** `vm new` → `svc add` →
  `cf tunnel route add HOST SERVICE`, each its own plan, through
  **Cloudflare Tunnel** (Tailscale Funnel serves only `ts.net` names);
  artoo manages the tunnel route and public record (§14).
- **Hard rule: Proxmox and UniFi are never publicly exposed**: no public
  DNS record, tunnel route, Funnel or edge route to them, by name or
  address; remote access only via Tailscale with tight ACLs. Every
  Cloudflare, edge or public operation refuses those targets, with no
  override. The protected set is derived from configuration
  (`src/exposure.zig`), never hard-coded per lab:
  - **names:** `pve`, `proxmox`, `unifi`, `gateway`; `pve.node`; the
    first label of the host in `pve.endpoint` and `unifi.endpoint`, and
    of `pve.ssh_host` when it is a name; every label in
    `guests.reserved_names`. Any label of a name counts
    (`pve.lab.example.com` is refused);
  - **addresses:** `pve.ssh_host` and the endpoint hosts when they are
    IPv4 literals, and the address of `guests.gateway` (e.g.
    `192.168.1.10`, `192.168.1.1`).

  Protected guest names are refused, and `vm new` never picks one
  (§9.1). Proxmox's and UniFi's HTTPS stays on the mkcert CA: a public
  certificate would publish their names in CT logs.

**Service names: `artoo svc`.** No local state; a service is two halves
that artoo keeps together:

- a **route file** `/etc/caddy/services/<name>.caddy` on the edge VM
  (§9.7), written through the guest agent, which records the upstream:

  ```caddyfile
  # artoo service grafana -> naboo:3000
  @svc-grafana host grafana.apps.lab.example.com
  handle @svc-grafana {
      reverse_proxy naboo.lab.example.com:3000
  }
  ```

  The upstream is the guest's **machine name**, plain HTTP: Caddy
  resolves it through UniFi, so a rebuilt guest at a new address keeps
  working, and the edge firewall still limits it to the guest pool;
- a **UniFi A record** `<name>.apps.lab.example.com` → the edge VM's
  address, one per service (visible in `dns ls`; unknown names stay
  NXDOMAIN).

**Health.** For a service that answers only under a sub-path (and `404`
at `/`), the route file may name its health path and optionally a text
that means "down" in that answer: header lines right after the first, in
this order, only when set. Without them the default is `/`, no text.

```caddyfile
# artoo service search -> hoth:8080
# artoo health /v1/health
# artoo health-down "down"
@svc-search host search.apps.lab.example.com
handle @svc-search {
    reverse_proxy hoth.lab.example.com:8080
}
```

The path starts with `/`: at most 128 characters of a URL path and query
(letters, digits and `-._~/%?=&+,;:@!$'()*`; no space, `"`, `#`, `\`,
`{`, `}`). The down text is literal (not a regex), 1–64 printable ASCII
characters, no backtick; the rest of its line is the text, quotes
included. Health is not routing (Caddy proxies every path); the edge
probe (below) and the watchdog's probe (§9.9) use it.

**Commands:**

- `svc ls`: name, URL, upstream `VM:PORT`, health (path, and the down
  text when set), record and route present, and drift (a record without
  a route, a route without a record, a route to a VM that no longer
  exists). `-o json` adds `health` (always a path, `/` by default) and
  `health_down` (`null` when unset).
- `svc add NAME VM:PORT [--health PATH [--health-down TEXT]]`: route,
  then record; a half that exists and matches is kept (repairs drift).
  An existing route to the same `VM:PORT` whose health differs from the
  flags is rewritten, so `svc add` also repairs health.
- `svc set NAME VM:PORT [--health PATH [--health-down TEXT]]`: moves a
  service; route only, name and record stay.
- In both, without `--health` the route file's health is kept;
  `--health` replaces both values (`--health /` alone resets to the
  default); `--health-down` without `--health` is a usage error.
- `svc rm NAME`: record, then route; typed confirmation (`--confirm
  NAME`), as a gateway delete.
- `vm urls VM` (read-only; `vm ls` stays fast and shows only machine
  names): each service whose route points at the VM (name, port,
  `https://<name>.apps…/`) and the lab tunnel's public hosts that reach
  it (§14). Cloudflare is read only when a service matches; an
  unreadable edge VM or Cloudflare is noted and exits 8.

**Refused before planning:** NAME not a single DNS label, taken, or
protected; VM not an artoo guest (templates and the edge VM included) or
with no address in the guest pool; PORT outside 1–65535, or 22; a health
path or down text outside the rules above. The hard rule applies with no
override.

**Apply** (one script through the guest agent, the route on stdin): the
new file is written under a temporary name (`.<name>.artoo-new`), the
current route, if any, is copied to `.<name>.artoo-old`, and the new
file is moved into place. `caddy validate` (run as `caddy`, with the env
file) then checks the whole configuration with it. A rejected
configuration puts the previous file back (or removes the new one when
there was none) and reloads nothing: the step fails "rejected by caddy
validate", nothing changed (exit 6). Otherwise `systemctl reload caddy`
runs; a failed reload restores the previous file the same way and
reloads again (exit 8). On success the backup is removed. `svc rm`
moves the route aside and reloads; a failed reload puts it back.

**Verify:** the fences of fenced guests involved as planned (§9.11);
the route read back from the edge (managed by artoo, the same VM, port
and health); for `svc add`, the record read back, enabled
and pointing at the edge; Caddy's admin API (`localhost:2019`) serving
the host. Then a probe of the health path from the edge
(`curl --resolve <name>:443:127.0.0.1 https://<name><path>`). No answer
(`000`) and a proxy error (502, 503, 504) mean the service does not
answer yet: reported in the result, not a failure; so are, when a
health path is set, a non-2xx answer and a body containing the down
text. Public routes (§14) point at a service: `cloudflared` → Caddy on
`localhost` → the same route.

### 9.7 Edge VM `bespin`

The always-on guest that terminates HTTPS for service names (§9.6) and
runs the Cloudflare Tunnel connector (§14). Rebuilt from this section,
never backed up.

- **Machine:** `vm new bespin --role edge --size small --cores 1` → 1
  vCPU, 2 GiB (the Go build peaks at about 1–1.5 GiB; guests have no
  swap), 20 GiB; a fixed pool address (`--ip`); `vm set bespin
  onboot=yes`. Ubuntu security updates stay automatic; kernel reboots are
  reported, never automatic.
- **Configured through the guest agent** (root, authenticated through
  the Proxmox API; no sudo password over SSH): `artoo edge setup` writes
  the files and runs fixed, versioned scripts embedded in artoo;
  idempotent, planned and confirmed, with a step ledger.
- **Caddy, built from source and pinned:** Ubuntu's Go 1.26
  (`golang-1.26-go`, `GOTOOLCHAIN=local`: no toolchain download), `xcaddy
  v0.4.7` (`go install`), Caddy **v2.11.7** with
  `github.com/caddy-dns/cloudflare` **v0.2.4**; Go's checksum database
  verifies every module. The build must list `dns.providers.cloudflare`
  (`caddy list-modules`). Binary at `/usr/local/bin/caddy`, a `caddy`
  system user, the upstream systemd unit; Go and the build cache are
  removed afterwards. Version bumps are deliberate SPEC edits.
- **Certificate:** one Let's Encrypt wildcard `*.apps.lab.example.com`
  via DNS-01 (`dns cloudflare {env.CF_API_TOKEN}`), never an individual
  name (§9.6). Caddy's DNS propagation check is off
  (`propagation_timeout -1`, `propagation_delay 60s`): it queries the
  zone's nameservers directly, which the egress policy forbids. The site
  is served with HSTS and no `Server` header. The token is the edge's
  own: a second account API token, *Specified Domains → example.com*,
  DNS Edit + Zone Read.
- **cloudflared** from Cloudflare's signed apt repository
  (`https://pkg.cloudflare.com/cloudflared any main`; key embedded,
  fingerprint `CC94B39C77AE7342A68B89628A682D308D4E5E73`, "CloudFlare
  Software Packaging 2025"), updated with the system. It runs the
  remotely managed tunnel under artoo's sandboxed unit (`cloudflared
  --no-autoupdate tunnel run`, user `cloudflared`, token from
  `TUNNEL_TOKEN` in an `EnvironmentFile`, metrics on `localhost`).
- **Secrets live only on the edge VM.** `artoo edge secret dns` reads a
  hidden prompt and writes the DNS-01 token through the guest agent into
  `/etc/caddy/cloudflare.env` (0640 root:caddy); artoo keeps no copy, so
  a rebuild asks again. `artoo edge tunnel` creates the remotely managed
  tunnel (`cloudflare.tunnel`, default `lab`; `POST …/cfd_tunnel`,
  `config_src: cloudflare`) when missing, fetches its token
  (`GET …/cfd_tunnel/{id}/token`), writes it through the guest agent into
  `/etc/cloudflared/tunnel.env` (0640 root:cloudflared) and enables the
  unit. The token is held only in memory for that request: never
  displayed, typed, logged or stored on the workstation. Idempotent;
  verified by the tunnel's connections (`GET …/cfd_tunnel/{id}` →
  `connections`).
- **Hardening.** The tunnel is outbound only; nothing listens for the
  internet. Public traffic takes one path: `cloudflared` → Caddy on
  `localhost` → guest.
  1. **Two firewalls, one policy:** nftables in the VM, and the
     **Proxmox VE firewall on the VM's NIC** (`firewall=1`, with
     `ipfilter`/`macfilter` against spoofing), which survives root in the
     guest. `edge setup` writes it through the Proxmox API
     (`VM.Config.Network`): rules (added last to first, as Proxmox
     inserts at the top), the `ipfilter-net0` IP set with the VM's
     address, the NIC flag, then the options. The datacenter firewall
     must be enabled (`scripts/pve-firewall.sh`; host rules keep `:8006`,
     `:3128`, SSH and ping open from the LAN).
  2. **Egress allow-list:** DNS to UniFi (53); HTTPS/HTTP to the internet
     (ACME, Cloudflare API, apt) and Cloudflare's tunnel port 7844 (TCP
     and UDP); NTP; the guest pool on service ports. Everything else on
     the LAN is dropped (Proxmox, UniFi's other ports, the workstation,
     every other client). IPv6 only to `2000::/3`. MLD reports (sent at
     every boot) are allowed with the other neighbor-discovery messages,
     so the drop counters stay at 0 after a reboot.
  3. **Ingress:** HTTP/HTTPS from the LAN (e.g. `192.168.1.0/24`); **SSH
     only from Proxmox** (`pve.ssh_host`), which already controls the VM
     through the hypervisor and so adds no trust. The workstation uses
     `ssh -J root@pve <user>@bespin` (its key authenticates end to end;
     Proxmox only forwards, `AllowTcpForwarding yes`). `vm ssh` and
     `vm verify` reach VMs tagged `ssh-jump` that way.
  4. **Services sandboxed:** Caddy and `cloudflared` under their own
     users with artoo's units (the package unit runs `cloudflared` as
     root): `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
     `NoNewPrivileges`, writable paths named; Caddy keeps only
     `CAP_NET_BIND_SERVICE`. Caddy's admin API and `cloudflared` metrics
     on `localhost` only.
  5. **Less to attack:** Tailscale removed (`vm verify` checks it
     absent); Go and the build cache removed; sysctl: no forwarding, no
     redirects, reverse-path filter, `kptr_restrict`, `dmesg_restrict`,
     unprivileged BPF off.
  6. **Secrets:** files root-owned, readable only by the service's group;
     the edge DNS token optionally limited to the lab's public IP.
  7. **Updates:** unattended security updates for Ubuntu and
     `cloudflared`; `edge status` compares Caddy with its pin. Comparing
     the pins with the latest upstream releases is the operator's.
  8. **Detection:** drop rules count hits; `edge status` shows attempts
     towards Proxmox or UniFi first (sign of compromise), with failed SSH
     logins and pending reboots. Caddy logs JSON, rotated.
- **`artoo edge status`** (read-only): drop counters towards Proxmox and
  UniFi first, then Caddy version and modules (against the pin), the certificate's names and expiry, cloudflared connection
  state, both firewalls loaded, failed SSH logins, pending reboot.
- **Live acceptance:** from `bespin`, Proxmox's `:8006`/`:22`, UniFi's
  `:443` and the workstation time out (the drop counters register them)
  while `dig @<gateway>` answers; SSH from the workstation is refused
  directly and works via Proxmox; `https://<test>.apps.lab.example.com`
  serves the wildcard; a second `edge setup -n` finds nothing to change.

### 9.8 Subnet router (remote access)

Remote access to the LAN goes through Tailscale only (§9.6): a
**dedicated small guest** tagged `role-router` advertises the LAN
(`192.168.1.0/24`, from `guests.gateway`) to the tailnet. Nothing
Tailscale runs on Proxmox; the edge VM stays without Tailscale.

- **Machine:** `vm new NAME --role router --size small --cores 1`, then
  `vm set NAME onboot=yes`; Tailscale comes with the template (§9.1).
  `vm verify` on a router: Tailscale *Running* is ok, not enrolled a
  warning (expected until `router setup`).
- **`artoo router setup`** (idempotent, planned like any mutation;
  through the guest agent as root): IP forwarding
  (`/etc/sysctl.d/90-artoo-router.conf`, IPv4 and IPv6) and, when not
  yet `Running`, enrollment with a **single-use auth key** the operator
  generates (Tailscale console → Keys, tag `tag:lab-router`). The key is
  read from a hidden prompt (or `--stdin`), written through the guest
  agent to a 0600 file under `/run`, used as `tailscale up
  --auth-key=file:… --advertise-routes=<LAN>
  --advertise-tags=tag:lab-router --accept-dns=false --hostname=<vm>`,
  and removed whatever happens; never argv, stored or logged. An enrolled
  router whose advertised routes differ gets `tailscale set
  --advertise-routes`. Never an exit node, never Funnel.
- **`artoo router status`** (read-only): backend state, tailnet name,
  tags, advertised and approved (primary) routes, forwarding on, version;
  exit 8 when one fails.
- **Tailnet side** (the operator's console, not artoo): `tag:lab-router`
  owned by admins, its route auto-approved; members reach their own
  devices (all ports), Proxmox `tcp:22,8006`, UniFi `tcp:443` and DNS
  `53`, and the guest pool (all ports), nothing else on the LAN; the
  router reaches no tailnet device. **Split DNS:** `lab.example.com` and
  `home.arpa` → the gateway (`192.168.1.1`). Tagged devices' keys do not
  expire. With a Tailscale credential (§17), artoo creates the join key,
  approves the route and sets split DNS itself; the policy stays the
  operator's.
- **Live acceptance:** away from home, `pve.home.arpa:8006`, `ssh` to a
  guest by machine name and a service name resolve and answer; other LAN
  clients do not. At home the workstation still reaches the LAN on its
  own interface: a client that accepts the route could send LAN traffic
  through the tailnet, where the policy blocks other LAN clients.

### 9.9 Watchdog VM `scarif`

The watchdog is rebuilt from this section, never backed up: metrics and
logs are lost with the VM (backups are out of scope, §1).

- **Machine.** `vm new scarif --role watch --size medium --ip <fixed pool
  address>` → 2 vCPU, 4 GiB, 40 GiB; `vm set scarif onboot=yes`. Exactly
  one VM carries `role-watch`. It is configured through the guest agent
  like the edge VM (§9.7): `artoo watch setup` writes rendered files and
  runs fixed, versioned scripts embedded in artoo — idempotent, planned,
  confirmed, with a step ledger.
- **Stack, pinned** (version bumps are deliberate SPEC edits; `watch
  status` compares the installed versions with these pins only):

  | Component | Version | Source | Role |
  | --- | --- | --- | --- |
  | VictoriaMetrics single-node | v1.153.0 | GitHub release tarball, SHA-256 from its `checksums.txt` pinned in artoo (no apt repository, no signatures) | metrics, `:8428`, retention 90 days |
  | Loki | 3.7.8 | `apt.grafana.com stable main` | logs, `:3100` (gRPC `:9096` on `localhost`), filesystem/TSDB in `/var/lib/loki`, retention 31 days (compactor) |
  | Grafana OSS (`grafana`, never `grafana-enterprise`) | 13.2.3 | `apt.grafana.com` | dashboards and alert rules, `:3000` |
  | ntfy | 2.29.0 | `archive.ntfy.sh/apt stable main` | notifications, `:2586` |
  | Grafana Alloy | 1.20.1 (`1.20.1-1`) | `apt.grafana.com` | the agent on every guest, `scarif` included |

  - VictoriaMetrics' LTS lines publish enterprise binaries only, so the
    pin is a community release. `apt.grafana.com` keeps every earlier
    version, so the pins stay installable.
  - Grafana's repository key (fingerprint
    `B53AE77BADB630A683046005963FA27710458545`, valid to about 2027-08)
    and ntfy's (`55BA774A6F5EE67431E4B6B7CFDB962D4F1EC4AF`) are embedded
    in artoo, each checked with `gpg --show-keys` when embedded.
  - An apt preferences pin holds the package versions; unattended upgrades
    cover Ubuntu's security origins only.
  - VictoriaMetrics runs as user `victoriametrics` under artoo's sandboxed
    unit: the documented one plus `ProtectSystem=strict` and `MemoryMax=`
    (its `-memory.allowedPercent` sizes caches only).
  - Alerts are Grafana-managed rules querying VictoriaMetrics through the
    built-in **Prometheus** data source and Loki through the built-in Loki
    data source — no plugins, no vmalert, no Alertmanager. Grafana 13's
    bundled Prometheus data source works with plugin preinstall disabled.
- **No telemetry.** Every documented off-switch is rendered into the
  configuration and read back by `watch status`:

  | Component | Switches |
  | --- | --- |
  | Grafana (`grafana.ini`) | `[analytics] reporting_enabled = false`, `check_for_updates = false`, `check_for_plugin_updates = false`, `feedback_links_enabled = false`; `[news] news_feed_enabled = false`; `[security] disable_gravatar = true`; `[snapshots] external_enabled = false`; `[plugins] preinstall_disabled = true` (otherwise Grafana 13 installs and auto-updates six plugins from grafana.com at start), `preinstall_auto_update = false`, `plugin_admin_enabled = false`, `public_key_retrieval_disabled = true`. Google Analytics, RudderStack, PostHog and frontend logging stay at their empty/off defaults. |
  | Loki | `analytics: reporting_enabled: false` (the default sends to `stats.grafana.org`) |
  | Alloy | `CUSTOM_ARGS="--disable-reporting --server.http.disable-support-bundle"` in `/etc/default/alloy` (the default reports every 4 h) |
  | ntfy | no `firebase-key-file`, no web-push keys, `upstream-base-url: ""` (the default relays a poll request per message to ntfy.sh, which only iOS needs, below) |
  | VictoriaMetrics | documents no telemetry and no switch for it |

  - **Enforced, not only configured.** `scarif`'s nftables egress drops
    internet traffic from the service users (`grafana`, `loki`,
    `victoriametrics`, `alloy`, `ntfy`) by `meta skuid`, with a
    `telemetry` counter; only apt (root/`_apt`) goes out. A non-zero
    counter is a telemetry or update attempt: `watch status` shows it first
    and an alert fires. On **every guest** Alloy runs under a systemd
    drop-in (`IPAddressDeny=any`, private networks and `localhost`
    allowed), so it cannot reach the internet.
  - **No start before configuration.** The service users exist and the
    firewall is loaded before any package is installed (Loki's package
    starts its service on install, with usage reporting on by default);
    configs are written first and kept (`--force-confold`). Alloy's drop-in
    also holds the service until its config exists, so a template guest
    runs no Alloy until it is enrolled.
  - **No Tailscale on the watchdog** (as on the edge, §9.7): `watch setup`
    removes the template's package (a tailscaled that is not enrolled sends
    a NAT-PMP probe to the gateway at every boot).
- **Network.** Two firewalls with the same policy, as §9.7: nftables in the
  VM and the Proxmox VM firewall on its NIC.
  - Ingress: `8428` and `3100` from the guest pool and Proxmox
    (`pve.ssh_host`); `3000` and `2586` from the edge VM only (Caddy); SSH
    only from Proxmox (VM tagged `ssh-jump`); ping from the LAN. Alloy's UI
    (`12345`) and Loki's gRPC stay on `localhost`.
  - Egress: DNS to UniFi; HTTPS for apt (root only); NTP; the edge's `:443`
    for the probes below. Nothing else on the LAN.
  - Ingest has no authentication (Loki has none; Proxmox's InfluxDB
    exporter sends only a token; VictoriaMetrics' `-httpAuth.*` is Basic):
    the firewall limits writers to the guest pool and Proxmox, so a
    compromised guest can write noise, nothing else.
  - `bespin` needs no change: its egress already allows the pool on every
    TCP port but 22 (§9.7).
- **Grafana and ntfy are LAN/tailnet services** through the edge: `svc add
  grafana scarif:3000` and `svc add ntfy scarif:2586` (§9.6), served under
  the public wildcard certificate. **Never public:** `cf tunnel route add`
  refuses any service whose upstream is the `role-watch` VM (or the
  `role-search` VM, below), with no override.
  - Grafana: `root_url` = its service URL; sign-up and anonymous access off
    (the defaults, rendered explicitly).
  - ntfy: `base-url` = its service URL, `behind-proxy: true`, `auth-file`,
    `auth-default-access: deny-all`, `cache-file`, attachments off.
- **Secrets live only on `scarif`** (as §9.7); artoo keeps no copy and a
  rebuild asks again.
  - Grafana's admin password: `watch setup` gives Grafana a random one made
    on the VM (`/etc/grafana/admin_password`, 0640 root:grafana, read with
    `$__file{}` on first start), so `admin/admin` is never valid. `artoo
    watch secret grafana` (hidden prompt twice, or `--stdin`) sets the
    operator's through Grafana's CLI (`admin reset-admin-password
    --password-from-stdin`, as user `grafana`).
  - ntfy users are declarative (`NTFY_AUTH_USERS`, `NTFY_AUTH_ACCESS`,
    `NTFY_AUTH_TOKENS` in `/etc/ntfy/auth.env`, 0640 root:ntfy, read by the
    unit's drop-in): `grafana` (write-only on topic `lab`) and `phone`
    (read-only). `artoo watch secret phone` hashes the phone's password
    (12–72 characters) with bcrypt **on the workstation**; only the hash
    reaches the VM. The phone's ntfy app logs in with username and password.
  - Grafana publishes with an ntfy token (`tk_` + 29 characters) that
    `watch setup` makes **on the VM**, keeps in `/etc/grafana/ntfy.env`
    (0640 root:grafana, read by Grafana's unit as `NTFY_TOKEN`) and fills
    into `auth.env`; it never leaves the VM.
- **Alerts → phone.** One Grafana webhook contact point,
  `http://localhost:2586/lab?template=grafana` (ntfy's built-in Grafana
  template), Bearer token. The phone is on the tailnet, where split DNS and
  the policy's guest-pool rule cover the service name. The Android ntfy
  app subscribes to `lab` on the ntfy service URL with *instant delivery*,
  keeping its own connection to `scarif` — no relay, no Firebase. iOS
  would need `upstream-base-url: https://ntfy.sh` (a poll request per
  message, carrying only its ID) and the `ntfy` user's HTTPS egress; its
  app trusts no private CA, hence the public wildcard certificate.
- **Readable notifications.** ntfy's built-in template shows only the
  webhook's `title` and `message` (ntfy 2.29.0 `server/templates/grafana.yml`:
  🚨 or ✅ before `title`, `message` cut at 2000 characters), and Grafana's
  defaults fill them with every label, annotation and link. So the webhook
  sets `title` and `message` from a **Grafana notification template**
  `artoo`, provisioned in the contact point's file (it sees the rule's
  annotations and handles grouped alerts); ntfy keeps its stock
  `?template=grafana`.
  - **Title:** one alert → its `summary`; several → `<rule title>: N
    firing` (and `, M resolved`). A resolved notification is `Resolved:
    <summary>` (ntfy adds ✅).
  - **Message:** per firing alert its `summary`, its `description` and
    `since <start, UTC>`, then the resolved ones' summaries under
    `Resolved:`; nothing else (no label dump, no silence links). A repeat
    every 4 h thus says how old the problem is.
- **Removed guests are forgotten.** "Guest silent" looks back a day
  (`tlast_over_time(…[1d])`), so a removed guest would keep firing for a
  day. `vm rm` therefore ends with "forget in watch": after the destroy,
  it deletes every series with `host=<name>` from VictoriaMetrics (`POST
  /api/v1/admin/tsdb/delete_series`, enabled by default; no
  `-deleteAuthKey`) through `scarif`'s guest agent (`8428` is not open to
  the workstation), counting with `/api/v1/series?start=-3d` (without
  `start` it covers only recent minutes) before and after; none may be
  left. The alerts resolve at the next evaluation and ntfy gets the
  RESOLVED message.
  - `watch forget HOST` does the same for a guest already gone; typed
    confirmation. Refused while a VM of that name exists, and for the
    watchdog itself.
  - A stopped or unreachable watchdog is a plan note naming `watch forget`.
  - Loki keeps the guest's logs until retention (31 days); no alert reads
    them.
- **Provisioned from files**, never clicked: `/etc/grafana/provisioning/`
  `datasources/` (VictoriaMetrics, Loki; `prune: true`), `dashboards/`,
  `alerting/` (contact point, notification policy, rule groups). The files
  are the truth: data sources and dashboards whose file is gone are deleted
  (`disableDeletion: false`), and `watch setup` removes any dashboard file
  it no longer renders.
  - **One board, "Proxmox · Homelab"**, Grafana's home page
    (`default_home_dashboard_path`), read-only in the UI. Grafana's JSON is
    `src/watch/dashboards/lab.json`, generated by `scripts/gen-lab-board.py`
    (edit the generator, not the JSON). Rows:

    | Row | Panels |
    | --- | --- |
    | Overview | tiles: Proxmox CPU, memory gauge, memory used / available / ZFS ARC / total, load against the host's threads, failed units, guests running, services down, certificate days, tunnel connections, router routes, edge drops towards Proxmox/UniFi and blocked telemetry over 24 h; then a strip with one cell per service name, `up` or `down` |
    | Proxmox | CPU with I/O wait, load, memory stacked to the total, `vmbr0` traffic, storage per pool |
    | Guests | a table with inline CPU, memory and disk gauges, uptime, pending reboot; per-guest CPU, memory and network; Proxmox's view without templates |
    | Edge & router | drop counters, tunnel, probe time, certificate expiry, Tailscale traffic, Caddy upstreams |
    | Logs (folded) | errors per host, warnings per host, the error lines (guests' boot-time warnings are noise) |

  - **Services by name.** The overview counts the services down and the
    strip shows each service, named from the probe's `job` with
    `label_replace` (so series from before the probe labels count too);
    the probe-time and certificate panels are labelled by service.
  - Files larger than 45 000 bytes reach a guest in parts, because Proxmox
    caps the agent's `input-data` at 65 536 characters: the part file is
    assembled beside the target and moved into place last (shared with
    `edge` and `svc`).
- **Alert rules.** Rule uids are `artoo-…` (`artoo-pve-*` for Proxmox's).
  Alert state and history stay in Grafana and VictoriaMetrics — artoo
  stores nothing. The rules:
  - a guest's Alloy silent > 5 min; Proxmox metrics silent > 5 min;
  - root filesystem > 85 %; memory > 90 % (host and guests); Proxmox
    storage > 85 %;
  - CPU > 90 % for 15 min (host and guests): a guest's busy share of all
    its cores, `1 −` idle over 5 min, from Alloy; Proxmox's `cpustat_cpu`
    averaged over 5 min, from its export — a runaway process shows, an apt
    run or a build does not;
  - failed systemd units; **any edge drop towards Proxmox or UniFi**
    (critical); blocked telemetry; tunnel not healthy; router route not
    primary (the minimum of `artoo_tailscale_running` and
    `artoo_tailscale_routes_primary` per host); certificate expiry < 14
    days; HTTPS probe failing 5 min; pending reboot > 7 days.
  - **Three steps.** The query returns the raw value (seconds, a fraction,
    packets), B reduces it (`last`), C compares it (`gt`/`lt` the
    threshold): the value is in `$values.B` for the text, and each series
    resolves when the condition clears.
  - **Each rule says what, where, how much and what next.** Annotations:
    `summary`, one line naming the guest (`host` on Alloy's and the
    guests' series), Proxmox (`host` on `object="nodes"`), the storage
    (`host` on `object="storages"`) or the service, with the value in its
    unit (`humanizePercentage`, `humanizeDuration`, a count);
    `description`, what it means and the artoo commands to run next. As
    rendered for naboo, hoth and the search service:

    | uid | `summary` | next, in `description` |
    | --- | --- | --- |
    | `artoo-guest-silent` | naboo is silent: no metrics for 12m 5s | `vm show naboo`, `vm verify naboo`; gone: `watch forget naboo` |
    | `artoo-pve-silent` | Proxmox is silent: no metrics for 6m 2s | `host show`, `watch status` |
    | `artoo-rootfs` | naboo: root filesystem 91.2% full | `vm ssh naboo -- df -h /` |
    | `artoo-memory` | naboo: memory 94.1% used | `vm show naboo`, `vm set naboo memory=…` |
    | `artoo-pve-memory` | Proxmox pve: memory 92.3% used | `status` (which guests hold it) |
    | `artoo-cpu` | naboo: CPU 97.0% busy for 15 minutes | `vm ssh naboo`, then `top` |
    | `artoo-pve-cpu` | Proxmox pve: CPU 95.5% busy for 15 minutes | `status` |
    | `artoo-pve-storage` | Proxmox storage local-zfs: 88.0% full | `storage show local-zfs` |
    | `artoo-units` | naboo: unit nginx.service failed | `vm ssh naboo -- systemctl status nginx.service` |
    | `artoo-edge-drops` | bespin (edge) tried to reach Proxmox: possible compromise | the count; `edge status` now |
    | `artoo-telemetry` | scarif: a service tried to reach the internet | the count; `watch status` |
    | `artoo-tunnel` | Cloudflare Tunnel down: cloudflared on bespin has no connection | `edge status`, `cf tunnel ls` |
    | `artoo-router` | dagobah (router): remote access down | Tailscale not running or the LAN route not primary; `router status` |
    | `artoo-cert` | search: HTTPS certificate expires in 9d 4h 12m 3s | the edge renews it; `edge status` |
    | `artoo-probe` | search (https://search.apps.lab.example.com/v1/health) is down, probed from scarif | runs on hoth; `vm verify hoth`, `svc ls`, `edge status` |
    | `artoo-reboot` | naboo has waited 8d 2h 31m 7s for a reboot | `vm reboot naboo`; the packages: `vm verify naboo` |

- **Alloy on the guests.** The template installs the pinned `alloy`
  package (§9.1: the vendor snippet carries Grafana's repository with the
  embedded key, an apt pin and Alloy's drop-in, written before packages),
  held off until enrolled. Its config is written per guest by **`artoo
  watch enroll VM…|--all`** (guest agent, idempotent, also the one-time
  path for existing guests) and by `vm new` as a step when a `role-watch`
  VM exists. `watch enroll` orders repository files, install, config,
  start (the config's `alloy` group needs the package first). The config,
  `/etc/alloy/config.alloy`: journald (`loki.source.journal`, unit and
  priority as labels) → `loki.write`; `prometheus.exporter.unix` (systemd
  collector, artoo's fact files) → `prometheus.remote_write` to
  `http://<watch vm>.lab.example.com:8428/api/v1/write` and
  `…:3100/loki/api/v1/push`. Alloy buffers while `scarif` is down.
  `vm verify` adds "Alloy active and enrolled" (not checked when no
  `role-watch` VM exists).
- **Guests kept out: `vm new --no-watch`.** For a short-lived test guest
  (made for one test, destroyed with `vm rm` when it is done) that would
  otherwise push metrics and its journal and raise alerts. `--no-watch`
  tags it `no-watch`:
  - `vm new` skips "enroll in watch" (Alloy stays held off by its drop-in,
    §9.1, so the guest pushes nothing), and its plan says so;
  - `watch enroll --all` skips it; naming it in `watch enroll` is refused
    while it carries the tag (drop the tag with `vm set NAME tags=…` to
    enroll it later);
  - `vm verify` and `watch status` show it as not checked instead of
    failed;
  - `vm rm` still looks for its series and finds none.

  Refused with `--role watch`.
- **Fleet signals as metrics** (small systemd timers writing Prometheus
  text files for Alloy's textfile collector, plus local scrapes):

  | Guest | Signals |
  | --- | --- |
  | `bespin` (`role-edge`, rendered by `watch enroll`) | nftables drop counters per rule (towards Proxmox, UniFi, other), Caddy's metrics (admin API, `localhost:2019`), cloudflared's metrics (`localhost`); failed SSH logins come from the journal |
  | `dagobah` (`role-router`) | `tailscale status --json` → backend state, route advertised and primary |
  | the search gateway (`role-search`, below) | Alloy scrapes the gateway's own `/v1/metrics` on `localhost:8080` (job `holocron`, named after the gateway software); on the guest, so the NIC firewall needs no rule; a gateway without the endpoint shows only as a failed scrape (`up{job="holocron"}` 0) |
  | every guest | pending reboot, unattended-upgrades last run |

  - One script, `artoo-facts` (root, every minute), writes
    `/var/lib/artoo-facts/artoo.prom` on every guest: pending reboot and its
    age, the last unattended upgrade, the `artoo_edge`/`artoo_watch`
    nftables counters where present, and on a router (Tailscale with
    advertised routes) its state and number of primary routes.
  - **Probes.** `scarif` probes (Alloy's `prometheus.exporter.blackbox`)
    each service name over HTTPS through the edge (status and certificate
    expiry, trusting the public roots), taken from the edge's route files
    at `watch setup` time (a new service or a changed health: run `watch
    setup` again). The target is `https://<name>.apps.<domain><path>` with
    the service's health path (§9.6; `/` by default); success is a 2xx
    answer (blackbox's default). A service with a down text gets its own
    module, `https-<name>` (module `https` plus
    `fail_if_body_matches_regexp` with the text regex-escaped), so a 200
    that reports itself down fails the probe too (e.g. `--health
    /v1/health --health-down '"down"'` for a search gateway whose health is
    always 200 and names each provider `ok` or `down`). Public tunnel
    routes are not probed — Alloy has no internet; the tunnel's health
    comes from cloudflared's metrics.
  - **Probe labels.** A probe's series carry
    `job="integrations/blackbox/<service>"` and `host=<watchdog>` (Alloy's
    names), so the watchdog's Alloy relabels them with `service` (the
    name), `url` (the probed target) and `vm` (the route file's upstream
    guest), rendered per service at `watch setup` time like the targets;
    `host` stays the watchdog that probes. A moved service (`svc set`) gets
    its new `vm` at the next `watch setup`.
- **Proxmox.** Proxmox's built-in External Metric Server, **InfluxDB over
  HTTP** to `scarif`'s address `:8428` (organization, bucket and token
  empty — VictoriaMetrics' documented Proxmox setup); not Proxmox's
  OpenTelemetry type (it posts JSON, VictoriaMetrics expects protobuf).
  Node, guest and storage statistics every pvestatd cycle; no agent on the
  host. Creating it needs `Sys.Modify` on `/`, which artoo's token
  deliberately lacks (§7): an operator-approved host change,
  `scripts/pve-metrics.sh` run as root (`pvesh create
  /cluster/metrics/server/scarif --type influxdb --influxdbproto http
  --server <address> --port 8428`). `watch status` reads it with the token
  (`Sys.Audit`). The export's names, as VictoriaMetrics stores them:

  | Object | Series | Labels |
  | --- | --- | --- |
  | node | `cpustat_*`, `memory_*`, `blockstat_*`, `system_uptime` | `object="nodes"`, `host="pve"` |
  | guest | `system_*` (`cpu`, `mem`, `maxmem`, `uptime`, …), `blockstat_*`, `nics_*` | `object="qemu"`, `host=<VM name>`, `vmid` |
  | storage | `system_used`, `system_total`, `system_avail` | `object="storages"`, `host=<storage>` |

- **`artoo watch status`** (read-only, through the guest agent and the PVE
  API), in order: blocked telemetry and outbound counters; both firewalls;
  each component's version against its pin; services running; the
  configuration as rendered (every telemetry switch, retention, ntfy
  without relay — by file hash); the phone user; the Proxmox metric server
  present and its last sample fresh; per running artoo guest the age of
  its latest metrics and whether its journal arrived in the last 10 min
  (> 5 min silent fails); pending reboot. Exit 8 when one fails. Firing
  alerts are Grafana's (its API needs a login) and the phone's; comparing
  pins with the latest releases is a manual step when bumping them.
- **Acceptance (approved run, §13):** `watch setup` converges in one run
  and a second `-n` finds nothing; `watch status` all ok with zero blocked
  counters after 24 h; every guest and Proxmox visible in Grafana; a test
  alert reaches the operator's phone on the tailnet through Grafana → ntfy
  with no relay; Grafana and ntfy unreachable from the internet, and
  anonymous ntfy reads and publishes get 403; from `scarif`, Proxmox
  `:8006`/`:22`, UniFi `:443` and the workstation time out; after a reboot
  everything returns on its own with every drop counter at 0.
- **Search gateway (`role-search`).** One VM tagged `role-search` runs the
  lab's search gateway (e.g. holocron): an unauthenticated search and
  fetch proxy, reached on the LAN and tailnet through a service name
  (§9.6). It is **never public** — `cf tunnel route add` refuses a service
  whose VM carries `role-search`, with no override. Alloy on it scrapes
  the gateway's `/v1/metrics` (above). Its NIC fence follows the
  edge/watchdog pattern: the Proxmox VE firewall on the VM's NIC with an
  outbound allow-list, written by `vm fence` (§9.11).

### 9.10 SSH config and copies (`vm ssh-config`, `vm cp`)

These commands give plain `ssh`, `scp`, `rsync` and editors' remote
modes `vm ssh`'s strictness (§9.3, "pin SSH host key"): the keys pinned in
`~/.artoo/known_hosts` and the Proxmox jump. Both act as the guest user
(`guests.user`) only; neither writes as root nor touches Proxmox or UniFi.
Placing files as root stays with the role setup commands (§9.7, §9.9).

- **`artoo vm ssh-config`** writes `~/.artoo/ssh_config` (0600, written
  atomically like the config file, §5; a symlink is refused): one `Host`
  block per artoo guest (tag `artoo`, templates excluded), sorted by name,
  with the same settings as `vm ssh`:

  ```sshconfig
  # Written by artoo vm ssh-config; vm new and vm rm rewrite it. Do not edit.
  Host naboo naboo.lab.example.com
    HostName 192.168.1.230
    User artoo
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes
    UserKnownHostsFile ~/.artoo/known_hosts
    HostKeyAlias naboo
    StrictHostKeyChecking yes

  Host bespin bespin.lab.example.com
    HostName 192.168.1.200
    …                                  (as above, HostKeyAlias bespin)
    ProxyCommand /usr/bin/ssh -i ~/.ssh/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -W %h:%p root@192.168.1.10
  ```

  - Paths are written expanded from `$HOME`, as artoo's own SSH uses them
    (the example shortens them). `IdentityFile` is `guests.ssh_public_key`
    without `.pub`. A path with spaces or quotes is refused.
  - The patterns are the VM name and its machine name, so `ssh naboo`,
    `ssh naboo.lab.example.com`, `scp naboo:…` and `rsync naboo:…` are all
    strict.
  - `HostName` is the guest's address, found as `vm ssh` finds it: the
    static `ipconfig0` (§9.5), or the agent's address — not the machine
    name, so it works for guests made with `--no-dns` and needs no DNS.
    `HostKeyAlias` ties the host key to the VM name.
  - Guests tagged `ssh-jump` get `vm ssh`'s exact `ProxyCommand`
    (`known_hosts.zig`), built from `pve.ssh_host` and `pve.ssh_identity`,
    never `ProxyJump`, whose hop would take its settings from whatever
    config matches Proxmox (ssh(1) on `-J`). The `ProxyCommand` carries the
    identity, `IdentitiesOnly`, `BatchMode` and strict checking against
    Proxmox's key in `~/.ssh/known_hosts`.
  - A running guest with no pinned key is pinned through the guest agent
    first, as `vm ssh` does. A stopped one still gets its block (ssh
    refuses it until the key is pinned) and a note; exit 8. A guest with no
    known address is left out with a note; exit 8. So is a VM whose name
    cannot be an ssh `Host` pattern; `--repin` and `vm cp` refuse such a
    VM (exit 5).
  - **artoo never edits `~/.ssh/config`.** The operator adds one line once,
    above the first `Host` or `Match` line (an `Include` after a `Host`
    line applies only to that block, ssh_config(5)):

    ```sshconfig
    Include ~/.artoo/ssh_config
    ```

    The command checks, read-only, whether that line is in effect by
    running `ssh -G <first guest>` (it opens no connection) and looking for
    `hostkeyalias`. If it is not, the command prints the line to add.
  - **Kept current.** Once the file exists, `vm new` (a step after it
    pins the host key), `vm rm` (a step after it forgets the key), `vm
    rename` (§9.18) and `vm set` when it changes `tags` (`ssh-jump` is a
    tag; after the change, when the file has the guest's block) update
    the guest's own block, reading no other guest. Without the file none
    of them makes one. A failed update is exit 8 naming `vm ssh-config`,
    which repairs it: `vm new` records it and goes on, `vm rm` stops
    there (its later steps do not run).
  - **Output:** the path, the number of guests, `written` or `unchanged`,
    and the notes. `-n` prints the file to stdout and writes nothing (it
    pins no key either). `-o json` (target `local`) is
    `{"path", "state" (written|unchanged|dry-run), "include" (true|false,
    null when not checked), "hosts": [{"name", "vmid", "hostname" (null
    without a usable address), "jump", "pinned"}]}`, with the notes in
    `meta.notes`. No prompt: the file is artoo's own, like `known_hosts`.
  - **`--repin VM`** replaces a pinned key whose guest has new host keys
    (cloud-init starting over after `vm rename`, §9.18; a rebuilt guest).
    The key is read through the guest agent, as at first pinning (§9.3);
    the plan shows the pinned and the new SHA256 fingerprint. It
    is confirmed like any change (`-y` skips the prompt, `-n` shows the
    plan and writes nothing), then the file is rewritten as usual. A key
    equal to the pin changes nothing. Refused for a VM that is not a
    running artoo guest.

- **`artoo vm cp SRC DST [-r] [--force]`** copies one file, or one
  directory tree with `-r`, as the guest user.
  - **Sides.** A word is `VM:PATH` when it has a `:` with no `/` before it
    (scp's rule); `./a:b` is a local path. One side or both are remote; two
    local sides are refused (exit 2). `VM` is an exact name or VMID (§3.2)
    and must be a running artoo guest with a known IPv4 address. Refused
    before anything runs (exit 5): a template, a VM without the `artoo`
    tag, a VM whose name cannot be an ssh `Host`, a `user@` part, an
    `scp://` URI, and under `-n` a guest whose host key is not pinned yet
    (pinning writes; without `-n` it is pinned first). Proxmox and UniFi (the protected names and addresses,
    §9.6) are refused, with no override.
  - **Paths.** A remote `PATH` is absolute or relative to the guest user's
    home; an empty one means home. A leading `~/` is rewritten as
    home-relative, so the scp transfer and the shell checks below resolve
    the same path; `~user` is refused (exit 5). No wildcards (`*?[`): one
    source, one target, one checksum. A wildcard, or a newline, carriage
    return or NUL in a path, is a usage error (exit 2).
  - **No overwrite without `--force`.** artoo works out the target: `DST`
    itself, or `DST/<name of SRC>` when `DST` is an existing directory. It
    checks the target locally with `stat` and remotely over SSH. An
    existing target is refused (exit 5), naming the target; with `-r` an
    existing target directory too, because scp would merge into it.
    `--force` allows both. A target that exists as the other kind (a file
    where the source is a directory, or the reverse) is refused even with
    `--force`. A missing source is exit 2, a directory without `-r` too.
    The check and the copy are separate steps.
  - **The copy** runs `/usr/bin/scp -F ~/.artoo/ssh_config -p [-r] [-3] --
    SRC DST`, with VM names as hosts, as a child process with its progress
    meter on the terminal. Before it, artoo renders the blocks from the
    live VM list and rewrites the file if it differs, so a missing
    `Include` or a stale file does not matter. Missing host keys are pinned
    first, as in `vm ssh`. With `-F`, ssh reads neither `~/.ssh/config` nor
    `/etc/ssh/ssh_config`. `-p` keeps mode and times.
  - **Per-host settings come from the file, not from `-o`:** for a copy
    between two guests scp passes its options to both ssh children, so an
    `-o HostKeyAlias=…` would apply to both.
  - **Guest to guest uses `-3`** (always passed, whatever the OpenSSH
    default): the data is relayed through the workstation, because the
    fences block SSH between guests (the edge and the watchdog accept it
    only from Proxmox, §9.7, §9.9; the search gateway drops the other
    guests' `:22`). Never `-R`.
  - **SFTP only** (scp's default since OpenSSH 9.0); artoo never passes
    `-O`, whose legacy protocol runs remote paths through the guest's
    shell (fish).
  - **Checksums.** When scp exits 0, artoo prints the SHA-256 of what was
    copied and compares it on the far side. artoo hashes a local side
    itself; a remote side runs `sha256sum` over SSH with `vm ssh`'s options
    plus `BatchMode` (one host per connection, so `-o` works here). The
    remote commands (the existence check, the hash) are fixed strings, run
    as `sh -c '…'` (guests' login shell is fish, as with `vm ssh -- CMD`);
    the path is sent on stdin, never on the command line. With `-r`, every
    regular file is compared by relative path and hash; scp follows
    symbolic links (scp(1)), so the source listing follows them too. A
    source file missing or different on the far side is exit 8, naming the
    files. Extra files in a target that `--force` merged into are not
    compared. A check that could not run reports "copied, not verified"
    (exit 8).
  - **Failures.** scp failing is exit 4, with scp's own message. A target
    scp had started stays as it is, and artoo names it; replacing it needs
    `--force`. An interrupt exits 130.
  - **`-n`** prints the resolved target and the exact scp argv
    (shell-quoted) and copies nothing. It writes nothing either, not even
    `ssh_config`; it says when the file would change.
  - **No prompt** (like `vm ssh`). The copy writes only as the guest user,
    inside a guest, or on the workstation. It is outside the mutation
    pipeline (§8.2): no plan, no ledger, no `--yes`. Its safeguards are the
    overwrite refusal and the checksum.
  - **Output:** `<sha256>  <target>` per file (for `-r`, a count), then
    `SHA-256 matches on <side>`. `-o json`: `{"source", "target", "files":
    [{"path", "sha256"}], "verified"}`.

- **Testing.** Offline: rendering of the file (direct, `ssh-jump`,
  unpinned), how a side is parsed and refused (the rules above, with
  `./a:b`), the target with and without `--force`, the scp argv for each
  direction, and comparison of the `-r` file lists. Live acceptance under
  an approved run (§13, a disposable guest): workstation → guest, guest →
  workstation, and guest → guest between a fenced guest and an `ssh-jump`
  guest, all verified; a second copy refused without `--force`; `-r` of a
  tree with a symbolic link; plain `ssh`/`scp`/`rsync` with a guest name
  once the `Include` is in place; `vm rm` removing the guest's block.

### 9.11 Guest fence (`vm fence`)

The edge VM and the watchdog carry the Proxmox VE firewall on their NIC
(§9.7, §9.9), written by their own setup. `artoo vm fence VM` puts the
same kind of host-side fence on any other artoo guest — an app guest, a
crawler that must not reach the LAN, the search gateway (§9.9) — so that
root inside the guest cannot widen it. It writes only the VM's own
firewall on Proxmox (`VM.Config.Network`, as §9.7) and nothing inside the
guest; it is not an nftables policy in the VM.

- **Rules, all derived** (no address is typed by hand; first match wins;
  Proxmox inserts at the top, so they are sent last to first):

  | # | Rule | From |
  | --- | --- | --- |
  | 1 | `IN ACCEPT tcp <port>` from the edge VM's address, one rule per service | each `svc` route whose upstream is this VM (§9.6), by service name; none without an edge VM |
  | 2 | `IN ACCEPT tcp 22` from the LAN — from Proxmox only (`pve.ssh_host`) for a guest tagged `ssh-jump` | `guests.gateway`'s subnet |
  | 3 | `IN ACCEPT Ping` from the LAN | as above |
  | 4 | `OUT ACCEPT udp 53`, `OUT ACCEPT tcp 53` to the gateway | `guests.gateway` |
  | 5 | `OUT ACCEPT tcp 8428,3100` to the watchdog (Alloy's push, §9.9) | the `role-watch` VM's static address; none without one |
  | 6 | `OUT ACCEPT` per exception (below) | `guests.fence_allow_out` |
  | 7 | `OUT DROP` to `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16`, then to `fc00::/7,fe80::/10` | — |
  | 8 | `OUT ACCEPT tcp 80,443`; `OUT ACCEPT udp 123`; `OUT ACCEPT Ping`; `OUT DROP` | — |

  Rule 7 keeps the guest from Proxmox, UniFi's other ports, other guests
  and other LAN clients. Every rule carries an `artoo: …` comment;
  comments are not compared.
- **IP set and options.** `ipfilter-net0` holds the VM's static
  `ipconfig0` address only (a guest without one is refused), so the guest
  cannot send from another address. The options are those of §9.7:
  `enable 1, ipfilter 1, macfilter 1, dhcp 0, ndp 1, radv 0, policy_in
  DROP, policy_out DROP`; the NIC flag is `firewall=1`. Write order as
  §9.7: rules, IP set, NIC (with the tag below), options last, so the VM is
  never filtered by a half-written rule set. The datacenter firewall must
  be on (`scripts/pve-firewall.sh`); when `/cluster/firewall/options` says
  it is off, the plan says the fence has no effect until it is, and `vm
  verify` warns.
- **The `fenced` tag** marks a guest fenced by `vm fence`; it is written in
  the same digest-guarded config PUT as the NIC flag. It tells `svc`, `vm
  verify`, `vm show` and `status` which guests to check without reading
  every VM's firewall. A fence that differs from the derived one (a new
  service, a moved watchdog, `ssh-jump` added or removed with `vm set`, a
  rule edited by hand) is **drift**: shown, never repaired silently; `vm
  fence VM` converges it.
- **Per-guest exceptions live in the config**, never in one-off flags, so
  every re-run derives the same fence: `guests.fence_allow_out`, entries
  `VM PEER PROTO PORTS` separated by `;` — e.g. `hoth naboo tcp 5432; hoth
  203.0.113.0/24 udp 51820`. `PEER` is an artoo guest's name (its static
  address, read at plan time) or an IPv4 address or CIDR; `PROTO` is `tcp`
  or `udp`; `PORTS` a Proxmox port list (`5432`, `80,443`, `6000:6010`).
  `config set` checks the syntax. `vm fence` refuses, before planning, an
  entry whose guest does not exist or has no static address, a peer that
  is the VM itself, and any peer that is a protected address (§9.6:
  Proxmox, the gateway) or contains one — the fence never opens a path to
  Proxmox or UniFi, with no override. Inbound exceptions are not offered: a
  guest's inbound services are its service names (rule 1).
- **Refused** (exit 5, before planning): a template; a VM without the
  `artoo` tag; a VM tagged `role-edge`, `role-watch` or `role-router`
  (their setup owns their fence, and a fence would break the subnet
  router's forwarding, §9.8); no static address; an edge VM that exists
  but is not running (its routes, and so rule 1, are unknown; a failed
  read of its routes fails the command too); a watchdog that exists
  without a static address (rule 5 needs it). `--off` reads neither the
  edge VM nor the watchdog. The guest may be stopped: the fence applies
  when it starts.
- **High-impact** (§3.4): typed confirmation, or `--yes --confirm VM`.
  - The plan renders the full rule diff, position by position — `rule N
    <current> → <wanted>`, `(none)` and `(removed)` at the ends — with the
    count of unchanged rules, and the IP set, NIC, tag and options changes.
  - Existing rules not written by artoo (a hand-written fence) are
    replaced, and the plan names them. Taking over a hand-written fence
    with the same rules changes only the tag (and whatever else differs).
  - `-n` sends nothing; a converged fence is a no-op (exit 5, "nothing to
    change").
  - Verified by read-back: rules, IP set, options, NIC flag and tag as
    planned, else exit 8.
  - While a fenced guest's rules are rewritten, its traffic drops between
    deleting and re-adding them (no other change on Proxmox is atomic
    either).
  - `pve-firewall` compiles the configuration on its own cycle (about
    10 s), so enforcement lags the write: the read-back checks the
    configuration, and live probes wait about 20 s.
- **`vm fence VM --off`** is the rollback: options `enable 0` first (the
  guest is unfiltered at once) with the other options reset to Proxmox's
  defaults, then every rule and the IP set removed, then `firewall=1` and
  the tag removed from the VM config. Same confirmation; a guest without a
  fence is a no-op.
- **Services keep the fence in step.** `svc add`, `svc set` and `svc rm`
  on a service whose old or new upstream is tagged `fenced` plan the fence
  change in the same plan — `fence <vm>` with the rule that opens or
  closes — and run it as a step of their ledger: the new upstream's fence
  opens before the route is written, the old one's closes after the route
  is gone. The fence step rewrites the VM's whole rule list as `vm fence`
  would, so drift in that fence is repaired too and the plan shows it.
- **Fence state.** `vm verify` adds "fence": not checked for a guest
  without the tag (and for the role VMs, whose setup checks theirs); ok
  when the read-back equals the derived fence; failed on drift, naming the
  first differing rule (`artoo vm fence VM` to converge); a warning when
  the datacenter firewall is off. `vm show` prints a "Fence" line (`on`,
  `drift`, `off`). `status` lists fenced guests in drift below the guest
  table — a warning, like a pending reboot.
- **Testing.** Offline: the derived rules for a plain guest and an
  `ssh-jump` guest, with and without edge, services, watchdog and
  exceptions; each refusal; the plan's rule diff; `-n` sending nothing; the
  order of writes (rules last to first, options last; `--off` options
  first) and the read-back against the fake server; `svc add` on a fenced
  guest planning and running its fence step. Live acceptance under an
  approved plan (§13, a disposable guest with a test service): `vm fence`
  converges in one run and a second `-n` finds nothing; from the guest,
  Proxmox `:8006`/`:22`, UniFi `:443`, another guest and the workstation
  time out while `dig @<gateway>` answers and HTTPS to the internet works;
  from the workstation the service answers through the edge and not
  directly, and SSH and ping work; `--off` restores reachability. Taking
  over an existing hand-written fence is its own approved plan: it plans
  only the tag, a second `-n` finds nothing to change, and `vm verify`
  shows the fence ok.

### 9.12 Package upgrades (`vm upgrade`)

Unattended upgrades install only the release and `-security` pockets
(§9.1); `-updates` waits for the operator. `vm upgrade VM` installs
everything pending through the guest agent, on the one pipeline (§8.2):
one VM per run (the edge, router and watchdog included), or every
ordinary guest with `--all`.

- **Read** (nothing changes in the guest): an artoo guest (tag `artoo`,
  not a template), running, its agent answering.
  - `LC_ALL=C apt-get -s --with-new-pkgs upgrade` on the current package
    lists. Each `Inst` line is one package: name, installed version (none
    for a new package such as the next kernel), candidate version and
    pockets (`Inst tmux [3.6a-2ubuntu0.1] (3.6a-2ubuntu0.2
    Ubuntu:26.04/resolute-updates [amd64])`); a pocket ending in
    `-security` makes it a security update.
  - The lists' age (`/var/lib/apt/periodic/update-success-stamp`), the
    packages phased updates defer, and those kept back.
  - Packages an interrupted dpkg left unfinished (`dpkg-query` status
    unpacked, half-installed, half-configured, awaiting or pending
    triggers, reinstall-required), read even when `apt-get -s` fails.
    `apt-get -s` does not report them, and apt's daily run skips while
    they exist, so the lists stop refreshing. None is reported while dpkg
    or apt runs (an unattended run, artoo's own unit). Otherwise the guest
    is refused, naming them and `sudo dpkg --configure -a` (over SSH,
    outside the agent).
  - artoo never runs `apt-get update`: the plan is what the lists say,
    with their age (apt's daily timer refreshes them).
- **Plan:** one line per package, `name  old → new`, marked `security`;
  nothing pending is a no-op (exit 5). Impact: new dependencies installed
  (a new kernel), nothing removed; services using an upgraded library
  restarted (needrestart, `NEEDRESTART_MODE=a`); configuration files keep
  local changes (`--force-confdef --force-confold`); never a reboot.
  Notes: the lists' age, the deferred and kept-back counts, pinned
  packages (Alloy, the watchdog's stack, §9.9) staying at their pins,
  and the agents at work on a guest tagged `rex` (§18.8).
  Recovery: the rollback to the `--snapshot` (§9.16) taken first, else
  none (apt has no undo). The fingerprint is the planned set and the
  lists' stamp.
- **Send once:** `apt-get -y --with-new-pkgs upgrade` as root,
  `DEBIAN_FRONTEND=noninteractive`, `DPkg::Lock::Timeout=300` (an
  unattended run holding the lock is waited for), output in
  `/var/log/artoo-upgrade.log`.
  - It runs in its own transient unit `artoo-upgrade.service`
    (`systemd-run --collect`), never as a child of the guest agent:
    upgrading `qemu-guest-agent` restarts the agent, and systemd kills
    every process of its unit (`KillMode=control-group`), leaving dpkg
    half done. systemd refuses a second unit while one runs.
    `RefuseManualStop=yes` keeps needrestart (no exclusion for this unit)
    from stopping and restarting apt.
  - Each run has an id (VMID and a clock value). When apt ends, the
    script writes the id, apt's exit code and, on failure, the log's last
    lines to `/run/artoo-upgrade.rc` (renamed into place); the file stays
    until the next run clears it. artoo polls it through the agent every
    2 s, for its own run's code only. apt's status lines
    (`APT::Status-Fd`) via `/run/artoo-upgrade.stage` are the step's live
    detail (`42% Unpacking tmux (amd64)`, §4.4).
  - Polls failing while the agent restarts are not errors. Unknown (exit
    7; apt may keep running): the agent silent for 5 minutes, the unit
    gone without this run's code (after three polls when systemd-run's
    own answer was lost, as the unit may not be registered yet), or 30
    minutes passing. apt failing is exit 6 with the log's last lines;
    systemd-run refusing (exit 6) started nothing.
- **Verify:** a fresh simulation shows no unfinished dpkg package and no
  planned package still pending at its planned version (a version the
  lists offer anew does not count). The result names a pending reboot
  with its packages (`/run/reboot-required`, §9.4) and `vm reboot VM`.

**`vm upgrade --all`:** the same upgrade for every running artoo guest,
one plan, one confirmation.

- **Left out:** `role-edge`, `role-router`, `role-watch` — the set `vm
  fence` refuses (§9.8). A `tailscaled` restart can cut a remote
  operator's path to Proxmox, a Caddy restart takes every service name
  down, and the watchdog reports the others' failures; each is upgraded
  alone. Every other role is included; there is no opt-out tag.
- **Read:** per guest as above. Stopped, agent silent, `apt-get -s`
  failing or dpkg interrupted: skipped, with the reason. Nothing pending:
  up to date. Nothing pending anywhere is a no-op (exit 5) whose message
  names the up-to-date and every skipped guest, never the generic
  "already has the requested state".
- **Plan:** one change row per package, the guest named on its first
  row; the action counts packages, guests and security updates; notes
  give the oldest lists' age, the deferred and kept-back totals, the
  up-to-date guests and each skipped guest with its reason. Refused with
  `--all` (usage): `--snapshot` (a way back is a per-guest decision) and
  `--no-wait` (it would start every apt at once and could not report a
  failed start). The fingerprint is every guest's planned set and lists'
  stamp.
- **Send:** one ledger step per guest (`upgrade NAME`), one after
  another, never in parallel. A failed step (apt failed) or an unknown
  one (the wait ended without an answer; an exec accepted without a pid)
  does not stop the next. Never a retry, never a reboot.
- **Verify:** a fresh simulation per upgraded guest; an unfinished dpkg
  package or a planned package still pending fails that guest's step.
  The result names the guests that want a reboot; a reboot check that
  does not answer says "reboot state unknown", never "no reboot needed".
  Steps changed while verifying show in the ledger printed after the
  live progress. Any unknown step → exit 7; else any failed step → exit
  8, naming how many guests were not upgraded.

**`vm reboot --pending`** reboots, in one plan, every running artoo guest
whose `/run/reboot-required` exists (the check `vm verify` reads, §9.4).

- **Read:** per running artoo guest with an answering agent, the reboot
  check and its packages; a missing `/run/reboot-required.pkgs` still
  wants a reboot ("packages not named"). Named but not rebooted: guests
  that do not want it ("not needed"); stopped guests, silent agents and
  failing checks (skipped, with the reason); `role-edge`, `role-router`
  and `role-watch` guests that want it, with their packages, left to `vm
  reboot VM` as for `vm upgrade --all`; the guest artoo runs on (its host
  name is the VM name). Nobody to reboot is a no-op (exit 5) naming all
  of these. Guests tagged `rex` have their agents read first (§18.8).
- **Plan:** one change row per guest, `running → rebooted (packages)`.
  Impact: one guest after another; each must be running again, its agent
  answering and its request gone before the next starts; the first that
  is not stops the run.
- **Send**, per guest: the request read again just before the write (a
  guest no longer wanting it is skipped); `POST …/status/reboot`, the task
  tracked, the agent awaited (10 minutes), then `uname -r` and the request
  read again. Each step ends in one state, set once:

  | State | When |
  | --- | --- |
  | failed before the write ("not rebooted") | its check failed, or Proxmox refused the POST |
  | unknown | the reboot was or may have been sent and its end is not known: ambiguous POST, no task ID, task not followed to its end, Ctrl-C, state unreadable once back |
  | failed after the write | the task failed, the agent silent for 10 minutes, the request still there |
  | done | |

  A failed or unknown step stops the run (a failed reboot leaves a guest
  down); the rest stay "not run". The error names the case and counts
  the guests not rebooted (the current one too when it was not); unknown
  exits 7 and names `vm verify NAME` before running again. Never a retry.
  `--no-wait`, and a VM with `--pending`, are refused (usage).
- **Verify:** every step done or skipped; none done (no guest wanted it
  when its turn came) is a no-op (exit 5). The result counts the guests
  rebooted and back.

### 9.13 Pending configuration

Proxmox applies some changes to a running VM only at its next start
(memory or cores beyond hot-plug, cloud-init keys): `PUT …/config` stores
them as pending, and `GET …/config` returns the pending value as if live
([API.md](API.md) §2). Wherever artoo shows or checks a configuration it reads `GET
…/pending` — per key `value`, `pending` and a pending `delete`, values as
strings, `cipassword` masked — and names the difference:

- **`vm config VM`:** every key, sorted; a pending key reads `current →
  pending` with "pending restart" in the warning color (`current →
  (removed)` for a pending delete, `(unset) → value` for a new key); a
  footer counts them and names `vm reboot VM`. `-o json` is the
  `/pending` list. `cipassword` stays masked in both.
- **`vm show VM`:** the vCPU line is the running count; every shown key
  with a pending value (vCPU, memory, network, cloud-init) gets the same
  `→ pending` marker.
- **`vm verify VM`:** "config pending" (§9.4), read through the API
  without the agent: none is ok; pending keys warn, naming them (`memory
  4096 → 2048`) and `vm reboot VM` (`vm start VM` when stopped).
- **`vm set VM`:** the fresh read verifies what was stored (§8.2 step 9);
  a key that stays pending makes the result "configuration saved; memory
  2048 pending until restart" with `vm reboot VM`, not "applied". With
  `--reboot`, a running VM whose change stays pending is rebooted through
  Proxmox: the plan shows "status running → rebooted, if a change waits
  for it" (one confirmation covers it), the task is tracked, the VM must
  run again and `/pending` hold none of the changes. Without such a
  change, or on a stopped VM, the plan says no reboot happens. No second
  prompt follows the write.

A reboot inside the guest does not apply pending changes (the QEMU
process keeps running); `vm reboot VM` (`status/reboot`, which "applies
pending changes") or a shutdown and start does.

### 9.14 Guest memory

Proxmox has three "memory used" figures for a running VM ([API.md](API.md) §2):

| Figure | Measures |
| --- | --- |
| `/nodes/{node}/qemu` `mem` (`memhost` on 9.2) | the QEMU process on the host; grows towards the assigned size as the guest touches pages, shrinks only with ballooning |
| `status/current` `mem` (web interface) | the balloon driver's `total_mem − free_mem`; page cache counts as used |
| guest `MemTotal − MemAvailable` (`/proc/meminfo`) | what the guest's programs need; the watchdog's `artoo-memory` alert (§9.9) uses it too |

artoo's **guest memory** is the third, from `agent/file-read` of
`/proc/meminfo` (one GET, no command in the guest,
`VM.GuestAgent.FileRead` in `PVEVMAdmin`), read only after the agent
answered in the same command so a guest without one costs no wait.
Without the agent it falls back to the balloon figure labelled "incl.
cache", else says so. The host figure is never shown as the guest's use.

- **`vm show VM`:** "Memory" is guest memory (used / total, bar), then
  "Cache" (`Buffers + Cached`, reclaimable) and "Host" (the QEMU
  process); a pending memory change (§9.13) stays marked.
- **`status`:** the MEMORY column is guest memory, from the agent reads
  `status` already makes per running guest.
- **`vm ls`:** Proxmox's list figure (one request, no per-VM agent
  reads), in a column titled HOST MEM.
- **`vm set VM memory=…`** on a running VM with an answering agent: the
  plan notes current guest use and warns (not refuses) when the new size
  leaves less than 512 MiB above it.
- `-o json` adds `guest_mem` (`source` `agent` or `balloon`, `total`,
  `used`, `available`, `cached` in bytes; the last two only from the
  agent) to `vm show` and each `status` guest; `mem` and `maxmem` keep
  Proxmox's values.

### 9.15 Disk growth (`vm disk grow`) and `vm set` keys

CPU and memory are configuration keys (`PUT …/config`: digest-guarded,
reversible, possibly pending, §9.13) in `vm set`. A disk grows through
its own endpoint (`PUT …/resize`, a task) and cannot shrink, so it has
its own command.

**`vm disk grow VM SIZE [--disk SLOT]`.** `SIZE` is the growth (`+20G`)
or the new size (`80G`): `M`, `G`, `T`, no unit is GiB, whole MiB, at
most 64 TiB. `SLOT` (default `scsi0`) is a non-CD-ROM
`scsiN`/`virtioN`/`sataN`/`ideN` slot of the VM.

- Refused before any write: a template, a missing slot (the VM's disks
  listed), a CD-ROM, a smaller size ("Proxmox cannot shrink a disk"),
  growth beyond the storage's free space. The same size is a no-op (exit
  5).
- Plan: slot and size (`20.0 GiB → 40.0 GiB`), "Final: Proxmox cannot
  shrink a disk", the storage's used space, "Recovery none", and what
  happens to the filesystem.
- One `PUT …/resize` with the absolute size in MiB and the config
  `digest`; the task is tracked; the fresh config must show the new
  `size=`.
- **Filesystem.** On the boot disk (first of `boot: order=`) of a running
  VM whose agent answers, a step grows `/` through the agent: `growpart`
  on its partition (exit 1, "nothing to grow", is fine), then `resize2fs`
  (ext4) or `xfs_growfs`; `/` not on a `/dev/sd*` or `/dev/vd*`
  partition, or another filesystem, fails the step. The step reports `/`
  before and after (`df`); an unchanged size fails it (exit 8), naming
  the next move: grow it in the guest, or reboot (cloud-init's growpart
  runs every boot). A stopped VM's or agentless VM's boot disk grows its
  filesystem at the next boot; another disk's partitions are the
  operator's — the plan and result say which.

**`vm set` keys.** Beyond `name`, `description`, `tags`, `onboot`,
`cores`, `sockets`, `memory` and `balloon` (`balloon=0` turns ballooning
off):

| Key | Value |
| --- | --- |
| `startup` | `order=N[,up=S][,down=S]`, a bare `N` is the order; normalized in that key order |
| `protection`, `numa` | yes/no |
| `vcpus` | 1–512 |
| `cpulimit` | 0–128 CPUs, 0 = none |
| `cpuunits` | 1–10000 (the cgroup v2 range) |
| `hotplug` | list of `network`, `disk`, `usb`, `cpu`, `memory`, `cloudinit`, or `0`/`1` |

Checked together with what is stored, so Proxmox's start-time refusals
come before the write: `cores × sockets` within the host's CPUs
(`/nodes/{node}/status` `cpuinfo.cpus`), `vcpus` within `cores ×
sockets`, `balloon` within `memory`, memory hotplug only with `numa=1`.
Network, cloud-init, disk-option and hardware keys are not accepted
(`net0`, `ipconfig0`, `bios`, `machine`, …). `name` on an artoo guest is
refused in favour of `vm rename` (§9.18). `vm show` lists "Boot" (onboot
and startup), "Protection", "Hot vCPUs", "CPU limit", "CPU weight",
"Balloon", "NUMA" and "Hotplug" when set, pending values marked.

### 9.16 Snapshots before changes (`--snapshot`, `vm snap prune`)

A snapshot is a rollback point for a change, not a backup: it lives on
the guest's storage (backups are out of scope, §1). artoo never schedules
snapshots (it runs on a workstation; Proxmox schedules only backups);
guest-changing commands take one first, and bounded retention keeps them
from filling the pool. On a thin-provisioned ZFS pool (`sparse 1`) a
RAM-less snapshot grows with every block the guest rewrites, so age, not
count, fills the pool; a snapshot with RAM costs the VM's memory each
time; and ZFS rolls back only to a volume's newest snapshot ([API.md](API.md) §2), so
more snapshots add cost, not rollback points.

**Ownership.** artoo's snapshots are named `artoo-<action>-<UTC>`
(`artoo-upgrade-20261105T0545Z`; at most 40 characters, [API.md](API.md) §2), never
include RAM, and carry the description `artoo <version>: <command>`.
`vm snap add` refuses the reserved prefix `artoo-`, so cleanup never
selects an operator's snapshot. Operator snapshots are untouched by
everything below except the age report.

**`--snapshot`** on `vm upgrade` (§9.12), `edge setup` (§9.7), `router
setup` (§9.8) and `watch setup` (§9.9). Not on `vm fence` (the NIC
firewall file is not in a VM snapshot) or `vm disk grow` (a disk cannot
shrink, §9.15).

- **Read/plan:** the guest's snapshots and the usage of every storage
  holding one of its disks (CD-ROMs left out), from
  `/nodes/{node}/storage`. Refused before any write (exit 5): the guest
  already holds `guests.snapshot_keep` artoo-owned snapshots ("naboo
  holds 2 artoo snapshots (keep 2): 'artoo vm snap prune naboo'"; artoo
  never deletes one to make room); a storage above 80 % used. The
  plan's first change line is the snapshot (`snapshot (none) →
  artoo-upgrade-… (no RAM)`), its recovery `artoo vm snap rollback VM
  NAME`.
- **Send:** the snapshot is the first ledger step (`POST …/snapshot`,
  `vmstate` off), its task tracked and the snapshot verified in the
  listing before the change's steps run. A failed or unknown snapshot
  step stops the workflow with the change unsent (exit 6 / 7). A re-run
  takes a new snapshot; the cap bounds it.
- **Result:** every outcome prints the rollback command with the exact
  snapshot name. Rolling back the edge rolls back its route files too:
  `svc ls` reports routes added since as missing, `svc add` restores
  them (§9.7).

**`vm snap prune VM|--all [--keep N] [--older-than DAYS]`** selects
artoo-owned snapshots only: those beyond the newest `N` (0–10, default
`guests.snapshot_keep`), and also any older than `DAYS` (1–3650, default
`guests.snapshot_max_age_days`). The plan lists each with its age and
parent; nothing selected is a no-op (exit 5). Destructive (§3.4): the
typed VM name, or `--yes --confirm VM`; `--all` covers every artoo
guest, is high-impact and takes `--confirm all`. One `DELETE
…/snapshot/{name}` per snapshot, oldest first, each task tracked and the
snapshot verified gone; the first failure stops the run (exit 6, or 8
when some were removed). Never `force`.

**`vm snap rollback`** reads the snapshot tree and the guest's disk
storages: where a newer snapshot would block the rollback (ZFS, [API.md](API.md) §2)
it refuses up front, naming the blockers ("Remove them first — they are
lost by this rollback anyway"). A guest that was running is started
again (`start=1`) when the snapshot has no RAM; the plan says so and
verify waits for `running`.

**Visibility.** `vm snap ls` has an OWNER column (`artoo`, `operator`,
`artoo, old: prune` past the age limit) beside TAKEN. `status` adds a
storage line when any guest has snapshots (`snapshots 3 on 2 VMs, oldest
16d`) and warns per artoo-owned snapshot past the age limit (`old
snapshot: naboo@artoo-… (16d) — 'artoo vm snap prune naboo'`).
`vm verify`'s "snapshots" check: `none`, `N (K artoo)`, or a warning
naming the oldest stale one. The API reports no per-snapshot size
([API.md](API.md) §2): artoo shows age and storage usage, never a guessed size.

**Testing.** Offline: name generation and the reserved prefix, the cap
and headroom refusals, prune selection (keep, age, operator snapshots
excluded), rollback blockers from a snapshot tree, the ledger stopping
on a failed snapshot step. Live (`scripts/live/vm-lifecycle.sh`, §13, on
a disposable guest without an OS, so only what needs no guest agent):
`vm snap add` refusing the `artoo-` prefix (exit 2), a rollback blocked
by a newer snapshot (exit 5), and two `artoo-` snapshots made over SSH
pruned with `--keep 1` (the newest stays) and `--keep 0` (none stays),
the operator's own snapshot untouched.

### 9.17 Guest passwords on several machines (`vm password --reset`)

A guest's sudo password is made by `vm new` and kept only in the secret
store of the machine that ran it (`guest/<name>`); a machine set up with
`config import` (§6.1) has no `sudo` password for guests it did not
create. Resetting it is no new power: the Proxmox token every artoo
machine holds has `VM.GuestAgent.Unrestricted` (§7), which already runs
commands as root (`agent/exec`) and sets passwords
(`agent/set-user-password`, the same privilege in the schema).

**`vm password VM --reset`**, on the mutation pipeline (§8.2), normal
risk:

- **Read:** an artoo guest (tag `artoo`), running, its agent answering, a
  name the store accepts; whether `guest/<name>` is stored here (a store
  that does not answer refuses now, not after the guest changed).
  Templates, foreign VMs, stopped guests and a silent agent refuse
  before any write. The fingerprint is VMID and status.
- **Plan:** the guest user's password `current → new, random (24
  characters)`, the store entry `stored|(none) → the new password`, the
  store named in the target. Impact: old copies on other machines stop
  working; SSH keys, sessions and processes are untouched; the VM's
  cloud-init password (first boot only) is unchanged.
- **Send:** a password from `vm new`'s generator (§9.3), hashed with
  SHA-512 crypt and a fresh salt; one `POST agent/set-user-password` with
  `crypted=1`, so the plaintext never reaches Proxmox. The guest changes
  first, then the store: a failed store leaves a guest whose password
  nobody holds, recovered by a second reset (exit 8 says so); the other
  order could store a password the guest lacks. A refusal (400, 401,
  403, 404) changed nothing. Any other failure — a 5xx such as the
  agent's "got timeout", after which it may still run the command, or a
  lost answer — is resolved by reading the guest's shadow entry: the new
  hash there is success; otherwise exit 7, the stored password
  unchanged, a second reset named as safe.
- **Verify:** `getent shadow USER` through the agent shows exactly the
  hash sent, and the entry is stored; a failed read-back is exit 8
  naming what was done. The generated password is wiped from memory
  after use.
- `--reset` does not combine with `--show`; `vm password VM` reveals the
  password afterwards.

The last machine to reset a guest holds its valid password; `config
export --guest-passwords` gives every machine the same ones (§6.1).

### 9.18 Renaming a guest (`vm rename`)

A guest's name is carried by its hostname, UniFi client record, DNS
record, pinned host key and `ssh_config`, the stored `guest/<name>`
password, service upstreams, fence exceptions, tailnet name, the
watchdog's series and the workstation's Rex host (§18.9). Changing Proxmox's `name` alone leaves it half
renamed, so `vm set name=` refuses on artoo guests (tag `artoo`) and
points to `vm rename`; foreign VMs keep it. `vm rename` is for guests
whose disk holds state; cheap ones may be rebuilt (`vm rm`, `vm new`).

**`artoo vm rename OLD NEW`**, on the mutation pipeline (§8.2), high
impact: typed confirmation of OLD (or `--confirm OLD`). The VM is found
under either name, so a stopped run continues.

- **Usage errors** (exit 2): NEW not a valid name as `vm new` checks it
  (§9.1: one lowercase DNS label, 2–40 characters), OLD not a valid
  label, OLD equal to NEW, and no VM under either name.
- **Read and refuse** (exit 5, before any write):
  - OLD: an artoo guest (no template, no foreign VM), running, its agent
    answering (the hostname changes inside). `role-edge` and
    `role-watch` refuse — their names sit in firewall rules and every
    guest's Alloy configuration (§9.7, §9.9); rebuild those.
  - NEW: not protected (§9.6, `guests.reserved_names`); no other VM of
    that name, no other client's UniFi record named NEW, no DNS record
    for NEW pointing elsewhere than the guest's address, no pinned host
    key under NEW (in a stopped rename: none other than OLD's). A name
    held by more than one VM refuses.
  - A VM found only under NEW continues a stopped rename only if it
    still carries a trace of OLD (its hostname, an `/etc/hosts` line, its
    UniFi record named OLD, OLD's DNS record at its address, its tailnet
    hostname, its Alloy `host` label); otherwise refused. A finished
    rename (no trace left) is a no-op (exit 5).
  - Before a rename began (VM still under OLD), leftovers under NEW
    refuse: a pinned key, `guest/NEW`, a `guests.fence_allow_out` entry.
    In a stopped rename `guest/OLD` and `guest/NEW` must match, an entry
    naming NEW is accepted only once none names OLD, and another pinned
    key under NEW refuses.
  - A hand-edited service route refuses.
- **Plan**, one line per place, `OLD → NEW` or "not present", run in
  this order:

  | Step | Change |
  | --- | --- |
  | Proxmox | `name` (digest-guarded, as `vm set`) |
  | DNS (add) | NEW's machine-name A record at the guest's address, before anything points at NEW |
  | Services | each `svc` with upstream OLD moved to `NEW:PORT` as `svc set` does, fence steps included (§9.6, §9.11) |
  | SSH | the pinned key's `HostKeyAlias`, then `~/.artoo/ssh_config`: NEW's block written as `vm ssh-config` writes it (static address, else the agent's IPv4), then OLD's removed — never OLD's alone (§9.10) |
  | Secret store | `guest/NEW` written and read back, then `guest/OLD` removed |
  | Rex host | when `~/.artoo/rex-hosts.json` records OLD: `rex hosts edit OLD --label NEW --endpoint ssh://USER@NEWFQDN`, then the record (§18.9); skipped with a note without a running Rex; its failure fails only this step (exit 8, `rex hosts sync` repairs it) |
  | Fence | entries naming OLD rewritten in `guests.fence_allow_out` (`~/.artoo/config.json`); the fences of the guest and of fenced guests whose exceptions name it re-derived, those that differ re-applied. The plan shows each one's rule diff as the renamed lab derives it, and the step applies only those rules (a fresh derivation that differs fails the step). Runs only alongside another step |
  | Tailnet | tag `tailnet` or `role-router`: `tailscale set --hostname=NEW` through the agent, read back from `tailscale status --json`; with a Tailscale credential, the device (by the node ID the guest reports) read every 2 s for up to about 30 s until the control plane shows NEW, renamed through the API only if it keeps the old hand-set name. Another device already named NEW refuses at read time (§17) |
  | Watchdog | below (§9.9) |
  | Guest | hostname (`hostnamectl set-hostname`) and the `/etc/hosts` line through the agent (a line's trailing CR is taken off before comparing names and put back); a running Alloy restarted, as its node metrics' `instance` label is the hostname read at start |
  | UniFi | the client record's `name` (§9.5), matched by MAC: `PUT rest/user/{_id}` with the name alone ([API.md](API.md) §1) |
  | DNS (remove) | OLD's machine-name A record, very last; a record of OLD pointing elsewhere is kept and named |

  Proxmox first, so a stopped run is found under NEW; the places that
  say OLD on the guest and in DNS last, so OLD resolves until everything
  else moved and a stopped run leaves a trace. Impact: other machines
  keep OLD in `known_hosts`, `ssh_config` and password copies until they
  run `vm ssh-config` and receive the password again (§6.1, §9.17); OLD's
  metric history is deleted once NEW reports; Loki keeps OLD's logs
  under `host=OLD`. Notes: the UniFi call is not verified live;
  cloud-init's instance ID follows the name, so the next boot (a guest
  reboot too) runs cloud-init as a new instance — new SSH host keys,
  `runcmd`, users and keys again, the hostname still NEW — and `ssh NEW`
  refuses the new key until `vm ssh-config --repin NEW` re-pins it
  (§9.10). `runcmd` is safe to rerun (§9.1).
- **Watchdog step.** `watch enroll` renders `host = "<vm>"` into a
  guest's Alloy configuration from the VM name, not the hostname, so the
  guest reports as OLD until re-enrolled; after that OLD's series go
  quiet and `artoo-guest-silent` would fire unless they are deleted.
  Read: the guest's label and, on a running watchdog whose agent
  answers, OLD's series and whether a probe names OLD as a service's
  `vm`. Then, in order:
  1. When services moved or a probe names OLD: the watchdog's own Alloy
     configuration re-rendered as `watch setup` does (that file alone,
     Alloy restarted if it changed), so no probe keeps `vm="OLD"`.
  2. The guest re-enrolled under NEW (`watch enroll`: files rendered,
     Alloy restarted).
  3. A wait (every 5 s, up to 2 min) until the metrics store, queried
     through the watchdog's agent as `watch forget` does, has samples
     with `host="NEW"`.
  4. OLD's series deleted exactly as `watch forget OLD` does, counted
     before and after.

  A wait that runs out, or any failure between the re-enrollment and the
  delete, stops with exit 8 naming `artoo watch forget OLD`; a re-run
  finishes it. Skipped,
  with the reason, for a `no-watch` guest, one never enrolled (no label,
  series or probe naming it), and without a `role-watch` VM. A stopped or
  unreachable watchdog leaves the step pending (a plan note, the other
  steps run, exit 8 with the re-run), never silently skipped; the
  guest's label, still OLD, is the trace. Plan notes: alerts active for
  OLD (a pending reboot, the root filesystem) resolve when its series
  are deleted and fire again under NEW while still true; Loki keeps
  OLD's logs.
- **Send** in table order, one ledger entry per step. Each step checks
  observed state first, so the same command after a failure continues
  under either name. A failure is exit 8 naming what is done and left;
  every failure after a finished step names the re-run (an unknown
  outcome stays exit 7, re-run after a check). A definitive answer (a
  4xx such as UniFi's 400, a failed command) is failed, never unknown. A
  Tailscale credential that fails at read time is a plan note, and the
  tailnet step runs only the guest's `tailscale set`. Rollback is `vm
  rename NEW OLD`.
- **Verify** re-reads every place with the plan's own reads: no step is
  left, and each place that held OLD carries NEW (Proxmox's name and the
  hostname, the UniFi record's name, NEW's DNS record, `guest/NEW`, the
  pinned key under NEW, NEW's `ssh_config` block and not OLD's). The
  command runs neither `vm verify` (§9.4) nor an SSH login; the result
  tells the operator to ("check it with 'artoo vm verify NEW'").

## 10. UniFi

### 10.1 Access

Integration API at `unifi.endpoint` (default
`https://unifi.home.arpa/proxy/network/integration`), `X-API-KEY` from the
secret store (`unifi`, §6), mkcert root. `/v1/info` (the application
version) is read only by `gw info`, `status` and `doctor --connect`;
no command is gated on the version. The operator creates the API key in
the UniFi UI.

### 10.2 Resource catalog and `gw` commands

A **comptime resource catalog**, built from the official v10.6.106
OpenAPI export ([API.md](API.md) §1), declares per resource: path, verbs, pagination,
columns, identifier, allowed and required body fields, and risk. It
generates the `gw` command tree, help and table columns. `artoo gw spec`
compares it with the gateway's live OpenAPI document (`GET
/proxy/network/api-docs/integration.json`, [API.md](API.md) §1), including every write
operation's body fields, so a firmware update is caught early.

| Resource (`artoo gw …`) | Verbs |
| --- | --- |
| `sites` | ls, show |
| `devices` | ls, show, stats, pending, adopt, restart, port-cycle, rm |
| `clients` | ls, show, authorize, unauthorize |
| `networks` | ls, show, refs, add, set, rm |
| `wifi` | ls, show, add, set, rm |
| `fw-policies` | ls, show, order SRC DST, add, set, patch, rm, reorder SRC DST |
| `fw-zones` | ls, show, add, set, rm |
| `acl` | ls, show, order, add, set, rm, reorder |
| `dns-policies` | ls, show, add, set, rm |
| `traffic-lists` | ls, show, add, set, rm |
| `vouchers` | ls, show, add, rm, purge |
| `wans` | ls, show, log — from the gateway's own WAN data (§10.4) |
| `vpn-servers`, `vpn-tunnels`, `radius`, `lags`, `mc-lag`, `stacks`, `dpi-apps`, `dpi-categories`, `device-tags`, `countries` | ls, show — read-only API areas |
| `api METHOD /v1/…` | generic request, `/v1/` paths only, same pipeline for writes |

List verbs take `--filter EXPR` (server filter syntax), `-l/--limit`,
`--offset`, `--all` (pages of 200; not a snapshot). Bodies come from
`--from FILE` (JSON), checked against the catalog's allowed and required
top-level fields (generated from the export; deeper validation is the
server's). An artoo `show -o json` document is accepted: the envelope is
unwrapped and the read-only fields (`id`, `metadata`, …) are dropped and
named in the plan; any `<redacted>` value is refused, so a copied secret
placeholder is never written. PUT means a complete body and artoo never
read-merge-PUTs silently: the `set` preview diffs the current object
against the file and lists the fields the PUT would reset. Writes are
verified by a fresh read where the API offers one (created, replaced and
patched objects, orderings, deletions via 404, purges); device and client
actions and adoption have no read-back and are reported as **accepted,
not verified** (exit 0). The API has no ETags; plans state that
concurrent edits cannot be detected.

### 10.3 DNS records

`artoo dns ls|add|rm` manages DNS policies of type `A_RECORD` (`domain`,
`ipv4Address`, `ttlSeconds`, `enabled`; other types are skipped); `vm
new`, `vm rm` and `svc` use it. Records are created enabled with a TTL
of 300 s (`dns add --ttl`: 0–86400).
Records are created under `guests.domain` (`lab.example.com`); one artoo
created is recognized by its name **and** matched against its VM before
removal. A record for a protected infrastructure name (§9.6) outside
`home.arpa` is refused.

**Resolution on the LAN.** The workstation's DNS server is the gateway
(`192.168.1.1`), directly or through Tailscale MagicDNS
(`100.100.100.100`, which forwards non-tailnet names to it); no
`/etc/resolver` files. DHCP hands every client the gateway as DNS server
and domain `home.arpa` (`gw networks set`: `dnsServerIpAddressesOverride`,
`domainName`). Away from home, names resolve once Tailscale split DNS
sends `lab.example.com` and `home.arpa` to the subnet router (§9.6).

### 10.4 WAN health and outages (`gw wans ls|show|log`)

The Integration API knows a WAN only by ID and name (`GET …/wans`,
[API.md](API.md) §1), so these commands read the gateway's own WAN data from
undocumented sources the same API key opens ([API.md](API.md) §1): the classic
`stat/health` and `stat/device` documents (current state) and the v2
system log (events). All are read-only; the system log is searched with a
`POST` that changes nothing and is never retried.

- **Matching** is by name: the Integration API's WAN name equals the
  gateway's; the classic documents key the primary WAN `WAN`/`wan1` and
  the second `WAN2`/`wan2`; the v2 `wan/load-balancing/status` lists
  `{name, state, wan_networkgroup}` (`ACTIVE`/`BACKUP`), tying name to
  group. A WAN is accepted by name or ID. Names are matched at run time
  only: the operator renames WANs in the UI.
- **No port:** a WAN can exist with no gateway port carrying it (UI: Port
  "Unassigned"). `ethernet_overrides` ([API.md](API.md) §1) names each group's
  interface; a group missing there **and** without a live `wanN` object
  (one with `up` or `ip`) has no port (a live `wanN` without an override
  is a normal WAN, its port from `wanN.port_idx`). Such a WAN has status
  "no port" and role "unassigned" (neither backup nor offline), no
  address, link or health; `status` does not count it offline and `log`
  leaves out its events. A WAN with a port shows its number (`port 5`).
- **`gw wans ls`** — one line per WAN: name, role (active, backup,
  unassigned), status (online, offline, no port, unknown), WAN address
  (marked "shared" inside `100.64.0.0/10`, the ISP's carrier-grade NAT),
  ISP, link (port number, speed, duplex), availability and average
  latency of the gateway's monitors, ID.
- **`gw wans show WAN`** — status and role; address, netmask, the ISP's
  next hop (`gateways[0]`) and whether it is reachable now (a
  `wan1.mac_table` entry with `lastReachable` ≤ 60 s; older or absent is
  not reachable); ISP name, organisation and AS number; the port (index,
  media, speed, duplex, rx/tx errors and drops); each monitor (target,
  type, health, availability, average latency, over the gateway's
  `time_period`); the last downtime (`last_downtime_stats`, seconds); the
  last 24 hours' outages as `log` shows them, or a note that the log was
  not searched because the WAN could not be tied to a network group.
- **`gw wans log [WAN] [--since 24h|7d|30d]`** (default 24h) — the
  system log's `INTERNET_AND_WAN` events in the window, paged until all
  are read, folded into **outages**. A `NETWORK_WAN_FAILED` opens one;
  the next `NETWORK_WAN_RESTORED` of that WAN closes it, and its
  `DURATION` is the outage's length (counted from the loss itself, so
  longer than the time between the two events, which starts at
  detection). A restore whose failure lies before the window is an
  outage of its `DURATION`; a `NETWORK_WAN_FAILED_TEMPORARY` (a short
  disconnection reported once over, with its `DURATION`) is a brief
  outage. An outage spans from the loss (`end − DURATION` once closed,
  else the failure event) to its end: the WAN's link-state events in that
  span are "during" it; `ISP_PACKET_LOSS`, high-latency and link-state
  events in the 10 minutes before it are its lead-up. At equal timestamps
  a failure folds before a restore. An open outage is "ongoing"; a WAN
  offline now with no failure in the window is an ongoing outage "since
  before the window", from the window's start. A summary ends the list:
  outages, total and longest downtime (both clipped to the window),
  availability over the window. Paging stops at 100 pages of 100 events;
  stopping there, or a page without `total_page_count` (then read until a
  short page), is a visible warning and `meta.warning`. Unknown events
  are shown as they are (title and message with parameters filled in),
  never dropped.
- **Likely cause**, per outage, from evidence only:

  | Evidence | Shown |
  | --- | --- |
  | a link-down event of the WAN port in the outage | link: cable, modem or ONT |
  | link up, ISP next hop unreachable (only while the outage is ongoing) | ISP access: modem or the ISP's first hop |
  | link up, every monitor failing | ISP network beyond the first hop |
  | only the DNS monitors failing | DNS: resolvers unreachable, ICMP answers |
  | packet loss or latency in the lead-up | adds "degraded before" |
  | nothing to go on | unknown |

  A past outage has no recorded next-hop or monitor state, so only the
  link row applies to it (else unknown); the other rows judge an ongoing
  outage from the state read now, and `show` says so.
- **`status`** (§11) adds one UniFi line: each WAN's status and role, and
  the last 24 hours' outages with their total downtime. An offline active
  WAN is a failed check; outages are a warning.
- **Firmware and failures** (the sources are not in the OpenAPI document
  and not covered by `gw spec`):

  | Failure | Result |
  | --- | --- |
  | a source answers 404 or an unexpected shape | its part is "not available on this firmware", the rest is shown; exit 8 when nothing answers (no state source for `ls`/`show`, the system log for `log`) |
  | a state source (`stat/device`, `stat/health`, load balancing) fails otherwise (transport, 5xx) | named, exit 8 — in `log` too, whose events are still shown |
  | `log`'s own search fails | failed read (exit 4), never an unknown write |
  | `show`'s 24-hour search fails that way | partial result: named, exit 8, the WAN's state shown (404: named as not available on this firmware, exit 0) |
- **JSON:** `ls` has `id`, `name`, `group`, `role`, `status`
  (`online|offline|no_port|unknown`), `address`, `shared_address`,
  `netmask`, `next_hop`, `isp`, `port`, `availability` and monitor
  availabilities as fractions, `latency_ms`, `time_period` as the gateway
  sends it (unit undocumented), `last_downtime_seconds`; `meta.errors`
  lists unanswered sources. `show` adds `outages` and `events`; `log` has
  `outages`, `events` (the unfolded rest) and `summary` per WAN. Times are
  epoch ms as the gateway sends them (`meta.units`).

**Testing.** Offline against the fake server with documents shaped like
the verified ones ([API.md](API.md) §1): matching by name and group, the shared-address
mark, folding (closed, ongoing, back to back, unknown events, paging),
every cause row, a missing source. Live: read-only runs on the
workstation.

## 11. Overview and health

`artoo status` reads one task per system concurrently (`Io.Group`, each
with its own `Context` copy: the arena is thread-safe, `diag` per task);
sections are sampled, not atomic, and rendering waits for all.

| Section | Content |
| --- | --- |
| Proxmox host | CPU %, load 1/5/15, RAM, swap, root FS, uptime, versions |
| Guests | running/stopped/templates; per VM: state, vCPU, RAM, CPU %, guest memory (§9.14), uptime, address (stopped → `--`); below the table, guests whose `/run/reboot-required` exists (a warning, §9.1) and fenced guests whose fence drifted (§9.11) |
| Storage | per backend, no invented totals |
| Tasks | running + recent failures, warnings shown as warnings |
| UniFi | version, WAN status, device/client counts, guest DNS records vs guests (records under `apps.` are services, not orphans) |
| Edge | `edge status`'s checks (§9.7), drop counters towards Proxmox and UniFi first: one line when all pass, else each check that does not |
| Router | `router status`'s checks (§9.8), the same way |
| Tunnel | the lab tunnel's state, connections and public routes (§14); a route to a service that does not exist is drift |
| Services | `svc ls`'s drift (§9.6), from what the other tasks read (edge route files, UniFi records, guests); no extra requests |

Every section is read-only. A role VM or tunnel that does not exist shows
as "none", not as an error. A failed check (edge, router) exits 8 like an
unavailable section; warnings and drift do not change the exit code.
Guest CPU is % of its vCPUs, host CPU % of host threads.

`artoo host health [CHECK…]` runs named checks (`api`, `node`, `storage`,
`tasks`, `zfs`, `services`), all through the API: `/disks/zfs` for pool
health, `/services` for the core PVE services plus chrony and cron
(corosync is idle on a single node and not checked). Thresholds are in
the command help; warnings do not fail. Total connection or
authentication failure keeps exit 4/3; otherwise any failed or not-run
requested check exits 8.

## 12. Architecture

```text
src/
  main.zig, dispatch.zig  process wiring; parse → config → run; exit codes mapped in dispatch only
  app.zig                 per-invocation Context
  cli.zig, cli/           declarative command table, parser, help, suggestions, completion
  commands/               registry.zig (the tree) + thin glue per noun: args → domain → view
  ui.zig, ui/             palette, sanitize, table, detail/plan blocks, diff, values, json
  activity.zig, prompt.zig  activity line (§4.5); confirmations and hidden secret entry
  config.zig, files.zig   schema 1; private dirs and locked atomic replacement
  secrets.zig, secrets/   SecretStore: keychain, secret-service, file (+ in-memory)
  setup_file.zig          `config export|import` sealed file (§6.1)
  proc.zig, clipboard.zig helper processes, secrets on stdin only
  http.zig, api.zig       transport (§8.1) + in-process fake server; shared client plumbing
  exec.zig                mutation pipeline (§8.2) + step ledger
  exposure.zig            the §9.6 hard rule
  pve/ unifi/ cloudflare/ tailscale/   API clients and typed resources (§7, §10, §14, §17)
  guest/                  crypt512, vendor data, images, names, apt, host keys, payload/
  edge/, watch/           files rendered for the edge VM (§9.7) and the watchdog (§9.9)
  update/                 self-update (§16)
  rex/                    Rex on guests: setup, state, agy bridge, agent profile, permissions, hosts (§18)
  testkit.zig             test harness (§13)
  version_tag.zig         `--version` from Git tags (RELEASING.md §1)
scripts/                  leak check, release archives, Grafana board generator, Proxmox host scripts, live/ (§13)
hosts/pve/                Proxmox root shell config (scripts/pve-shell.sh)
```

**Rules.** Resource modules never print; commands never touch HTTP
directly; renderers only see sanitized view models. Explicit
`Allocator`/`Io`, one arena per invocation, no globals, no `catch
unreachable` or panics on command paths, `errdefer` for acquired
resources. stdout and stderr use streaming file writers. No third-party
package (`build.zig.zon` has no dependencies); no platform framework is
linked.

**Build.** `build.zig` steps: the binary (version from `git describe`,
RELEASING.md §1; `-Dversion` overrides), `test` (the colocated `test`
blocks reachable from `main.zig`), `fmt` (`zig fmt --check`) and `cross`
(binary and tests for `x86_64-linux` and `aarch64-linux`, which must
always compile). The `Makefile` wraps them: `make test` runs the leak
check (AGENTS.md) and `zig build test fmt cross`; `make install` builds
`ReleaseSafe` into `~/.local/bin/artoo` with shell completion
(`COMPLETION=fish|zsh|bash|none`). CI runs the same checks
(`.github/workflows/ci.yml`, AGENTS.md).

## 13. Testing

- `zig build test` (offline) and `zig fmt --check` pass before every
  commit, no exceptions.
- Every command has table-driven tests for parsing, planning (including
  refusals) and rendering (golden output, color off).
- `src/testkit.zig` runs a command line through `dispatch.run` with
  captured output, a private `HOME`, an in-memory SecretStore and
  scripted prompts, against the in-process fake server of `http.zig`
  (plain HTTP in tests). HTTP behaviour is tested there: retries,
  deadlines, idle-closed connections, write-once and every
  unknown-outcome path, PVE task states, UniFi pagination.
- Executor scenarios: dry-run, declined and non-interactive runs send
  nothing; writes are sent at most once; failed or unknown is never
  reported as success.
- Tests that need a vendor document (the UniFi export, [API.md](API.md) §1) read it
  from `../homelab/api/` and skip without it.

**Live runs** are scripts in `scripts/live/` against disposable resources
created in the same run. Ownership is written to a ledger
(`~/.artoo/live-ledger.txt` or `$ARTOO_LEDGER`) before any destructive
step; the first failed guard aborts the run, leaving what exists in place
and reported.

| Script | Runs |
| --- | --- |
| `vm-lifecycle.sh [VMID]` | after `doctor --connect`, ordinary `artoo` invocations against a guest without an OS that it creates with `qm create` over SSH (VMID default 990, its clone VMID + 1, both must be free; name `artoo-lt-<time>`; ownership = VMID + name + tag `artoo-test`, re-checked before each destructive step): `vm ls`/`show`/`config`; `vm set` and a no-op set (exit 5); `vm snap add`; `vm start` and a no-op start (exit 5); `vm stop` refused without `--confirm` (exit 5), then forced; `vm snap rollback`; `vm clone --id` and `vm rm` of the clone; the snapshot refusals and prune of §9.16; `vm snap rm`; `vm rm`; both VMIDs gone |
| `unifi-reservation-probe.sh` | the classic client API (§9.5, [API.md](API.md) §1): creates and forgets a client record with a name and Fixed IP for a locally administered MAC; the API key reaches `curl` as a header on stdin |

`vm-lifecycle.sh` and `scripts/pve-*.sh` take the Proxmox host from
`PVE_SSH` (required, no default) and the SSH key from `artoo config get
pve.ssh_identity`. Gateway live tests are read-only unless a plan is
approved.

## 14. Cloudflare

Built from Cloudflare's official OpenAPI document (`cloudflare/api-schemas`
commit `3fad73eb`, Cloudflare API 4.0.0), not committed; re-fetch it
before changing behaviour.

**Scope.** The `example.com` zone (`cloudflare.zone`) — the public
names of services made public and other records artoo marks — and the
ingress routes of the lab's one
Cloudflare Tunnel. Nothing else in the account.

**Credential.** One **account API token** (Manage account → Account API
tokens; owned by the account, not a user; DNS, zones and Tunnels accept
them), secret `cloudflare` (§6),
created by the operator and entered with `auth set cloudflare`:

| Permission | Resource | Needed for |
| --- | --- | --- |
| Zone → Zone → Read | zone `example.com` | zone ID by name (`GET /zones?name=`) |
| Zone → DNS → Edit | zone `example.com` | records: list, create, delete ("DNS Write") |
| Account → Cloudflare One Connector: cloudflared → Edit | the account | tunnel routes: `GET`/`PUT …/cfd_tunnel/{id}/configurations` (schema groups "Cloudflare One Connector: cloudflared Write", or the broader "Cloudflare One Connectors Write" / older "Cloudflare Tunnel Write"; not "Argo Tunnel (Legacy)") |

The tunnel permission cannot be narrowed to one zone or tunnel; one token
for both is deliberate for a personal account. Recommended at creation:
an expiry and a client-IP filter for the lab's public address. The edge
VM's DNS-01 token is separate (§9.6). Because a leaked token could route
a public name to anything `cloudflared` can reach, the §9.6 hard rule is
also enforced in the network: the edge VM's firewall drops Proxmox's and
UniFi's management ports (§9.7).

**Transport.** `https://api.cloudflare.com/client/v4`, `Authorization:
Bearer <token>` injected at request time. TLS verified against the
operating system's root store (`std.crypto.Certificate.Bundle.rescan`:
macOS system keychain roots, Linux `/etc/ssl/certs/…`), never the mkcert
root; same deadlines, no pooling, no write retries (§8.1). Every response
is the envelope `{success, errors[{code, message}], messages, result,
result_info{page, per_page, count, total_count}}`; `success: false` or a
non-2xx status becomes an error carrying `errors[].message` (sanitized).
Lists page with `page`/`per_page` (100) until an empty or short page,
or until `total_count` items are read. Cloudflare
stores and returns TXT content unquoted.

**Zone.** Resolved by name once per invocation; the account ID comes from
the zone object (`account.id`), so config holds names only:
`cloudflare.zone`, `cloudflare.timeout_seconds`, `cloudflare.tunnel`
(tunnel name).

**Ownership.** artoo writes only records it marks — `comment: "artoo:
<purpose>"` (comments exist on every plan; tags do not) — and refuses to
change or delete unmarked records. `cf dns ls` shows every record with
an `ARTOO` column.

**Commands.**

- `auth set cloudflare`; `doctor --connect` resolves the zone (which
  names its account) and verifies the token with `GET
  /accounts/{account_id}/tokens/verify` (status, expiry; an account token
  is unknown to `/user/tokens/verify`).
- `cf dns ls [--type T] [--name N]` — every record (name, type, content,
  proxied, TTL, artoo-owned, ID).
- `cf dns add NAME TYPE CONTENT [--proxied] [--ttl S] [--note TEXT]` —
  types `A`, `AAAA`, `CNAME`, `TXT`; a short NAME gets the zone appended;
  TTL 1 (auto) or 60–86400; `POST /zones/{id}/dns_records`, verified by a
  fresh `GET` of the returned ID. Refused before planning (exit 5, no
  override): names or contents matching Proxmox or UniFi (§9.6); A/AAAA
  contents that are LAN, loopback or link-local addresses (no LAN layout
  in public DNS); names under
  `guests.domain` (private guest names never go public; public names come
  from `cf tunnel route add`); a CNAME target that is a private name
  (`home.arpa`, under `guests.domain`). At planning, an existing record
  with the same name and type, or any record beside a CNAME, is refused
  (exit 5); an identical one is a no-op (exit 5). `--note` is at most 80
  printable characters.
- `cf dns rm NAME [--type T]` — a short NAME gets the zone appended; a
  NAME with several records needs `--type` (else exit 2); no record is
  a no-op (exit 5). Marked records only; typed confirmation of the FQDN
  (or `--confirm FQDN`); `DELETE`, verified by a `GET` answering 404.

**Tunnel routes.** The tunnel is remotely managed: its ingress list lives
in Cloudflare and `cloudflared` on the edge VM fetches it. A public host
always reaches an existing **service** (§9.6), one path: Cloudflare →
`cloudflared` → Caddy on `localhost` → the service's route → guest.

- `cf tunnel ls` — the account's tunnels (name, ID, status, connections)
  and the lab tunnel's routes (public host → service). Read-only.
- `cf tunnel route add HOST SERVICE` — HOST in the zone (a short name gets
  it appended), SERVICE an existing `svc`. Ingress rule `{hostname: HOST,
  service: "https://localhost:443", originRequest: {originServerName:
  <svc>.apps.<guests.domain>, httpHostHeader: <same>}}`: TLS to Caddy
  verified against the wildcard (never `noTLSVerify`), and the app sees
  the service name as Host (an app building absolute URLs gets its public
  URL in its own settings). Plus a marked, proxied `CNAME HOST →
  <tunnel-id>.cfargotunnel.com` (`artoo: tunnel <svc>`).
- `cf tunnel route rm HOST` — typed confirmation; the rule and the marked
  CNAME.

`PUT …/configurations` replaces the **whole** list, so add and rm read
the current configuration, plan the complete new list (diff shown; the
catch-all `http_status:404` stays last), re-read before sending and
refuse if the `version` changed, then verify by a fresh read. The public
name is checked by hand afterwards: probing it at once could make a
resolver cache the not-yet-visible name as NXDOMAIN. Refused before
planning: HOST under `guests.domain`, names of Proxmox or UniFi (§9.6), an
existing record for HOST, a SERVICE that does not exist, a SERVICE whose
VM carries `role-watch` or `role-search` (§9.9; no override). `svc rm`
refuses while a public route points at the service.

**Testing.** Offline: fake server for the envelope, paging, errors and
every refusal. Live, under an approved plan: one disposable marked `TXT`
record `_artoo-test.example.com`, added and verified, listed as artoo's,
answered by `1.1.1.1` within seconds, removed and verified by 404.

## 15. References

- Proxmox VE API schema: `/usr/share/pve-docs/api-viewer/apidoc.js` on any
  PVE host (pve-docs 9.2.13), copied to `../homelab/api/pve/`; viewer at
  <https://pve.proxmox.com/pve-docs/api-viewer/>. The installed source
  (`/usr/share/perl5/PVE/API2/`) is authoritative for its version.
- Cloud-init on Proxmox: <https://pve.proxmox.com/wiki/Cloud-Init_Support>.
- UniFi Integration API: [API.md](API.md) §1. Cloudflare API: §14. Tailscale API:
  [API.md](API.md) §4; trust credentials and scopes:
  <https://tailscale.com/docs/reference/trust-credentials>.
- Rex: [API.md](API.md) §5; <https://www.superlogical.com/rex>.
- Zig 0.17.0 stdlib: `~/.local/opt/zig/stable/lib/std`.

## 16. Self-update (`artoo update`)

`artoo update` replaces the running binary with a GitHub release, on
macOS and Linux. `.github/workflows/release.yml` (docs/RELEASING.md)
publishes per target `artoo-<ver>-<target>.tar.gz`, holding
`artoo-<ver>-<target>/artoo`, plus `SHA256SUMS`. GitHub API facts: [API.md](API.md) §3.

- **Command.** `artoo update [VERSION] [--check]`. Without VERSION: the
  latest release (never a pre-release or a draft). VERSION (`0.4.0`,
  `v0.4.0`, `0.4.0-rc.1`) is checked as SemVer before any request
  (exit 2); a release that does not exist is exit 2. A downgrade or a
  pre-release happens only when named, and the plan says so. VERSION is
  a positional because `--version` is a global flag (§3.1). No config,
  secret or token is used; the repository `tildaslashalef/artoo` is
  built in.
- **Versions** compare by SemVer precedence (`std.SemanticVersion.order`,
  build metadata ignored): `0.4.0-dev.3+abc` < `0.4.0-rc.1` < `0.4.0`.
  The same version is a no-op (exit 5, nothing downloaded); so is a build
  newer than the latest release (a dev build, docs/RELEASING.md §1)
  unless VERSION is named.
- **`--check`** reads release metadata only: nothing downloaded, no
  prompt. Exit 0 when an update is available, 5 when there is nothing to
  update (`artoo update --check && artoo update -y`); other failures
  keep their codes.
- **Target.** From the build's OS and CPU: `aarch64-macos`,
  `x86_64-macos`, `aarch64-linux`, `x86_64-linux`; any other is refused
  before a request (exit 5). A release without this target's archive or
  without `SHA256SUMS`, or with either asset in a state other than
  `uploaded` (not fully uploaded yet), is exit 4.
- **Transport.** §8.1 with the system roots, never an Authorization
  header. The transport refuses redirects; only the
  updater takes them back, following at most two hops, each `https` to
  `github.com`, `api.github.com`, `release-assets.githubusercontent.com`
  or `objects.githubusercontent.com` (anything else: exit 4). `-v` shows
  a redirected hop's host and path, never its signed query. A used-up
  rate limit is exit 4 with GitHub's message.

  | | Metadata | `SHA256SUMS` | Archive | Binary |
  | --- | --- | --- | --- | --- |
  | Deadline (`--timeout` overrides) | 15 s | 15 s | 120 s | |
  | Size cap | 1 MiB | 64 KiB | 64 MiB | 128 MiB |
- **Verification**, before the plan is shown (so before any change): the
  archive's length equals the asset's `size`; its SHA-256 equals its one
  line in `SHA256SUMS` (`<hex>  <name>`) and the asset's `digest` when
  GitHub gives one. gzip and tar are read with the stdlib only (never
  `tar` or `curl`). Only the entry `artoo-<ver>-<target>/artoo`, a
  regular file present once, is used; every other entry is skipped and
  never written. It is streamed into `<dir>/.<name>.update-<hex>` beside
  the target, `<name>` being the executable's own file name and `<hex>`
  12 random hex digits (exclusive create, 0755, fsync), and that file run
  with `--version` must print exactly `artoo <ver>`. Any mismatch or
  malformed archive is exit 5; the staged file is removed, nothing
  changed. This catches corruption and a changed download; the trust
  root is GitHub's TLS and the release itself (releases are not signed).
- **Replacement.** The target is the running executable
  (`std.process.executablePath`, which follows links). Refused: the path
  artoo was invoked by (argv[0], or the `PATH` entry for a bare name) is
  a symbolic link (exit 5: update what owns its target, or install the
  binary itself); the target is not a regular file or was deleted
  (exit 5); its directory is not writable (exit 3; artoo never runs
  `sudo`). The current binary is copied to `<dir>/.<name>.previous` (one
  generation, atomic, 0755): a copy, not a hard link (Linux's
  `protected_hardlinks`) and not a rename (no moment without a binary).
  Then the staged file is renamed over the target and the directory is
  synced. The new inode avoids Linux's "text file busy" and macOS killing
  a binary whose signed pages changed in place; the running process keeps
  the old one. Shell completion needs nothing (§3.5).
- **Pipeline** (§8.2): read (release, target identity) → plan (no-op
  check, download, verify, stage) → preview → `--dry-run` stops (exit 0:
  downloaded and verified, nothing replaced) → confirm (normal risk,
  `-y`) → after a prompt of 3 s or more, re-read (a changed release or
  target file aborts, exit 5) → back up and rename → verify: the
  installed file's `--version` prints `artoo <ver>`, else exit 8 with
  the rollback command. Every path that does not install the staged file
  removes it. Rollback: `mv <dir>/.<name>.previous <dir>/<name>` (the plan
  and a failed verify print it with the real paths), or `artoo update
  OLDVERSION`.
- **Plan:** current → new version, the release and its date, the asset
  and its size, the SHA-256 and what it matched, the staged binary's
  version, the target path, the backup and the recovery command. `-o
  json` uses target `github`: `current`, `version`, `latest`,
  `update_available`, `asset`, `sha256`, `path`, `backup`, `result`
  (`dry-run`, `applied`); `--check` gives the first five.
- **Testing.** Offline against the fake server, with archives built in
  the test (`std.tar.Writer`, gzip) around a shell script that prints a
  version, installed into a temp directory: newer, same, a dev build,
  explicit and missing VERSION, checksum and digest mismatch, wrong
  version inside, a missing entry, other entries, an off-list redirect,
  unsupported target, symlinked and non-writable targets, dry run,
  declined and non-interactive runs, `--check`, JSON. Live: `--check`
  and `-n` against the published release on a workstation; an actual
  update is the operator's.

## 17. Tailscale

API facts: [API.md](API.md) §4. Tailscale calls its endpoints stable and its OpenAPI
schema unstable: re-read the schema before changing behaviour.

**Scope.** The lab's side of the tailnet: the subnet router's join key
and route (§9.8), the lab's devices (guests on the tailnet), split DNS
for `guests.domain` and `home.arpa`, reading the policy, and replacing
it with a reviewed file under its own credential. Users and roles,
invites, webhooks, log streaming, posture, services and settings stay in
the admin console.

**Credential.** One **OAuth client** (Settings → Trust credentials →
OAuth), owned by the tailnet, not a user; never a personal API access
token (`tskey-api-…`: all of the operator's admin rights, 1–90 days).
Config (§5): `tailscale.client_id` (not secret), `tailscale.tailnet`
(default `-`, the client's own tailnet), `tailscale.timeout_seconds`
(10), `tailscale.guest_tags`. Its secret (`tskey-client-…`) is the
secret `tailscale` (§6), set with `auth set tailscale` and carried by
`config export` (§6.1). Each invocation that needs the API exchanges it
once for an access token ([API.md](API.md) §4; valid one hour), held in memory for
that invocation only.

| Scope | Needed for |
| --- | --- |
| `devices:core` (write), tags `tag:lab-router` and every `tailscale.guest_tags` entry | read, rename and remove devices, set tags; auth keys it creates are limited to its tags |
| `devices:routes` (write) | read and approve the router's advertised route |
| `auth_keys` (write), the same tags | create and delete the join keys |
| `dns` (write) | read and set split DNS |
| `policy_file:read` (+ `devices:core:read`, `devices:posture_attributes:read`, which it requires) | show, validate and preview the policy |

`doctor --connect` reports the granted scopes (the token response's
`scope`) against this table, and compares `tag:lab-router` plus
`tailscale.guest_tags` with the token response's `tags` when present.
The documented response names scopes only; then doctor says which tags
the client needs, and Tailscale refuses an unowned tag when a key is
created (400, before anything reaches a guest).

Protection model: a leaked secret can add tagged devices, approve routes
and rename or remove devices, but cannot change who may reach what.
`doctor --connect` fails the check when the main client's token grants
`policy_file` or `all`; `doctor` fails when `tailscale.client_id` equals
`tailscale.policy_client_id`. Revoking the client revokes its access
tokens, not the auth keys it made; artoo's keys are single-use and
expire in 10 minutes, so none outlives a run.

**Policy credential.** Writing the policy needs `policy_file` (write),
which the main client never holds: a second OAuth client with
`policy_file` (+ `devices:core:read`, `devices:posture_attributes:read`),
config `tailscale.policy_client_id`, secret `tailscale-policy` (`auth
set|status|rm tailscale-policy`). Only `ts policy apply` uses it, and
neither credential falls back to the other. `config export` never
carries it (§6.1). The operator creates it for a policy change and
revokes it afterwards. `doctor` shows "not stored" without a warning
when it is absent; when stored, `--connect` exchanges it and reports its
scopes.

**Transport.** `https://api.tailscale.com/api/v2`, `Authorization:
Bearer <access token>` injected at request time; TLS against the
operating system's root store, as Cloudflare (§14); deadlines, no
pooling and no write retries as §8.1. Errors are an HTTP status with
`{"message": …}`, sanitized into the error; every server-sent ID or name
is sanitized wherever shown (request paths, confirmation targets, plans,
errors). `429` is reported as rate limited, never retried by a write. A
write answered with another `5xx` is an unknown outcome, except `501`,
the API's documented definitive refusal (e.g. "Device not owned by
tailnet" on `DELETE /device`): a refused step, nothing applied. No
pagination: lists arrive whole.

**Ownership.** Writes touch **lab devices only**: a device tagged
`tag:lab-router` or a `tailscale.guest_tags` entry, or one whose name is
a VM on Proxmox tagged `artoo` whatever its tag (a guest that joined
under its own purpose tag stays a lab device). A device shared in from
another tailnet (`isExternal`) is never a lab device, nor the subnet
router, whatever its tags or name. The operator's own devices are
listed, never renamed, retagged or removed. The router's
routes may be set only to the LAN (`guests.gateway`'s subnet): never an
exit node, never another subnet. Split DNS writes touch only
`guests.domain` and `home.arpa`, both pointing at the gateway.

**Join keys.** `router setup` and `ts join` create their own auth key
(`POST …/keys`): single-use, preauthorized, not ephemeral, one tag,
expiry 10 minutes, description `artoo router <vm>` or `artoo join <vm>`
([API.md](API.md) §4's character rule). It goes over the guest agent's stdin into a
0600 file under `/run`, passed as `file:` and removed whatever happens,
and is never displayed. A failed run that left it unused deletes it;
when that delete fails, the key step is marked failed with the key's ID
and expiry (the creation response's `expires`, else about ten minutes
on), so the operator can delete it sooner. The device is always the
node the guest reports (`Self.ID`, the API's `nodeId`), never one found
by name (a stale device may keep the name). No command prints a key for
a machine that is not a guest; other machines join from the console.

**Commands.** NAME is a machine name, MagicDNS name or node ID.

- `ts devices ls`: NAME, TAGS, ADDRESS (the IPv4 address), OS, LAST
  SEEN, KEY EXPIRY, ROUTES (advertised and approved), LAB (whether it is
  a lab device; by tag only when Proxmox cannot be read, which a note
  says) and ID. `ts device show NAME`: names, node ID, OS and version,
  addresses, tags, lab standing, then last seen, key expiry,
  authorization and routes.
- `ts dns show`: nameservers, MagicDNS, search paths, split DNS.
- `ts keys ls`: the key metadata the client may see — ID, TYPE,
  DESCRIPTION, TAGS, FLAGS (`reusable` or `single-use`, `ephemeral`,
  `preauthorized`), CREATED, EXPIRES, STATE (`valid`, `invalid`); never
  a key's value.
- `ts policy show [--json]`: the policy as stored (HuJSON) or as JSON.
- `ts policy validate FILE` (read-only): valid only on the documented
  answers, `{}` or `data` entries with warnings and no errors; any other
  shape is invalid (exit 8). A file that is a JSON list (the endpoint's
  mode that tests the live policy) is refused before anything is sent.
- `ts policy preview USER|IP:PORT` (read-only): which rules match.
- `ts device rename NAME NEW`: NEW must be one lowercase DNS label,
  letter first, 2–40 characters (else exit 2); `POST /device/{id}/name`,
  verified by a fresh read; refused when another device has NEW. A device that is a
  lab device only by its VM name (no lab tag) keeps that standing only
  under an artoo VM's name: NEW must be one, else refused (`vm rename`
  renames the guest itself, §9.18).
- `ts device tag NAME TAGS`: `POST /device/{id}/tags` with the whole
  list (comma-separated, duplicates folded), verified by a fresh read.
  Every tag must be in `tailscale.guest_tags`, else refused before
  anything is sent; `tag:lab-router` is never accepted and the subnet
  router is refused (its tag belongs to `router setup`). Tailscale
  refuses a tag the client or the policy's `tagOwners` does not name
  (400, nothing changed), and refuses to remove a tag the node
  advertises itself ("cannot remove current tags"); that error names
  `ts join VM --tag TAG`. So `ts device tag` suits devices tagged
  through the API or the console. Moving a guest to a new tag: the tag
  into `tagOwners` (`ts policy apply`), given to the OAuth client (on
  `devices:core` and `auth_keys`), added to `tailscale.guest_tags`, then
  `ts join VM --tag NEW`; the old tag leaves the policy last.
- `ts device rm NAME`: typed confirmation; `DELETE /device/{id}`,
  verified by a read answering 404.
- `ts routes approve ROUTER`: `POST /device/{id}/routes` with exactly
  the LAN, after reading what the device advertises. Refused when it
  does not advertise the LAN, and for any device but the subnet router
  (tagged `tag:lab-router`, or named after an artoo VM tagged
  `role-router`).
- `ts dns split set DOMAIN NAMESERVER…`: `PATCH …/dns/split-dns` with
  that one domain (others untouched), verified by a fresh read.
- `ts join VM [--tag TAG]` enrolls a running guest tagged `tailnet`
  (§9.6) as a tagged node, with `--tag` (which must be in
  `tailscale.guest_tags`, else refused before planning) or the list's
  first entry: `tailscale up --advertise-tags=<tag> --hostname=<vm>
  --accept-routes=false --advertise-routes= --accept-dns=false
  --ssh=false`, with a join key. Refused (exit 5): a template, a guest
  not tagged `artoo` or `tailnet`, `role-edge`, `role-watch` and
  `role-router` (which joins with `router setup`), a stopped guest, a
  silent agent. A guest whose `tailscale status` says `Running` is only
  reported (exit 5, nothing created), unless `--tag` names a tag it does
  not carry alone: then it **moves** to that tag. A node's advertised
  tags change only when it logs in again (Tailscale logs out a node
  whose `--advertise-tags` changes), so the move is the join with
  `--force-reauth`: a new key with the new tag, the same node and
  address, connections down for a few seconds; the plan shows old → new
  tags. Verified by the guest's `tailscale status --json` (`Running`,
  the tag) and its device in the API with the tag.
- `ts policy apply FILE` (HuJSON, the policy credential):
  1. Refused before any request (exit 5, no override) when the file is
     not HuJSON or a `nodeAttrs` entry's `attr` names `funnel` (§9.6).
     Tailscale reads keys case-insensitively, as Go's JSON decoder does
     (Unicode folds such as U+017F included): artoo compares keys
     ASCII-case-insensitively at every level it inspects, checks every
     matching key, and refuses any non-ASCII object key.
     A file over 1 MiB is a usage error (exit 2).
  2. Read the live policy (HuJSON) and its `ETag`; an answer without
     one is a protocol error (exit 4), since the write is sent only
     against the version read.
  3. `POST …/acl/validate` with the file (errors → refused, exit 5;
     Tailscale runs the file's `tests`).
  4. Plan: a unified diff live → file; a file whose text equals the live
     policy has nothing to change (exit 5). High impact, typed confirmation
     of the tailnet's name (`tailscale.tailnet`, or the suffix of the
     MagicDNS name of a device not shared in from another tailnet,
     `isExternal`; `--confirm` non-interactively). `-n` stops here.
  5. Sent once: `POST …/acl`, `Content-Type: application/hujson`,
     `If-Match` set to the ETag as received (quoted, as the document's
     example). `412` → refused, "changed since it was read", nothing
     applied.
  6. Verified by a fresh read whose text (outer whitespace aside) or
     JSON equals the file.

**Into existing commands**, each only when `tailscale.client_id` is set
and the `tailscale` credential is stored (otherwise without the tailnet
part):

- `router setup` (§9.8) creates its join key, approves the route as `ts
  routes approve` does and checks that the device's key expiry is off.
- `router status` adds the device's tags, approved and primary routes,
  key expiry and last seen.
- `vm rm` of a guest that is a lab device plans removing that device
  after the VM is destroyed.
- `vm rename` (§9.18) checks the device's name and renames it when the
  guest's own `tailscale set --hostname` did not change it.

**Testing.** Offline: a fake server for the token exchange, every
endpoint used, `{"message"}` errors, `429`, and every refusal (non-lab
device, a route other than the LAN, a key value reaching output). Live
runs, each under an approved plan: read-only first (`doctor --connect`,
`ts devices ls`); then a disposable guest joined, renamed and removed;
the router flow when a router is rebuilt.

## 18. Rex on guests

[Rex](https://www.superlogical.com/rex) is a terminal and multiplexer
whose server runs on a guest and whose client runs on the workstation;
sessions outlive the connection. artoo installs it on ordinary guests
that run coding agents (Claude Code, Antigravity `agy`), sets the agents
up the same way on each, and lets the lab's own operations (reboots,
upgrades, removal, renames) know an agent is working there. Rex's
packages, files and CLI: [API.md](API.md) §5.

### 18.1 Scope

- **Which guests.** Ordinary artoo guests: running, tagged `artoo`, not
  a template, and not the edge, the router or the watchdog (roles
  `edge`, `router`, `watch`, §9.7–§9.9). A guest with Rex carries the
  Proxmox tag `rex`; `rex status` without a VM, `rex hosts sync` and
  the reboot guard (§18.8) find guests by it.
- **Access.** Rex for Mac reaches a guest at `ssh://<guests.user>@<fqdn>`
  through the SSH config of `vm ssh-config` (§9.10). The guest runs no
  Rex listener: sshd authenticates, Rex has no authentication of its own.
- **What artoo installs.** Rex from Superlogical's apt repository,
  signed by a pinned key; nothing is built on the guest. The agents
  (Claude Code, `agy`) are the operator's to install and sign in to.
  artoo never reads, writes or copies an agent's credentials
  (`~/.claude/.credentials.json`, `~/.gemini/` OAuth state).
- **Updates.** Rex updates arrive with `vm upgrade` (§9.12), not with
  unattended upgrades, which install only Ubuntu's release and
  `-security` pockets (§9.1): a preview's changes are the operator's to
  take. A personal server keeps running, with its
  sessions, after an upgrade and runs the new version once it stops
  (`rex status` says when the two differ). `vm upgrade` never restarts
  it: needrestart's default configuration leaves `user@N.service` alone
  on the baseline's Ubuntu 26.04. A reboot ends every session.

### 18.2 Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `rex.channel` | `preview` | apt suite: `preview`, `snapshot` or `stable`. `rex setup` writes it; a change takes effect on the next `rex setup`. |
| `rex.default` | `false` | `true`: `vm new` sets up Rex on every ordinary guest it creates (`--no-rex` opts out); `false`: only with `--rex`. |
| `agents.profile` | empty | the agent profile's directory on the workstation (§18.5); empty: no profile. |

### 18.3 `rex setup VM…`

Through the guest agent as root, one plan for every guest named (a
change row per guest), confirmed once (risk normal). Each step reads the
guest first and is reported, not redone, when its state is already
right: a rerun on a set-up guest changes nothing and says so (exit 0,
"nothing to change").

1. **apt key**: `/etc/apt/keyrings/rex-archive-keyring.gpg`, the binary
   keyring embedded in artoo ([API.md](API.md) §5), compared by SHA-256.
2. **apt source**: `/etc/apt/sources.list.d/rex.sources` (deb822, suite
   `rex.channel`, the guest's architecture).
3. **apt pin**: `/etc/apt/preferences.d/rex`, exactly upstream's file
   (Rex's origin at 1001, every other origin at −1). Ubuntu's archive
   carries an unrelated `rex` (a Perl tool) that must never win.
4. **package**: `apt-get update`, then upstream's install command, both
   with `-o DPkg::Lock::Timeout=300` as `vm upgrade`, when `rex` is
   missing or not Superlogical's (its Maintainer field, as upstream's
   installer judges it). A guest already on Rex keeps its version
   (updates are `vm upgrade`'s). The guest is read again after the
   install; terminfo and the skill are decided then. `rex status` judges
   the origins by `apt-cache policy rex`.
5. **linger**: `loginctl enable-linger <guests.user>`, so sessions
   survive the last logout. artoo uses `loginctl` rather than `rex
   server install` (which also enables a user socket), so the server
   still starts on first use and stops when idle.
6. **terminfo**: `rex terminfo setup --system` when `rex terminfo
   status` is not `Ready`.
7. **agent skill**: as the guest user, `rex skill setup --session-naming
   --agent A` for each harness `rex skill status` detects (Claude Code,
   Codex, OpenCode, pi) with an item outdated or missing or session
   naming off; skipped with a note when none is detected. Claude counts
   as detected when the agent profile writes under `~/.claude`: Rex
   detects Claude by that directory, which step 9 creates on a fresh
   guest, after this step has run. Items Rex
   reports `foreign` or `unreadable` are left alone and named in the
   plan; a `foreign` item is replaced only by `rex skill setup --force`
   on the guest, never by artoo.
8. **agy bridge** (§18.4), when `agy` is on the guest user's PATH.
9. **agent profile** (§18.5) when `agents.profile` is set, and the
   **permission kind** (§18.6) always: for Claude where it is (on the
   PATH, or `~/.claude/settings.json` exists), for agy where it is. The
   guest is read again just before this step, so the merges keep what
   steps 7 and 8 wrote.
10. **tag** `rex`, added with the config digest.

Commands as the guest user run through `runuser -u USER -- env HOME=…
XDG_RUNTIME_DIR=/run/user/UID REX_AUTOSTART=0 PATH=…`, never a login
shell (the user's shell is fish), so no step starts a Rex server. `rex
terminfo setup --system` runs as root (`HOME=/root`); every other `rex`
command as the guest user. Scripts on the guest use `jq` (in the
baseline, §9.1).

**Refusals** (exit 5, nothing sent): a template, a guest not tagged
`artoo`, a role `edge`, `router` or `watch`, a stopped guest, a guest
whose agent does not answer, an `agents.profile` that is not a directory
or holds a refused file (§18.5). Every guest is read first; one refused
guest refuses the whole run, naming it.

After the steps, and on a run with nothing to change, `rex status`'s
checks (§18.7) run for each guest; a failed check → exit 8. With `-o
json`, a run with nothing to change prints the envelope `{result:
"unchanged", guests}` and runs no checks.
`--force-profile` overwrites profile files changed on the guest (§18.5).

### 18.4 The agy bridge

Rex has no harness for `agy`. artoo bridges it, and steps aside when
`rex skill status` lists an `agy` harness (the bridge is then a no-op,
reported):

- **Skill**: `~/.gemini/config/skills/rex/SKILL.md`, a stub that runs
  `rex __internal skill` for the guide, as Rex's own stub does.
- **Hooks**: the key `artoo-rex` in `~/.gemini/config/hooks.json` (other
  keys kept), whose commands run `~/.config/artoo/agy-rex-hook EVENT`:
  - `SessionStart` injects the text of `rex __internal session-start
    --agent claude` as a system message (its context is agent-neutral);
  - `PreInvocation` reports `working` and `Stop` reports `done`
    (`USER_CANCELED` → `idle`, `ERROR` → `error`), with OSC 7501
    (`state=S:app=agy`, no `msg`) written to `/dev/tty`.

  Timeouts: 10 s for `SessionStart`, 5 s for the others. Outside Rex
  (`REX_BLOCK` unset) the hook prints `{}` and does nothing. It always
  exits 0 and prints valid JSON, so a Rex fault never stops an agent.

### 18.5 Agent profile (`agents.profile`)

One directory on the workstation, the same for every guest; `rex setup`
copies it, and copies it again after it changes.

| Profile path | Guest path |
| --- | --- |
| `rules/AGENTS.md` | `~/.claude/CLAUDE.md`, and `~/.gemini/config/AGENTS.md` when `agy` is present |
| `skills/NAME/**` | `~/.claude/skills/NAME/**`, and `~/.gemini/config/skills/NAME/**` when `agy` is present (`skills/rex` is skipped: `rex skill setup` owns it) |
| `claude/settings.json` | merged into `~/.claude/settings.json` |
| `claude/**` (other files; a top-level `claude/README.md` skipped) | `~/.claude/**` |
| `agy/settings.json` | merged into `~/.gemini/antigravity-cli/settings.json` |
| `agy/hooks.json` | merged into `~/.gemini/config/hooks.json` |
| `agy/**` (other files) | `~/.gemini/config/**` |

Anything else in the directory (a `README.md`, `.git/`, `.DS_Store`) is
ignored. Only the rows that say so depend on `agy` being present; the
`claude/**` and other `agy/**` rows are written whatever is installed;
the permission kind alone follows which agents are there (§18.3 step 9).
Every guest-side read and write of the profile runs as the guest user,
never root: the home's links are the user's to set, and root following
one would reach outside it. Files keep their executable bit (0755, else
0644), owned by the guest user.

- **Merged JSON**: objects merge key by key at every depth, the
  profile's value winning on a leaf; arrays are joined, the profile's
  entries first and then the guest's extra ones, each value kept once;
  the top-level `hooks` merge per event, an entry kept once (by
  command), the profile's last; a key only the guest has is kept. So an
  agent's own state on the guest (an effort level, an "always allow"
  answer) and Rex's own hooks survive; the permission kind is applied on
  top (§18.6). A guest file that already holds the merge is current. A merged
  file is never "changed on the guest"; one that is not a JSON object on
  the guest is left alone and named (plan, `rex status`).
- **Copied files**: the manifest `~/.config/artoo/agent-profile.json`
  (`{"files": {PATH: SHA256}}`) on the guest records what artoo wrote. A
  guest file equal to the profile is current; one absent, or equal to
  the manifest's hash, is written; one changed on the guest since (or
  never written by artoo) is left alone and named in the plan and in
  `rex status` ("changed on the guest"), and `--force-profile`
  overwrites it. A file dropped from the profile stays on the guest,
  named in the plan. A directory where a profile file goes is left
  alone and named, even with `--force-profile`.
- **Refused** (the run refuses, naming the file, never its content):
  `.credentials.json`, `credentials`, `credentials.json`,
  `oauth_creds.json`, `.netrc`, `.env`, `.envrc`, `.env.*`, `*.pem`,
  `*.key`, `*.p12`, `*.pfx`, `id_*` without `.pub`, a symbolic link, any
  file containing `PRIVATE KEY`, a merged JSON file (`claude/settings.json`,
  `agy/settings.json`, `agy/hooks.json`) whose `env` names a variable
  that looks like a secret (containing `KEY`, `TOKEN`, `SECRET`,
  `PASSWORD`, `PASSWD` or `CREDENTIAL`, in any case), two profile files that land on one guest
  path, a file over 1 MiB, a profile over 4 MiB or 500 files.
- MCP servers are not part of the profile: Claude keeps them in
  `~/.claude.json`, its own state file.

### 18.6 Permission kinds

How freely the agents act depends on what the guest can reach:

| Kind | When | Claude | agy |
| --- | --- | --- | --- |
| `sandboxed` | the guest is fenced (tag `fenced`, §9.11) **and** the guest user holds no private key in `~/.ssh` (a file whose first line names `PRIVATE KEY`) | `permissions.defaultMode` `bypassPermissions`; `disableBypassPermissionsMode` removed | `~/.config/fish/conf.d/artoo-agents.fish` defines `agy` as `agy --dangerously-skip-permissions` |
| `trusted-reach` | every other guest | the profile's `defaultMode` kept unless it is `bypassPermissions` (then `default`); `permissions.disableBypassPermissionsMode: "disable"` | the fish file defines nothing |

A fenced guest holding keys is `trusted-reach`, and the plan names the
keys ("fenced, but holds ~/.ssh/id_ed25519"). The kind is decided on
every `rex setup`, so fencing or unfencing a guest changes it on the
next run. `rex status` and `vm verify` warn when an agent may run
unrestricted (`bypassPermissions` in Claude's settings, or the fish
file's flag) on a guest that is not `sandboxed`.

### 18.7 `rex status [VM…]`

Read-only. Without a VM: every guest tagged `rex`. One embedded script
through the guest agent gathers everything as one JSON object; only the
fields below leave the guest.

| Check | ok | warning | failed |
| --- | --- | --- | --- |
| package | Rex's origin, version | — | missing, or another origin |
| apt pin | Rex 1001, others −1 | Ubuntu's `rex` not at −1, Rex's origin not at 1001 or unknown to apt, the pin file missing or not upstream's | — |
| linger | on | off (sessions end at logout) | — |
| server | running version, sessions | installed ≠ running ("runs X; Y once it stops"), not running | — |
| terminfo | `Ready` | not ready (`artoo rex setup VM`) | — |
| skill A | current (a `foreign` or `unreadable` item named, left alone) | an item outdated or missing, session naming off | — |
| agy bridge | current | missing or changed | — |
| profile | N files current | changed on the guest, or behind the workstation's profile | — |
| permissions | the kind | unrestricted on a guest not `sandboxed` | — |
| agent (one per terminal with a status) | `claude-code working in naboo-api` | `blocked` (waiting for the operator), `error` | — |

A read that fails is its row's warning: `server`, `terminfo` and `skill`
"could not be read as the guest user", `terminfo` and `skill` "status
unreadable", and one `agents` row "not all read" when a program-status
read fails. `profile` fails when `agents.profile` cannot be loaded or the
guest's files cannot be read; a probe that fails as a whole is one
failed row `rex`. A row that is not checked says why (no agent, no
profile set). A stopped guest, or one whose agent does not answer, shows
the rows package, apt pin, linger, server, terminfo and skill as not
checked, which is not a failure. A terminal's records (an agent and its
subagents) fold into one row with the most pressing state (blocked,
error, working, done, idle). A named VM not tagged `rex` is refused
(exit 5, naming `rex setup`). Several guests: one block per guest, then
a summary line. `-o json`: the envelope (§4.2) with `collected_at`,
`failed` (the guests with a failed check) and a list of `{vm, vmid,
checks: [{check, status, detail}], agents: [{session, block, app, state,
title, updated_at}]}`. Any failure → exit 8.

### 18.8 Agents and the lab's own operations

- **`vm reboot --pending`** reads each `rex` guest's agents first and
  skips a guest where one is `working` or `blocked` ("naboo (claude-code
  working in naboo-api)") and one whose agents cannot be read, and reads
  them again just before each reboot, unless the run was confirmed with
  the typed target below. `--force-agents` includes them all; the plan names the agents and, when a busy or unreadable guest is
  actually included, the risk is destructive: the confirmation becomes
  the typed target `every-guest` (`--yes --confirm every-guest`
  non-interactively). When nothing was busy at the plan (only y/N
  asked), a guest busy by its turn is still skipped. A server socket
  that does not answer, or an answer `jq` cannot read, counts as
  unreadable, never as "no agents". Whether each guest is busy is part
  of the plan's fingerprint.
- **`vm upgrade`** names, in its plan, the agents working on each `rex`
  guest (or that they could not be read), and goes ahead: it reboots nothing and restarts no user
  session (§18.1).
- **`vm rm`** and **`vm rename`** remove or rename the guest's Rex host
  on the workstation when artoo recorded it (§18.9, §9.3, §9.18).

### 18.9 `rex hosts sync`

The workstation's Rex hosts (`rex hosts`, on its home server): one host
per guest tagged `rex`, labelled with the guest's name, endpoint
`ssh://<guests.user>@<fqdn>`. artoo records the labels it manages in
`~/.artoo/rex-hosts.json`.

- A missing host is added; a recorded host whose endpoint differs is
  edited; a recorded host whose guest is gone or no longer tagged `rex`
  is removed. A recorded label with no Rex host any more is dropped from
  the record ("recorded, no longer a Rex host"). Removal is part of the
  same confirmed plan and touches only hosts artoo recorded.
- A host with the guest's label and exactly the wanted endpoint is
  adopted (recorded, nothing sent). One with other endpoints that artoo
  did not add is left alone and named in the plan, with the commands
  that let artoo manage it (`rex hosts remove LABEL`, then sync again).
- The `rex` CLI is found on the PATH or in Rex for Mac's bundle
  ([API.md](API.md) §5). Without it, or without a running Rex on the
  workstation, the command refuses (exit 5); it never starts Rex. `vm
  rm` and `vm rename` skip their Rex step with a note then.
- Nothing to change (foreign hosts aside, which it names) is a no-op
  (exit 5).

### 18.10 Testing

Offline: the probe script's JSON for every state (a fresh guest, Rex
from another origin, wrong pins, linger off, a stale server, an
outdated skill, profile drift, each permission kind); the profile's
refusals; the JSON merges; the bridge's hook output for each event; the
hosts plan from a fake `rex` runner; the reboot guard. Live runs, each
under an approved plan (§13): a disposable guest with `vm new --rex`, a
Rex session over SSH from the workstation, `rex status` with an agent
working, `rex hosts sync`, the reboot guard, and `vm rm`; the bridge's
OSC from a hook process (`/dev/tty`) and Rex's session-start text for
`agy` are checked there.
