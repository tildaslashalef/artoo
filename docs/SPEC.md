# artoo — design specification

Status: **artoo 0.1 design.** artoo began as a clean rewrite of an
earlier prototype, with no backward compatibility to its code, config,
commands or Keychain items. Dates in parentheses record when a decision
was taken. This document is the contract for behavior; it does not claim
anything is implemented.

## 1. Purpose

`artoo` is the operator's single, fast CLI for a home lab:

- **Proxmox** — one host running Proxmox VE 9.2 (e.g. `https://pve.home.arpa:8006`).
- **UniFi** — a UniFi gateway such as the Cloud Gateway Ultra (e.g. `https://unifi.home.arpa`, Integration API).
- **Cloudflare** — the public DNS zone `example.com` and Cloudflare Tunnel,
  only for guests explicitly made public (§15).

End-to-end goal: from the workstation, inspect and operate both systems, and run one
command that produces a ready Ubuntu guest — guest user and shell
environment configured, reachable as `<name>.lab.example.com` through a DNS
record on UniFi (§9.6) — and one command that removes it cleanly again.
Infrastructure keeps its private `home.arpa` names and is never publicly
exposed (§9.6).

Native Zig 0.17.0 binary, standard library only, no runtime dependencies.
Client platforms: **macOS arm64** (primary workstation) and **Linux
arm64/amd64** (e.g. a guest or another machine), with identical commands,
config and behavior; only the credential store backend differs (§6).

Out of scope for v1: host package management, clustering/Ceph, LXC
management (reported, not managed), consoles/VNC, a TUI, backups, tailnet
administration (policy, DNS, keys — the operator's console; the subnet
router's own enrollment is in scope, §9.8), gateway firmware/OS
administration.

## 2. Principles

1. **Efficient to type, obvious to read.** Noun–verb grammar, positional
   targets, names accepted wherever IDs are, short flags for common options,
   output designed for a human first and JSON on request.
2. **Honest.** Missing data is `--`/`null`, never zero. A check that did not
   run is "not checked", never "ok". An ambiguous write is "unknown", never
   success. Partial results are shown and exit non-zero.
3. **Safe mutations, one pipeline.** Every write: validate → plan → preview →
   confirm → send once → track → verify (§8).
4. **Proportionate security.** TLS verified against the mkcert root; secrets
   never printed, logged, put in argv/env/config/Git. No ceremony beyond that
   (no custom code-signing, no in-process wiping rules, no multi-token role
   matrices).
5. **Typed, tested, small.** Typed API models, offline tests for every
   command's parsing/planning/rendering, live tests only as explicit runs.

## 3. Command interface

Grammar: `artoo <noun> <verb> [TARGET…] [flags]`. Global flags are accepted
anywhere after the program name. `artoo help <noun> [verb]` and `-h` on any
command print usage **with every flag, its type/default and examples** — all
generated from the same declarative command table that drives parsing, so
help and behavior cannot diverge. Unknown commands suggest the closest match.

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
| `--config PATH` | Alternate config file |

### 3.2 Targets

- `VM` is a numeric VMID or a VM name. Names must match exactly one VM;
  ambiguity is an error listing the candidates. Templates are VMs too.
- `TASK` is a UPID or any unique suffix/prefix shown in `task ls`
  (artoo prints short task handles, e.g. `qmstart:9010@14:32`, and accepts
  them back).
- Gateway objects accept their ID or their unique name (`dns rm web-01`).

### 3.3 Command tree

```text
artoo status                          one-screen overview of the lab (§11)
artoo doctor [--connect]              local install/config/keychain/CA checks

artoo host  show | health [CHECK…]    Proxmox node: versions, CPU/RAM/load, uptime
artoo storage ls | show STORAGE
artoo task  ls [--running|--failed] [-l N] | show TASK | log TASK [--all] | wait TASK

artoo vm ls [--all] [--status S] [--name GLOB]
artoo vm show VM | config VM          pending values marked (§9.13)
artoo vm urls VM                      service URLs and public hosts that reach the VM
artoo vm start|shutdown|reboot VM
artoo vm stop VM                      forced stop (destructive confirmation)
artoo vm set VM KEY=VALUE…            allowlisted config keys, digest-guarded
artoo vm clone VM NEWNAME [--id N]
artoo vm rm VM [--keep-dns]           destroy VM + disks (+ its DNS record)
artoo vm snap ls VM | add VM NAME | rm VM NAME | rollback VM NAME
artoo vm new NAME [--size S] [--cores N] [--memory SIZE] [--disk SIZE] [--ip ADDR]
                 [--id N] [--template T] [--no-dns]
artoo vm verify VM|--all [--no-dns]   read-only readiness checks (§9.4)
artoo vm upgrade VM                   install the guest's pending package updates (§9.12)
artoo vm ssh VM [-- CMD…]             exec ssh <user>@<address> (convenience)
artoo vm ssh-config                   write ~/.artoo/ssh_config: strict plain ssh/scp/rsync (§9.10)
artoo vm cp SRC DST [-r] [--force]    copy as <user> to, from or between guests, SHA-256 checked (§9.10)
artoo vm password VM                  print the guest user's password (TTY only, §7)
artoo vm fence VM [--off]             Proxmox NIC firewall around a guest (§9.11)

artoo template ls | show T | build T [--id N] | rm T | vendor [T]
artoo image ls | fetch IMAGE | rm IMAGE    pinned images on Proxmox (never the workstation)

artoo gw info                         UniFi: app version, site, WAN, counts
artoo gw <resource> ls|show|…         full Integration API surface (§10)
artoo gw spec                         live OpenAPI vs built-in catalog drift report
artoo dns ls | add NAME IP | rm NAME  shortcut for gw dns-policy A records
artoo cf dns … | cf tunnel …          Cloudflare zone records + tunnel routes (§15)
artoo svc ls | add NAME VM:PORT [--health PATH [--health-down TEXT]] | set NAME VM:PORT [--health …] | rm NAME
                                      service names on the edge VM (§9.6)
artoo watch setup | status | enroll VM…|--all | secret grafana|phone | forget HOST
                                      the watchdog VM `scarif` (§9.9)

artoo config show | get KEY | set KEY VALUE | unset KEY | edit | init
artoo config export FILE | import FILE   artoo's setup to another machine (§6.1)
artoo completion fish|bash|zsh        print the shell completion script (§3.5)
artoo update [VERSION] [--check]      replace this binary with a verified GitHub release (§18)
artoo auth set pve|unifi|cloudflare | status | rm pve|unifi|cloudflare
```

Command availability follows delivery: a command is absent from the table
(and therefore from help) until it works.

### 3.4 Confirmation

- Normal mutations: preview, then `Proceed? [y/N]`. Non-interactive without
  `--yes` refuses (exit 5).
- **Destructive** (`vm rm`, `vm stop`, `vm snap rollback|rm`, `template rm`,
  gateway deletes, firewall/ACL/network/Wi-Fi changes, generic `gw api`
  writes): interactive mode requires typing the target's name; non-interactive
  mode requires `--yes --confirm TARGET` where `TARGET` equals the resolved
  name or ID.

### 3.5 Shell completion

`artoo completion fish|bash|zsh` prints a thin
script; on every Tab it runs the hidden `artoo __complete -- WORDS…` (the
words after `artoo`, the last one being completed, maybe empty), which
prints `candidate<TAB>description` lines or the directive `:file` (the
shell's own path completion). Candidates come from the same command table
that drives parsing and help — nouns, verbs, `help <noun> [verb]`, flags
(global ones included) and their choices — so a new command completes
without regenerating the script. A positional may declare live candidates:
**VM names** (`VM` arguments) and **template names** (`TEMPLATE`), read
from Proxmox with a 1 s deadline; any error, timeout or missing secret
completes nothing. `vm new NAME` offers the **curated guest names**
(§9.1) that no VM or template carries; without Proxmox it offers all of
them. Nothing else touches the network or prompts, and stdout
never carries an error message.

## 4. Output

### 4.1 Human output

One shared rendering kit (`ui/`) used by every command:

- **Header line**: `ARTOO · <context>` left, target + collection time right.
- **Tables**: column specs (title, alignment, min width, priority). Numbers
  right-aligned; width-aware (drop low-priority columns on narrow terminals;
  identifiers are never truncated); UTF-8-safe truncation with `…`.
- **Values**: IEC sizes (`1.8 TiB`), percentages with one decimal, `used /
  total (pct)` plus an optional 10-cell bar, relative times (`2m ago`,
  `in 3d`) with absolute time in `show`/JSON, durations (`3h 12m`).
- **Status**: a word plus color and glyph (`● running`, `○ stopped`,
  `✓ ok`, `▲ warning`, `✗ failed`, `– not checked`); ASCII fallbacks.
- **Detail views** (`show`): aligned key/value sections.
- **Plans**: the preview block (target, current → intended, impact,
  recovery) shown before every confirmation.
- **Progress**: live step lines for multi-step writes (§4.4); an activity
  line while a command reads before printing (§4.5).
- Gruvbox dark palette (truecolor, 256-color fallback, none):

| Role | Color |
| --- | --- |
| text / muted / border | `#ebdbb2` / `#a89984` / `#504945` |
| titles, IDs | `#83a598` |
| ok / warning / failure | `#b8bb26` / `#fabd2f` / `#fb4934` |
| changed / emphasis / high-impact | `#8ec07c` / `#d3869b` / `#fe8019` |

All server- and user-supplied strings are sanitized for terminal controls
(C0, DEL **and** C1, including UTF-8-encoded C1) before rendering.

### 4.2 JSON

`-o json` prints exactly one document on stdout:
`{"schema_version":1,"target":"pve|unifi|cloudflare|github|local","data":…,"meta":{…}}`,
where `meta` carries collection times, pagination and per-section errors.
No ANSI, no prose on stdout; errors are a JSON object on stderr. Values are
raw units (bytes, seconds, fractions → documented), missing values `null`.
JSON and tables are rendered from the same view model.

Workflows with a step ledger (§4.4, §8.2) add it to their result,
`data.steps` (with `data.result` `applied`/`accepted`), and — when they
fail after steps ran — to the error object, beside `error`: one object per
step, `{"name", "state" (done|failed|not_run|unknown|skipped), "detail",
"seconds"}`, `seconds` null for a step that never ran. A failure before
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

Every workflow that keeps a step ledger (§8.2: `vm new`, `vm rm`, `template build`, `edge
setup|tunnel`, `svc add|set|rm`, `cf tunnel route add|rm`, `router setup`,
`watch setup|enroll`, …) shows its steps **while they run**, on **stderr** (stdout keeps
results). The ledger drives it: a step is shown when it starts and
finalized when it ends; long waits update the running step's detail
through a `Note` (ledger + step) they are handed — a note never starts or
ends a step:
- Proxmox tasks (`template build`'s fetch, create and convert): the task
  log's newest non-empty line, read incrementally (`log?start=N`) each
  poll — download progress, disk import.
- cloud-init (`vm new`): `cloud-init status --format json` polled every
  3 s instead of one `--wait`; while `running`/`not started` its `stage`
  is the note ("stage modules-final"), else its `detail` (the datasource,
  `DataSourceNoCloud [seed=/dev/sr0]` — seen live 2026-10-11); the final
  status is judged as before.
- The Caddy build (`edge setup`): the script writes its stage ("installing
  Go", "building xcaddy …", "building Caddy … (modules, then compile)",
  "checking the binary", "removing Go") to `/run/artoo-caddy-build.stage`
  (removed on exit); artoo reads it through the guest agent about every
  2 s while the script runs. A missing file or failed read reports
  nothing.
  Verified live (2026-10-11) against a disposable guest: the cloud-init
  detail note and `vm rm -o json` with all six steps and durations. Not
  yet seen live: the `stage …` note, the template build's task-log line,
  the Caddy build stages (offline tests only).

- **Terminal** (stderr is a TTY, no `-v`): finished steps stay as lines;
  the running step is one line redrawn about ten times a second — a
  spinner (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`; `|/-\` with `--ascii`), its name, elapsed time
  and the latest detail, cut to the terminal width (never wraps). When it
  ends it becomes its final line (`✓ wait for cloud-init  2m 05s  …`,
  `✗ …`). A total time follows the last step. The redraw runs as one
  concurrent task (`io.concurrent`); where concurrency is unavailable the
  line is redrawn only on step and detail changes (no animation, same
  result). The cursor is not hidden, so an interrupt leaves a normal
  terminal; the pipeline ends any open line before printing an error.
- **Not a terminal** (or `-v`, whose trace lines would collide with the
  redraw): one plain line per step start and end with a local timestamp —
  `14:32:01 ▸ wait for cloud-init` / `14:34:06 ✓ wait for cloud-init
  (2m 05s) done, …` — readable in logs and by agents. A changed detail
  of the running step is one more line, printed only when it changes:
  `14:33:10 · wait for cloud-init  stage modules-final`.
- **Results:** when stdout and stderr are both the terminal, the live
  lines are the ledger: the end-of-run ledger on stdout is not printed
  again. Otherwise stdout keeps it unchanged (a captured result). `-o
  json` is unchanged (one document on stdout; progress on stderr).
- **Prompts** (confirmation, a hidden key) happen only outside a running
  step; the redraw stops while one is open.
- **Testing:** offline, the non-TTY lines and the final lines are
  asserted exactly; the redraw logic is a pure function of (steps, now,
  width, frame) and tested without a terminal. Verified 2026-10-11 under a
  pseudo-terminal (`vm rm` of a disposable clone): the spinner cycled
  through all frames, the step ended as one line with its duration, the
  total followed and stdout's summary was not repeated. Steps run in the
  order they are added: the first added step and the step after each
  finished one start automatically, so nothing may prompt once steps are
  added. With `-o json` stdout's text summary is skipped too.

### 4.5 Activity line

A command that reads before it prints (`vm verify --all`, `status`,
`doctor --connect`, listings, the read and plan phase of a write) shows
that it is working: one line on **stderr**, erased before anything else
is printed, so the output is the same as without it.
- **When:** stderr is a terminal, no `-v`, no `-o json`, and the command
  is not hidden (`__complete` runs inside the shell's prompt). Nothing
  appears for the first 400 ms, so quick commands never flicker. Then
  the line is redrawn about ten times a second, as in §4.4: the spinner,
  the command path, elapsed time and the latest detail
  (`⠹ vm verify  12s  4/7 done, waiting on naboo, hoth`), cut to the
  terminal width.
- **Central:** dispatch starts it for every command; nothing has to opt
  in. Commands only add details. The line ends for good at the first
  output: the first bytes that actually reach stdout or stderr, or any
  flush (a plan before its question, a prompt, §4.4's step lines, an
  error). When it ends, the line is erased (`\r` plus clear line) before
  that output, and nothing stays in scrollback. A command that gives the
  terminal to a child process (`vm ssh`'s `exec`, `vm cp`'s scp) ends it
  first. Without concurrency there is no ticker and nothing is drawn.
- **Details:** `vm verify --all` and `status` count finished guests or
  sections and name the ones still running (`3/5 done, waiting on edge,
  tunnel`). `doctor --connect` names the API being probed. Details from
  concurrent tasks are serialized. Other commands show only the path and
  elapsed time.
- **Not a terminal** (pipes, logs, agents), `-v` or `-o json`: nothing is
  written. Output is unchanged byte for byte.
- **Testing:** offline, the drawn line is a pure function of (path,
  detail, seconds, frame, width), the end-on-output writers are
  asserted exactly (erase before the first bytes, nothing when never
  drawn), and the counter's detail text is checked. Verified live
  (2026-10-25, read-only) under a pseudo-terminal: `vm verify --all` and
  `status` cycled all frames with their counts, `doctor --connect` named
  its probe, `vm new -n` showed the line until its plan; each time the
  line was erased right before the output, stdout carried no control
  sequence, and with stderr piped or `-o json` nothing was written.

## 5. Configuration

`~/.artoo/config.json` (dir 0700, file 0600), non-secret only:

```json
{
  "schema_version": 1,
  "output": { "format": "table", "color": "auto" },
  "credentials": { "store": "auto" },
  "pve": {
    "endpoint": "https://pve.home.arpa:8006",
    "node": "pve",
    "token_id": "artoo@pve!cli",
    "ca_bundle": "~/.artoo/tls/rootCA.pem",
    "timeout_seconds": 15,
    "ssh_host": "192.168.1.10",
    "ssh_identity": "~/.ssh/id_ed25519"
  },
  "unifi": {
    "endpoint": "https://unifi.home.arpa/proxy/network/integration",
    "site": "default",
    "ca_bundle": "~/.artoo/tls/rootCA.pem",
    "timeout_seconds": 10
  },
  "cloudflare": {
    "zone": "example.com",
    "tunnel": "lab",
    "timeout_seconds": 10
  },
  "guests": {
    "domain": "lab.example.com",
    "template": "ubuntu-2604",
    "ssh_public_key": "~/.ssh/id_ed25519.pub",
    "extra_ssh_keys": "",
    "address_pool": "192.168.1.200-192.168.1.254",
    "gateway": "192.168.1.1/24",
    "user": "artoo",
    "reserved_names": "",
    "fence_allow_out": ""
  }
}
```

The values shown are the defaults. Four `guests` keys need a word:

- `guests.user` (default `artoo`): the account `vm new` creates on every
  guest — SSH key login, `sudo` with a generated password kept in the
  secret store as `guest/<name>` (§6, §9.1); `vm ssh` and `vm cp` log in
  as it. A Linux user name: lowercase letter first, then lowercase
  letters, digits, `_` or `-`, at most 32 characters, never `root`.
- `guests.extra_ssh_keys` (default empty): comma-separated paths of
  more public key files `vm new` installs for the guest user next to
  `guests.ssh_public_key` — the other machines that log in (a second
  device, the Proxmox host). Each file holds one OpenSSH public key line;
  a private key is refused without echoing it. The `vm new` plan lists
  them by comment ("more SSH keys"); `doctor` checks they are readable.
  artoo itself logs in with `guests.ssh_public_key` only. Existing guests
  are unchanged (cloud-init applies keys once).
- `guests.reserved_names` (default empty): comma-separated DNS labels —
  the lab's own host and equipment names that guests may never take and
  that are never published (§9.1, §9.6).
- `guests.fence_allow_out` (default empty): outbound exceptions for
  fenced guests, `VM PEER PROTO PORTS` entries separated by `;` (§9.11).

`config show` prints an empty value as `--`.

No profiles: the lab has one Proxmox host and one gateway. `config set`
validates keys and types against the schema; writes are atomic (unique temp
file in the same directory, fsync, rename; lock file) and refuse symlinked
destinations. `config edit` opens `$EDITOR` and validates before saving.
There is no migration (config schema 1): `config init` writes a fresh file and refuses
to overwrite an existing one.

## 6. Credentials

Simple and secure on macOS **and** Linux.

Four secret kinds: `pve` (Proxmox API token secret), `unifi` (UniFi API
key), `cloudflare` (Cloudflare API token: `example.com` DNS + the account's tunnels, §15), `guest/<name>`
(per-guest password of the guest user). One small `SecretStore`
interface (`get`, `set`, `delete`, `exists`) with backends chosen by
`credentials.store` (`auto` default):

| Backend | Used by `auto` when | Storage |
| --- | --- | --- |
| `keychain` | macOS | login Keychain, service `artoo`, account = secret name, via `/usr/bin/security` |
| `secret-service` | Linux with a running Secret Service (desktop session; `secret-tool` present and answering) | GNOME Keyring / KWallet, attributes `service=artoo account=<name>` |
| `file` | Linux otherwise (headless/SSH) — or explicitly chosen anywhere | `$XDG_CONFIG_HOME/artoo/secrets.json` (default `~/.config/artoo/`), dir 0700 + file 0600 |

Rules for every backend:

- Secrets travel only over pipes/stdin to helper processes, never argv or
  environment variables. macOS reads with `security find-generic-password -w`
  (secret on stdout) and writes by feeding `add-generic-password -U … -T
  /usr/bin/security` to `security -i` on stdin; the item is owned by Apple's
  stable `security` binary, so artoo rebuilds never cause Keychain prompts
  and no code-signing identity is needed. Linux `secret-tool store` reads
  the secret from stdin.
- The `file` backend refuses to read a secrets file that is a symlink, not
  owned by the user, or group/world-accessible (like `ssh` does with keys),
  and writes it atomically with 0600.
- `auth set pve|unifi|cloudflare` reads a hidden TTY prompt or `--stdin`; `auth status`
  shows backend + presence without reading the secret; `auth rm` confirms.
- Secrets are fetched only when a request is about to be sent; never
  printed, logged, cached elsewhere, put in error text, flags or env vars.
  The one exception is the passphrase-sealed setup file of `config
  export` (§6.1).
  No custom in-memory wiping ceremony is required.
- Protection model, stated honestly: every backend protects against other
  user accounts, accidental commits/dotfile sync and (Keychain / encrypted
  disk) offline disk access; none protects against malware already running
  as the same user. The real limit is therefore **what each credential can
  do**: the Proxmox token has VM/storage administration but no host,
  user or permission administration (§7), and can be given an expiry; the
  Cloudflare token is limited to the `example.com` zone's DNS and the
  account's tunnels, ideally with an expiry and an IP filter (§15).

### 6.1 Setup transfer (`config export` / `config import`)

Decided 2026-10-23: one file carries artoo's setup to another Mac or
Linux machine — the deliberate, only exception to "secrets never leave
the store" (§6).

- **Contents:** the config file as it is, the CA bundles it names
  (`pve.ca_bundle`, `unifi.ca_bundle`, once each) and the stored `pve`,
  `unifi` and `cloudflare` credentials. Never `guest/<name>` passwords,
  SSH keys, `known_hosts` or `ssh_config`: each machine has its own SSH
  key (added to Proxmox root and to `guests.extra_ssh_keys`).
- **Sealing** (`setup_file.zig`, stdlib only): Argon2id (64 MiB, 3
  passes, one lane — checked against the reference implementation's
  test vector, as Zig 0.17 skips its own Argon2 tests) derives the key
  from the passphrase and a random 16-byte salt; XChaCha20-Poly1305 with
  a random 24-byte nonce encrypts a JSON payload; the header (magic,
  version, parameters, salt, nonce) is the associated data. The file is
  ASCII-armored (`BEGIN/END ARTOO SETUP`). Reading bounds the parameters
  (1–10 passes, at most 1 GiB) before any work; a wrong passphrase and a
  changed file give the same refusal.
- **Passphrase:** a hidden prompt (asked twice on export) or the first
  line of `--stdin`; never an argument or variable. At least 12
  characters.
- **Export:** a plan of names only (config, CA bundles, which
  credentials are stored), confirmation, then FILE atomically with mode
  0600 (an existing FILE needs `--force`), opened again and compared
  before success is reported. `--dry-run` writes nothing.
- **Import:** a plan per item — new, same (skipped) or different;
  anything different is replaced only with `--force`. Paths under the
  exporting machine's home become `~/…`; a `credentials.store` this
  system lacks (`keychain` off macOS, `secret-service` on macOS) becomes
  `auto`; both show in the plan. Credentials go to the store the
  imported config selects. Values are never shown or compared in the
  output. It ends with the machine's own next steps (SSH key, `doctor
  --connect`).
- **Protection model:** the file is an offline copy of the lab's API
  credentials; its strength is the passphrase's. Delete it after use;
  for a machine kept long-term, a fresh Proxmox token is better still.

## 7. Proxmox access

One token, built-in roles.

- User `artoo@pve`, token `artoo@pve!cli`, **privilege separation off**.
- ACL on `/` for the user: `PVEAuditor`, `PVEVMAdmin`, `PVEDatastoreAdmin`,
  `PVESDNUser` (all built-in, verified present on 9.2.21).
- One single-privilege custom role `ArtooFetch = Sys.AccessNetwork` on
  `/nodes/<node>`, required by `download-url` (only `Administrator` carries
  it among built-in roles — verified). Lets Proxmox fetch images itself.
  PVE ACLs replace rather than merge along the path, so the
  `/nodes/<node>` entry repeats the four built-in roles (verified live).
- Setup and verification in §17.2 and GUIDE.md. Rotation is an
  operator-approved host change over the root SSH key, fed to `artoo auth
  set pve --stdin`.

`vm password VM` reveals a guest password only on an interactive TTY, after
confirmation, never in JSON.

## 8. Transport and mutation pipeline

### 8.1 HTTP

One transport for both APIs (`std.http.Client`):

- CA bundle from config only (`now` pinned so the stdlib never replaces it),
  hostname verified, redirects refused, `accept-encoding: identity`. The
  Cloudflare API is the one public endpoint: it is verified against the
  operating system's root store instead (§15).
- **No connection reuse.** The pool is disabled (`free_size = 0`); every
  request opens a fresh connection. Proven root cause of a "lost clone
  response" in the prototype: pveproxy closes idle connections after 5 s and the stdlib reused
  the dead socket. Cost: one LAN TLS handshake per request.
- **Every request has a deadline** covering connect, send and receive.
  Mechanism (phase 1 spike, verified in tests): the attempt runs as a
  concurrent task raced against a sleep in an `Io.Select`; on expiry the
  attempt is canceled and `Io.Threaded` interrupts the blocked syscall with
  `SIG.IO`. (Zig 0.17's `Io.Threaded` panics on a timed `connect`, so
  connect options carry no timeout.) Bodies are size-capped while
  streaming, not after.
- GETs retry transport failures and 5xx with bounded backoff. Writes are
  sent **once**: a failure before any byte is sent → exit 4; any failure
  after sending (no head, body read error, timeout, malformed 2xx) → exit 7
  "unknown", with the UPID if one was parsed and the inspection command to run.
- Typed decoding: API responses parse into Zig structs
  (`ignore_unknown_fields`), tolerating PVE's number-as-string fields;
  outbound bodies are built from typed values and form/URL-encoded.

### 8.2 Pipeline

Every mutation (PVE and UniFi) runs the same executor:

1. Parse and validate locally.
2. Resolve and **read** the target (identity, state, config digest).
3. Build a typed plan; refuse no-ops (exit 5).
4. Render the preview; `--dry-run` stops here (exit 0).
5. Confirm (§3.4).
6. **Re-read** the target if the prompt took longer than a few seconds;
   abort if identity/digest changed.
7. Send once (config PUTs carry the `digest`).
8. Track: PVE UPIDs are polled with a deadline; `stopped` with `OK` or
   `WARNINGS: n` is success (warnings shown); anything else is failure (6).
   A poll error after submission reports "submitted, outcome unknown" with
   the task handle (7).
9. Verify the intended state with a fresh read; failure to confirm → 8.

Multi-step workflows (`vm new`, `vm rm`, `template build`) print a step
ledger (done / failed / not run / unknown) and never auto-destroy to
compensate; re-running a workflow continues safely from observed state where
that is defined (§9.3).

## 9. Guests and provisioning

### 9.1 Guest baseline

- Ubuntu Server LTS cloud image (26.04), pinned build + SHA-256; existing
  guests never change when the pin advances.
- User `guests.user` (default `artoo`, §5), SSH key login only
  (`guests.ssh_public_key`, `~/.ssh/id_ed25519.pub`, plus
  `guests.extra_ssh_keys`),
  `PasswordAuthentication no`, root login disabled.
- `sudo` asks for a password (vendor drop-in
  `/etc/sudoers.d/99-artoo-sudo-password` overrides cloud-init's
  `NOPASSWD` rule: sudoers applies the last match). The password is **unique per guest**, generated
  by artoo, stored in the secret store (`guest/<name>`), and sent to Proxmox only
  as a SHA-512 crypt hash in the native `cipassword` field (PVE 9.2 accepts a
  pre-hashed value unchanged and masks it on every read — verified in
  `PVE/API2/Qemu.pm`). The plaintext never leaves the workstation.
- Shell environment and tools: the embedded payload in
  `src/guest/payload/` (fish default shell with helper functions, tmux,
  Vim, starship) and the package list in its README; `qemu-guest-agent`;
  Tailscale installed but **not enrolled**, from its apt repository for the
  image's release with the signing key embedded in artoo
  (`src/guest/tailscale.asc`, fingerprint
  `2596A99EAAB33821893C0A79458CA832957F5868`), not fetched at boot.
  Grafana Alloy at its pin from Grafana's repository (key embedded,
  §9.9), held off by its drop-in until `watch enroll`.
- **Ghostty terminfo, system-wide.** The operator connects from Ghostty, which
  sends `TERM=xterm-ghostty`. Ubuntu/Debian `ncurses-term` 6.5 ships the
  entry only as `ghostty` (verified on Proxmox), so without our entry every
  curses program fails ("unknown terminal"). The payload's
  `terminfo/xterm-ghostty.terminfo` (source from Ghostty's `infocmp -x`) is
  written to `/usr/local/share/artoo/xterm-ghostty.terminfo` and compiled
  **as root** with `tic -x -o /etc/terminfo` — the distro's local
  system-wide directory, searched for every user including root (`sudo`,
  `sudo -i`, pagers). It is compiled from vendor-data `bootcmd` (init
  stage, once per instance via `cloud-init-per`), so before package
  installs; the source stays in place so the entry can be rebuilt. Not
  per-user `~/.terminfo` (root sessions would break). Client-side Ghostty `ssh-terminfo`/`ssh-env` features are
  not relied on (interactive-shell-only).
- **Static address on 26.04.** The cloud image's dracut initramfs DHCPs
  every NIC; an up NIC cannot be renamed to Proxmox's `eth0`, so the
  static config would never apply (live 2026-10-10). Vendor-data drops
  networking from the initramfs (`/etc/dracut.conf.d/90-artoo-no-initrd-network.conf`,
  `dracut -f --regenerate-all` in `runcmd`) and runs `netplan apply` once
  on the first boot (whose initramfs already ran; that boot also pays
  cloud-init's 2-minute wait-online timeout, and cloud-init records the
  rename/wait-online messages, which `vm verify` counts as handled).
  Verified 2026-10-10 on a fresh guest: static address on first boot,
  again after a reboot (8.9 s boot, no initramfs network).
- **Security updates, never a reboot** (decided 2026-10-11). The
  image's `unattended-upgrades` (enabled by default, daily timers, Ubuntu's
  release and `-security` pockets) is kept and made explicit by
  `/etc/apt/apt.conf.d/52artoo-unattended-upgrades`: periodic update and
  upgrade on, Tailscale's repository added (`origin=Tailscale,
  codename=${distro_codename}` — its `Release` has no suite) so the VPN daemon gets fixes too,
  `Automatic-Reboot "false"`, unused kernels removed. Pinned packages stay
  pinned (Alloy, the watchdog's stack: apt preferences, §9.9). A reboot an
  update needs is the operator's: `vm verify` and `status` show it
  (`/run/reboot-required`, with `.pkgs`), `vm reboot VM` does it.
  Bug fixes from `-updates` are not installed unattended: `vm verify`
  counts them and `vm upgrade VM` installs them (§9.12).
  Verified live (2026-10-11) against a disposable guest: "unattended
  updates ok" with the Tailscale origin, no failed units, and — on every
  fresh guest — a pending reboot, because first boot's package upgrade
  installs a newer kernel (handled by `vm new`, §9.3). Existing guests
  keep their baseline; older guests need the file added by hand.
- **First-boot unit failure cleared.** The first boot pays
  `systemd-networkd-wait-online`'s timeout (above), which leaves the unit
  failed — the watchdog's failed-unit alert fired for it (seen
  2026-10-11). The final `runcmd` resets it (`systemctl reset-failed`,
  tolerant of a unit that did not fail).
- **No firmware refresh in guests** (decided 2026-10-21). A guest's
  firmware is QEMU's, updated on the Proxmox host (`pve-qemu-kvm`,
  `pve-edk2-firmware`, microcode); fwupd inside a VM finds nothing to
  update, yet `fwupd-refresh.timer` fetches LVFS metadata hourly and
  fails whenever the CDN stalls — the watchdog's failed-unit alert fired
  on several guests at once (2026-10-21). `runcmd` stops the timer, then
  masks it, so an upgrade cannot re-enable it (`mask --now` on a running
  timer left it failed, "Unit to trigger vanished", seen 2026-10-21); the
  package stays, because `ubuntu-server` depends on it. Existing guests
  need the mask by hand.
- Unique per guest: machine-id, SSH host keys, password; nothing secret or
  identity-bearing in templates or payload.
- Size presets (vCPU / RAM / disk): `tiny` 1 / 1 GiB / 20 GiB, `small`
  2 / 2 GiB / 20 GiB (default), `medium` 2 / 4 / 40, `large` 4 / 8 / 80,
  `xlarge` 8 / 16 / 160; `--cores`, `--memory`,
  `--disk` override. 20 GiB is the floor (≈4 GiB used after first boot;
  disks only grow); RAM, not vCPUs, bounds how many guests Proxmox holds.
- **Names** (decided 2026-10-10): one lowercase
  DNS label (letter first; letters, digits, single hyphens; 2–40
  characters). artoo carries a curated list — Star Wars planets and moons,
  Lord of the Rings places (`src/guest/names.zig`) — and `vm new` without
  NAME picks a free one at random (no VM, DNS record or UniFi client
  record uses it, never a protected name). Any other valid label may be
  given. Always refused: the protected names (§9.6), which include
  `guests.reserved_names` (the lab's own equipment names). A name is
  reusable after `vm rm` (which clears its DNS record, client record and
  pinned host key). Purpose is not in the name: `vm new
  --role ROLE` tags the VM `role-ROLE`, and service names (§9.6) carry
  what a service is. FQDN `<name>.lab.example.com` (§9.6). The guest's
  hostname is its VM name, and UniFi must list the guest under that name:
  a static guest sends no DHCP hostname, so artoo gives it a
  UniFi client record with that name (§9.5).

### 9.2 Templates

A template is named after its image pin (`ubuntu-2604`; pins in
`src/guest/image.zig`: release, build, URL, SHA-256 and size taken from the
release's `SHA256SUMS`, whose signature is checked against Ubuntu's
cloud-image key when pinning). `template build ubuntu-2604` is API-driven
except the snippet, runs only the steps the observed state needs, and
prints a step ledger:

1. Ensure the pinned image is on Proxmox: `image fetch` asks Proxmox to
   download it itself (`POST /nodes/{node}/storage/local/download-url`,
   `content=import`, `checksum-algorithm=sha256` + pinned checksum), so
   Proxmox verifies the SHA-256 before keeping it — no image is ever
   stored on the workstation. Target: storage `local`
   (`/var/lib/vz`, dataset `rpool/var-lib-vz`, content type *Import* already
   enabled) → `/var/lib/vz/import/`. PVE 9.2 accepts only
   `.qcow2|.raw|.vmdk|.ova` there (verified `PVE/Storage.pm`), so Ubuntu's
   `.img` (qcow2 format) is saved as
   `ubuntu-<release>-<build>-amd64.qcow2`. Downloaded once per pinned build;
   a file with the pinned name and size is reused, one with another size is
   refused (`image rm` first).
2. Ensure the shared **vendor-data snippet** exists
   (`src/guest/vendor.zig`: payload, packages, Tailscale repository,
   sudo/sshd drop-ins; secret- and identity-free). Its name is
   content-addressed — `local:snippets/artoo-vendor-<first 12 hex of
   SHA-256>.yaml` — so a changed payload is a new file and existing guests
   never see a changed one; `template vendor` prints the exact document.
   Proxmox's upload API does not accept snippets (verified), so this one
   file is placed over the root SSH key (`pve.ssh_host`, `pve.ssh_identity`;
   BatchMode, strict host keys, fixed remote script, content on stdin). It
   is written only if absent and never replaced; a present file is checked
   by its SHA-256.
3. Create the VM (lowest free VMID ≥ 9000, or `--id`) from the imported
   disk: `scsi0: local-zfs:0,import-from=local:import/<file>` (virtio-scsi
   single, iothread, discard, ssd), `ide2: local-zfs:cloudinit`, `q35`,
   `cpu: host`, 1 core, 1 GiB, `agent: enabled=1,fstrim_cloned_disks=1`,
   `serial0: socket` + `vga: serial0`, `net0: virtio,bridge=vmbr0`,
   `cicustom: vendor=<snippet>`, tag `artoo-template`; the description
   records image file, SHA-256 and snippet name.
4. Convert to template.

An existing template built from the same image only gets the current
snippet (`cicustom` + description, digest-guarded); an unconverted VM left
by an interrupted build is converted; a template from another image or a
VM without the tag is refused (`template rm` first). `template rm` removes
the template and its disks; image and snippet stay (guests reference the
snippet). Templates are found by name/tag at run time; no server IDs are
stored in the repository.

### 9.3 `vm new [NAME]`

1. Validate (or pick, §9.1) name, size, free VMID (lowest free ≥ 200 unless `--id`), template
   present, storage space, address (§9.5), no existing VM or DNS record with
   that name, access mode (`private` default; `public` per §9.6).
2. Plan + confirm (one confirmation for the whole workflow).
3. Generate password → Keychain `guest/<name>` → SHA-512 crypt hash.
4. Full clone of the template; reserve its address on UniFi (§9.5).
5. Configure in one digest-guarded PUT: cores, memory, `ciuser=<guests.user>`,
   `cipassword=<hash>`, `sshkeys`, `ipconfig0`, `nameserver`,
   `searchdomain=lab.example.com`, `cicustom=vendor=local:snippets/artoo-vendor-<rev>.yaml`,
   tags `artoo`. Resize disk if requested.
6. Start; wait for the guest agent; wait for `cloud-init status` done via
   the agent (`agent/exec`), bounded. Then **reboot once if an update asks
   for it**: first boot's package upgrade installs
   a newer kernel, so a fresh guest has `/run/reboot-required`; the guest
   is not in service yet, so `vm new` reboots it through Proxmox
   (`status/reboot`, task tracked), waits for the agent again and checks
   that the request is gone (`/run` is a tmpfs) — else the step fails.
   Skipped ("not needed") without the request. The second boot also
   proves the static address without the initramfs network (§9.1).
   Verified live (2026-10-11) against a disposable guest: reboot in
   seconds, back on the new kernel, `vm verify` all ok with no reboot
   pending.
7. Pin the guest's SSH host key: read `/etc/ssh/ssh_host_ed25519_key.pub`
   through the guest agent (an authenticated channel) and record it in
   `~/.artoo/known_hosts` under the VM name (`HostKeyAlias`), so SSH is
   strict from the first connection; `vm rm` forgets it. Both rewrite
   `~/.artoo/ssh_config` (§9.10).
8. Create the DNS A record `<name>.lab.example.com → address` on UniFi
   (§10.3), unless `--no-dns`. Public exposure is per service, never
   part of `vm new` (§9.6).
9. Verify (§9.4) and print the ledger: name, VMID, address, FQDN, SSH command,
   and the pinned host key as one known_hosts line (`NAME,FQDN,ADDRESS
   ssh-ed25519 …`) for the other machines in `guests.extra_ssh_keys`.

Guests are tagged `artoo`; the gateway and DNS server come from
`guests.gateway` (`192.168.1.1/24`). Steps 6–9 always run (they are
idempotent); a failed or degraded cloud-init is recorded and the workflow
continues, so the guest can be inspected (exit 8).

Re-running `vm new NAME` on a VM that artoo created (tag + Keychain entry)
continues from the first incomplete step; otherwise it refuses.
`vm rm VM` stops/destroys the VM and disks, forgets its UniFi client
record, removes its DNS record (unless `--keep-dns`), any public
record/tunnel route, and, after confirmation, its Keychain entry and its
metrics on the watchdog (§9.9). It
refuses while a service name (§9.6) points at the VM, listing them
(`svc set` or `svc rm` first).

### 9.4 `vm verify VM`

Read-only (commands run through the guest agent need
`VM.GuestAgent.Unrestricted`, in `PVEVMAdmin` — verified): VM running;
agent responding; cloud-init done (not degraded);
hostname and FQDN; payload files present and owned by the guest user (via
agent); the guest user's home owned by it; `infocmp -x xterm-ghostty`
succeeds as the guest user
**and** as root and resolves from `/etc/terminfo`, and `tput -T
xterm-ghostty colors` prints 256; SSH key login from the workstation works (strict host
key handling keyed by VM name); UniFi client record for the VM's MAC
with the VM's name and its address as Fixed IP; DNS record present and
resolving via UniFi; for public guests the Cloudflare record and tunnel route exist;
Tailscale installed and not enrolled; also `sudo -n` refused for the
guest user, `sshd -T` showing no root and no password login, the guest
user's shell fish ("user account": home and shell), the baseline tools
present, and Alloy enrolled and running when a `role-watch` VM exists (§9.9; not checked otherwise); the fence of a
guest tagged `fenced` (§9.11); unattended updates
(§9.1): periodic upgrade on, the `-security` pocket allowed, the daily
timer enabled and no automatic reboot (else failed), Tailscale's origin
where Tailscale is installed (else a warning: a baseline older than
2026-10-11), with the last run's time; pending updates (§9.12's
simulation on the guest's current package lists, nothing refreshed or
installed): security updates waiting are a warning naming them and `vm
upgrade VM` — the unattended run installs them within a day, so one that
stays is the updater falling behind; other updates are counted in the ok
detail; lists older than 2 days are a warning (apt's daily refresh is
not running); phased updates are not counted; reboot pending (a warning, with the
packages that want it); config pending (§9.13: Proxmox keys waiting
for a restart, a warning). DNS resolution is checked with `dig
@<gateway>` from the workstation (not checked without `dig`; `--no-dns`
skips both DNS checks). Each check reports ok / warning / failed / not
checked; any failure → exit 8.

`vm verify --all` checks every artoo guest (tag `artoo`, not templates),
concurrently — one task per guest with its own `Context` copy, as
`status` (§11) — and prints one block per guest, then a summary line;
any failure in any guest → exit 8. `-o json` is a list of `{vm, vmid,
checks}`.

### 9.5 Addressing

Guests get **static addresses from a dedicated pool**
(`guests.address_pool`, e.g. `.200–.254`, kept outside the gateway's DHCP
range) through `ipconfig0`, **and a matching UniFi client record**:
after the clone, artoo reads the MAC Proxmox
assigned to `net0` (stable for the VM's life) and creates the record —
name = VM name, Fixed IP = the address, network = the classic network
whose subnet is `guests.gateway` — before the first start
(`POST group/user`, §17.1). UniFi matches clients by MAC, so the guest
appears under its name, and the reserved address is visible to the next
`vm new` even while the guest is off. The address is the lowest pool
address with no Fixed IP on any client record (offline ones included), no
connected client, no DNS record and no VM config claiming it. `vm rm`
forgets the record (`forget-sta`) after the VM is destroyed, only when the
record carries the VM's MAC and name. `--no-dns` skips only the DNS
record. The guest stays static: no DHCP and no change to the verified
first-boot network handling (§9.1). The Integration API offers no
reservations; the classic calls live in `src/unifi/classic.zig` only.

### 9.6 Names, HTTPS and exposure

- **Names — two kinds** (decided 2026-10-10, option C):
  - **Machine names** `<vm>.lab.example.com` → the guest itself (UniFi
    A record made by `vm new`, §9.3): SSH and anything addressed to the
    machine.
  - **Service names** `<service>.apps.lab.example.com` → the edge VM, which
    proxies HTTPS to the guest that runs the service. A service can move
    to another guest without renaming it.
  Optional vanity public names for public guests (§15). Infrastructure
  keeps `home.arpa` (`pve.home.arpa`, `unifi.home.arpa`).
- **LAN resolution.** UniFi DNS-policy A records answer LAN lookups for
  both kinds (§10.3). Private names never enter public DNS.
- **HTTPS.** An always-on **Caddy edge VM** on Proxmox holds the Let's
  Encrypt DNS-01 wildcard `*.apps.lab.example.com`, using its own DNS-edit
  token (not artoo's), and routes service names to guests. Only the
  wildcard is ever requested: certificates land in public CT logs, so no
  individual service or machine name is published. The transient
  `_acme-challenge.apps.lab.example.com` TXT record (made and removed by
  Caddy) is the only public record under `lab.example.com`. Machine names
  get no public certificate.
- **Remote access.** Tailscale only: remote SSH and private access through
  a subnet router plus split DNS for `lab.example.com`. Tailnet ACL,
  subnet-router and enrollment changes are separate approvals.
- **Public access is per service** (decided 2026-10-11): `vm new` → `svc add` → `cf tunnel route add HOST
  SERVICE`, each its own plan. Public names reach a service through
  **Cloudflare Tunnel** (Tailscale Funnel serves only `ts.net` names);
  artoo manages the tunnel route and public record (§15).
- **Hard rule: Proxmox and UniFi are never publicly exposed** — no
  public DNS record, tunnel route, Funnel or edge route to them, by name or
  address; remote access only via Tailscale with tight ACLs. artoo
  enforces it: every Cloudflare, edge or public operation refuses those
  targets, with no override. The protected set is derived from
  configuration (`src/exposure.zig`), never hard-coded per lab:
  - **names** — the generic words `pve`, `proxmox`, `unifi`, `gateway`;
    `pve.node`; the first label of the host in `pve.endpoint` and
    `unifi.endpoint`, and of `pve.ssh_host` when it is a name; every label
    in `guests.reserved_names`. Any label of a name counts
    (`pve.lab.example.com` is refused);
  - **addresses** — `pve.ssh_host` and the endpoint hosts when they are
    IPv4 literals, and the address of `guests.gateway` (e.g.
    `192.168.1.10`, `192.168.1.1`).

  Guest names are refused when protected, and `vm new` without NAME never
  picks one (§9.1). Consequence: Proxmox's and UniFi's HTTPS stays on
  the mkcert CA (a public certificate would publish their names in CT
  logs).
- **Verify before building** (read-only research, recorded in the owning
  doc): Funnel limits; the Caddy Cloudflare DNS module. Verified
  2026-10-10: a UniFi DNS policy answers LAN queries for names in the
  public domain (§17.1).
- **Decided 2026-10-10 (option C above):** machine names resolve to the
  guest, service names to the edge VM; one label each, no overlap.
- **Service names — `artoo svc`** (decided 2026-10-11). No local
  state; a service is two halves that artoo keeps together:
  - a **route file** `/etc/caddy/services/<name>.caddy` on the edge VM
    (§9.7), written through the guest agent — the record of the upstream:

    ```caddyfile
    # artoo service grafana -> naboo:3000
    @svc-grafana host grafana.apps.lab.example.com
    handle @svc-grafana {
        reverse_proxy naboo.lab.example.com:3000
    }
    ```

    The upstream is the guest's **machine name**: Caddy resolves it
    through UniFi, so a rebuilt guest at a new address keeps working,
    and the edge firewall still limits it to the guest pool. Upstreams are
    plain HTTP in v1.

    **Health** (added 2026-10-16, for services such as a search gateway
    that answer only under `/v1/…` and `404` at `/`): a service may name
    the path that reports its health, and optionally a text that means
    "down" in that answer. Both are header lines right after the first,
    in this order, and only when set — a file without them is the
    default (`/`, no text) and reads exactly as before:

    ```caddyfile
    # artoo service search -> hoth:8080
    # artoo health /v1/health
    # artoo health-down "down"
    @svc-search host search.apps.lab.example.com
    handle @svc-search {
        reverse_proxy hoth.lab.example.com:8080
    }
    ```

    The path starts with `/`, at most 128 characters of a URL path and
    query (letters, digits and `-._~/%?=&+,;:@!$'()*`; no space, `"`,
    `#`, `\`, `{`, `}`). The down text is literal (not a regex), 1–64
    printable ASCII characters, no backtick; the rest of its line is the
    text, quotes included. Health is not routing: Caddy proxies every
    path whatever it says. It is used by the edge probe (below) and the
    watchdog's probe (§9.9). Verified live (2026-10-16): `svc add search
    hoth:8080 --health /v1/health --health-down '"down"'` on an existing
    service rewrote only the route file (record kept, plan "Set the health
    of service search"), and the edge probe of the health path passed.
  - a **UniFi A record** `<name>.apps.lab.example.com` → the edge VM's
    address, one per service (visible in `dns ls`; unknown names stay
    NXDOMAIN).

  Commands:
  - `svc ls` — name, URL, upstream `VM:PORT`, health (path, and the down
    text when set), record and route present, and drift: a record without
    a route, a route without a record, a route to a VM that no longer
    exists. `-o json` adds `health` (always a path, `/` by default) and
    `health_down` (`null` when unset).
  - `svc add NAME VM:PORT [--health PATH [--health-down TEXT]]` — route,
    then record; a half that already exists and matches is kept (repairs
    drift). An existing route to the same `VM:PORT` whose health differs
    from the flags is rewritten (so `svc add` also repairs a service's
    health).
  - `svc set NAME VM:PORT [--health PATH [--health-down TEXT]]` — moves a
    service: route only, name and record stay.

  Without `--health` both keep what the route file says; `--health`
  replaces both (`--health /` alone resets to the default);
  `--health-down` without `--health` is a usage error.
  - `svc rm NAME` — record, then route; typed confirmation (`--confirm
    NAME`), as a gateway delete.
  - `vm urls VM` (its own command; `vm ls` stays fast and shows only
    machine names) — read-only: each service whose
    route points at the VM (name, port, `https://<name>.apps…/`) and the
    lab tunnel's public hosts that reach it (§15). Cloudflare is read only
    when a service matches; an unreadable edge VM or Cloudflare is noted
    and exits 8.

  Refused before planning: NAME not a single DNS label, already taken, or
  a protected name (above); VM not an artoo guest
  (templates and the edge VM itself included) or with no address in the
  guest pool; PORT outside 1–65535 or 22; a health path or down text
  outside the rules above. The §9.6 hard rule applies with no override.

  Apply: the file is written under a temporary name, `caddy validate`
  checks the whole configuration with it, then it is moved into place and
  `systemctl reload caddy` runs; a failed validation removes the file and
  reloads nothing. Verify: the record read back, Caddy's admin API
  (`localhost:2019`) serving the host, and a probe of the health path
  from the edge (`curl --resolve <name>:443:127.0.0.1
  https://<name><path>`) — a 502 (service not answering yet) is a
  warning, not a failure; so are, when a health path is set, an answer
  that is not 2xx or a body containing the down text. Public routes (§15) point at a
  service: `cloudflared` → Caddy on `localhost` → the same route.
  Verified live (2026-10-11) against a disposable guest: `caddy validate`
  runs as `caddy` with the env file; HTTPS from the workstation through
  the edge with the wildcard trusted and no public answer; `svc set` to a
  closed port reported the 502 warning; `vm rm` refused while a service
  pointed at the guest.

### 9.7 Edge VM `bespin`

The always-on guest that terminates HTTPS for
service names (§9.6) and runs the Cloudflare Tunnel connector (§15).
Rebuilt from this section, never backed up.

- **Machine.** `vm new bespin --role edge --size small --cores 1` → 1
  vCPU, 2 GiB (the Go build peaks at ~1–1.5 GiB; guests have no swap),
  20 GiB; a fixed pool address (`--ip`).
  `vm set bespin onboot=yes`. Ubuntu security updates stay automatic;
  kernel reboots are reported, never automatic.
- **Configured through the guest agent** (root, authenticated through the
  Proxmox API; no sudo password over SSH): `artoo edge setup` writes the
  files and runs fixed, versioned scripts embedded in artoo — idempotent,
  planned and confirmed like any mutation, with a step ledger.
- **Caddy, built from source and pinned:** Ubuntu's Go 1.26
  (`golang-1.26`, `GOTOOLCHAIN=local` — no toolchain download), `xcaddy
  v0.4.7` (`go install`), Caddy **v2.11.7** with
  `github.com/caddy-dns/cloudflare` **v0.2.4**; Go's checksum database
  verifies every module. The build must list `dns.providers.cloudflare`
  (`caddy list-modules`); the binary goes to `/usr/local/bin/caddy` with a
  `caddy` system user and the upstream systemd unit; Go and the build
  cache are removed afterwards. Version bumps are deliberate SPEC edits.
- **Certificate:** one Let's Encrypt wildcard `*.apps.lab.example.com` via
  DNS-01 (`dns cloudflare {env.CF_API_TOKEN}`) — never an individual
  name (CT logs, §9.6). The token is the edge's own: a second account API
  token, *Specified Domains → example.com*, DNS Edit + Zone Read.
- **cloudflared** from Cloudflare's signed apt repository
  (`https://pkg.cloudflare.com/cloudflared any main`; signing key embedded
  in artoo, fingerprint `CC94B39C77AE7342A68B89628A682D308D4E5E73`,
  "CloudFlare Software Packaging 2025"), updated with the system; runs the
  remotely managed tunnel under artoo's sandboxed unit (`cloudflared
  --no-autoupdate tunnel run`, user `cloudflared`, token from
  `TUNNEL_TOKEN` in an `EnvironmentFile`, metrics on `localhost`).
- **Secrets live only on the edge VM**: `artoo
  edge secret dns` reads a hidden prompt and writes the edge's DNS-01
  token through the guest agent into `/etc/caddy/cloudflare.env` (0640
  root:caddy); artoo keeps no copy. A rebuild asks for it again.
- **Tunnel token**: `artoo edge tunnel` creates
  the remotely managed tunnel (`cloudflare.tunnel`, default `lab`;
  `POST …/cfd_tunnel`, `config_src: cloudflare`) when it does not exist,
  fetches its token (`GET …/cfd_tunnel/{id}/token`) and writes it through
  the guest agent into `/etc/cloudflared/tunnel.env` (0640
  root:cloudflared), then enables the unit. The token is held only in
  memory for that request: never displayed, typed, logged or stored on
  the workstation. Idempotent; verified by the tunnel's connections
  (`GET …/cfd_tunnel/{id}` → `connections`).
- **Hardening** (exposed, so hardened properly).
  The tunnel is outbound only; nothing listens for the internet. Public
  traffic flows `cloudflared` → Caddy on `localhost` → guest, one path.
  1. **Two firewalls with the same policy.** nftables inside the VM, and
     the **Proxmox VE firewall on the VM's NIC** (`firewall=1`, with
     `ipfilter`/`macfilter` so it cannot spoof another address) — the
     host-side copy survives root inside the guest. `edge setup` writes it
     through the Proxmox API (`VM.Config.Network`): rules (Proxmox inserts
     at the top, so they are added last to first), the `ipfilter-net0` IP
     set with the VM's address, the NIC flag, then the options. The
     datacenter firewall must be enabled (`scripts/pve-firewall.sh`; host
     rules keep `:8006`, `:3128`, SSH and ping open from the LAN).
  2. **Egress allow-list:** DNS to UniFi (53); HTTPS/HTTP to the
     internet (ACME, Cloudflare API, apt) and Cloudflare's tunnel port
     7844 (TCP and UDP); NTP; the guest pool on service ports. Everything
     else on the LAN is dropped — Proxmox, UniFi's other ports, the
     workstation and every other client. IPv6 only to `2000::/3`.
  3. **Ingress:** HTTP/HTTPS from the LAN (e.g. `192.168.1.0/24`; service
     names); **SSH only from Proxmox** (`pve.ssh_host`) — Proxmox already
     controls the VM through the hypervisor, so it adds no trust; the
     workstation reaches it with `ssh -J root@pve <user>@bespin` (its key
     authenticates end to end; Proxmox only forwards — `AllowTcpForwarding yes` verified). VMs
     tagged `ssh-jump` are reached that way by `vm ssh` and `vm verify`.
  4. **Services sandboxed:** Caddy and `cloudflared` under their own
     users with artoo's units (the package unit runs `cloudflared` as
     root): `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
     `NoNewPrivileges`, Caddy keeps only `CAP_NET_BIND_SERVICE`,
     writable paths named. Caddy's admin API and `cloudflared` metrics
     on `localhost` only.
  5. **Less to attack:** Tailscale removed (not the subnet router); Go and
     the build cache removed after the build; sysctl: no forwarding, no
     redirects, reverse-path filter, `kptr_restrict`, `dmesg_restrict`,
     unprivileged BPF off.
  6. **Secrets:** files root-owned, readable only by the service's group;
     the edge DNS token optionally limited to the lab's public IP.
  7. **Updates:** unattended security updates for Ubuntu and
     `cloudflared`; Caddy (built from source) is compared with its latest
     release by `edge status`.
  8. **Detection:** drop rules count hits; any attempt towards Proxmox or
     UniFi is shown first by `edge status` (sign of compromise), with
     failed SSH logins and pending reboots. Caddy logs JSON, rotated.
  9. **Public routes** may put Cloudflare Access (login) in front, per
     route (§15; not in the first version).
- **`artoo edge status`** (read-only): drop counters towards Proxmox and
  UniFi first, then Caddy version and modules (against the latest
  release), the certificate's names and expiry, cloudflared connection
  state, both firewalls loaded, failed SSH logins, pending reboot. Live
  acceptance: from `bespin`, Proxmox's `:8006`/`:22`, UniFi's `:443`
  and the workstation time out while `dig @<gateway>` answers; SSH from
  the workstation directly is refused and via Proxmox works;
  `https://<test>.apps.lab.example.com` serves the wildcard.
  Verified live (2026-10-10): `edge setup` converges in one run and a
  second `-n` finds nothing to change; the drop counters register the
  probes. Caddy's own DNS propagation check is off
  (`propagation_timeout -1`, `propagation_delay 60s`) because it queries
  the zone's nameservers directly, which the egress policy forbids. The
  site is served with HSTS and no `Server` header. MLD reports, sent at
  every boot, are allowed out with the other neighbor-discovery messages,
  so the drop counters stay at 0 after a reboot; `vm verify` checks
  Tailscale as absent for the edge role.

### 9.8 Subnet router (remote access)

Remote access to the LAN goes through Tailscale
only (§9.6): a **dedicated small guest** tagged `role-router` advertises
the LAN (`192.168.1.0/24`, from `guests.gateway`) to the tailnet. Nothing
Tailscale runs on Proxmox; the edge VM stays without Tailscale.

- **Machine.** `vm new NAME --role router --size small --cores 1`, then
  `vm set NAME onboot=yes`. Tailscale is already in the template (§9.1).
  `vm verify` on a router: Tailscale *Running* is ok, not enrolled is a
  warning (expected until `router setup`).
- **`artoo router setup`** (idempotent, planned like any mutation; through
  the guest agent as root): IP forwarding (`/etc/sysctl.d/90-artoo-router.conf`,
  IPv4 and IPv6) and, when the router is not yet `Running`, enrollment
  with a **single-use auth key** the operator generates (Tailscale
  console → Keys, tag `tag:lab-router`): read from a hidden prompt (or
  `--stdin`), written through the guest agent to a 0600 file under `/run`,
  used as `tailscale up --auth-key=file:… --advertise-routes=<LAN>
  --advertise-tags=tag:lab-router --accept-dns=false --hostname=<vm>`,
  and removed whatever happens. Never argv, never stored, never logged.
  An enrolled router whose advertised routes differ gets `tailscale set
  --advertise-routes`. Never an exit node, never Funnel.
- **`artoo router status`** (read-only): backend state, tailnet name,
  tags, advertised and approved (primary) routes, forwarding on, version;
  exit 8 when one fails.
- **Tailnet side (operator's console; not artoo):** the intended policy:
  `tag:lab-router` owned by admins; its route auto-approved; members
  reach their own devices (all ports), Proxmox `tcp:22,8006`, UniFi
  `tcp:443` and DNS `53`, the guest pool (all ports); nothing else on the
  LAN; the router reaches no tailnet device. **Split DNS:**
  `lab.example.com` and `home.arpa` → the gateway (`192.168.1.1`). Tagged
  devices' keys do not expire.
- **Acceptance:** away from home (another network), `pve.home.arpa:8006`,
  `ssh` to a guest by machine name and a service name resolve and answer;
  other LAN clients do not. At home, the workstation must still reach the
  LAN directly — checked, because a client that accepts the route could
  send LAN traffic through the tailnet, where the policy blocks other LAN
  clients.
  Verified live (2026-10-11): `router setup` enabled forwarding and
  joined as `tag:lab-router`; the route was auto-approved; no key file
  was left under `/run`; a second run found nothing to change. Split DNS
  answered through `100.100.100.100`; at home the workstation's LAN
  routes stayed on its own interface.

### 9.9 Watchdog VM `scarif`

Decided and accepted live 2026-10-11. Sources checked 2026-10-11: grafana.com/docs (Grafana, Loki, Alloy),
docs.victoriametrics.com, docs.ntfy.sh, pve.proxmox.com (External Metric
Server, API viewer), the projects' GitHub releases. Rebuilt from this
section, never backed up: metrics and logs are lost with the VM (backups
are out of scope, §1).

- **Machine.** `vm new scarif --role watch --size medium --ip <fixed pool
  address>` (the eye that sees the whole fleet) → 2 vCPU, 4 GiB, 40 GiB;
  `vm set scarif onboot=yes`. Exactly one VM carries `role-watch`;
  configured through the guest agent like the edge VM (§9.7): `artoo
  watch setup` writes rendered files and runs fixed, versioned scripts
  embedded in artoo — idempotent, planned, confirmed, with a step ledger.
- **Stack, pinned** (version bumps are deliberate SPEC edits; `watch
  status` compares with the latest release):

  | Component | Version | Source | Role |
  | --- | --- | --- | --- |
  | VictoriaMetrics single-node | v1.153.0 | GitHub release tarball, SHA-256 from its `checksums.txt` pinned in artoo (no apt repository, no signatures) | metrics, `:8428`, retention 90 days |
  | Loki | 3.7.8 | `apt.grafana.com stable main` | logs, `:3100` (gRPC `:9096` on `localhost`), filesystem/TSDB in `/var/lib/loki`, retention 31 days (compactor) |
  | Grafana OSS (`grafana`, never `grafana-enterprise`) | 13.2.3 | `apt.grafana.com` | dashboards and alert rules, `:3000` |
  | ntfy | 2.29.0 | `archive.ntfy.sh/apt stable main` | notifications, `:2586` |
  | Grafana Alloy | 1.20.1 (`1.20.1-1`) | `apt.grafana.com` | the agent on every guest, `scarif` included |

  VictoriaMetrics' LTS lines (1.148, 1.136, 1.122) publish enterprise
  binaries only, so the pin is the current community release; its
  "window size exceeded" note concerns non-CGO builds, not `linux/amd64`.
  Checked 2026-10-11: `apt.grafana.com` keeps every earlier version (567
  `grafana`, 92 `loki`, 59 `alloy` builds), so pins stay installable;
  `archive.ntfy.sh` carries 2.29.0; the keys' fingerprints match.

  Grafana's repository key is embedded in artoo (fingerprint
  `B53AE77BADB630A683046005963FA27710458545`, valid to about 2027-08),
  as is ntfy's (`55BA774A6F5EE67431E4B6B7CFDB962D4F1EC4AF`); both are
  checked with `gpg --show-keys` when embedded. Package versions are held
  by an apt preferences pin; unattended upgrades cover Ubuntu's security
  origins only, so the stack never moves on its own. VictoriaMetrics runs
  as user `victoriametrics` under artoo's sandboxed unit (the documented
  one plus `ProtectSystem=strict` and `MemoryMax=`, since its
  `-memory.allowedPercent` sizes caches only). Alerts are Grafana-managed
  rules querying VictoriaMetrics through the built-in **Prometheus** data
  source and Loki through the built-in Loki data source — no plugins, no
  vmalert, no Alertmanager.
- **No telemetry**. Every documented off-switch is
  rendered into the configuration and read back by `watch status`:
  - Grafana (`grafana.ini`): `[analytics] reporting_enabled = false`,
    `check_for_updates = false`, `check_for_plugin_updates = false`,
    `feedback_links_enabled = false`; `[news] news_feed_enabled = false`;
    `[security] disable_gravatar = true`; `[snapshots] external_enabled =
    false`; `[plugins] preinstall_disabled = true` (Grafana 13 otherwise
    installs and auto-updates six plugins from grafana.com at start),
    `preinstall_auto_update = false`, `plugin_admin_enabled = false`,
    `public_key_retrieval_disabled = true`. Google Analytics, RudderStack,
    PostHog and frontend logging stay at their empty/off defaults.
  - Loki: `analytics: reporting_enabled: false` (default sends to
    `stats.grafana.org`).
  - Alloy: `CUSTOM_ARGS="--disable-reporting
    --server.http.disable-support-bundle"` in `/etc/default/alloy`
    (default reports every 4 h).
  - ntfy: no `firebase-key-file`, no web-push keys, and
    `upstream-base-url: ""` — ntfy's default relays a poll request per
    message to ntfy.sh, which only iOS needs (below). VictoriaMetrics
    documents no telemetry and no switch for it.
  - **Enforced, not only configured:** `scarif`'s nftables egress drops
    internet traffic from the service users (`grafana`, `loki`,
    `victoriametrics`, `alloy`, `ntfy`) by `meta skuid`, with a
    `telemetry` counter; only apt (root/`_apt`) goes out. A non-zero counter is a telemetry or update attempt:
    `watch status` shows it first and an alert fires. On **every guest**
    Alloy runs under a systemd drop-in (`IPAddressDeny=any`, private
    networks and `localhost` allowed), so it cannot reach the internet
    even if a switch were missed.
  - **No start before configuration:** the service users exist and the
    firewall is loaded before any package is installed (Loki's package
    starts its service on install, with usage reporting on by default);
    configs are written first and kept (`--force-confold`). Alloy's
    drop-in also holds the service until its config exists, so a template
    guest runs no Alloy until it is enrolled.
  - **No Tailscale on the watchdog** (as on the edge, §9.7): `watch
    setup` removes the template's package — while not enrolled,
    tailscaled sends a NAT-PMP probe to the gateway at every boot (seen
    live: one 30-byte packet on `to_gateway`).
- **Network** (two firewalls with the same policy, as §9.7: nftables in the
  VM and the Proxmox VM firewall on its NIC):
  - Ingress: `8428` and `3100` from the guest pool and Proxmox
    (`pve.ssh_host`); `3000` and `2586` from the edge VM only (Caddy);
    SSH only from Proxmox (VM tagged `ssh-jump`); ping from the LAN.
    Alloy's UI (`12345`) and Loki's gRPC stay on `localhost`.
  - Egress: DNS to UniFi; HTTPS for apt (root only); NTP; the edge's
    `:443` for the probes below. Nothing else on the LAN.
  - Ingest has no authentication (Loki has none; Proxmox's InfluxDB
    exporter sends only a token, VictoriaMetrics' `-httpAuth.*` is Basic):
    the firewall limits writers to the guest pool and Proxmox. Accepted:
    a compromised guest can write noise, nothing else.
  - `bespin` needs no change: its egress already allows the pool on
    every TCP port but 22 (§9.7).
- **Grafana and ntfy are LAN/tailnet services** through the edge: `svc add
  grafana scarif:3000` and `svc add ntfy scarif:2586` (§9.6), so both are
  served under the public wildcard certificate. **Never public:** `cf
  tunnel route add` refuses any service whose upstream is the `role-watch`
  VM (or the `role-search` VM, below), with no override. Grafana: `root_url` = its service URL, sign-up
  and anonymous access off (defaults, rendered explicitly). ntfy:
  `base-url` = its service URL, `behind-proxy: true`, `auth-file`,
  `auth-default-access: deny-all`, `cache-file`, attachments off.
- **Secrets live only on `scarif`** (as §9.7); artoo keeps no copy and a
  rebuild asks again:
  - Grafana's admin password: `watch setup` gives Grafana a random one
    made on the VM (`/etc/grafana/admin_password`, 0640 root:grafana,
    read with `$__file{}` on first start), so `admin/admin` is never
    valid; `artoo watch secret grafana` (hidden prompt twice, or
    `--stdin`) sets the operator's through Grafana's CLI
    (`admin reset-admin-password --password-from-stdin`, as user
    `grafana`).
  - ntfy users are declarative (`NTFY_AUTH_USERS`, `NTFY_AUTH_ACCESS`,
    `NTFY_AUTH_TOKENS` in `/etc/ntfy/auth.env`, 0640 root:ntfy, read by
    the unit's drop-in): `grafana` (write-only on topic `lab`) and
    `phone` (read-only). `artoo watch secret phone` hashes the phone's
    password with bcrypt **on the workstation** (12–72 characters); only the hash
    reaches the VM; the phone's ntfy app logs in with username and
    password.
  - Grafana publishes with an ntfy token (`tk_` + 29 characters) made
    **on the VM** by `watch setup`, kept in `/etc/grafana/ntfy.env` (0640
    root:grafana, read by Grafana's unit as `NTFY_TOKEN`) and filled into
    `auth.env` there; it never leaves the VM.
- **Alerts → phone.** One Grafana webhook contact point,
  `http://localhost:2586/lab?template=grafana` (ntfy's built-in Grafana
  template), Bearer token. The operator's phone is on the tailnet, where
  split DNS and the policy's guest-pool rule cover the service name. On
  Android the ntfy app subscribes to `lab` on the ntfy service URL with
  *instant delivery*, keeping its own connection to `scarif` — no relay,
  no Firebase. An iOS device would
  need `upstream-base-url: https://ntfy.sh` (per message a poll request
  with the message ID only; the app then fetches from `scarif`) and the
  `ntfy` user's HTTPS egress; its app trusts no private CA, so the public
  wildcard serves both.
- **Readable notifications** (decided 2026-10-18). ntfy's built-in
  template shows only the webhook's `title` and `message` (ntfy 2.29.0
  `server/templates/grafana.yml`: 🚨 or ✅ before `title`, `message` cut
  at 2000 characters). Grafana's defaults put every label into the title
  and every label, annotation and link into the message, so a probe alert
  read "[FIRING:1] HTTPS probe failing Lab (scarif
  prometheus.exporter.blackbox.https integrations/blackbox/search
  warning)", naming the watchdog that probes rather than the service. The
  webhook therefore sets `title` and `message` from a **Grafana
  notification template** `artoo`, provisioned in the contact point's
  file; ntfy keeps its stock `?template=grafana`. Not a custom ntfy
  template: it would need a template directory on the server and would
  have to pick the rule's annotations out of Grafana's raw payload, while
  Grafana's template sees them directly and handles grouped alerts.
  - **Title:** one alert → its `summary`; several → `<rule title>: N
    firing` (and `, M resolved`). A resolved notification is `Resolved:
    <summary>` (ntfy adds ✅).
  - **Message:** per firing alert its `summary`, its `description` and
    `since <start, UTC>`, then the resolved ones' summaries under
    `Resolved:`; nothing else (no label dump, no silence links). A repeat
    every 4 h thus says how old the problem is.
- **Removed guests are forgotten** (decided 2026-10-12). "Guest
  silent" looks back a day (`tlast_over_time(…[1d])`), so a guest removed
  without cleanup kept firing — and re-notifying every 4 h — for a day
  (seen 2026-10-12). `vm rm` therefore ends
  with "forget in watch": after the destroy, it deletes every series with
  `host=<name>` from VictoriaMetrics (`POST
  /api/v1/admin/tsdb/delete_series`, enabled by default; no
  `-deleteAuthKey`), through `scarif`'s guest agent (`8428` is not open to
  the workstation), counting with `/api/v1/series?start=-3d` (without
  `start` it covers only recent minutes) before and after; none may be
  left. The alerts resolve at the next evaluation and ntfy gets the
  RESOLVED message. `watch forget HOST` does the same for a guest already
  gone (refused while a VM of that name exists, or for the watchdog
  itself); typed confirmation. A stopped or unreachable watchdog is a
  plan note naming `watch forget`. Loki keeps the guest's logs until
  retention (31 days); no alert reads them. VictoriaMetrics documents
  deletion for one-off use, which this is (once per removed guest).
  Verified live (2026-10-12): every series deleted in about a second,
  none left.
- **Provisioned from files**, never clicked: `/etc/grafana/provisioning/`
  `datasources/` (VictoriaMetrics, Loki; `prune: true`), `dashboards/`,
  `alerting/` (contact point, notification policy, rule groups). The files
  are the truth: data sources and dashboards whose file is gone are
  deleted (`disableDeletion: false`), and `watch setup` removes any
  dashboard file it no longer renders.
  - **One board, "Proxmox · Homelab"**, Grafana's
    home page (`default_home_dashboard_path`), read-only in the UI:
    Overview tiles (Proxmox CPU, memory gauge, memory used / available /
    ZFS ARC / total, load against the host's threads, failed units, guests
    running, services down, certificate days, tunnel connections, router
    routes, edge drops towards Proxmox/UniFi and blocked telemetry over
    24 h, then a strip with one cell per service name, `up` or `down`);
    Proxmox (CPU with I/O wait, load, memory stacked to the total,
    `vmbr0` traffic, storage per pool); Guests (a table with inline CPU,
    memory and disk gauges, uptime, pending reboot; per-guest CPU, memory
    and network; Proxmox's view without templates); Edge & router (drop
    counters, tunnel, probe time, certificate expiry, Tailscale traffic,
    Caddy upstreams); Logs, folded (errors per host, warnings per host,
    the error lines — guests' boot-time warnings are noise). Grafana's
    JSON in `src/watch/dashboards/lab.json`, generated by
    `scripts/gen-lab-board.py` (edit the generator, not the JSON).
  - Files larger than 45 000 bytes reach a guest in parts: Proxmox caps
    the agent's `input-data` at 65 536 characters (seen live with the
    board), so the part file is assembled beside the target and moved
    into place last (shared with `edge` and `svc`). Initial rules: a guest's Alloy
  silent > 5 min, Proxmox metrics silent > 5 min; root filesystem > 85 %,
  memory > 90 % (host and guests); CPU > 90 % for 15 min (host and
  guests, added 2026-10-16: a guest's busy share of all its cores,
  `1 −` idle over 5 min, from Alloy; Proxmox's `cpustat_cpu` averaged over
  5 min, from its export — a runaway process shows, an apt run or a build
  does not); failed systemd units; **any edge drop
  towards Proxmox or UniFi** (critical); tunnel not healthy; router
  route not primary; certificate expiry < 14 days; HTTPS probe failing
  5 min; pending reboot > 7 days. Alert state and history stay in
  Grafana and VictoriaMetrics — artoo stores nothing. Rule uids are
  `artoo-…` (`artoo-pve-*` for Proxmox's).
  - **Each rule says what, where, how much and what next** (decided
    2026-10-18). The query returns the raw value (seconds, a fraction,
    packets), B reduces it (`last`) and C compares it (`gt`/`lt` the
    threshold), so the value is in `$values.B` for the text and every
    series is still judged 0 or 1 (it resolves when the condition clears,
    as with `bool`). Annotations: `summary`, one line naming the guest
    (`host` on Alloy's and the guests' series), Proxmox (`host` on
    `object="nodes"`), the storage (`host` on `object="storages"`) or the
    service, with the value in its unit (`humanizePercentage`,
    `humanizeDuration`, a count); `description`, what it means and the
    artoo commands to run next. As rendered for naboo, hoth and the
    search service:

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

  - **The board names services too** (decided 2026-10-18): one
    aggregated "DOWN" tile for every probe read as "search is down" while
    another service failed. The overview counts the services down and a
    strip shows each service (`up`/`down`), named from the probe's `job`
    with `label_replace` (so series from before the probe labels count
    too); the probe-time and certificate panels are labelled by service.
  - **Probe labels.** A probe's series carry `job="integrations/blackbox/<service>"`
    and `host=<watchdog>` (Alloy's names, seen live 2026-10-18), so the
    watchdog's Alloy relabels them with `service` (the name), `url` (the
    probed target) and `vm` (the route file's upstream guest), rendered
    per service at `watch setup` time like the targets; `host` stays
    the watchdog that probes. A moved service (`svc set`) gets its new
    `vm` at the next `watch setup`.
  - Verified live (2026-10-18): `watch setup` rewrote the two alerting
    files, the board and the watchdog's Alloy config in one run, and a
    second `-n` found nothing; Grafana provisioned the 16 rules without
    error and loaded the `artoo` template; every probe series carried
    `service`, `url` and `vm` within a minute; no notification error
    in Grafana's log when the failing probe re-fired under its new labels.
    The phone's rendering is not yet confirmed.
  - The router rule takes the minimum of `artoo_tailscale_running` and
    `artoo_tailscale_routes_primary` per host; the earlier `… < bool 1 or
    … < bool 1` never looked at the right side, whose series match the
    left one's labels.
- **Alloy on the guests.** The template installs the pinned `alloy`
  package (§9.1: the vendor snippet carries Grafana's repository with the
  embedded key, an apt pin and Alloy's drop-in, written before packages),
  held off until enrolled. Its config is written per guest
  by **`artoo watch enroll VM…|--all`** (guest agent, idempotent, also
  the one-time path for existing guests) and by `vm new` as a step when a
  `role-watch` VM exists: `/etc/alloy/config.alloy` — journald
  (`loki.source.journal`, unit and priority as labels) → `loki.write`;
  `prometheus.exporter.unix` (systemd collector, artoo's fact files) →
  `prometheus.remote_write` to `http://<watch vm>.lab.example.com:8428/api/v1/write`
  and `…:3100/loki/api/v1/push`. Alloy buffers while `scarif` is down.
  `vm verify` adds "Alloy active and enrolled" (not checked when no
  `role-watch` VM exists).
- **Fleet signals as metrics** (small systemd timers writing Prometheus
  text files for Alloy's textfile collector, plus local scrapes):
  - `bespin`: nftables drop counters per rule (towards Proxmox,
    UniFi, other), Caddy's metrics (admin API, `localhost:2019`),
    cloudflared's metrics (`localhost`), failed SSH logins come from the
    journal. Rendered by `watch enroll` for `role-edge`.
  - `dagobah`: `tailscale status --json` → backend state, route advertised
    and primary. For `role-router`.
  - The search gateway (`role-search`, below): Alloy scrapes the
    gateway's own `/v1/metrics` on `localhost:8080` (job `holocron`,
    named after the gateway software). On the guest, so the NIC firewall
    needs no rule; a gateway without the endpoint only shows as a failed
    scrape (`up{job="holocron"}` 0).
  - Every guest: pending reboot, unattended-upgrades last run.
  - `scarif` probes (Alloy's `prometheus.exporter.blackbox`): each
    service name over HTTPS through the edge (status and certificate
    expiry, trusting the public roots), from the edge's route files at
    `watch setup` time (a new service, or a changed health: run `watch
    setup` again). The target is `https://<name>.apps.<domain><path>`
    with the service's health path (§9.6; `/` by default, so Grafana and
    ntfy are probed as before); success is a 2xx answer (blackbox's
    default). A service with a down text gets its own module,
    `https-<name>` (module `https` plus `fail_if_body_matches_regexp`
    with the text regex-escaped), so a 200 that reports itself down
    fails the probe too (e.g. `--health /v1/health --health-down
    '"down"'` for a search gateway whose health is always 200 and names
    each provider `ok` or `down`). Verified live (2026-10-16): `watch
    setup` wrote only `/etc/alloy/artoo.alloy` and restarted Alloy; the
    health path turned a 404 probe into a passing one. The down text
    failing the probe is not yet seen live. Public tunnel routes are not probed — Alloy has no internet; the tunnel's
    health comes from cloudflared's metrics.
  - One script, `artoo-facts` (root, every minute), writes
    `/var/lib/artoo-facts/artoo.prom` on every guest: pending reboot and
    its age, the last unattended upgrade, the `artoo_edge`/`artoo_watch`
    nftables counters where present, and on a router (Tailscale with
    advertised routes) its state and number of primary routes.
- **Proxmox.** Proxmox's built-in External Metric Server, **InfluxDB over
  HTTP** to `scarif`'s address `:8428` (organization, bucket and token
  empty — VictoriaMetrics' documented Proxmox setup); not Proxmox's
  OpenTelemetry type (it posts JSON, VictoriaMetrics expects protobuf).
  Node, guest and storage statistics every pvestatd cycle; no agent on
  the host. Creating it needs `Sys.Modify` on `/`, which artoo's token
  deliberately lacks (§7): an operator-approved host change,
  `scripts/pve-metrics.sh` run as root (`pvesh create
  /cluster/metrics/server/scarif --type influxdb --influxdbproto http
  --server <address> --port 8428`). `watch status` reads it with the
  token (`Sys.Audit`).
- **`artoo watch status`** (read-only, through the guest agent and the
  PVE API): blocked telemetry and outbound counters first; then both
  firewalls, each component's version against its pin, services
  running, the configuration as rendered (every telemetry switch,
  retention, ntfy without relay — by file hash), the phone user, the Proxmox
  metric server present and its last sample fresh, and per running
  artoo guest the age of its latest metrics and whether its journal
  arrived in the last 10 min (> 5 min silent fails); pending reboot.
  Exit 8 when one fails. Firing alerts are Grafana's (its API needs a
  login) and the phone's; comparing pins with the latest releases is a
  manual step when bumping them.
- **Acceptance (approved run):** `watch setup` converges in one run and a
  second `-n` finds nothing; `watch status` all ok with zero blocked
  counters after 24 h; every guest and Proxmox visible in Grafana; a test
  alert reaches the operator's phone on the tailnet; Grafana and ntfy
  unreachable from the internet; from `scarif`, Proxmox `:8006`/`:22`,
  UniFi `:443` and the workstation time out.
  Verified live (2026-10-11): `watch setup` converged in one run and a
  second `-n` found nothing; `watch enroll` orders repository files,
  install, config, start (the config's `alloy` group needs the package
  first); public resolvers answer NXDOMAIN for both service names and
  anonymous ntfy reads/publishes get 403; real and deliberate alerts
  reached the phone through Grafana → ntfy with no relay; after two
  reboots everything returned on its own with every drop counter at 0.
- **Settled in the live run:** Grafana 13's bundled Prometheus data source
  (13.2.1) works with plugin preinstall disabled; Grafana evaluates the
  three-step rules as rendered and delivers through the webhook;
  Proxmox's InfluxDB export names, as stored by VictoriaMetrics: node
  `cpustat_*`, `memory_*`, `blockstat_*`, `system_uptime` with
  `object="nodes"`, `host="pve"`; guests `system_*` (`cpu`, `mem`,
  `maxmem`, `uptime`, …), `blockstat_*`, `nics_*` with `object="qemu"`,
  `host=<VM name>`, `vmid`; storages `system_used`/`system_total`/
  `system_avail` with `object="storages"`, `host=<storage>` (the first
  dashboard draft assumed `used`/`total`; fixed, and a Proxmox storage
  rule above 85 % added).
- **Search gateway (`role-search`).** One VM tagged `role-search` runs
  the lab's search gateway (e.g. holocron): an unauthenticated search and
  fetch proxy, reached on the LAN and tailnet through a service name
  (§9.6). It is **never public** — `cf tunnel route add` refuses a service
  whose VM carries `role-search`, with no override. Alloy on it scrapes
  the gateway's `/v1/metrics` on `localhost:8080` (job `holocron`, above).
  Its NIC fence follows the edge/watchdog pattern: the Proxmox VE firewall
  on the VM's NIC with an outbound allow-list, written by `vm fence`
  (§9.11).
- **Later:** UniFi metrics; `status` reading alert state from
  Grafana (§11).

### 9.10 SSH config and copies (`vm ssh-config`, `vm cp`)

Decided 2026-10-16; live acceptance pending. `vm ssh` (§9.3 step 7) is
strict, but only for itself: plain `ssh`, `scp`, `rsync` and editors'
remote modes know nothing of the keys pinned in `~/.artoo/known_hosts` or
of the Proxmox jump, so copying a file to a guest took a long
hand-written `scp` line. Two commands close the gap. Both act as the
guest user (`guests.user`) only, like
`vm ssh`; neither writes as root, and neither touches Proxmox or UniFi.
Placing files as root stays with the role setup commands through the
guest agent (§9.7, §9.9).

- **`artoo vm ssh-config`** writes `~/.artoo/ssh_config` (0600, written
  atomically like the config file, §5; a symlink is refused): one `Host`
  block per artoo guest (tag `artoo`, templates excluded), sorted by name.
  Each block uses the same settings as `vm ssh`:

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
    (the example shortens them). `IdentityFile` is
    `guests.ssh_public_key` without `.pub`. A path with spaces or quotes
    is refused.
  - The patterns are the VM name and its machine name, so `ssh naboo`,
    `ssh naboo.lab.example.com`, `scp naboo:…` and `rsync naboo:…` are
    all strict.
  - `HostName` is the guest's address, found the way `vm ssh` finds it:
    the static `ipconfig0` (§9.5), or the agent's address. It is not the
    machine name: the address works for guests made with `--no-dns`, needs
    no DNS on the workstation or on Proxmox, and stays correct because addresses are
    static and `vm new`/`vm rm` rewrite the file. `HostKeyAlias` keeps the
    host key tied to the VM name.
  - Guests tagged `ssh-jump` get `vm ssh`'s exact `ProxyCommand`
    (`known_hosts.zig`), built from `pve.ssh_host` and `pve.ssh_identity`,
    and not `ProxyJump root@<pve.ssh_host>`. With `ProxyJump`, the hop to
    Proxmox would take its settings from whatever config matches Proxmox
    (ssh(1) on `-J`: command-line settings "generally apply to the
    destination host and not any specified jump hosts"). The
    `ProxyCommand` carries the identity, `IdentitiesOnly`, `BatchMode` and
    strict checking against Proxmox's key in `~/.ssh/known_hosts`.
  - A running guest with no pinned key is pinned through the guest agent
    first, as `vm ssh` does. A stopped one still gets its block (ssh
    refuses it until the key is pinned) and a note; exit 8. A guest with
    no known address is left out with a note; exit 8.
  - **artoo never edits `~/.ssh/config`.** The operator adds one line
    once, above the first `Host` or `Match` line. ssh uses the first value
    it finds for each option, and an `Include` placed after a `Host` line
    only applies to that block (ssh_config(5)):

    ```sshconfig
    Include ~/.artoo/ssh_config
    ```

    The command checks whether that line is in effect, read-only, by
    running `ssh -G <first guest>` (it opens no connection) and looking
    for `hostkeyalias`. If it is not, the command prints the line to add.
  - Once the file exists, `vm new` (after it pins the host key) and `vm
    rm` (after it forgets the key) update the guest's own block as a step
    of their own, and leave the other blocks as they are; so does `vm set`
    when it changes `tags`, because `ssh-jump` is a tag. They read no
    other guest, so they add no API calls. Before the operator's first
    `vm ssh-config` there is no file, and none of them makes one. A failed
    update fails only that step (exit 8); the next `vm ssh-config`
    repairs it. Output:
    the path, the number of guests, `written` or `unchanged`. `-n` prints
    the file to stdout and writes nothing. `-o json` lists the blocks
    (`name`, `hostname`, `jump`, `pinned`). No prompt: the file is artoo's
    own, like `known_hosts`.

- **`artoo vm cp SRC DST [-r] [--force]`** copies one file, or one
  directory tree with `-r`, as the guest user.
  - **Sides.** A word is `VM:PATH` when it has a `:` with no `/` before it
    (scp's rule); `./a:b` stays a local path. One side or both are
    remote; two local sides are refused (exit 2). `VM` is an exact name or
    VMID (§3.2), and it must be a running artoo guest. Anything else is
    refused before anything runs (exit 5): a template, a VM without the
    `artoo` tag, a `user@` part, an `scp://` URI. Proxmox and UniFi (the
    protected names and addresses, §9.6) are refused, with no override.
  - **Paths.** A remote `PATH` is absolute, or relative to the guest user's home;
    an empty one means home. A leading `~/` is rewritten as home-relative,
    so the scp transfer and the shell checks below resolve the same path;
    `~user` is refused. No wildcards (`*?[`): one source, one target, one
    checksum. A newline or NUL in a path is refused.
  - **No overwrite without `--force`.** Before copying, artoo works out
    the target: `DST` itself, or `DST/<name of SRC>` when `DST` is an
    existing directory. It checks the target locally with `stat` and
    remotely over SSH. If the target exists, the copy is refused (exit 5)
    and the message names the target. With `-r` an existing target
    directory is refused too, because scp would merge into it.
    `--force` allows both. The check and the copy are separate steps, and
    that gap is accepted (one operator, own files).
  - **The copy** runs `/usr/bin/scp -F ~/.artoo/ssh_config -p [-r] [-3]
    -- SRC DST`, with VM names as hosts. scp runs as a child process, its
    progress meter on the terminal. Before it, artoo renders the blocks
    from the live VM list and rewrites the file if it differs, so a
    missing `Include` or a stale file does not matter. Missing host keys
    are pinned first, as in `vm ssh`. With `-F`, ssh reads neither
    `~/.ssh/config` nor `/etc/ssh/ssh_config` (ssh(1)). `-p` keeps the
    mode, so a copied binary stays executable, and keeps the times.
  - **Per-host settings come from the file, not from `-o`.** For a copy
    from one guest to another, scp starts one ssh per host and passes its
    own options to both. Checked 2026-10-16 with a stand-in `-S` program:
    each child got `-F <file>` and its own host name. An
    `-o HostKeyAlias=…` would therefore apply one guest's alias to both.
  - **Guest to guest uses `-3`**: the data is relayed through the
    workstation. The fences block SSH between guests by design: the edge
    and the watchdog accept it only from Proxmox (§9.7, §9.9), and the
    search gateway drops the other guests' `:22`. `-3` is the default in
    OpenSSH 10.3p1 (macOS's `/usr/bin/scp`); artoo passes it anyway so the behaviour
    does not depend on the version. Never `-R` (one guest logging in to
    another).
  - **SFTP only.** scp's default protocol since OpenSSH 9.0; artoo never
    passes `-O`. The legacy protocol runs remote paths through the remote
    shell, which is fish on guests (scp(1), CAVEATS). SFTP starts the
    `sftp` subsystem, which gets no shell interpretation of paths.
  - **Checksums.** When scp exits 0, artoo prints the SHA-256 of what was
    copied and compares it on the far side. artoo computes the hash of a
    local side itself; a remote side runs `sha256sum` over SSH with `vm
    ssh`'s options plus `BatchMode` (one host per connection, so `-o`
    works here). The remote commands (the existence check,
    the hash) are fixed strings, run as `sh -c '…'` (guests' login shell
    is fish, as with `vm ssh -- CMD`). The path is sent on stdin, never on
    the command line. With `-r`, every regular file is compared by relative
    path and hash. scp follows symbolic links (scp(1)), so the source
    listing follows them too. A source file that is missing or different
    on the far side is exit 8, and the message names the files. Extra
    files in a target that `--force` merged into are not compared. A check
    that could not run
    reports "copied, not verified" (exit 8).
  - **Failures.** If scp fails: exit 4, with scp's own message. A target
    that scp had started stays as it is, and artoo names it; replacing it
    needs `--force`. An interrupt exits 130.
  - **`-n`** prints the resolved target and the exact scp argv
    (shell-quoted), and copies nothing. It writes nothing either, not even
    `ssh_config`; it says when the file would change.
  - **No prompt** (like `vm ssh`). The copy writes only as the guest user,
    inside a guest, or on the workstation. It is outside the mutation pipeline (§8.2): no
    plan, no ledger, no `--yes`. Its safeguards are the overwrite refusal
    and the checksum. Output: `<sha256>  <target>` per file (for `-r`, a
    count), then `SHA-256 matches on <side>`. `-o json`: `{"source",
    "target", "files": [{"path", "sha256"}], "verified"}`.

- **Testing.** Offline tests: rendering of the file (direct, `ssh-jump`,
  unpinned), how a side is parsed and refused (the table above, with
  `./a:b`), the target with and without `--force`, the scp argv for each
  direction, and comparison of the `-r` file lists. Live acceptance under
  an approved run (§13, a disposable guest): workstation → guest, guest →
  workstation, and
  guest → guest between a fenced guest and an `ssh-jump` guest, all
  verified. Also: a second copy refused without `--force`, `-r` of a tree
  with a symbolic link, plain `ssh`/`scp`/`rsync` with a guest name once
  the `Include` is in place, and `vm rm` removing the guest's block.
  Checked read-only (2026-10-16): `vm ssh-config -n` renders the Proxmox
  `ProxyCommand` for `ssh-jump` guests; `ssh -F <that file>` logs in
  strictly both through the jump and directly; `vm cp -n bespin:/etc/hostname
  naboo:` resolves the target `naboo:hostname` and prints the scp command
  with `-3`.

### 9.11 Guest fence (`vm fence`)

Decided and accepted live 2026-10-18. The edge VM and the
watchdog carry the Proxmox VE firewall on their NIC (§9.7, §9.9), written
by their own setup. `artoo vm fence VM` puts the same kind of host-side
fence on any other artoo guest — an app guest, a crawler that must not
reach the LAN, the search gateway (§9.9) — so that root inside the guest
cannot widen it. It writes only the VM's own firewall on Proxmox
(`VM.Config.Network`, as §9.7) and nothing inside the guest; it is not
an nftables policy in the VM.

- **Rules, all derived** (no address is typed by hand; first match
  wins; Proxmox inserts at the top, so they are sent last to first):

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

  So the guest answers its services only through the edge, SSH and
  ping from the LAN, and reaches DNS on UniFi, the watchdog, the
  internet's web and NTP — never Proxmox, UniFi's other ports, other
  guests or other LAN clients (rule 7 covers them, the private and CGNAT
  ranges). Every rule carries an `artoo: …` comment; comments are not
  compared.
- **IP set and options.** `ipfilter-net0` holds the VM's static
  `ipconfig0` address only (a guest without one is refused), so the
  guest cannot send from another address; the options `enable 1,
  ipfilter 1, macfilter 1, dhcp 0, ndp 1, radv 0, policy_in DROP,
  policy_out DROP` — those of §9.7 — and the NIC flag `firewall=1`.
  Order as §9.7: rules, IP set, NIC (with the tag below), options last,
  so the VM is never filtered by a half-written rule set. The datacenter
  firewall must be on (`scripts/pve-firewall.sh`); when
  `/cluster/firewall/options` says it is off, the plan says the fence
  has no effect until it is, and `vm verify` warns.
- **The `fenced` tag** marks a guest fenced by `vm fence`; it is written
  in the same digest-guarded config PUT as the NIC flag. It is how `svc`,
  `vm verify`, `vm show` and `status` know which guests to check without
  reading every VM's firewall. A fence that differs from the derived one
  (a new service, a moved watchdog, `ssh-jump` added or removed with `vm
  set`, a rule edited by hand) is **drift**: shown, never repaired
  silently; `vm fence VM` converges it.
- **Per-guest exceptions live in the config**, never in one-off flags, so
  every re-run derives the same fence: `guests.fence_allow_out`, entries
  `VM PEER PROTO PORTS` separated by `;` — e.g. `hoth naboo tcp 5432;
  hoth 203.0.113.0/24 udp 51820`. `PEER` is an artoo guest's name (its
  static address, read at plan time) or an IPv4 address or CIDR;
  `PROTO` is `tcp` or `udp`; `PORTS` a Proxmox port list (`5432`,
  `80,443`, `6000:6010`). `config set` checks the syntax; `vm fence`
  refuses, before planning, an entry whose guest does not exist or has no
  static address, a peer that is the VM itself, and any peer that is a
  protected address (§9.6: Proxmox, the gateway) or contains one — the
  fence never opens a path to Proxmox or UniFi, with no override.
  Inbound exceptions are not offered: a guest's inbound services are its
  service names (rule 1).
- **Refused** (exit 5, before planning): a template; a VM without the
  `artoo` tag; a VM tagged `role-edge`, `role-watch` or `role-router`
  (their setup owns their fence, and a fence would break the subnet
  router's forwarding, §9.8); no static address; an edge VM that exists
  but is not running or cannot be read (its routes, and so rule 1, are
  unknown). The guest may be stopped: the fence applies when it starts.
- **High-impact** (§3.4): typed confirmation, or `--yes --confirm VM`.
  The plan renders the full rule diff, position by position — `rule N
  <current> → <wanted>`, `(none)` and `(removed)` at the ends — with the
  count of unchanged rules, and the IP set, NIC, tag and options changes.
  Existing rules not written by artoo (a hand-written fence) are replaced;
  the plan names them. A takeover of a hand-written fence with the same
  rules is a change of the tag (and whatever else differs) only. `-n`
  sends nothing; a converged fence is a no-op (exit 5, "nothing to
  change"). Verified by read-back: rules, IP set, options, NIC flag and
  tag as planned, else exit 8. While a fenced guest's rules are
  rewritten its traffic drops for the moment between deleting and
  re-adding them (no other change on Proxmox is atomic either).
- **`vm fence VM --off`** is the rollback: options `enable 0` first (the
  guest is unfiltered at once) with the other options reset to Proxmox's
  defaults, then every rule and the IP set removed, `firewall=1` and the
  tag removed from the VM config. Same confirmation; a guest without a
  fence is a no-op.
- **Services keep the fence in step.** `svc add`, `svc set` and `svc rm`
  on a service whose old or new upstream is tagged `fenced` plan the
  fence change in the same plan — `fence <vm>` with the rule that opens
  or closes — and run it as a step of their ledger: the new upstream's
  fence opens before the route is written, the old one's closes after
  the route is gone. The fence step rewrites the VM's whole rule list as
  `vm fence` would, so drift in that fence is repaired too and the plan
  shows it.
- **Fence state.** `vm verify` adds "fence": not checked for a guest
  without the tag (and for the role VMs, whose setup checks theirs); ok
  when the read-back equals the derived fence; failed on drift, naming the
  first differing rule (`artoo vm fence VM` to converge); a warning when
  the datacenter firewall is off. `vm show` prints a "Fence" line (`on`,
  `drift`, `off`). `status` lists fenced guests below the guest table
  when any is in drift — a warning, like a pending reboot.
- **Later:** `vm new --fence` (the fence as the last step of a new guest).
- **Testing.** Offline: the derived rules for a plain guest, an `ssh-jump`
  guest, with and without edge, services, watchdog and exceptions; each
  refusal; the plan's rule diff; `-n` sending nothing; the order of
  writes (rules last to first, options last; `--off` options first) and
  the read-back against the fake server; `svc add` on a fenced guest
  planning and running its fence step. Live acceptance under an approved
  plan (§13, a disposable guest): `vm fence` converges in one run and a
  second `-n` finds nothing; from the guest, Proxmox `:8006`/`:22`,
  UniFi `:443`, another guest and the workstation time out while `dig
  @<gateway>` answers and HTTPS to the internet works; the service answers
  through the edge and not directly; `--off` restores reachability.
  Taking over an existing hand-written fence is its own approved plan.
  Verified live (2026-10-18), approved: two guests fenced by hand-written
  `<vmid>.fw` files with this rule set planned only the tag, a second `-n`
  found nothing to change and `vm verify` showed the fence ok. On a
  disposable guest with a test service: one run converged and a second
  `-n` found nothing; from the guest Proxmox `:8006`/`:22`, UniFi `:443`,
  other guests and the workstation were blocked while `dig @<gateway>`
  and HTTPS to the internet answered; from the workstation the service
  answered through the edge (200) and not directly, SSH and ping worked;
  `--off` opened every one of those paths again. **Enforcement lags the
  write:** `pve-firewall` compiles the configuration on its own cycle
  (about 10 s), so a probe right after the write still passes — the
  read-back checks the configuration, and live probes wait about 20 s.
  The workstation's tailnet path (through the subnet router, which
  masquerades by default, so the guest sees a LAN source) is not yet
  checked from away.

### 9.12 Package upgrades (`vm upgrade`)

Decided 2026-10-25. Unattended upgrades install only the release and
`-security` pockets (§9.1); bug fixes from `-updates` wait for the
operator. `vm upgrade VM` installs everything pending through the guest
agent, on the one pipeline (§8.2), one VM per run — the edge, the router
and the watchdog included.

- **Read** (nothing changes in the guest): an artoo guest (tag `artoo`,
  not a template), running, its agent answering. `LC_ALL=C apt-get -s
  --with-new-pkgs upgrade` on the guest's current package lists; each
  `Inst` line is one package — name, installed version (none for a new
  package such as the next kernel), candidate version and pockets
  (`Inst tmux [3.6a-2ubuntu0.1] (3.6a-2ubuntu0.2
  Ubuntu:26.04/resolute-updates [amd64])`, seen 2026-10-25); a pocket
  ending in `-security` makes it a security update. Also read: the
  lists' age (`/var/lib/apt/periodic/update-success-stamp`), the
  packages Ubuntu's phased updates defer and those kept back. artoo
  never runs `apt-get update`: the plan is what the lists say, and their
  age is in it (apt's daily timer refreshes them).
- **Plan:** one line per package, `name  old → new`, marked `security`;
  nothing pending is a no-op (exit 5). Impact: new dependencies are
  installed (a new kernel), nothing is removed; services that use an
  upgraded library are restarted (needrestart, `NEEDRESTART_MODE=a`);
  configuration files keep local changes (`--force-confdef
  --force-confold`); never a reboot. Notes: the lists' age, the deferred
  and kept-back counts, and that pinned packages (Alloy, the watchdog's
  stack, §9.9) stay at their pins. No recovery command: apt has no undo,
  so a snapshot taken first (`vm snap add VM NAME`) is the way back.
  The fingerprint is the planned set and the lists' stamp.
- **Send once:** `apt-get -y --with-new-pkgs upgrade` as root with
  `DEBIAN_FRONTEND=noninteractive` and `DPkg::Lock::Timeout=300` (an
  unattended run holding the lock is waited for), its output in
  `/var/log/artoo-upgrade.log`. apt's status lines (`APT::Status-Fd`)
  are the step's live detail (`42% Unpacking tmux (amd64)`) through
  `/run/artoo-upgrade.stage` (§4.4). Deadline 30 minutes: past it the
  outcome is unknown (exit 7) and apt keeps running in the guest; apt
  failing is exit 6 with the log's last lines.
- **Verify:** a fresh simulation shows none of the planned packages
  still pending at its planned version (a version the lists offer anew
  does not count). The result names a pending reboot with its packages
  (`/run/reboot-required`, as §9.4) and `vm reboot VM`.

Verified live (2026-10-25, approved plan) on the watchdog guest: `vm
verify` counted "no security updates; 10 other", `vm upgrade -n` planned
those 10 from `-updates` with 14 phased updates deferred, and `vm
upgrade -y` installed them in 18 s. apt's stage lines showed while it ran
(`0% Retrieving file 1 of 10`, `51% Configuring snapd (amd64)`), the
result said no reboot was needed, `vm verify` then showed "pending updates
ok none" and every other check unchanged, no unit had failed, and the
stage and exit-code files were gone.

### 9.13 Pending configuration

Decided 2026-10-26. Proxmox applies some changes to a running VM only at
its next start (memory or cores beyond what hot-plug allows, cloud-init
keys): `PUT …/config` stores them as pending, and `GET …/config` returns
the pending value as if it were live (§17.2). So wherever artoo shows or
checks a VM's configuration it reads `GET …/pending` — per key the
current `value`, the `pending` one and a pending `delete` — and names
the difference instead of hiding it:

- **`vm config VM`:** every key, sorted; a pending key reads `current →
  pending` with "pending restart" in the warning color (a pending delete
  `current → (removed)`, a new key `(unset) → value`), and a footer counts
  them and names `vm reboot VM`. `-o json` is the `/pending` list.
  `cipassword` stays masked in both.
- **`vm show VM`:** the vCPU line is the running count, and every shown
  key with a pending value (vCPU, memory, network, cloud-init) gets the
  same `→ pending` marker.
- **`vm verify VM`:** "config pending" (§9.4), read through the API, so
  it is checked without the guest agent: none is ok; pending keys are a
  warning naming them (`memory 4096 → 2048`) and `vm reboot VM` (`vm
  start VM` for a stopped VM).
- **`vm set VM`:** the fresh read still verifies what was stored
  (§8.2 step 9); a changed key that stays pending makes the result say
  so — "configuration saved; memory 2048 pending until restart" with `vm
  reboot VM` — instead of "applied".

A reboot from inside the guest does not apply them: the QEMU process
keeps running. `vm reboot VM` (`status/reboot`, which "applies pending
changes") or a shutdown and start does.

Verified live (2026-10-26, read-only) on a running guest whose memory
was lowered with `vm set`: `/pending` answered `{"key":"memory",
"value":"4096","pending":"2048"}` (values as strings, `cipassword`
masked); `vm config` and `vm show` marked it and `vm verify` warned
"memory 4096 → 2048".

## 10. UniFi

### 10.1 Access

Integration API at `https://unifi.home.arpa/proxy/network/integration`,
`X-API-KEY` from the secret store (`unifi`, §6); mkcert root; `/v1/info`
read once per invocation and version gates kept in one table. The API key
is created by the operator in the UniFi UI.

### 10.2 Parity with the legacy `unifi-cli`

Reference documentation: the official v10.6.106 OpenAPI + Postman export,
kept in a private checkout next to artoo (`../homelab/api/unifi/`, §17.1)
— consulted for every catalog entry.

artoo carries a **comptime resource catalog** (the Zig equivalent of
`unifi-cli/resources/catalog.py`), derived from the gateway's live OpenAPI
document (`GET /proxy/network/api-docs/integration.json`, §17.1);
`artoo gw spec` fetches it and reports operations the catalog lacks or that
changed, so firmware updates are caught early. Each entry declares path, verbs,
pagination, columns, identifier, allowed/required body fields and risk. The
catalog generates the `gw` command tree, help and table columns.

| Resource (`artoo gw …`) | Verbs |
| --- | --- |
| `sites` | ls |
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
| `wans`, `vpn-servers`, `vpn-tunnels`, `radius`, `lags`, `mc-lag`, `stacks`, `dpi-apps`, `dpi-categories`, `device-tags`, `countries` | ls (show where the API has it) — read-only API areas |
| `api METHOD /v1/…` | generic request, `/v1/` paths only, same pipeline for writes |

List verbs support `--filter EXPR` (server filter syntax), `-l/--limit`,
`--offset`, `--all` (pages of 200; not a snapshot). Bodies come from
`--from FILE` (JSON), checked against the catalog's allowed and required
top-level fields, which are generated from the export (deeper validation
is the server's). An artoo `show -o json` document is accepted as a body:
the envelope is unwrapped and the resource's read-only fields (`id`,
`metadata`, …) are dropped and named in the plan; any `<redacted>` value
is refused, so a copied secret placeholder can never be written. Direct
flags for common inputs are added per verb where they pay off (`dns` is
the first). PUT means a complete body; artoo never read-merge-PUTs
silently: the `set` preview diffs the current object against the file
and lists fields the PUT would reset. Writes are verified by a fresh read
where the API offers one (created/replaced/patched objects, orderings,
deletions via 404, purges); device/client actions and adoption have no
read-back and are reported as **accepted, not verified** (exit 0). The API
has no ETags; plans state that concurrent edits cannot be detected.
`gw spec` also checks every write operation and its body fields.

### 10.3 DNS records

`artoo dns ls|add|rm` manages `type: A` DNS policies
(`domain`, `ipv4Address`, `ttlSeconds`, `enabled`); `vm new`/`vm rm` use it.
Records artoo creates are recognizable by name pattern **and** matched
against the VM they belong to before removal.

Records are created under `guests.domain` (`lab.example.com`). artoo
refuses any record for the protected infrastructure names (§9.6) outside
`home.arpa`.

**Resolution on the LAN.** The workstation resolves through UniFi at
home: its DNS server is the gateway (`192.168.1.1`), directly or through
Tailscale MagicDNS (`100.100.100.100`), which forwards non-tailnet names
to it — no `/etc/resolver` files. DHCP hands every client the gateway as
DNS server and domain `home.arpa` (set with `gw networks set`:
`dnsServerIpAddressesOverride`, `domainName`). Away from home, names resolve only once
Tailscale split DNS sends `lab.example.com` and `home.arpa` to the subnet
router (§9.6).

## 11. Overview and health

`artoo status` collects sampled-not-atomic sections concurrently — one
task per system (`Io.Group`), each with its own `Context` copy (the arena
is thread-safe, `diag` per task); rendering waits for all (~0.6 s on the
LAN, from ~0.9 s sequential):
Proxmox host (CPU %, load 1/5/15, RAM, swap, root FS, uptime, versions),
guests (running/stopped/templates; per VM: state, vCPU, RAM, CPU %, memory,
uptime, address; stopped → `--`; below the table, guests whose
`/run/reboot-required` exists — a warning, not a failure, §9.1 — and fenced
guests whose fence drifted, §9.11), storage (per backend, no invented totals),
tasks (running + recent failures, warnings shown as warnings), UniFi
(version, WAN status, device/client counts, guest DNS records vs guests;
service records under `apps.` are services, not orphans), then the rest
of the lab (read-only):
- **Edge** — `edge status`'s checks (§9.7), drop counters towards Proxmox
  and UniFi first: one line when all pass, else each check that does
  not.
- **Router** — `router status`'s checks (§9.8), the same way.
- **Tunnel** — the lab tunnel's state, connections and public routes
  (§15); a route to a service that does not exist is drift.
- **Services** — `svc ls`'s drift (§9.6), computed from what the other
  tasks read (edge route files, UniFi records, guests): no extra
  requests.

A role VM or tunnel that does not exist shows as "none", not as an error.
A failed check (edge, router) exits 8 like an unavailable section;
warnings and drift are shown but do not change the exit code. Guest CPU is
labelled as % of its vCPUs; host CPU as % of host threads.

`artoo host health [CHECK…]` runs named checks (`api`, `node`, `storage`,
`tasks`, `zfs`, `services`) — all through the API (`/disks/zfs` pool
health, `/services` for the core PVE services plus chrony and cron;
corosync is idle on a single node and not checked). Thresholds are in the
command help; warnings do not fail. Total connection/auth failure keeps
exit 4/3; otherwise any failed or not-run requested check → 8.

`--watch [--interval S]` for `status` is a later increment.

## 12. Architecture

```text
src/
  main.zig            process wiring; exit codes mapped here only
  cli/                declarative command/flag table, parser, help, completion
  ui/                 palette, sanitize, table, detail, plan, progress, json
  config.zig          schema 1, atomic save
  secrets/            SecretStore: keychain (macOS), secret-service, file (+ in-memory fake)
  http.zig            transport (§8.1)
  pve/                client, typed models, resources (vm, task, storage, …)
  unifi/              client, catalog, typed models
  cloudflare/         client, typed models (§15)
  exec.zig            mutation pipeline (§8.2) + workflow ledger
  guest/              baseline, crypt512, vendor-data renderer, payload embed
  update/             self-update: GitHub releases, archive checks, install (§18)
  commands/           one file per noun: thin glue from args → domain → view
```

Rules: resource modules never print; commands never touch HTTP directly;
renderers only see sanitized view models. Explicit `Allocator`/`Io`, one
arena per invocation, no globals, no `catch unreachable`/panics on command
paths, `errdefer` for acquired resources. stdout/stderr use streaming file
writers. `make install` builds `ReleaseSafe`. Platform frameworks are never
linked: `zig build -Dtarget=x86_64-linux` and `aarch64-linux` must succeed
in CI-equivalent local checks.

## 13. Testing

- `zig build test` (offline, default) and `zig fmt --check` must pass before
  every commit — no exceptions.
- Every command has table-driven tests for parsing, planning (including
  refusals) and rendering (golden output, color off).
- HTTP behavior is tested against an in-process fake server (plain HTTP in
  tests): retries, deadlines, idle-closed connections, write-once and every
  unknown-outcome path, PVE task states, UniFi pagination.
- Executor scenarios: dry-run/declined/non-interactive send nothing; writes
  sent at most once; failed/unknown never reported as success.
- Live runs are ordinary `artoo` invocations driven by a script in
  `scripts/live/` (`vm-lifecycle.sh`: set, snapshots, power, clone, rm —
  passed 2026-10-10) against **disposable guests it created in the same run**
  (ownership = VMID + name + tag recorded in a ledger,
  `~/.artoo/live-ledger.txt` or `$ARTOO_LEDGER`, before any destructive
  step; guards abort the run on the first failed precondition). Live
  scripts and `scripts/pve-*.sh` take the Proxmox host from `PVE_SSH`
  (required, no default). Gateway live tests are read-only unless a plan is approved.

## 14. Delivery phases

UniFi first: discovering the gateway's real
configuration early informs the Proxmox, addressing and DNS work.

1. **Clean slate + foundations** — only `payload/` and `crypt512` carried
   over from the prototype; build the declarative
   CLI + generated help, UI kit, config, `SecretStore`, transport
   (no pooling, deadlines) with an in-process fake server, exec pipeline.
   Linux cross-builds green.
2. **UniFi read-only + discovery** — `auth set unifi`, `gw info`, the
   full read catalog from the *current* Integration API docs on the gateway
   (export kept in the private API checkout, §17.1).
3. **UniFi DNS + mutations** — `dns`, then catalog writes and `gw api`
   (live writes only under approved plans); replaces the legacy `unifi-cli`.
4. **Proxmox operations** — `status`, `host`, `storage`, `task`, `vm` inspect,
   lifecycle and snapshots.
5. **Proxmox setup (approval)** — single token + built-in roles +
   `ArtooFetch`.
6. **Cloudflare client** — `auth set cloudflare`, `doctor` token check,
   `cf dns ls|add|rm` (§15); writes under approved plans. Tunnel routes
   follow in phase 8 with the edge VM that runs `cloudflared`.
7. **Templates and provisioning** — `image`, `template build`, vendor
   snippet, `vm new|verify|rm|ssh|password`; two disposable guests end to end.
8. **Names for guests (approval)** — the guest pool kept outside the DHCP
   range, `vm new`/`vm rm` machine names and client records, DHCP DNS
   server = the gateway and domain `home.arpa`; then, each its own
   approval: the edge VM (Caddy, `*.apps.lab.example.com`, firewall) and
   service names; Cloudflare Tunnel and public guests; Tailscale subnet
   router + split DNS.

## 15. Cloudflare

Designed from Cloudflare's official OpenAPI document
(`cloudflare/api-schemas` commit `3fad73eb`, 2026-10-09; Cloudflare API
4.0.0), fetched from Cloudflare's published OpenAPI, not committed;
re-fetch it before changing behaviour.

**Scope.** The `example.com` zone (`cloudflare.zone`) — DNS records for
public guests and vanity names — and the ingress routes of the lab's one
Cloudflare Tunnel. Nothing else in the account.

**Credential.** One **account API token** (Manage account → Account API
tokens; owned by the account, not a user — DNS, zones and Tunnels support
them), secret `cloudflare` (§6), created by the operator and entered with
`auth set cloudflare`:

| Permission | Resource | Needed for |
| --- | --- | --- |
| Zone → Zone → Read | zone `example.com` | zone ID by name (`GET /zones?name=`) |
| Zone → DNS → Edit | zone `example.com` | records: list, create, delete ("DNS Write") |
| Account → Cloudflare One Connector: cloudflared → Edit | the account | tunnel routes: `GET`/`PUT …/cfd_tunnel/{id}/configurations` (schema groups "Cloudflare One Connector: cloudflared Write", or the broader "Cloudflare One Connectors Write" / older "Cloudflare Tunnel Write"; not "Argo Tunnel (Legacy)") |

The tunnel permission cannot be narrowed to one zone or one tunnel; one
token for both is a deliberate choice for a personal account.
Recommended at creation: an expiry and a client-IP filter for the lab's
public address. The edge VM's DNS-01 token stays separate (§9.6).
Consequence: a leaked token could route a public name to anything
`cloudflared` can reach, so the §9.6 hard rule is also enforced in the
network — the edge VM that runs `cloudflared` (phase 8) cannot reach
Proxmox's or UniFi's management ports (its firewall drops them).

**Transport.** `https://api.cloudflare.com/client/v4`, `Authorization:
Bearer <token>` injected at request time. TLS verified against the
operating system's root store (`std.crypto.Certificate.Bundle.rescan`:
macOS system keychain roots, Linux `/etc/ssl/certs/…`), never the mkcert
root; same deadlines, no pooling, no write retries (§8.1). Every response is
the envelope `{success, errors[{code, message}], messages, result,
result_info{page, per_page, count, total_count}}`; `success: false` or a
non-2xx status becomes an error carrying `errors[].message` (sanitized).
Lists page with `page`/`per_page` (100) until `total_count`.

**Zone.** Resolved by name once per invocation; the account ID comes from
the zone object (`account.id`), so config holds names only:
`cloudflare.zone`, `cloudflare.timeout_seconds`, and in phase 8
`cloudflare.tunnel` (tunnel name).

**Ownership.** artoo writes only records it marks — `comment:
"artoo: <purpose>"` (comments exist on every plan; tags do not) — and
refuses to change or delete unmarked records.
`cf dns ls` shows every record with an `ARTOO` column.

**Commands (phase 6).**

- `auth set cloudflare`; `doctor --connect` resolves the zone (which
  names its account) and verifies the token with
  `GET /accounts/{account_id}/tokens/verify` (status, expiry; an account
  token is unknown to `/user/tokens/verify`).
- `cf dns ls [--type T] [--name N]` — every record (name, type, content,
  proxied, TTL, artoo-owned, ID).
- `cf dns add NAME TYPE CONTENT [--proxied] [--ttl S] [--note TEXT]` —
  types `A`, `AAAA`, `CNAME`, `TXT`; a short NAME gets the zone appended;
  TTL 1 (auto) or 60–86400; `POST /zones/{id}/dns_records`, verified by a
  fresh `GET` of the returned ID. Refused before planning (exit 5, no
  override): names or contents matching Proxmox or UniFi (§9.6), A/AAAA
  contents that are LAN, loopback or link-local addresses (no LAN layout in
  public DNS), names under `guests.domain` (private guest names never go
  public; public names come from `cf tunnel route add`), and
  an existing record with the same name and type.
- `cf dns rm NAME|ID` — marked records only; typed confirmation (or
  `--confirm NAME`); `DELETE`, verified by a `GET` answering 404.

**Tunnel routes (phase 8, with the edge VM).**
The tunnel is remotely managed: its ingress list lives in Cloudflare and
`cloudflared` on the edge VM fetches it. A public host always reaches an
existing **service** (§9.6), one path: Cloudflare → `cloudflared` →
Caddy on `localhost` → the service's route → guest. Commands:

- `cf tunnel ls` — the account's tunnels (name, ID, status, connections)
  and the lab tunnel's routes (public host → service). Read-only.
- `cf tunnel route add HOST SERVICE` — HOST in the zone (a short name gets
  it appended), SERVICE an existing `svc`. Ingress rule
  `{hostname: HOST, service: "https://localhost:443", originRequest:
  {originServerName: <svc>.apps.<guests.domain>, httpHostHeader: <same>}}`
  — TLS to Caddy verified against the wildcard (never `noTLSVerify`); the
  app sees the service name as Host (an app building absolute URLs gets
  its public URL in its own settings). Plus a marked, proxied `CNAME HOST →
  <tunnel-id>.cfargotunnel.com` (`artoo: tunnel <svc>`).
- `cf tunnel route rm HOST` — typed confirmation; the rule and the marked
  CNAME.

`PUT …/configurations` replaces the **whole** list, so add/rm read the
current configuration, plan the complete new list (diff shown; the
catch-all `http_status:404` stays last), re-read before sending and refuse
if the `version` changed, then verify by a fresh read. The public name is
checked by hand afterwards: probing it right away could make a resolver
cache the not-yet-visible name as NXDOMAIN. Refused before planning: HOST under `guests.domain`,
names of Proxmox or UniFi (§9.6), an existing record for HOST, a
SERVICE that does not exist, a SERVICE whose VM carries `role-watch` or
`role-search` (§9.9; no override). `svc rm` refuses while a public route
points at the service.

Verified live (2026-10-11) against a disposable guest and service:
`edge setup` adds the cloudflared unit and user without restarting
Caddy; `edge tunnel` creates the tunnel, delivers its token API → VM and
reports its connections (`healthy`), and a second run finds nothing to
change; `cf tunnel route add` published the service over HTTPS through
Cloudflare's edge; `svc rm` refused while the route existed; `route rm`,
`svc rm`, `vm rm` left no route, record, service or guest. The tunnel
stays.

**Testing.** Offline: fake server for the envelope, paging, errors and
every refusal. Live (approved plan, passed 2026-10-10): one disposable
marked `TXT` record `_artoo-test.example.com` — added and verified,
listed as artoo's, answered by `1.1.1.1` within seconds, removed and
verified by 404. Verified live the same day: system-root TLS to
`api.cloudflare.com`, the account token's verify via
`/accounts/{account_id}/tokens/verify`, TXT content stored and returned
unquoted.

## 16. References

- Proxmox VE API viewer: <https://pve.proxmox.com/pve-docs/api-viewer/>;
  installed source on Proxmox (`/usr/share/perl5/PVE/API2/`) is authoritative
  for its version.
- Cloud-init on Proxmox: <https://pve.proxmox.com/wiki/Cloud-Init_Support>.
- UniFi Integration API: §17.1; official export in the private checkout
  next to artoo (`../homelab/api/unifi/`).
- Zig 0.17.0 stdlib: `~/.local/opt/zig/stable/lib/std`.
- Proxmox VE API schema: `/usr/share/pve-docs/api-viewer/apidoc.js` on
  any PVE host (pve-docs 9.2.13), a copy in the private checkout next to
  artoo (`../homelab/api/pve/`).

## 17. API facts (implementation reference)

Facts the code depends on, established from the official documents and
live, read-only or approved runs. Lab state (addresses, configuration,
equipment) belongs in the operator's own lab record; operating
procedures in GUIDE.md.

### 17.1 UniFi Network Integration API

- **Reference documents:** the official Network API v10.6.106 export
  (`network_v10.6.106_openapi.json`, OpenAPI 3.1 — authoritative for
  paths, parameters, schemas and per-endpoint filterable properties; plus
  the Postman collection), matching UniFi's firmware. It is expected in a
  private checkout next to artoo, at
  `../homelab/api/unifi/network_v10.6.106_openapi.json` relative to the
  artoo checkout; tests that need it skip without it. Re-obtain from
  <https://developer.ui.com/network/v10.6.106/> or from the gateway:
  `GET /proxy/network/api-docs/integration.json` with the API key (what the
  UI's "Network API" page renders) — `artoo gw spec --save PATH` fetches it
  without exposing the key. After a firmware update: fetch, run `gw spec`,
  update the catalog before changing behaviour. The download equals the
  gateway's document except `servers`.
- **Shape:** 44 paths, 73 operations (41 GET, 12 POST, 9 PUT, 1 PATCH, 10
  DELETE), 380 schemas; no security scheme declared — auth is the
  `X-API-KEY` header, injected at request time and never logged. Base
  `https://unifi.home.arpa/proxy/network/integration`.
- **Pagination:** `offset` (default 0), `limit` (default 25, max 200); no
  stable sort — a set of pages is not a snapshot.
- **Errors:** `{statusCode, statusName, code, message, requestId,
  requestPath, timestamp}`; operations declare no non-2xx responses, so
  error handling follows the live server.
- **Filter grammar** (confirmed live 2026-10-10): `property.function(args)`
  — `name.eq('ap-office')`, `name.in('a','b')`, `firmwareVersion.gt('6.0.0')`,
  `features.contains('accessPoint')`, `supported.eq(true)`; combine with
  `and(…)`, `or(…)`, `not(…)`. Strings take **single quotes only**,
  booleans are bare, `like` uses `*`. Bad filters → 400
  `api.request.invalid-filter` with a positioned message (artoo: exit 2).
  Each list's filterable properties come from its description table; the
  catalog's tables are generated from the export and tested against it.
- **Secrets in responses:** Wi-Fi broadcast details return the passphrase
  in clear (`securityConfiguration.passphrase`); RADIUS/VPN fields may
  carry secrets. artoo redacts secret-bearing keys before any output.
- **Schemas:** code-generation-hostile polymorphism (77 discriminator
  nodes, 190 `allOf`, schema names with spaces). Do not generate a client:
  handwritten models, tolerant on responses, strict on requests; write
  bodies are checked against generated top-level field lists (union over
  discriminator variants).
- **`/v1/info`** exposes only `applicationVersion`; gate version-specific
  behaviour centrally, never compare versions lexically.
- **No ETags, idempotency keys or rate-limit documentation** — plans state
  that concurrent edits cannot be detected; writes are never retried.
- **Coverage:** CRUD for networks, Wi-Fi broadcasts, firewall
  policies/zones, ACL rules, DNS policies, traffic matching lists, hotspot
  vouchers (plus filtered bulk delete); device actions (restart, PoE port
  power-cycle, adopt, remove) and client guest authorization. Read-only:
  sites, switching, WANs, VPN, RADIUS, DPI, countries, device tags. Only
  firewall policy has PATCH. **Not in the API:** DHCP reservations, client
  renames, port forwarding, static routes, QoS, NAT, firmware/UniFi OS.
- **DNS policies:** A, AAAA, CNAME, MX, SRV, TXT and forward-domain. A
  records answer on the gateway a few seconds after creation — also for
  names inside the public `example.com` domain (verified 2026-10-10:
  approved `artoo-test.lab.example.com` add → `dig @192.168.1.1` → rm →
  NXDOMAIN; public resolvers never saw it). DHCP DNS servers, domain name
  and range are settable via `PUT …/networks/{id}`.
- **Classic API (undocumented):** the same `X-API-KEY` authenticates
  `/proxy/network/api/s/default/…` — verified 2026-10-10 with read-only
  `GET self` (key = site admin, super) and `GET rest/user` (every known
  client, offline included). Client records carry `name` (the UI alias),
  `hostname` (from DHCP), `use_fixedip` + `fixed_ip` (the UI's Fixed IP =
  DHCP reservation) and `local_dns_record_enabled` + `local_dns_record`.
  `POST group/user {"objects":[{"data":{mac, name, use_fixedip,
  network_id, fixed_ip}}]}` creates a record for a MAC never seen, name
  and Fixed IP applied in one request (`network_id` = the classic
  `rest/networkconf` `_id`; verified 2026-10-10 by
  `scripts/live/unifi-reservation-probe.sh`).
  `POST cmd/stamgr {"cmd":"forget-sta","macs":[…]}` works with the key
  (2026-10-10): an offline client's record is gone; a client the gateway
  still counts as connected is re-created at once. Not covered by `gw
  spec`; firmware may change it.
- **Client names:** UniFi names a client from its DHCP hostname; a
  static client inherits the hostname of the last lease on its IP
  (verified 2026-10-10: a static guest showed under the name of the
  device that last leased its address) — hence the client record, §9.5.
- **Live quirks (2026-10-10):** firewall zones/policies answer 400 "Zone
  Based Firewall is not configured"; the device list reports the gateway's
  WAN address as its `ipAddress`; device-to-port mapping is not exposed.

### 17.2 Proxmox VE API

- **Access:** user `artoo@pve`, token `artoo@pve!cli`, privilege
  separation off; ACLs `/` and `/nodes/<node>` → `PVEAuditor`,
  `PVEVMAdmin`, `PVEDatastoreAdmin`, `PVESDNUser`, plus `ArtooFetch`
  (`Sys.AccessNetwork`) on `/nodes/<node>` (set up and verified
  2026-10-10: 32/33 privileges, none of `Sys.Modify`, `Sys.PowerMgmt`,
  `Sys.Console`, `User.Modify`, `Permissions.Modify`).
- **ACLs replace, not merge, along the path:** the most specific path with
  an entry for a user replaces inherited roles; node-level entries repeat
  the full role set. A privsep token without its own ACL answers 200 with
  empty data — permission checks assert on content. `pveum acl list`
  silently omits entries naming a deleted token; verify cleanups by
  grepping `/etc/pve/user.cfg`.
- **Privileges per operation** (`PVE/API2/Qemu.pm`, `QemuServer.pm`):
  power → `VM.PowerMgmt`; clone → `VM.Clone` + `VM.Allocate` +
  `Datastore.AllocateSpace` + `SDN.Use` on `/sdn/zones/localnetwork/vmbr0`
  even for untagged `vmbr0`; destroy → `VM.Allocate`; config per key
  (`cores` → `VM.Config.CPU`, `memory` → `VM.Config.Memory`,
  `name`/`description` → `VM.Config.Options`, cloud-init keys →
  `VM.Config.Cloudinit` or `VM.Config.Network`); snapshots →
  `VM.Snapshot` (rollback also `VM.Snapshot.Rollback`); deleting a storage
  volume → `Datastore.Allocate`.
- **Errors:** pveproxy puts the message in the status line's reason
  phrase (sometimes also JSON `message`/`errors`); a missing VM answers
  **500** "Configuration file … does not exist", not 404; a token secret
  with the wrong token ID answers 401.
- **Requests:** writes are form-encoded; GET and DELETE carry parameters
  in the query string and must not have a body (the Zig stdlib asserts).
  Most writes return a UPID; `PUT …/config` is synchronous and accepts
  `digest` for optimistic locking; `GET …/config` shows pending values
  as if live; `GET …/pending` lists each key with `value` (current),
  `pending` and `delete` (1, or 2 for a forced delete) — §9.13;
  `status/reboot` applies pending changes.
- **Tasks:** `stopped` with `OK` or `WARNINGS: n` is success; the
  `errors=1` filter also returns tasks with warnings.
- **Listing:** `/cluster/resources` is refreshed by pvestatd — a VM created
  seconds ago appears with its VMID but no name or status; per-node
  `/nodes/{node}/qemu` reads configs and live status directly.
- **Guests:** a guest without an OS ignores ACPI shutdown (the task times
  out); rolling back a RAM-less snapshot leaves the VM stopped.
- **Provisioning constraints:** no API endpoint uploads snippets
  (`download-url` allows only `iso|vztmpl|import`) — hence §9.2's SSH
  placement; `local` = dir `/var/lib/vz` (import, snippets, backup,
  vztmpl, iso), `local-zfs` = images and rootdir only; the cloud-init ISO
  is generated at VM start from config + `cicustom` snippet, so a missing
  snippet breaks the next start.
- **Ubuntu 26.04 guests (observed live 2026-10-10, test guest):** sudo is
  `sudo-rs` ("interactive authentication is required"); sshd is
  socket-activated, so `/run/sshd` is missing until the first connection
  and `sshd -T` fails — `sshd -G` (OpenSSH 10) works; Proxmox's generated
  user-data uses the deprecated `user:` key, so `cloud-init status` is
  always "degraded done" (exit 2) — artoo judges the JSON status instead;
  the first-boot upgrade installs a newer kernel (and its initramfs);
  `qmreboot` finishes once the guest has shut down and the restart
  follows, so `vm reboot` polls for `running`;
  1 GiB RAM is ~99% used right after cloud-init.
- **Template build (verified live 2026-10-10, approved):** the token's
  roles suffice for `download-url` (`content=import`, SHA-256 checked;
  825 MiB in under a minute), `POST /qemu` with
  `scsi0=local-zfs:0,import-from=local:import/…` and `cicustom`
  (snippet must exist first), and `POST /qemu/{id}/template` (UPID
  `qmtemplate`). The imported disk becomes `base-<id>-disk-0` at the
  image's virtual size (3.5 GiB for 26.04); the API lists snippets
  (`content=snippets`, with size) though it cannot upload them.


### 17.3 GitHub releases

Checked 2026-10-23 against the public repository, read-only and without
a token:

- `GET https://api.github.com/repos/<owner>/<repo>/releases/latest` is
  the newest release that is neither a draft nor a pre-release;
  `…/releases/tags/vX.Y.Z` names one (404 when absent). Fields used:
  `tag_name`, `prerelease`, `draft`, `published_at`, and per asset
  `name`, `size`, `state` (`uploaded`) and `digest` (`sha256:<hex>`,
  GitHub's own hash of the upload). Headers sent: `Accept:
  application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, a
  `User-Agent` (required).
- An asset's download URL `https://github.com/<owner>/<repo>/releases/download/<tag>/<name>`
  answers **302** to a signed, short-lived URL on
  `release-assets.githubusercontent.com` (formerly
  `objects.githubusercontent.com`), which serves the bytes.
- Without a token the API allows 60 requests an hour per address; a
  used-up limit answers 403 or 429 with a JSON `message`.
- Zig 0.17's `std.http` reaches both hosts with the system roots; its
  `std.compress.flate` (gzip) and `std.tar` read the release archives
  that `scripts/release-binaries.sh` makes on the macOS runner (a
  directory, `LICENSE`, `artoo` mode 755, `README.md`; no PAX entries).

## 18. Self-update (`artoo update`)

Decided 2026-10-23. `artoo update` replaces the running binary with a
release from GitHub, on macOS and Linux, so a machine without a checkout
(`make install`) stays current. Releases are made by
`.github/workflows/release.yml` (docs/RELEASING.md): per target an
archive `artoo-<ver>-<target>.tar.gz` holding
`artoo-<ver>-<target>/artoo`, plus `SHA256SUMS`.

- **Command.** `artoo update [VERSION] [--check]`. Without VERSION: the
  latest release (§17.3; pre-releases and drafts are never chosen).
  VERSION (`0.4.0`, `v0.4.0`, `0.4.0-rc.1`) names one release; it is
  checked as SemVer before any request (exit 2), and a release that does
  not exist is exit 2. A downgrade or a pre-release happens only when
  named; the plan says so. VERSION is a positional because `--version` is
  a global flag (§3.1). No config, secret or token is used; the
  repository is `tildaslashalef/artoo`, built in.
- **Versions** compare by SemVer precedence (`std.SemanticVersion.order`,
  build metadata ignored): `0.4.0-dev+abc` < `0.4.0-rc.1` < `0.4.0`. The
  same version is a no-op (exit 5, nothing downloaded); so is a build
  newer than the latest release (a `-dev` build after its predecessor's
  release) unless VERSION is named.
- **`--check`** is read-only: release metadata only, nothing downloaded,
  no prompt. Exit 0 when an update is available, 5 when there is nothing
  to update (the no-op `artoo update` itself would refuse), so
  `artoo update --check && artoo update -y`. Other failures keep their
  codes.
- **Target.** From the build's own OS and CPU: `aarch64-macos`,
  `x86_64-macos`, `aarch64-linux`, `x86_64-linux`. Any other is refused
  before a request (exit 5). A release that lacks this target's archive
  or `SHA256SUMS` is exit 4.
- **Transport.** §8.1 with the system roots (as Cloudflare, §15), no
  Authorization header ever. The transport refuses redirects; the
  updater alone asks for them back and follows at most two hops, each
  `https` to `github.com`, `api.github.com`,
  `release-assets.githubusercontent.com` or
  `objects.githubusercontent.com` — anything else is exit 4. `-v` shows a
  redirected hop's host and path, not its signed query. Deadlines: 15 s
  for metadata and `SHA256SUMS`, 120 s for the archive (`--timeout`
  overrides both). Size caps: metadata 1 MiB, `SHA256SUMS` 64 KiB,
  archive 64 MiB, binary 128 MiB. A used-up rate limit is exit 4 with
  GitHub's message.
- **Verification, before the plan is shown** (so before any change):
  the archive's length equals the asset's `size`; its SHA-256 equals its
  one line in `SHA256SUMS` (`<hex>  <name>`) and the asset's `digest`
  when GitHub gives one; gzip and tar are read with the stdlib only
  (never `tar` or `curl`); only the entry `artoo-<ver>-<target>/artoo`,
  a regular file present once, is used — every other entry is skipped
  and never written. It is streamed into `<dir>/.artoo.update-<random>`
  beside the target (exclusive create, 0755, fsync), and that file run
  with `--version` must print exactly `artoo <ver>`. Any mismatch or
  malformed archive is exit 5; the staged file is removed and nothing
  changed. Protection model, stated honestly: this catches corruption
  and a changed download; the trust root is GitHub's TLS and the
  release itself (releases are not signed).
- **Replacement.** The target is the running executable
  (`std.process.executablePath`, which follows links). Refused: the path
  artoo was invoked by (argv[0], or the `PATH` entry for a bare name) is
  a symbolic link (exit 5: update what owns its target, or install the
  binary itself); the target is not a regular file or was deleted
  (exit 5); its directory is not writable (exit 3) — artoo never runs
  `sudo`. The current binary is copied to `<dir>/.artoo.previous` (one
  generation, atomic, 0755) — a copy, not a hard link (Linux's
  `protected_hardlinks`), and not a rename (no moment without a binary).
  Then the staged file is renamed over the target, and the directory is
  synced. A new inode avoids Linux's "text file busy" and macOS killing
  a binary whose signed pages changed in place; the running process
  keeps the old one. Shell completion needs nothing (§3.5).
- **Pipeline** (§8.2): read (release, target identity) → plan (no-op
  check, then download, verify, stage) → preview → `--dry-run` stops,
  removing the staged file (exit 0: downloaded and verified, nothing
  replaced) → confirm (normal risk, `-y`) → re-read after a long prompt
  (a changed release or target file aborts, exit 5) → back up and rename
  → verify: the installed file's `--version` prints `artoo <ver>`, else
  exit 8 with the rollback command. The staged file is removed on every
  path that does not install it. Rollback: `mv <dir>/.artoo.previous
  <dir>/artoo`, or `artoo update OLDVERSION`.
- **Plan** names current → new version, the release and its date, the
  asset and size, the SHA-256 and what it matched, the staged binary's
  version, the target path, the backup and the recovery command. `-o
  json` uses target `github`: `current`, `version`, `latest`,
  `update_available`, `asset`, `sha256`, `path`, `backup` and `result`
  (`dry-run`, `applied`; `--check` gives the first five fields).
- **Testing.** Offline against the fake server, with archives built in
  the test (`std.tar.Writer`, gzip) around a shell script that prints a
  version, installed into a temp directory: newer, same, a dev build,
  explicit and missing VERSION, checksum and digest mismatch, wrong
  version inside, a missing entry, entries outside the one used, an
  off-list redirect, unsupported target, symlinked and non-writable
  targets, dry run, declined and non-interactive runs, `--check` and
  JSON. Live: `artoo update --check` and `-n` against the published
  release on a workstation; an actual update is the operator's.
