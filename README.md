# ARTOO (R2D2)

**My opinionated CLI for my own home lab** — one Proxmox VE host, one
UniFi gateway, a Cloudflare zone and Tailscale — published because the
approach may be useful to others. It is not a general-purpose tool and
does not try to be: it encodes my stack, my defaults and my taste. If
your lab looks similar, use it as is; if not, **fork it and adapt it** —
the design is documented in detail precisely so that this is practical.

Like R2-D2, the small droid that fixes things while bigger systems argue.

```console
artoo status                               # the whole lab on one screen
artoo vm new naboo --role web              # a ready guest: static address, names, SSH
artoo svc add grafana naboo:3000           # https://grafana.apps.lab.example.com
artoo cf tunnel route add grafana grafana  # https://grafana.example.com
```

## What it does

- **Guests in one command.** `vm new` clones an Ubuntu template, sets a
  static address from a pool, reserves it on the gateway, creates the
  guest's DNS name, waits for cloud-init, pins the SSH host key and runs
  readiness checks. `vm ssh`, `vm cp`, snapshots, power, resize, `vm rm`.
- **Names and HTTPS.** An edge VM runs Caddy with a Let's Encrypt
  wildcard for `*.apps.<your domain>`; `svc add` gives any guest port a
  LAN name with a real certificate.
- **Public only on purpose.** A Cloudflare Tunnel publishes chosen
  services (`cf tunnel route add`); nothing else is reachable from the
  internet.
- **Remote access** through a Tailscale subnet router guest.
- **A watchdog** guest with VictoriaMetrics, Loki, Grafana and ntfy:
  metrics and logs from every guest and the host, alerts to your phone.
- **The UniFi gateway** through its Integration API (`gw …`), with
  every endpoint checked against the official OpenAPI export.

## How it behaves

- **Every write is a plan first.** It reads, validates, shows a redacted
  plan, asks, sends once and verifies the result. `-n` previews only;
  `-y` skips only the prompt. Deletions require typing the target's name.
  Writes are never retried; an ambiguous timeout is reported as unknown.
- **Never public.** The Proxmox host and the gateway can never be given
  a public name, route or tunnel — by name or address, derived from your
  config, with no override.
- **Secrets** live in the macOS Keychain, the Linux Secret Service or a
  0600 file; they are never printed, logged or accepted as arguments.
  TLS is always verified; there is no insecure mode.
- **Scriptable and agent-friendly.** Stable exit codes, `-o json` with a
  versioned envelope, help generated from the command table, shell
  completion. [docs/GUIDE.md](docs/GUIDE.md) is written so an AI agent
  can operate a lab safely with it.
- Native Zig 0.17, standard library only, one static binary for macOS and
  Linux (arm64, x86-64).

## Is this for you?

artoo assumes this stack. Each piece is load-bearing:

| You need | Used for |
| --- | --- |
| **Proxmox VE 9** — one node | guests, templates, storage; an API token for artoo and root SSH for one step |
| **A UniFi gateway** with UniFi Network 10.6+ (Integration API) | DHCP reservations and DNS records for every guest — **`vm new` requires it** |
| **Ubuntu 26.04** cloud image (pinned in artoo) | every guest and template |
| **mkcert** (or your own CA) | trusted HTTPS to the Proxmox and UniFi web APIs |
| **A Cloudflare zone** — optional | DNS-01 for the edge's wildcard certificate, the tunnel, public records |
| **Tailscale** — optional | the subnet router for remote access |
| **macOS or Linux** workstation | where artoo, its secrets and your SSH key live |

No LXC containers, no clusters, no other gateways or DNS providers. If you
use something else — OPNsense, Pi-hole, a different hypervisor — artoo is
best read as a reference design to fork.

## Personal preferences baked in

Some choices are simply mine. Change them in a fork:

- **The guest home configuration is my own.** Every guest's user (named
  by `guests.user`) gets my shell environment: fish as login shell,
  starship, tmux, Vim, a Gruvbox theme, a few helper functions and the
  Ghostty terminfo — see [src/guest/payload/](src/guest/payload/). Edit
  those files, `make install`, then `artoo template build ubuntu-2604`.
- The guest baseline: key-only SSH, no root login, sudo with a generated
  password, daily security updates and never an automatic reboot.
- Curated Star Wars and Middle-earth guest names, purpose in a
  `role-…` tag.
- The watchdog stack and its pinned versions, the dashboard and the
  alert rules.

## Getting started

[docs/QUICKSTART.md](docs/QUICKSTART.md) goes from nothing to a first
guest: prerequisites on Proxmox and UniFi, configuration, credentials,
the template and `vm new`.

## Build

```console
make            # debug build
make test       # tests, zig fmt --check, Linux cross-builds (what CI runs)
make install    # ReleaseSafe → ~/.local/bin/artoo, plus fish completion
```

Requires Zig 0.17.0. Or download a release: each
[GitHub release](https://github.com/tildaslashalef/artoo/releases) carries
`artoo-<version>-<target>.tar.gz` for macOS and Linux (arm64, x86-64) and
`SHA256SUMS` (`shasum -a 256 -c SHA256SUMS`). The macOS binaries are not
signed: after download, `xattr -d com.apple.quarantine artoo`.

## Documents

| | |
| --- | --- |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | from zero to a first guest |
| [docs/GUIDE.md](docs/GUIDE.md) | operating a lab with artoo, by task |
| [docs/RELEASING.md](docs/RELEASING.md) | version rules and the release procedure |
| [docs/SPEC.md](docs/SPEC.md) | the design: commands, output, safety, every subsystem |
| [AGENTS.md](AGENTS.md) | rules for agents and contributors; branches and releases |

## Contributing

Issues and pull requests are welcome, but artoo follows my lab first:
changes that keep it simple and safe for this stack are the ones likely
to be merged. Forks that take it somewhere else are very welcome.

## License

[MIT](LICENSE)
