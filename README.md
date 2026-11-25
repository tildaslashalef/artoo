# ARTOO (R2D2)

**My opinionated CLI for my own home lab**: one Proxmox VE host, one UniFi
gateway, a Cloudflare zone and a tailnet. It encodes my stack, my defaults
and my taste, and it is published because the approach may be useful to
others. If your lab looks like mine, use it as is; if not, **fork it and
adapt it**: the design is documented in detail so that this is practical.

Like R2-D2, the small droid that fixes things while bigger systems argue.

```console
artoo status                               # the whole lab on one screen
artoo vm new naboo --role web              # a ready guest: address, names, SSH
artoo svc add grafana naboo:3000           # https://grafana.apps.lab.example.com
artoo cf tunnel route add grafana grafana  # https://grafana.example.com
```

## Every write is a plan first

artoo reads the current state, validates, shows a redacted plan, asks,
sends once, and verifies the result. This is `vm new` with `-n`, which
stops after the plan:

```console
$ artoo vm new hoth --no-watch -n
Plan · Create guest hoth (208)
  Target    Proxmox (node pve)
  Change    VM             (none) → 208 hoth, full clone of ubuntu-2604 (9000)
            size           (none) → 2 vCPU, 2.0 GiB RAM, 20 GiB disk (small)
            address        (none) → 192.168.1.208/24 via 192.168.1.1 (static)
            user           (none) → artoo: your SSH key; sudo password generated, kept in the Keychain
            tags           (none) → artoo;no-watch
            client record  (none) → hoth, Fixed IP 192.168.1.208 on UniFi (the VM's MAC)
            DNS record     (none) → hoth.lab.example.com → 192.168.1.208 on UniFi
            host key       (none) → ~/.artoo/known_hosts entry hoth (read through the guest agent)
            ssh config     (none) → Host hoth in ~/.artoo/ssh_config
  Impact    A new VM on Proxmox; its client record and an A record on UniFi
  Recovery  artoo vm rm hoth
  Note      --no-watch: not enrolled with the watchdog (tag no-watch): no metrics, journal or alerts; 'watch enroll --all' skips it.
            Cloud-init installs packages on first boot; the workflow waits for it (several minutes), then reboots the guest once if the updates ask for it.
            Steps run in order and stop at the first failure; nothing is undone automatically. Re-running continues.

Dry run: nothing was sent.
```

- `-n` previews any write; `-y` skips only the prompt, never the checks.
  Deleting, rolling back or force-stopping asks you to type the target's
  name.
- Writes are never retried. A timeout whose outcome is unclear is
  reported as unknown, with the command that checks it.
- **Never public.** The Proxmox host and the gateway can never get a
  public name, route or tunnel, by name or by address. artoo works this
  out from your config and has no override.
- **Secrets** live in the macOS Keychain, the Linux Secret Service or a
  0600 file. They are never printed, logged or accepted as arguments,
  and TLS is always verified.

## What it does, by task

| Task | Commands |
| --- | --- |
| **Create a guest** in one command: clone the Ubuntu template, a static address from the pool, the reservation and DNS name on the gateway, cloud-init, the pinned SSH host key, readiness checks | `vm new`, `vm verify` |
| **Work on guests**: SSH, checksum-verified copies, plain `ssh`/`scp`/`rsync` through a generated config, sudo passwords on several machines | `vm ssh`, `vm cp`, `vm ssh-config`, `vm password` |
| **Change and keep them**: power, CPU and memory, disk growth, snapshots before changes, a rename everywhere the name lives, removal with every record | `vm set`, `vm disk grow`, `vm snap`, `vm rename`, `vm rm` |
| **Keep them patched**: pending updates on one guest or all, reboots only where a guest asks for one | `vm upgrade --all`, `vm reboot --pending` |
| **Give a service a name** with a real certificate: an edge VM runs Caddy with a Let's Encrypt wildcard for `*.apps.<domain>` | `edge setup`, `svc add` |
| **Publish on purpose**: a Cloudflare Tunnel exposes chosen services; nothing else is reachable from the internet | `cf tunnel route add`, `cf dns` |
| **Isolate a guest**: a firewall at its Proxmox NIC, so a compromised guest cannot reach the rest of the LAN | `vm fence` |
| **Reach the lab from away**: a Tailscale subnet router guest, the tailnet's devices, routes, split DNS and policy | `router setup`, `ts …` |
| **Watch the lab**: a watchdog guest with VictoriaMetrics, Loki, Grafana and ntfy; metrics and logs from every guest and the host, alerts on your phone | `watch setup`, `watch enroll`, `status` |
| **Drive the gateway** through UniFi's Integration API, every endpoint checked against the official OpenAPI export | `gw …`, `dns …` |
| **Run coding agents on guests** with [Rex](https://www.superlogical.com/rex) (experimental, see below) | `vm new --rex`, `rex setup`, `rex status`, `rex hosts sync` |

It is scriptable and agent-friendly: stable exit codes, `-o json` with a
versioned envelope, help generated from the command table, and shell
completion for fish, bash and zsh. [docs/GUIDE.md](docs/GUIDE.md) is
written so an AI agent can operate a lab safely with it. artoo is native
Zig 0.17 using only the standard library, and ships as one static binary
for macOS and Linux (arm64, x86-64) that updates itself from verified
releases (`artoo update`).

## Coding agents on guests with Rex (experimental)

> **Experimental.** Rex support is new and takes shape over the coming
> releases: commands, output and defaults may still change. Rex itself
> is in preview; artoo installs it from Superlogical's `preview` channel.

[Rex](https://www.superlogical.com/rex) by
[Superlogical](https://www.superlogical.com) is a terminal and
multiplexer whose server runs on the guest and whose client runs on your
workstation, so a session (and the agent in it) outlives the connection.
artoo turns an ordinary guest into a place to run coding agents:

```sh
artoo vm new hoth --rex       # a new guest with Rex, or 'artoo rex setup hoth' for an existing one
artoo rex hosts sync          # add every Rex guest to the workstation's Rex hosts
artoo rex status hoth         # package, pins, server, skills, profile, permissions, agents at work
```

- **Rex from its signed apt repository**, pinned, with linger so sessions
  survive logout, the terminfo, and Rex's agent skill for Claude Code and
  Antigravity (`agy`). You install and sign in to the agents yourself;
  artoo never touches their credentials.
- **One agent setup on every guest**: point `agents.profile` at a
  directory (your skills, `CLAUDE.md`, settings) and `rex setup` copies it
  to each guest, merging JSON settings with what the guest already has.
- **Permissions follow reach**: a fenced guest with no SSH keys lets the
  agents run without asking; every other guest keeps them asking.
- **The lab knows an agent is working**: `vm reboot --pending` skips a
  guest whose agent is busy, `vm upgrade` names them, and `vm rm` and
  `vm rename` remove or rename its Rex host.
- **Reached over SSH** (`ssh://user@guest`) through the config of
  `vm ssh-config`: no listener on the guest, no tailnet node per guest.
  Rex for Mac lists only hosts saved in the app, so add a guest there
  with the same address (Settings > Remote Hosts).

The details are in [docs/SPEC.md](docs/SPEC.md) §18.

## Is this for you?

artoo assumes this stack, and each piece is load-bearing:

| You need | Used for |
| --- | --- |
| **Proxmox VE 9**, one node | guests, templates, storage; an API token for artoo and root SSH for one step |
| **A UniFi gateway** with UniFi Network 10.6+ (Integration API) | DHCP reservations and DNS records for every guest; **`vm new` requires it** |
| **Ubuntu 26.04** cloud image (pinned in artoo) | every guest and template |
| **mkcert** (or your own CA) | trusted HTTPS to the Proxmox and UniFi APIs |
| **A Cloudflare zone** (optional) | DNS-01 for the edge's wildcard certificate, the tunnel, public records |
| **Tailscale** (optional) | the subnet router for remote access |
| **A macOS or Linux** workstation | where artoo, its secrets and your SSH key live |

There is no support for LXC containers, clusters, or other gateways or DNS
providers. If you run something else (OPNsense, Pi-hole, another
hypervisor), read artoo as a reference design to fork.

## Personal preferences baked in

Some choices are simply mine. Change them in a fork:

- **The guest home configuration is my own.** The guest user (named by
  `guests.user`) gets fish as its login shell, starship, tmux, Vim, a
  Gruvbox theme, a few helper functions and the Ghostty terminfo: see
  [src/guest/payload/](src/guest/payload/). Edit those files,
  `make install`, then `artoo template build ubuntu-2604`.
- The guest baseline: key-only SSH, no root login, sudo with a generated
  password, daily security updates and never an automatic reboot.
- Curated Star Wars and Middle-earth guest names, with each guest's
  purpose in a `role-…` tag.
- The watchdog stack and its pinned versions, the dashboard and the alert
  rules.

## Getting started

[docs/QUICKSTART.md](docs/QUICKSTART.md) goes from nothing to a first
guest: the prerequisites on Proxmox and UniFi, configuration,
credentials, the template and `vm new`.

## Build

```console
make            # debug build
make test       # tests, zig fmt --check, Linux cross-builds, leak check (what CI runs)
make install    # ReleaseSafe → ~/.local/bin/artoo, plus fish completion
make hooks      # the commit-msg hook contributors use
```

It needs Zig 0.17. Or download a release: each
[GitHub release](https://github.com/tildaslashalef/artoo/releases) carries
`artoo-<version>-<target>.tar.gz` for macOS and Linux (arm64, x86-64) and
`SHA256SUMS` (`shasum -a 256 -c SHA256SUMS`). The macOS binaries are not
signed: after downloading, run `xattr -d com.apple.quarantine artoo`.

## Documents

| | |
| --- | --- |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | from zero to a first guest |
| [docs/GUIDE.md](docs/GUIDE.md) | operating a lab with artoo, by task |
| [docs/SPEC.md](docs/SPEC.md) | what artoo does: commands, output, safety, every subsystem |
| [docs/API.md](docs/API.md) | the UniFi, Proxmox, GitHub and Tailscale API facts artoo relies on |
| [docs/RELEASING.md](docs/RELEASING.md) | version rules and the release procedure |
| [AGENTS.md](AGENTS.md) | rules for agents and contributors: branches, commits, releases |

## Contributing

Issues and pull requests are welcome, but artoo follows my lab first:
changes that keep it simple and safe for this stack are the ones likely
to be merged. Forks that take it somewhere else are very welcome.

## License

[MIT](LICENSE)
