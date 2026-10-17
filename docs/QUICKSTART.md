# Quickstart

From nothing to a first guest. artoo is opinionated (see the
[README](../README.md#is-this-for-you)): this assumes one Proxmox VE 9
node, a UniFi gateway with UniFi Network 10.6+, and a macOS or Linux
workstation. The examples use the documentation defaults — host `pve` at
`192.168.1.10`, gateway `192.168.1.1`, guests under `lab.example.com` —
replace them with your own values.

Every write artoo makes previews a plan and asks first; add `-n` to any
write to see the plan without sending anything.

## 1. Install

Download a release archive for your platform from the
[releases](https://github.com/tildaslashalef/artoo/releases), check it
against `SHA256SUMS`, and put `artoo` on your `PATH` (on macOS:
`xattr -d com.apple.quarantine artoo`). Or build it with Zig 0.17.0:

```console
make install          # ~/.local/bin/artoo + fish completion (COMPLETION=zsh|bash|none)
artoo --version
```

## 2. Prepare Proxmox (once, as root on the host)

artoo uses one API token with built-in roles, plus one tiny custom role
so Proxmox can download images itself. It has no host, user or
permission administration. Replace `pve` in `/nodes/pve` with your node
name.

```console
pveum user add artoo@pve
pveum role add ArtooFetch --privs Sys.AccessNetwork
pveum acl modify / --users artoo@pve --roles PVEAuditor,PVEVMAdmin,PVEDatastoreAdmin,PVESDNUser
pveum acl modify /nodes/pve --users artoo@pve --roles PVEAuditor,PVEVMAdmin,PVEDatastoreAdmin,PVESDNUser,ArtooFetch
pveum user token add artoo@pve cli --privsep 0
```

Proxmox ACLs replace rather than merge along a path, so the node entry
repeats the four roles. Keep the token secret that the last command
prints for step 5 — do not paste it anywhere else.

artoo also needs:

- **Root SSH from the workstation to the host** with your key, for one
  thing the API cannot do: placing the cloud-init vendor snippet in
  `local:snippets` (`/var/lib/vz/snippets`). The remote script is fixed
  and host-key checking is strict, so connect once by hand first
  (`ssh root@192.168.1.10`) to record the host key in
  `~/.ssh/known_hosts`.
- Storages as on a default install: `local` (directory, with the
  *Import* and *Snippets* content types enabled) and `local-zfs` (or
  another storage for VM disks), and the bridge `vmbr0`.

## 3. Prepare UniFi (once, in the UniFi UI)

- Create an API key under **Settings → Integrations**; keep it for
  step 5.
- Pick an **address range for guests outside the DHCP range** (for
  example DHCP `.6–.199`, guests `.200–.254`). artoo gives every guest a
  static address from it and reserves it as a Fixed IP.
- Guests use the gateway as their DNS server; artoo creates their A
  records there (`<name>.lab.example.com`).

## 4. Trust the Proxmox and UniFi certificates

artoo always verifies TLS. The simplest way is a private CA with
[mkcert](https://github.com/FiloSottile/mkcert):

```console
mkcert -install
mkcert pve.home.arpa 192.168.1.10          # install on Proxmox: pvenode cert set …
mkcert unifi.home.arpa 192.168.1.1         # upload in the UniFi UI
mkdir -p ~/.artoo/tls && cp "$(mkcert -CAROOT)/rootCA.pem" ~/.artoo/tls/
```

Any CA works: `pve.ca_bundle` and `unifi.ca_bundle` name the PEM bundle
artoo trusts. The CA's private key never needs to leave your
workstation. The names must resolve from your workstation (a DNS record
on the gateway, or `/etc/hosts`).

## 5. Configure artoo

```console
artoo config init
artoo config set pve.endpoint https://pve.home.arpa:8006
artoo config set pve.node pve
artoo config set pve.ssh_host 192.168.1.10
artoo config set unifi.endpoint https://unifi.home.arpa/proxy/network/integration
artoo config set guests.domain lab.example.com
artoo config set guests.address_pool 192.168.1.200-192.168.1.254
artoo config set guests.gateway 192.168.1.1/24
artoo config set guests.user ops                       # the account on every guest
artoo config set guests.reserved_names nas,printer     # your own device names, never used or published
artoo config show
```

`artoo config set -h` lists every key. The file is
`~/.artoo/config.json` and holds no secrets.

Store the credentials — each one is read from a hidden prompt (or
`--stdin`), never from an argument:

```console
artoo auth set pve        # the token secret from step 2
artoo auth set unifi      # the API key from step 3
artoo auth status
```

## 6. Check everything

```console
artoo doctor --connect
```

This checks the binary, config, secret store, the stored secrets, the CA
bundles and your SSH public key, then calls the Proxmox and UniFi APIs.
Fix anything marked failed before going on.

## 7. Build the template

```console
artoo template build ubuntu-2604 -n     # preview
artoo template build ubuntu-2604
```

Proxmox downloads the pinned Ubuntu 26.04 cloud image itself and checks
its SHA-256; artoo places the vendor snippet over SSH, creates the VM
and converts it to a template (VMID 9000 unless taken).

## 8. Your first guest

```console
artoo vm new naboo -n                   # preview: address, size, user, DNS name
artoo vm new naboo
artoo vm ssh naboo
artoo status
```

`vm new` clones the template, reserves the address on UniFi, creates
`naboo.lab.example.com`, waits for cloud-init (several minutes on first
boot, one reboot if the updates ask for it), pins the SSH host key and
runs `vm verify`. The guest user gets your SSH key and a generated sudo
password (`artoo vm password naboo`, terminal only). Its shell setup is
the author's own — fish, starship, tmux, Vim — from
[src/guest/payload/](../src/guest/payload/); change it in your fork.

`artoo vm ssh-config` writes `~/.artoo/ssh_config`; add
`Include ~/.artoo/ssh_config` at the top of `~/.ssh/config` and plain
`ssh naboo` and `scp` work with the same strict settings.

## Without Cloudflare or Tailscale

The core — guests, templates, the gateway, `status` — needs only Proxmox
and UniFi. Know these limits:

- `vm new` always talks to UniFi (Fixed IP and, unless `--no-dns`, the
  DNS record); there is no Proxmox-only mode.
- Without a Cloudflare token, `cf …` commands fail with exit 3 and
  `artoo status` reports its tunnel section as unavailable, so `status`
  exits 8 even when everything else is healthy. `doctor` only warns.
- The edge VM's wildcard certificate uses a Cloudflare DNS-01 token, so
  service names (`svc add`) need a Cloudflare zone too.

## Next

[GUIDE.md](GUIDE.md) covers everything by task: service names and the
edge VM (§7, §10), publishing on the internet (§8), remote access with
Tailscale (§9), the watchdog (§10), the gateway (§12), credentials and
certificates (§15), troubleshooting (§17). The design and every decision
behind it are in [SPEC.md](SPEC.md).
