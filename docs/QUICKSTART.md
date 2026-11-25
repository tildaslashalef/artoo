# Quickstart

From nothing to a first guest. artoo assumes one Proxmox VE 9 node, a
UniFi gateway with UniFi Network 10.6+ and a macOS or Linux workstation
(see the [README](../README.md#is-this-for-you)). The examples use the
documentation values: host `pve` at `192.168.1.10`, gateway
`192.168.1.1`, guests under `lab.example.com`. Use your own.

Every write shows a plan and asks first. Add `-n` to see the plan and
send nothing.

## 1. Install

Download the archive for your platform from the
[releases](https://github.com/tildaslashalef/artoo/releases), check it
against `SHA256SUMS` and put `artoo` on your `PATH` (on macOS, then run
`xattr -d com.apple.quarantine artoo`). Or build it with Zig 0.17.0:

```console
make install          # ~/.local/bin/artoo + fish completion (COMPLETION=zsh|bash|none)
artoo --version
```

`artoo update` later replaces the binary with a verified newer release;
`artoo update --check` only asks.

## 2. Prepare Proxmox (once, as root on the host)

artoo uses one API token with built-in roles, plus one custom role so
that Proxmox downloads images itself. Replace `pve` in `/nodes/pve` with
your node name.

```console
pveum user add artoo@pve
pveum role add ArtooFetch --privs Sys.AccessNetwork
pveum acl modify / --users artoo@pve --roles PVEAuditor,PVEVMAdmin,PVEDatastoreAdmin,PVESDNUser
pveum acl modify /nodes/pve --users artoo@pve --roles PVEAuditor,PVEVMAdmin,PVEDatastoreAdmin,PVESDNUser,ArtooFetch
pveum user token add artoo@pve cli --privsep 0
```

Proxmox ACLs replace rather than merge along a path, so the node entry
repeats the four roles. The last command prints the token secret: keep
it for step 5 and paste it nowhere else.

artoo also needs:

- **Root SSH to the host** with your key (`~/.ssh/id_ed25519` by
  default), for the one thing the API cannot do: placing the cloud-init
  vendor snippet in `/var/lib/vz/snippets`. Host keys are checked
  strictly, so connect once by hand (`ssh root@192.168.1.10`) to record
  the host key in `~/.ssh/known_hosts`.
- **The names of a default install**, which artoo uses as they are:
  storage `local` (a directory, with the *Import* and *Snippets* content
  types enabled), storage `local-zfs` for VM disks, and bridge `vmbr0`.

## 3. Prepare UniFi (once, in the UniFi UI)

- Create an API key under **Settings → Integrations**; keep it for
  step 5.
- Choose an **address range for guests outside the DHCP range** (for
  example DHCP `.6–.199`, guests `.200–.254`). Each guest gets a static
  address from it, reserved as a Fixed IP.
- Guests use the gateway as their DNS server; artoo creates their A
  records there (`<name>.lab.example.com`).

## 4. Trust the Proxmox and UniFi certificates

artoo always verifies TLS. The simplest way is a private CA made with
[mkcert](https://github.com/FiloSottile/mkcert):

```console
mkcert -install
mkcert pve.home.arpa 192.168.1.10          # install on Proxmox: pvenode cert set …
mkcert unifi.home.arpa 192.168.1.1         # upload in the UniFi UI
mkdir -p ~/.artoo/tls && cp "$(mkcert -CAROOT)/rootCA.pem" ~/.artoo/tls/
```

Any CA works: `pve.ca_bundle` and `unifi.ca_bundle` name the PEM bundle
artoo trusts. The CA's private key stays on your workstation. Both names
must resolve from the workstation (a record on the gateway, or
`/etc/hosts`).

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
artoo config set guests.user ops                       # the account on every guest (default artoo)
artoo config set guests.reserved_names nas,printer     # your own device names: never used or published
artoo config show
```

`pve.token_id` defaults to `artoo@pve!cli`, the token from step 2.
`artoo config set -h` lists every key. The file is
`~/.artoo/config.json` and holds no secrets.

Store the credentials. Each is read from a hidden prompt (or `--stdin`),
never from an argument:

```console
artoo auth set pve        # the token secret from step 2
artoo auth set unifi      # the API key from step 3
artoo auth status
```

**Already set up on another machine?** There, run `artoo config export
~/artoo-setup.txt`; here, `artoo config import ~/artoo-setup.txt`. This
brings the config, the CA bundle and the credentials in one step,
sealed under a passphrase you choose. SSH keys stay per machine: see
[GUIDE.md](GUIDE.md) §3.

## 6. Check everything

```console
artoo doctor --connect
```

This checks the installation, config, secret store, stored secrets, CA
bundles and SSH keys, then calls each API with a stored credential.
Fix anything marked failed before going on.

## 7. Build the template

```console
artoo template build ubuntu-2604 -n     # preview
artoo template build ubuntu-2604
```

Proxmox downloads the pinned Ubuntu 26.04 cloud image itself and checks
its SHA-256. artoo places the vendor snippet over SSH, creates the VM
and converts it to a template (the lowest free VMID from 9000).

## 8. Your first guest

```console
artoo vm new naboo -n                   # preview: address, size, user, DNS name
artoo vm new naboo
artoo vm ssh naboo
artoo status
```

`vm new` clones the template, reserves the address on UniFi, creates
`naboo.lab.example.com`, waits for cloud-init (several minutes, with one
reboot if the first boot's updates ask for it), pins the SSH host key
and runs `vm verify`. The guest user gets your SSH key and a generated
sudo password: `artoo vm password naboo` copies it to the clipboard
(`--show` prints it). The shell setup is the author's own (fish,
starship, tmux, Vim), from [src/guest/payload/](../src/guest/payload/);
change it in your fork.

`artoo vm ssh-config` writes `~/.artoo/ssh_config`. Add `Include
~/.artoo/ssh_config` once at the top of `~/.ssh/config` (above the
first `Host` line), and plain `ssh naboo`, `scp` and `rsync` work with
the same strict settings.

## Without Cloudflare or Tailscale

Guests, templates, the gateway and `status` need only Proxmox and
UniFi. The limits:

- `vm new` always writes to UniFi (the Fixed IP and, unless `--no-dns`,
  the DNS record). There is no Proxmox-only mode.
- Without a Cloudflare token, `cf …` commands fail with exit 3, and
  `status` shows its tunnel section as unavailable and exits 8 even when
  everything else is healthy. `doctor` only warns.
- Service names (`svc add`) need a Cloudflare zone too: the edge VM gets
  its wildcard certificate through a Cloudflare DNS-01 token.
- Without the Tailscale OAuth client, `ts …` commands refuse. The subnet
  router still works with an auth key made in the Tailscale console.

## Next

[GUIDE.md](GUIDE.md) covers the rest by task: service names (§7),
publishing on the internet (§8), remote access with Tailscale (§9), the
edge VM and the watchdog (§10), the gateway (§12), credentials and
certificates (§15) and troubleshooting (§17). [SPEC.md](SPEC.md) holds
the rules behind every command.
