# Proxmox root shell config (`hosts/pve/`)

Root on Proxmox uses the same shell environment as every guest: the guest
payload in [`src/guest/payload/`](../../src/guest/payload/) (fish, tmux,
Vim, starship, helper functions), **minus** `upd.fish` (plain `apt
upgrade` is wrong on Proxmox, and it calls sudo), **plus** these files:

| File | Purpose |
| --- | --- |
| `fish/functions/pveupd.fish` | Proxmox update: `apt update` → a simulated `full-upgrade` as the summary (Proxmox/kernel/ZFS packages with old → new versions, security updates, a new kernel or QEMU, running guests) → refused when it would remove a Proxmox core package or the running kernel → `apt full-upgrade` → optional autoremove (listed first) → reboot check naming running guests that would not start again (onboot off). `-c` checks only, `-a` lists every package. Never reboots. |
| `fish/functions/ispeed.fish` | Internet speed test with `curl` against speed.cloudflare.com: edge and public IP, latency/jitter, one download and one upload stream, bars scaled to the default route's link speed. `-d`/`-u` sizes in MB (default 90/25), `-n` latency samples. |
| `fish/functions/sudo.fish` | Proxmox has no sudo; lets `journal`, `ports` and `killport` run as root unchanged. |

The Ghostty terminfo is compiled system-wide into `/etc/terminfo` (as on
guests, SPEC §9.1). Root's login shell stays Bash; `/root/.bashrc` execs
fish for interactive terminals, so automation keeps Bash.

Apply (an approved host change, GUIDE §14): `scripts/pve-shell.sh`
backs up the current files to `/root/pve-setup-backups/shell-<UTC>/`,
replaces them, compiles the terminfo and verifies. Rollback: extract the
backup's `root-shell.tgz` into `/` and remove the `/etc/terminfo` entries.
