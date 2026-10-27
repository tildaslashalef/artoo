#!/usr/bin/env bash
# Install the guest shell payload (minus upd.fish) plus hosts/pve/ as
# root's shell config on Proxmox (hosts/pve/README.md). Approved host
# change only. Backs up first; aborts on the first error.
set -euo pipefail
cd "$(dirname "$0")/.."
host=${PVE_SSH:?set PVE_SSH=root@<Proxmox host address>}
# The SSH key is artoo's (pve.ssh_identity), so the scripts follow its config.
identity=$(artoo config get pve.ssh_identity) || { echo "cannot read pve.ssh_identity (artoo on PATH? make install)" >&2; exit 1; }
ssh_opts=(-i "$identity" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10)

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
p=src/guest/payload
mkdir -p "$stage/root/.config/fish/functions" "$stage/root/.config/tmux" "$stage/usr/local/share/artoo"
cp "$p/fish/config.fish" "$stage/root/.config/fish/"
for f in "$p"/fish/functions/*.fish hosts/pve/fish/functions/*.fish; do
  [ "$(basename "$f")" = upd.fish ] || cp "$f" "$stage/root/.config/fish/functions/"
done
cp "$p/tmux/tmux.conf" "$stage/root/.config/tmux/"
cp "$p/starship.toml" "$stage/root/.config/"
cp "$p/vimrc" "$stage/root/.vimrc"
cp "$p/terminfo/xterm-ghostty.terminfo" "$stage/usr/local/share/artoo/"
sums=$(cd "$stage" && find . -type f -exec shasum -a 256 {} + | sed 's|  \./|  /|' | sort -k2)
printf '%s\n' "$sums" > "$stage/sums"

remote=/root/.artoo-shell-staging
COPYFILE_DISABLE=1 tar --no-xattrs -C "$stage" -czf - root usr sums | ssh "${ssh_opts[@]}" "$host" "rm -rf $remote && mkdir -p $remote && tar -C $remote -xzf -"
ssh "${ssh_opts[@]}" "$host" bash -s -- "$remote" <<'REMOTE'
set -euo pipefail
src=$1
bk=/root/pve-setup-backups/shell-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$bk"
cd /
old=()
for f in root/.config/fish root/.config/starship.toml root/.config/tmux root/.vimrc root/.terminfo root/.local/bin/fd; do
  if [ -e "$f" ] || [ -L "$f" ]; then old+=("$f"); fi
done
tar -czf "$bk/root-shell.tgz" "${old[@]}"
echo "backup: $bk/root-shell.tgz (${#old[@]} paths)"
rm -rf /root/.config/fish /root/.terminfo
rm -f /root/.config/starship.toml /root/.config/tmux/tmux.conf /root/.vimrc
cp -a "$src/root/." /root/
install -d -m 0755 /usr/local/share/artoo /etc/terminfo /root/.local/bin
install -m 0644 "$src/usr/local/share/artoo/xterm-ghostty.terminfo" /usr/local/share/artoo/
tic -x -o /etc/terminfo /usr/local/share/artoo/xterm-ghostty.terminfo
ln -sfn /usr/bin/fdfind /root/.local/bin/fd
chown -R root:root /root/.config /root/.vimrc
sed 's|  /|  |' "$src/sums" | sha256sum -c --quiet
for f in /root/.config/fish/config.fish /root/.config/fish/functions/*.fish; do fish -n "$f"; done
infocmp -x xterm-ghostty | head -1
fish -c 'for f in pveupd ispeed ts bakit extract journal killport myip ports sudo; functions -q $f; or echo "missing $f"; end; functions -q upd; and echo "upd present"; echo functions checked'
rm -rf "$src"
echo done
REMOTE
