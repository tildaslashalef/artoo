#!/usr/bin/env bash
# Enable the Proxmox VE firewall on the host (SPEC §9.7: the host-side copy
# of the edge VM's policy needs it). Approved host change only.
#
# Host policy: inbound DROP except SSH (22), the web UI/API (8006) and the
# SPICE proxy (3128) and ping from the LAN; outbound unchanged. VMs are
# filtered only where their NIC has firewall=1 (none yet), so guests are
# unaffected. Side effect: rpcbind (111) is no longer reachable from the LAN.
#
# Lock-out guard: before enabling, a transient systemd timer on Proxmox is
# armed to switch the firewall off again after 180 s. The script then opens
# a NEW SSH connection and calls :8006 from this Mac; only if both work is
# the timer cancelled. Any failure leaves the timer to roll back.
#
# Rollback by hand: set 'enable: 0' in /etc/pve/firewall/cluster.fw (web
# UI: Datacenter → Firewall → Options), or 'pve-firewall stop' on the
# console.
set -euo pipefail
host=${PVE_SSH:?set PVE_SSH=root@<Proxmox host address>}
# The SSH key is artoo's (pve.ssh_identity), so the scripts follow its config.
identity=$(artoo config get pve.ssh_identity) || { echo "cannot read pve.ssh_identity (artoo on PATH? make install)" >&2; exit 1; }
ssh_opts=(-i "$identity" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10)
lan=${LAN:-192.168.1.0/24}
api=https://pve.home.arpa:8006
ca="$HOME/.artoo/tls/rootCA.pem"

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

log "guard: firewall currently disabled and unconfigured"
ssh "${ssh_opts[@]}" "$host" bash -s <<'REMOTE'
set -euo pipefail
pve-firewall status | grep -q '^Status: disabled' || { echo "firewall is not disabled: $(pve-firewall status)"; exit 1; }
for f in /etc/pve/firewall/cluster.fw /etc/pve/nodes/pve/host.fw; do
  if [ -s "$f" ] && ! grep -q '^# artoo' "$f"; then echo "$f exists and is not artoo's"; exit 1; fi
done
echo ok
REMOTE

log "write host rules, arm the 180 s rollback timer, enable"
ssh "${ssh_opts[@]}" "$host" bash -s -- "$lan" <<'REMOTE'
set -euo pipefail
lan=$1
cat > /etc/pve/nodes/pve/host.fw <<EOF
# artoo: host firewall (SPEC §9.7); managed by scripts/pve-firewall.sh
[OPTIONS]
enable: 1

[RULES]
IN ACCEPT -source $lan -p tcp -dport 22 -log nolog # artoo: SSH from the LAN
IN ACCEPT -source $lan -p tcp -dport 8006 -log nolog # artoo: web UI and API
IN ACCEPT -source $lan -p tcp -dport 3128 -log nolog # artoo: SPICE proxy
IN Ping(ACCEPT) -source $lan -log nolog # artoo: ping from the LAN
EOF
systemctl stop artoo-fw-rollback.timer 2>/dev/null || true
systemd-run --quiet --unit=artoo-fw-rollback --on-active=180 \
  /bin/sh -c "sed -i 's/^enable: 1/enable: 0/' /etc/pve/firewall/cluster.fw; pve-firewall restart"
cat > /etc/pve/firewall/cluster.fw <<EOF
# artoo: datacenter firewall (SPEC §9.7); managed by scripts/pve-firewall.sh
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: ACCEPT
EOF
pve-firewall compile >/dev/null
pve-firewall restart
for i in $(seq 1 15); do pve-firewall status | grep -q '^Status: enabled/running' && break; sleep 1; done
pve-firewall status
REMOTE

log "verify from this Mac with NEW connections (rollback armed)"
sleep 3
ok=1
ssh "${ssh_opts[@]}" "$host" true && echo "ssh: ok" || { echo "ssh: FAILED"; ok=0; }
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --cacert "$ca" "$api/api2/json/version" || echo 000)
[ "$code" = 401 ] || [ "$code" = 200 ] && echo "web UI/API: answers ($code)" || { echo "web UI/API: FAILED ($code)"; ok=0; }

if [ "$ok" = 1 ]; then
  log "all good: cancel the rollback timer"
  ssh "${ssh_opts[@]}" "$host" 'systemctl stop artoo-fw-rollback.timer && pve-firewall status && echo "rollback cancelled"'
else
  log "verification failed: the firewall switches itself off within 180 s"
  exit 1
fi
