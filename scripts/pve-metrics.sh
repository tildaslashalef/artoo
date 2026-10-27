#!/usr/bin/env bash
# Point Proxmox's built-in External Metric Server at the watchdog VM
# (SPEC §9.9): InfluxDB line protocol over HTTP to VictoriaMetrics on
# ADDRESS:8428; organization, bucket and token stay empty (VictoriaMetrics'
# documented Proxmox setup). No agent on Proxmox. Approved host change only:
# it needs Sys.Modify on /, which artoo's token deliberately lacks (SPEC §7).
#
# Usage: scripts/pve-metrics.sh ADDRESS     (the role-watch VM's address)
#
# Proxmox's datacenter firewall keeps outbound ACCEPT (pve-firewall.sh),
# so pvestatd reaches the watchdog; its own firewall admits Proxmox on 8428.
#
# Rollback: ssh root@pve pvesh delete /cluster/metrics/server/scarif
# (web UI: Datacenter → Metric Server).
set -euo pipefail
address=${1:?usage: scripts/pve-metrics.sh ADDRESS}
[[ $address =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || { echo "ADDRESS must be an IPv4 address (the watchdog VM)" >&2; exit 2; }
host=${PVE_SSH:?set PVE_SSH=root@<Proxmox host address>}
# The SSH key is artoo's (pve.ssh_identity), so the scripts follow its config.
identity=$(artoo config get pve.ssh_identity) || { echo "cannot read pve.ssh_identity (artoo on PATH? make install)" >&2; exit 1; }
ssh_opts=(-i "$identity" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10)

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

log "guard: no metric server named scarif yet, the watchdog answers on :8428"
ssh "${ssh_opts[@]}" "$host" bash -s -- "$address" <<'REMOTE'
set -euo pipefail
address=$1
if pvesh get /cluster/metrics/server/scarif --output-format json >/dev/null 2>&1; then
  echo "metric server 'scarif' exists already:"; pvesh get /cluster/metrics/server/scarif; exit 1
fi
curl -fsS --max-time 5 "http://$address:8428/health" | grep -qx OK || { echo "no VictoriaMetrics answering on $address:8428"; exit 1; }
echo ok
REMOTE

log "create the InfluxDB (HTTP) metric server"
ssh "${ssh_opts[@]}" "$host" bash -s -- "$address" <<'REMOTE'
set -euo pipefail
address=$1
pvesh create /cluster/metrics/server/scarif --type influxdb --influxdbproto http \
  --server "$address" --port 8428 --timeout 3
pvesh get /cluster/metrics/server/scarif --output-format json
REMOTE

log "verify: Proxmox's first samples arrive (pvestatd cycle)"
for _ in $(seq 1 12); do
  if ssh "${ssh_opts[@]}" "$host" "curl -fsS --max-time 5 'http://$address:8428/api/v1/series?match%5B%5D=system_uptime%7Bobject%3D%22nodes%22%7D'" | grep -q '"host"'; then
    echo "samples arriving — 'artoo watch status' shows the Proxmox export"; exit 0
  fi
  sleep 10
done
echo "no samples after 2 minutes; check 'journalctl -u pvestatd' on Proxmox" >&2
exit 1
