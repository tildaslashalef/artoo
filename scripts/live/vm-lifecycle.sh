#!/usr/bin/env bash
# Live run of the Proxmox VM verbs (SPEC §13): ordinary `artoo` invocations
# against a disposable guest created by this run. Ownership (VMID, name,
# tag) is written to ~/.artoo/live-ledger.txt ($ARTOO_LEDGER) before any destructive
# step; every destructive step re-checks it; the first failed guard or
# command aborts. On failure the guest is left in place and reported —
# nothing is destroyed to compensate.
#
# Usage: scripts/live/vm-lifecycle.sh [VMID]   (default 990; must be free)

set -euo pipefail

SSH=(ssh -i "$HOME/.ssh/id_ed25519" -o IdentitiesOnly=yes -o BatchMode=yes
     -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${PVE_SSH:?set PVE_SSH=root@<Proxmox host address>}")
LEDGER="${ARTOO_LEDGER:-$HOME/.artoo/live-ledger.txt}"
VMID=${1:-990}
CLONE_ID=$((VMID + 1))
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME="artoo-lt-$(date -u +%H%M%S)"
CLONE="$NAME-c"
TAG=artoo-test

mkdir -p "$(dirname "$LEDGER")"
log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ledger() { printf '%s vmid=%s name=%s tag=%s %s\n' "$(date -u +%FT%TZ)" "$1" "$2" "$TAG" "$3" >> "$LEDGER"; }
fail() { printf '\nABORT: %s\nGuests of this run may remain: %s (%s), %s (%s). See %s\n' "$*" "$VMID" "$NAME" "$CLONE_ID" "$CLONE" "$LEDGER" >&2; exit 1; }
trap 'fail "command failed at line $LINENO"' ERR

# Guard: VMID $1 exists, carries name $2 and our tag.
owned() {
  local json
  json=$(artoo -o json vm show "$1") || fail "cannot read VM $1"
  python3 -c '
import json, sys
d = json.loads(sys.argv[1])["data"]["vm"]
ok = d["vmid"] == int(sys.argv[2]) and d["name"] == sys.argv[3] and "'"$TAG"'" in d["tags"].split(";")
sys.exit(0 if ok else 1)' "$json" "$1" "$2" || fail "ownership guard failed for $1 ($2)"
}

log "preconditions"
command -v artoo >/dev/null || fail "artoo not on PATH (make install)"
artoo doctor --connect >/dev/null || fail "artoo doctor --connect is not green"
for id in "$VMID" "$CLONE_ID"; do
  if artoo -o json vm ls --all | python3 -c 'import json,sys; sys.exit(0 if any(v["vmid"]=='"$id"' for v in json.load(sys.stdin)["data"]) else 1)'; then
    fail "VMID $id is in use"
  fi
done

log "create disposable guest $VMID ($NAME) over SSH"
"${SSH[@]}" "qm create $VMID --name $NAME --memory 512 --cores 1 --net0 virtio,bridge=vmbr0 --scsi0 local-zfs:1 --tags $TAG --description 'artoo live test $STAMP; disposable'"
ledger "$VMID" "$NAME" "created (qm create)"

log "reads";             artoo vm ls --all; artoo vm show "$NAME"; artoo vm config "$VMID" >/dev/null
log "set";               artoo vm set "$NAME" memory=768 description="artoo live test $STAMP" -y
log "set again (no-op → exit 5)"
if artoo vm set "$NAME" memory=768 -y; then fail "no-op set did not refuse"; else [ $? -eq 5 ] || fail "no-op set: wrong exit"; fi
log "snapshot";          artoo vm snap add "$NAME" s1 -d "before start" -y; artoo vm snap ls "$NAME"
log "start";             artoo vm start "$NAME" -y
log "start again (no-op → exit 5)"
if artoo vm start "$NAME" -y; then fail "no-op start did not refuse"; else [ $? -eq 5 ] || fail "no-op start: wrong exit"; fi
log "stop without --confirm (refused → exit 5)"
if artoo vm stop "$NAME" -y; then fail "stop without --confirm ran"; else [ $? -eq 5 ] || fail "stop: wrong exit"; fi
owned "$VMID" "$NAME"
log "stop";              artoo vm stop "$NAME" --yes --confirm "$NAME"
owned "$VMID" "$NAME"
log "rollback";          artoo vm snap rollback "$NAME" s1 --yes --confirm "$NAME@s1"
log "clone";             artoo vm clone "$NAME" "$CLONE" --id "$CLONE_ID" -y
"${SSH[@]}" "qm set $CLONE_ID --tags $TAG" >/dev/null
ledger "$CLONE_ID" "$CLONE" "created (artoo vm clone)"
owned "$CLONE_ID" "$CLONE"
log "rm clone";          artoo vm rm "$CLONE" --yes --confirm "$CLONE"
ledger "$CLONE_ID" "$CLONE" "destroyed (artoo vm rm)"
owned "$VMID" "$NAME"
log "snapshot rm";       artoo vm snap rm "$NAME" s1 --yes --confirm "$NAME@s1"
owned "$VMID" "$NAME"
log "rm";                artoo vm rm "$NAME" --yes --confirm "$NAME"
ledger "$VMID" "$NAME" "destroyed (artoo vm rm)"

log "verify both are gone"
artoo -o json vm ls --all | python3 -c 'import json,sys; ids={v["vmid"] for v in json.load(sys.stdin)["data"]}; sys.exit(1 if {'"$VMID"','"$CLONE_ID"'} & ids else 0)' \
  || fail "a test guest still exists"
trap - ERR
log "PASS (ledger: $LEDGER)"
