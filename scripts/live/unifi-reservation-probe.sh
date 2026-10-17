#!/usr/bin/env bash
# Live probe of UniFi's classic client API (SPEC §9.5, §17.1): can the
# artoo API key create a client record with a name and a fixed IP before the
# device ever connects, and forget it again? Uses a locally administered MAC
# that no real device carries and the top pool address. Ownership is written
# to ~/.artoo/live-ledger.txt ($ARTOO_LEDGER) first; the first failed guard aborts.
# On failure the record is left in place and reported — remove it with
# `forget-sta` or the UniFi UI.
#
# Usage: scripts/live/unifi-reservation-probe.sh

set -euo pipefail

LEDGER="${ARTOO_LEDGER:-$HOME/.artoo/live-ledger.txt}"
BASE=https://unifi.home.arpa/proxy/network/api/s/default
CA="$HOME/.artoo/tls/rootCA.pem"
MAC=02:a7:00:00:00:01
NAME=artoo-probe
IP=192.168.1.254
NET=6956ef9623496924ef8d526f   # classic _id of network Default
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\nABORT: %s\nThe record for %s (%s) may remain. See %s\n' "$*" "$MAC" "$NAME" "$LEDGER" >&2; exit 1; }
trap 'fail "command failed at line $LINENO"' ERR

# api METHOD PATH [BODY]: the key goes from the Keychain to curl as a header
# on stdin — never in argv, never printed. Response body → $TMP/out.json.
api() {
  local args=(-sS -o "$TMP/out.json" -w '%{http_code}' -X "$1" -H @- --cacert "$CA")
  if [ $# -ge 3 ]; then
    printf '%s' "$3" > "$TMP/body.json"
    args+=(-H 'Content-Type: application/json' --data @"$TMP/body.json")
  fi
  /usr/bin/security find-generic-password -s artoo -a unifi -w | sed 's/^/X-API-KEY: /' |
    curl "${args[@]}" "$BASE/$2"
}

# record: print our record's relevant fields, exit 1 when absent.
record() {
  [ "$(api GET rest/user)" = 200 ] || fail "GET rest/user failed"
  python3 - "$TMP/out.json" "$MAC" <<'EOF'
import json, sys
for r in json.load(open(sys.argv[1]))["data"]:
    if r["mac"] == sys.argv[2]:
        print(json.dumps({k: r.get(k) for k in ("_id", "mac", "name", "hostname", "use_fixedip", "fixed_ip", "network_id", "noted")}))
        sys.exit(0)
sys.exit(1)
EOF
}

log "guard: $MAC unknown, $IP not fixed for any client"
if record > /dev/null; then fail "$MAC already has a record"; fi
python3 - "$TMP/out.json" "$IP" <<'EOF' || fail "$IP is already fixed for a client"
import json, sys
sys.exit(1 if any(r.get("use_fixedip") and r.get("fixed_ip") == sys.argv[2] for r in json.load(open(sys.argv[1]))["data"]) else 0)
EOF
mkdir -p "$(dirname "$LEDGER")"
printf '%s unifi-client mac=%s name=%s ip=%s probe\n' "$(date -u +%FT%TZ)" "$MAC" "$NAME" "$IP" >> "$LEDGER"

log "create: POST group/user with name and fixed IP"
code=$(api POST group/user "{\"objects\":[{\"data\":{\"mac\":\"$MAC\",\"name\":\"$NAME\",\"use_fixedip\":true,\"network_id\":\"$NET\",\"fixed_ip\":\"$IP\"}}]}")
echo "HTTP $code: $(cat "$TMP/out.json")"
[ "$code" = 200 ] || fail "create refused"
rec=$(record) || fail "record not found after create"
echo "$rec"

id=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["_id"])' "$rec")
if ! python3 -c 'import json,sys; r=json.loads(sys.argv[1]); sys.exit(0 if r["use_fixedip"] and r["fixed_ip"]==sys.argv[2] and r["name"]==sys.argv[3] else 1)' "$rec" "$IP" "$NAME"; then
  log "create ignored name/fixed IP: PUT rest/user/$id"
  code=$(api PUT "rest/user/$id" "{\"_id\":\"$id\",\"name\":\"$NAME\",\"use_fixedip\":true,\"network_id\":\"$NET\",\"fixed_ip\":\"$IP\"}")
  echo "HTTP $code: $(cat "$TMP/out.json")"
  [ "$code" = 200 ] || fail "PUT refused"
  rec=$(record) || fail "record not found after PUT"
  echo "$rec"
fi

log "forget: cmd/stamgr forget-sta"
code=$(api POST cmd/stamgr "{\"cmd\":\"forget-sta\",\"macs\":[\"$MAC\"]}")
echo "HTTP $code"
[ "$code" = 200 ] || fail "forget refused"
sleep 3
if record > /dev/null; then fail "record still present after forget"; fi
echo "gone"
printf '%s unifi-client mac=%s removed\n' "$(date -u +%FT%TZ)" "$MAC" >> "$LEDGER"
log "probe passed"
