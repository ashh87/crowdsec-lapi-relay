#!/usr/bin/env bash
# End-to-end test against real CrowdSec binaries: two LAPIs, the relay, and
# two crowdsec log processors pointed at the relay.
#
#   CROWDSEC_SRC=~/src/crowdsec scripts/integration-test.sh [workdir]
#
# CROWDSEC_SRC must be a crowdsec checkout after `make build` (BUILD_RE2_WASM=1
# works without libre2-dev). Needs envsubst (gettext-base) and access to the
# CrowdSec hub. Everything runs on 127.0.0.1:8081/8082/8090 under workdir.
# Nothing touches a system CrowdSec install.
set -euo pipefail

: "${CROWDSEC_SRC:?set CROWDSEC_SRC to a built crowdsec checkout}"
HERE=$(cd "$(dirname "$0")/.." && pwd)
W=$(realpath -m "${1:-$(mktemp -d)}")
mkdir -p "$W"
echo "workdir: $W"

PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }
wait_until() { # timeout_s description cmd...
	local t=$1 what=$2; shift 2
	for _ in $(seq "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
	fail "$what"
}

(cd "$HERE" && go build -o "$W/lapi-relay" .)

env_tree() { # name
	rm -rf "${W:?}/$1"; mkdir -p "$W/$1"
	(cd "$CROWDSEC_SRC" && ./scripts/test_env.sh -d "$W/$1" >"$W/$1-setup.log" 2>&1) || true
	local d="$W/$1"
	[ -x "$d/cscli" ] || fail "test_env.sh failed for $1, see $W/$1-setup.log"
	# Dev builds have no hub branch of their own; prometheus off avoids port clashes.
	sed -i 's/^  output: human/  output: human\n  hub_branch: master/; s/^  enabled: true/  enabled: false/' "$d/dev.yaml"
	(cd "$d" && ./cscli -c dev.yaml hub update >/dev/null && ./cscli -c dev.yaml collections install crowdsecurity/linux crowdsecurity/sshd >/dev/null)
}
cs() { local d=$1; shift; (cd "$W/$d" && timeout 20 ./cscli -c dev.yaml "$@" 2>/dev/null); }

for n in lapi1 lapi2 agent-a agent-b; do env_tree "$n"; done
# cscli reads alerts/decisions through the API, and test_env.sh points every
# tree's credentials at :8081, so lapi2's cscli must be redirected too.
sed -i 's/127.0.0.1:8081/127.0.0.1:8082/' "$W/lapi2/dev.yaml" "$W/lapi2/config/local_api_credentials.yaml"

PA=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
PB=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
for n in lapi1 lapi2; do
	cs "$n" machines add agent-a -p "$PA" -f /dev/null --force >/dev/null
	cs "$n" machines add agent-b -p "$PB" -f /dev/null --force >/dev/null
done

umask 077
cat >"$W/relay.json" <<EOF
{
  "listen": "127.0.0.1:8090",
  "queue_dir": "$W/queue",
  "shutdown_grace": "3s",
  "agents": [
    {"login": "agent-a", "password": "$PA"},
    {"login": "agent-b", "password": "$PB"}
  ],
  "lapis": [
    {"name": "lapi1", "url": "http://127.0.0.1:8081/"},
    {"name": "lapi2", "url": "http://127.0.0.1:8082/"}
  ]
}
EOF
mkdir -p "$W/logs"
for a in agent-a agent-b; do
	pw=$PA; [ "$a" = agent-b ] && pw=$PB
	printf 'url: http://127.0.0.1:8090/\nlogin: %s\npassword: %s\n' "$a" "$pw" >"$W/$a/config/local_api_credentials.yaml"
	printf 'filenames:\n  - %s\nlabels:\n  type: syslog\n' "$W/logs/$a.log" >"$W/$a/config/acquis.yaml"
	: >"$W/logs/$a.log"
done

start_lapi() { (cd "$W/$1" && exec ./crowdsec -c dev.yaml -no-cs >>"$W/$1.log" 2>&1) & PIDS+=($!); eval "PID_$1=$!"; }
start_relay() { "$W/lapi-relay" -c "$W/relay.json" -debug >>"$W/relay.log" 2>&1 & PIDS+=($!); PID_relay=$!; }
start_agent() { (cd "$W/$1" && exec ./crowdsec -c dev.yaml -no-api >>"$W/$1.log" 2>&1) & PIDS+=($!); }

start_lapi lapi1; start_lapi lapi2; start_relay
wait_until 30 "LAPIs up" curl -sf 127.0.0.1:8081/health
wait_until 30 "LAPI2 up" curl -sf 127.0.0.1:8082/health
wait_until 10 "relay up" curl -sf 127.0.0.1:8090/health
start_agent agent-a; start_agent agent-b
wait_until 30 "agent-a login" grep -q 'agent logged in.*machine_id=agent-a' "$W/relay.log"
wait_until 30 "agent-b login" grep -q 'agent logged in.*machine_id=agent-b' "$W/relay.log"
sleep 3 # tailers start at end of file

ssh_bf() { # agent ip
	for i in 1 2 3 4 5 6 7 8; do
		echo "$(date '+%b %e %H:%M:%S') host sshd[10$i]: Failed password for invalid user u$i from $2 port 40$i ssh2" >>"$W/logs/$1.log"
	done
}
has_decision() { cs "$1" decisions list -i "$2" -o raw | grep -q ",ban,"; }
machine_of() { # lapi ip -> machine_id of its ssh-bf alert
	local id
	id=$(cs "$1" alerts list -i "$2" -s crowdsecurity/ssh-bf -o raw | awk -F, 'NR==2{print $1}')
	[ -n "$id" ] && cs "$1" alerts inspect "$id" -o json | sed -n 's/.*"machine_id": *"\([^"]*\)".*/\1/p' | head -1
}

# 1. both LAPIs get the alert and decide, attributed to the right agent
ssh_bf agent-a 192.0.2.10
ssh_bf agent-b 198.51.100.7
for n in lapi1 lapi2; do
	wait_until 20 "$n decision for 192.0.2.10" has_decision "$n" 192.0.2.10
	wait_until 20 "$n decision for 198.51.100.7" has_decision "$n" 198.51.100.7
	[ "$(machine_of "$n" 192.0.2.10)" = agent-a ] || fail "$n: 192.0.2.10 not attributed to agent-a"
	[ "$(machine_of "$n" 198.51.100.7)" = agent-b ] || fail "$n: 198.51.100.7 not attributed to agent-b"
done
pass "both LAPIs decided on both alerts, attributed per agent"

# 2. LAPI2 down: LAPI1 still gets alerts, LAPI2's copy is queued
kill "$PID_lapi2"; wait "$PID_lapi2" 2>/dev/null || true
ssh_bf agent-a 192.0.2.20
wait_until 20 "lapi1 decision while lapi2 down" has_decision lapi1 192.0.2.20
wait_until 20 "batch queued for lapi2" sh -c "ls '$W/queue/lapi2/agent-a/' | grep -q json"
pass "LAPI1 decided while LAPI2 was down; LAPI2 batch queued"

# 3. relay restart with the batch queued, then LAPI2 back: replay
kill "$PID_relay"; wait "$PID_relay" 2>/dev/null || true
start_relay
wait_until 10 "relay back" curl -sf 127.0.0.1:8090/health
start_lapi lapi2
wait_until 90 "replay to lapi2" has_decision lapi2 192.0.2.20
[ "$(machine_of lapi2 192.0.2.20)" = agent-a ] || fail "replayed alert not attributed to agent-a"
wait_until 10 "queue empty" sh -c "! ls '$W/queue/lapi2/agent-a/' | grep -q json"
pass "queued batch survived a relay restart and replayed to LAPI2"

# 4. agents keep working after the relay restart (they log in again on 401)
ssh_bf agent-b 198.51.100.30
for n in lapi1 lapi2; do wait_until 30 "$n decision after relay restart" has_decision "$n" 198.51.100.30; done
pass "agents recovered from the relay restart"

# 5. decisions agree across LAPIs (scope, value, type, expiry to the second)
dec() { cs "$1" decisions list -a -o raw | awk -F, 'NR>1{print $3,$4,$5}' | sort; }
diff <(dec lapi1) <(dec lapi2) || fail "decisions differ between LAPIs"
pass "decisions match across LAPIs"

curl -s 127.0.0.1:8090/metrics | grep -E '^lapi_relay_(queue_depth|delivered_total|dropped_total)' || true
echo "ALL PASSED"
