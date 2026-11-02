# lapi-relay

A small relay between CrowdSec log processors and **several independent Local APIs**.
Log processors (agents) send alerts to the relay as if it were a LAPI. The relay delivers each
alert batch to every configured LAPI, and keeps a disk queue for any LAPI that is down, which it
replays when that LAPI comes back. Each LAPI keeps its own database and makes its own
decisions. Bouncers keep reading from their local LAPI.

It is written in Go using only the standard library (about 1,300 lines plus tests).

```
 agent A ─┐                        ┌─▶ LAPI 1 (own DB) ◀── bouncers on host 1
 agent B ─┼─▶ lapi-relay ─(queue)──┤
 agent C ─┘                        └─▶ LAPI 2 (own DB) ◀── bouncers on host 2
```

## Machine identity: the LAPIs see which agent sent each alert

Each agent logs in to the relay with its own machine ID and password. The relay then logs in to
**each LAPI as that agent**, so it holds one JWT session per agent per LAPI. The LAPI records the
alert under the machine from the JWT: it overwrites `alert.machine_id`
(`pkg/apiserver/controllers/v1/alerts.go`). As a result, `cscli alerts inspect` and
`cscli machines list` on every LAPI show the real originating machine, with its version, OS
(from usage metrics) and heartbeat, not "relay".

- **Default:** the relay uses the same machine ID and password on every LAPI. Register the agent's
  machine on each LAPI with `cscli machines add <id> -p <password>`.
- **Per-LAPI override:** an agent's `upstream` map sets a different login per LAPI, for example if a
  machine ID already exists on one LAPI with a different password.
- **Scenarios:** the agent's scenario list and User-Agent from its login are forwarded on the
  upstream login. Each LAPI therefore sees what the agent runs, which is also what it reports to
  CAPI.
- **Agents never get a LAPI token.** The relay authenticates agents itself, so an agent can still
  log in and hand over alerts while every LAPI is down.
- **One relay can serve many agents.** Queues are kept per agent per LAPI, so one agent's backlog
  or rejected batch never blocks another agent.

## Behaviour

| Endpoint | What the relay does |
|---|---|
| `POST /v1/watchers/login` | Checks the agent against `agents` and issues a relay token (`{"code":200,"expire":RFC3339,"token":…}`). A wrong password gets 401. The body may be gzipped: the login carries the agent's scenarios and AppSec rules, so an agent with AppSec virtual patching sends a login over the client's 5 KB compression threshold. |
| `POST /v1/alerts` | Validates that the body is a non-empty JSON array (gzip allowed). It writes the batch once, fsyncs it, hard-links it into every LAPI's queue for that agent, then answers `201 []`. If that fails it answers 503, and the agent re-queues the batch in memory. |
| `GET /v1/heartbeat` | Answers 200 and marks the agent active. While an agent is active (seen in the last 5 minutes), the relay heartbeats every LAPI **as that agent** once a minute. |
| `POST /v1/usage-metrics` | Forwarded to every LAPI as the agent, best effort, without queueing. These are periodic snapshots. |
| `GET/HEAD /v1/allowlists…`, `POST /v1/allowlists/check` | Read-only passthrough to the first LAPI that answers, in config order. AppSec uses these. |
| `HEAD /v1/decisions/stream` (bouncer API key) | Forwarded with the bouncer's `X-Api-Key` to the first LAPI in `lapis` only, which answers 200 or 403. AppSec checks each bouncer's key this way, against its agent's LAPI URL, so without it AppSec refuses every bouncer and the web server answers with errors. Needs no relay token: the LAPI checks the key. Register those bouncers on the first LAPI (the host's own). |
| `GET /v1/alerts` | Passthrough to the first LAPI that answers. This is `cscli alerts list` and `cscli decisions list` on a host whose agent uses the relay (see below). |
| `GET /v1/alerts/<id>`, `DELETE /v1/alerts/<id>`, `DELETE /v1/decisions/<id>` | First LAPI in `lapis` only, with no fallback: IDs differ between LAPIs, so another LAPI's record with the same ID is a different one. Answers 502 while that LAPI is down. |
| `DELETE /v1/decisions`, `DELETE /v1/alerts` (by filter, e.g. `cscli decisions delete --ip …`) | Sent to every LAPI, so an unban isn't left undone on one. If only some succeed, the answer is 502 naming the ones that failed; run the command again once they're back. Not queued. |
| `GET /metrics`, `GET /health` | Prometheus text and a liveness check. No authentication; bind the relay to a private address. |
| anything else | `501`. |

**`cscli` on an agent host.** `cscli` reads the same `local_api_credentials.yaml` as the agent,
so once the agent points at the relay, `cscli`'s alert and decision commands go through the relay
too, with the agent's identity. Lists and inspects come from the first LAPI in `lapis`; put the
host's own LAPI first. `cscli decisions add` is sent to every LAPI like any alert. Deletes by
filter go to every LAPI and deletes by ID to the first only. Commands that work on the database
directly (`cscli machines`, `cscli bouncers`) are unaffected.

Delivery rules:
- Bodies are forwarded byte-for-byte with their `Content-Encoding`. The CrowdSec client gzips
  bodies over 5 KB.
- On a network error, 5xx, 408 or 429, the batch stays queued and the relay retries with backoff
  from 1 s up to 1 min. A good heartbeat cuts the backoff short.
- On 401 or 403, the relay logs in again once and retries. If that still fails (for example the
  machine isn't registered on that LAPI), the batch stays queued.
- On any other 4xx, the batch is dropped and logged as `rejected`, so a poison batch can't block
  the queue.
- `max_queue_files` (default 10000 per agent per LAPI) drops the oldest batch when exceeded.
  `max_queue_bytes` (default 1 GiB across all queues) drops the oldest batches overall, whichever
  agent or LAPI they belong to. `max_queue_age` (default 7 days) drops batches instead of
  replaying them. Both limits are also applied at startup, so lowering them takes effect on restart.
- **Queues no longer in the config.** If an agent or LAPI is renamed or removed, its queue folder
  is no longer read. At startup the relay removes such folders when they are empty. Otherwise it
  logs a warning for each one and reports the count in `lapi_relay_orphan_queue_batches`; with
  `prune_orphan_queues` set it deletes them instead. To keep the batches after renaming an agent,
  move the files into the new folder (`<queue_dir>/<lapi>/<new login>/`) before restarting.
- **Replays don't extend bans.** The LAPI computes a decision's `until` as the alert's `stop_at`
  plus the profile duration, not from arrival time (`pkg/database/alerts.go`). This was checked in
  the integration test below. A late replay only adds alert history, which counts for profiles
  using `GetDecisionsCount` in `duration_expr`.
- **Shutdown** (SIGTERM): the relay stops accepting connections, waits up to `shutdown_grace` for
  queues to drain to LAPIs that are up, then exits. Anything left stays on disk and is delivered
  after the next start.

Queue layout: `<queue_dir>/<lapi>/<agent>/<unixnano>-<seq>.json[.gz]`. Temporary files live in
`<queue_dir>/tmp`. Because the queue is plain files, `ls` shows the backlog.

## What was tested, and what is assumed

**Tested against real CrowdSec** (built from `crowdsecurity/crowdsec` main at `9642ed6`,
2026-10-16), using `scripts/integration-test.sh`. The setup was two LAPIs, the relay, and two
real `crowdsec` agents tailing syslog files, each with its own machine ID:
- One agent has AppSec virtual patching installed, so its login lists over 200 scenarios and
  rules and is gzipped. Both LAPIs store the full list for that machine.
- The `ssh-bf` and `ssh-bf_user-enum` scenarios fire. Both LAPIs store the alerts and create ban
  decisions, attributed to the right machine (`agent-a` or `agent-b`).
- With LAPI2 stopped, LAPI1 keeps deciding, the agent sees no error, and LAPI2's batch is queued
  (gzipped body).
- The relay was restarted with the batch still queued. When LAPI2 came back, the batch was
  delivered to it and its decision appeared.
- Agents recover from a relay restart on their own: they get a 401 and log in again.
- Decisions match on both LAPIs: same scope, value, type, origin and `until` to the nanosecond,
  including the replayed one (compared in each SQLite DB).
- `cscli machines list` on each LAPI shows the agent's version, OS and heartbeat through the
  relay. The allowlist passthrough answered `GET`/`HEAD /v1/allowlists/check/<ip>` and
  `GET /v1/allowlists` from a real LAPI.
- Usage metrics: the LAPI accepted them (201) through the relay.
- AppSec on the agent with a bouncer key registered on LAPI1: a request with that key was
  allowed (200), one with a wrong key refused (401), and a virtual-patching match blocked (403).
- `cscli` run with the agent's credentials, so through the relay: `alerts list`, `alerts inspect`
  and `decisions list` answered from LAPI1; `decisions add` reached both LAPIs; `decisions delete
  --ip` removed the decision from both. The agent's scenario list on each LAPI was unchanged
  afterwards.
- Docker image: built (with the base image pulled from `mirror.gcr.io` because of Docker Hub rate
  limits) and run as non-root with a named volume; a queued batch was written.
- `scripts/install.sh` under systemd (Debian 12 in a container): fresh install, first start,
  update with a queued batch kept, automatic rollback when the new version fails to start, a
  custom `queue_dir`, uninstall and purge.
- `systemd-analyze verify` passes on the unit. TLS listener: checked with `curl` only.
- Unit tests (`go test -race ./...`) against a mock LAPI cover the cases above, plus poison
  batches, upstream token expiry, queue limits (file count, age and total size), queues left over
  from removed agents or LAPIs, per-LAPI credentials and config validation. The size limit and
  the leftover-queue check were only unit-tested; the integration run doesn't fill a queue or
  rename anything.

**Not tested / assumed:**
- Packaged agents (container images, appliance add-ons). They run the same `crowdsec` binary
  and should behave like the agents above.
- A real CAPI enrolment. CAPI was disabled in the test LAPIs.
- LAPIs across a real network (WAN or VPN latency, outages mid-request), and a LAPI over
  HTTPS (`ca_file`).
- An agent connecting to the relay over TLS. Only `curl` was used. The CrowdSec client should
  need `ca_cert_path` in `local_api_credentials.yaml` for a private CA.
- AppSec with an allowlist entry, through the allowlist passthrough. A real web server bouncer
  in front of AppSec (the test calls AppSec with `curl`).
- The systemd unit and install script on a real host rather than a container, distributions
  other than Debian, and long runs or large backlogs.

## Configuration

JSON, unknown keys rejected. Run `lapi-relay -c config.json -check` to validate. See
[`deploy/config.example.json`](deploy/config.example.json).

| Key | Default | |
|---|---|---|
| `listen` | `127.0.0.1:8081` | Must be loopback, RFC 1918, IPv6 ULA or RFC 6598 (`100.64.0.0/10`, used by CGNAT and VPN overlays) unless `allow_public_listen` is set. |
| `tls_cert`, `tls_key` | none | Optional TLS listener. Agents send their password at login. |
| `queue_dir` | required | Fsynced, so put it on real storage. |
| `max_queue_files` | 10000 | Per agent per LAPI. |
| `max_queue_age` | `168h` | |
| `max_queue_bytes` | `"1GiB"` | Total across all queues. A number of bytes or a string such as `"512MiB"` or `"2GB"`. A batch waiting for two LAPIs counts twice, although it is stored once, so disk use stays at or below this. Must be at least 32 MiB per LAPI so the largest batch the relay accepts fits. |
| `prune_orphan_queues` | `false` | Delete queues for agents or LAPIs that are no longer in the config, instead of only warning. |
| `token_ttl` | `1h` | Lifetime of tokens the relay issues to agents. |
| `shutdown_grace` | `10s` | |
| `agents[]` | required | `login`, `password` or `password_file`, and an optional `upstream: {<lapi>: {login, password/password_file}}`. |
| `lapis[]` | required | `name` (used in queue paths and metric labels), `url`, optional `ca_file`. |

Keep secrets in `password_file`s (mode 0640, `root:lapi-relay`), not in the JSON. The relay never
logs passwords or tokens. It does log failed login attempts with the machine ID and remote
address.

Metrics: `lapi_relay_queue_depth`, `lapi_relay_queue_bytes`, `lapi_relay_lapi_up`, `lapi_relay_delivered_total`,
`lapi_relay_dropped_total{reason=overflow|expired|rejected}` (all labelled by `lapi` and `agent`),
plus `lapi_relay_received_total`, `lapi_relay_failed_logins_total` and
`lapi_relay_orphan_queue_batches`. Non-empty queues are also
logged once a minute.

## Running

```sh
go build -o lapi-relay .            # Go >= 1.22, no dependencies
go test -race ./...
CROWDSEC_SRC=~/src/crowdsec scripts/integration-test.sh   # optional, real CrowdSec
```

**systemd:** run [`scripts/install.sh`](scripts/install.sh) as root from a checkout. It builds the
relay (or takes a prebuilt one with `--binary PATH`, for hosts without Go), creates the
`lapi-relay` system user, and installs the binary to `/usr/local/bin`, the unit
([`deploy/lapi-relay.service`](deploy/lapi-relay.service)) and a starting
`/etc/lapi-relay/config.json`. The first run stops there so you can edit the config and add
password files. Run it again and it sets the permissions on the config and password files,
checks the config as the service user, and starts the service. The queue lives in
`/var/lib/lapi-relay` (`StateDirectory`). For a different `queue_dir` the script adds a systemd
drop-in so the relay can write to it.

```sh
sudo scripts/install.sh                       # install, or update after a git pull
sudo scripts/install.sh --binary ./lapi-relay # use a binary built elsewhere
sudo scripts/install.sh --uninstall [--purge] # --purge also deletes config and queue
```

**Checking it works:** `journalctl -u lapi-relay -f`. When an agent logs in to the relay you
should see `agent logged in`. Straight after that, the relay sends a heartbeat as that agent to
each LAPI, and logs one line per LAPI:
`LAPI reachable lapi=<name> agent=<id>`, or `LAPI unreachable, queueing ... err=...`. The error
names the cause. For example, `login as <id>: HTTP 401` usually means the machine isn't
registered on that LAPI (`cscli machines add <id> -p <password>`) or the password differs.
Failing LAPIs are retried every minute; alerts for them stay queued and are delivered once they
accept the login. On each LAPI, `cscli machines list` shows the agent's last heartbeat. The same
state is on `/metrics` as `lapi_relay_lapi_up` and `lapi_relay_queue_depth`.

**Updating** is the same command. The new version is checked against your config before anything
is replaced. Queued alerts stay on disk across the restart. If the new version doesn't stay up,
the previous one is put back. The config and password files are never overwritten. The unit file
is replaced on every run, so put local changes in a drop-in (`systemctl edit lapi-relay`).

**Docker:** see the `Dockerfile`. Inside a container the relay must listen on `0.0.0.0:8081` with
`allow_public_listen: true`, so publish the port on a private address only:

```sh
docker run -d --name lapi-relay --restart unless-stopped \
  -v /etc/lapi-relay:/etc/lapi-relay:ro -v lapi-relay-queue:/var/lib/lapi-relay \
  -p 192.168.1.20:8081:8081 lapi-relay
```

## Deployment

1. **LAPIs.** Run one independent LAPI per host, each with its own database. Keep **profiles,
   allowlists and parser whitelists the same** on all of them, because each LAPI applies its own
   when an alert arrives. `cscli allowlists` changes are per LAPI and are **not** replicated, so
   run them on every LAPI. `cscli decisions add` and `delete` reach every LAPI only when run on a
   host whose `cscli` goes through the relay (see "`cscli` on an agent host"). Each LAPI enrolled with CAPI pulls the
   community blocklist and shares signals independently.
2. **Register every agent's machine on every LAPI** with the same ID and password:
   `cscli machines add <id> -p <password>`. Use `upstream` only if a LAPI needs different
   credentials. If an agent used to talk to a LAPI directly, the LAPI logs
   `new IP address detected for machine` once when the relay logs in. This is harmless.
3. **Where to run relays.** Run a relay close to the agents it serves, so it stays reachable when
   a LAPI host is down:
   - one relay per host that runs agents, listening on `127.0.0.1`. If that host also runs a
     LAPI, put it first in `lapis`, so `cscli` lists show that LAPI.
   - one relay for a group of agents on a LAN (a small VM or container), listening on its LAN or
     VPN address, with TLS if that network isn't trusted.
4. **Point agents at the relay.** Set `url` in the agent's `local_api_credentials.yaml`, or the
   equivalent setting of a packaged agent, to the relay, with the password from the relay's
   `agents` entry.
5. **Bouncers** keep reading from their **local** LAPI, not from the relay.
6. **Behind reverse proxies,** check that the banned IP is the client's, not the proxy's. An
   application that trusts only some of its proxies will log the others' addresses, and every
   LAPI will then ban that proxy. Trigger a test alert through each proxy before relying on it,
   and consider allowlisting the proxies' own addresses on every LAPI.
7. **Loss window.** An agent only gets 201 once the batch is fsynced into every LAPI's queue.
   After that, alerts are lost only if the relay's disk is lost, or a LAPI stays down past
   `max_queue_age`, `max_queue_files` or `max_queue_bytes`. Before the relay acknowledges a batch, the agent holds
   it in memory and retries, which is the same as with a direct LAPI. **If a relay is down, no
   LAPI gets its agents' alerts**, so treat it like any other critical service and monitor
   `lapi_relay_lapi_up` and `lapi_relay_queue_depth`.

## Design notes

Considered and rejected:
- **Shared Postgres for both LAPIs.** CrowdSec recommends one LAPI per DB. Running several LAPIs
  on one DB needs flushing disabled on all but one. Free managed Postgres tiers are weak: Neon's
  scale-to-zero can't be disabled and its 100 CU-hours run out, Supabase pauses after a week
  idle, and Aiven's free tier is single-node.
- **A single central LAPI.** It's a single point of failure, and remote bouncers would have
  stale blocklists while it is down.
- **Passing agent logins through to one "primary" LAPI.** Agents couldn't log in while that LAPI
  is down, and the other LAPIs would need a separate identity. `POST /v1/alerts` only accepts a
  machine JWT, not a bouncer API key.

## Possible future work

**De-duplicating signals to CAPI.** Every LAPI enrolled with CAPI shares signals from its own
database. Behind the relay all LAPIs store the same alerts, so CAPI gets each signal once per
LAPI. Turning sharing off on all but one LAPI (`api.server.online_client.sharing: false`) isn't a
fix: a LAPI that doesn't share doesn't get the community blocklist either.

An aggregator between the LAPIs and CAPI could share each signal once and hand the community
blocklist to every LAPI. Each LAPI would point the `url` in its `online_api_credentials.yaml` at
the aggregator, which speaks CAPI's v3 API to the LAPIs and holds the one real CAPI identity.
What is known so far, from the CrowdSec source:
- The CAPI address is configurable per LAPI (`url`, and `papi_url` for the Console's PAPI).
- The LAPI routes to emulate: `/v3/watchers`, `/v3/watchers/login`, `/v3/watchers/enroll`,
  `/v3/signals`, `/v3/decisions/stream`, `/v3/metrics`, `/v3/usage-metrics` and the heartbeat.
- Duplicates have to be matched by content, not ID: each LAPI gives an alert a new UUID when
  it stores it (`pkg/apiserver/controllers/v1/alerts.go`). The relay gives every LAPI
  byte-identical alerts, so scenario, source, start/stop times and event count match.
- The decision stream returns the full list on startup and changes after that, so the
  aggregator has to keep the full set and track each LAPI's position in it.

Open questions before building it:
- Whether CrowdSec minds duplicate signals from one operator's engines at all.
- Whether serving one engine's community blocklist to several of the same operator's LAPIs fits
  their terms.
- How to handle the v3 API changing, since it isn't a published, stable interface.
- How to handle the aggregator being down: no blocklist updates, and signals must be queued.
- Whether to proxy PAPI, so Console features keep working.

It would be a separate project, not part of the relay. It sits elsewhere (between the LAPIs and
the internet, one per fleet), speaks a different protocol and holds the real CAPI credentials,
and would share almost no code with the relay.
