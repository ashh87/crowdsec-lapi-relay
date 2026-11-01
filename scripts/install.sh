#!/bin/sh
# Install or update lapi-relay as a systemd service. Run as root.
#
#   scripts/install.sh [--binary PATH]      install, or update in place
#   scripts/install.sh --uninstall [--purge]
#
# To update, run it again from a newer checkout (git pull first). The new
# version is checked against your config before anything is replaced, queued
# alerts are kept, and if it fails to start the previous version is put back.
# Your config and password files are never overwritten.
#
# Without --binary the relay is built from this checkout, which needs Go >= 1.22.
# To install on a host without Go, build elsewhere and copy the binary over:
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o lapi-relay .   # or arm64
set -eu

BIN=/usr/local/bin/lapi-relay
ETC=/etc/lapi-relay
CONFIG=$ETC/config.json
UNIT=/etc/systemd/system/lapi-relay.service
DROPIN_DIR=/etc/systemd/system/lapi-relay.service.d
DROPIN=$DROPIN_DIR/queue-dir.conf
STATE=/var/lib/lapi-relay
USER_NAME=lapi-relay

HERE=$(cd "$(dirname "$0")/.." && pwd)

usage() { sed -n '2,14s/^# \{0,1\}//p' "$0"; exit "${1:-0}"; }
die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

# A string setting from the config, if set (the relay itself validates it).
config_value() {
	[ -f "$CONFIG" ] || return 0
	sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$CONFIG" | head -n 1
}

binary=
uninstall=
purge=
while [ $# -gt 0 ]; do
	case $1 in
	--binary) [ $# -ge 2 ] || die "--binary needs a path"; binary=$2; shift ;;
	--uninstall) uninstall=1 ;;
	--purge) purge=1 ;;
	-h | --help) usage ;;
	*) echo "unknown option: $1" >&2; usage 2 ;;
	esac
	shift
done
[ -z "$purge" ] || [ -n "$uninstall" ] || die "--purge only goes with --uninstall"
[ "$(id -u)" -eq 0 ] || die "run as root (e.g. with sudo)"

# Without a running systemd (containers, chroots) only the files are installed.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
	have_systemd=1
else
	have_systemd=
	echo "note: systemd is not running here, so the service won't be enabled or started" >&2
fi

if [ -n "$uninstall" ]; then
	if [ -n "$have_systemd" ]; then
		systemctl disable --now lapi-relay.service 2>/dev/null || true
	fi
	queue_dir=$(config_value queue_dir)
	rm -f "$BIN" "$BIN.prev" "$UNIT" "$DROPIN"
	rmdir "$DROPIN_DIR" 2>/dev/null || true # keeps your own drop-ins
	[ -z "$have_systemd" ] || systemctl daemon-reload
	say "removed the binary and the service"
	if [ -n "$purge" ]; then
		rm -rf "$ETC" "$STATE"
		if id "$USER_NAME" >/dev/null 2>&1; then
			userdel "$USER_NAME"
		fi
		say "removed $ETC, $STATE and the $USER_NAME user; any queued alerts there are gone"
		# Not removed automatically: it could be any directory.
		if [ -n "$queue_dir" ] && [ "${queue_dir%/}" != "$STATE" ] && [ -d "$queue_dir" ]; then
			say "your queue_dir $queue_dir is still there; remove it yourself if you no longer need it"
		fi
	else
		say "kept $ETC (config, passwords) and the queue in ${queue_dir:-$STATE}; add --purge to remove them"
	fi
	exit 0
fi

# 1. Get the new binary into a directory the service user can read, so it can
# be checked as that user before it replaces anything.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
chmod 0755 "$tmp"
if [ -z "$binary" ]; then
	command -v go >/dev/null || die "Go is not installed here; build elsewhere and pass --binary PATH"
	say "building from $HERE"
	(cd "$HERE" && CGO_ENABLED=0 go build -trimpath -o "$tmp/lapi-relay" .)
else
	[ -f "$binary" ] || die "$binary not found"
	install -m 0755 "$binary" "$tmp/lapi-relay"
fi
"$tmp/lapi-relay" -version >/dev/null 2>&1 || die "the binary does not run on this host (wrong architecture?)"
new_version=$("$tmp/lapi-relay" -version)
old_version=
[ ! -x "$BIN" ] || old_version=$("$BIN" -version 2>/dev/null || echo unknown)

# 2. User
if ! id "$USER_NAME" >/dev/null 2>&1; then
	command -v useradd >/dev/null || die "useradd not found; create a system user named $USER_NAME and run this again"
	nologin=$(command -v nologin || echo /usr/sbin/nologin)
	useradd --system --no-create-home --home-dir /nonexistent --shell "$nologin" "$USER_NAME"
	say "created system user $USER_NAME"
fi

# 3. Config. Never overwritten; only its permissions are fixed.
install -d -m 0750 -o root -g "$USER_NAME" "$ETC"
new_config=
if [ ! -e "$CONFIG" ]; then
	install -m 0640 -o root -g "$USER_NAME" "$HERE/deploy/config.example.json" "$CONFIG"
	new_config=1
	say "created $CONFIG from the example"
fi
# The relay reads these as $USER_NAME; nobody else should.
for f in "$CONFIG" "$ETC"/*.password "$ETC"/*.pem "$ETC"/*.key; do
	[ -f "$f" ] || continue
	chown root:"$USER_NAME" "$f"
	chmod 0640 "$f"
done

# 4. Check the new binary against the config, as the service user so that
# unreadable password files show up now rather than at start.
if [ -z "$new_config" ]; then
	if command -v setpriv >/dev/null; then
		set -- setpriv --reuid="$USER_NAME" --regid="$USER_NAME" --clear-groups
	else
		set --
	fi
	if ! "$@" "$tmp/lapi-relay" -c "$CONFIG" -check; then
		[ -z "$old_version" ] || die "the config check failed; still on $old_version, nothing was replaced"
		die "the config check failed; fix $CONFIG and run this again"
	fi
fi

# 5. Files. Keep the old binary and unit to roll back to.
if [ -n "$old_version" ]; then
	cp -p "$BIN" "$BIN.prev"
	[ ! -f "$UNIT" ] || cp -p "$UNIT" "$tmp/unit.prev"
fi
install -m 0755 "$tmp/lapi-relay" "$BIN.new"
mv -f "$BIN.new" "$BIN"
if [ -z "$old_version" ]; then
	say "installed $BIN ($new_version)"
elif [ "$old_version" = "$new_version" ]; then
	say "reinstalled $BIN ($new_version)"
else
	say "updated $BIN from $old_version to $new_version"
fi

# The unit is replaced on every run. Put your own changes in a drop-in
# (systemctl edit lapi-relay), which this script leaves alone.
install -m 0644 "$HERE/deploy/lapi-relay.service" "$UNIT"
say "installed $UNIT"
# systemd's StateDirectory would create this too, but not outside systemd.
install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$STATE"

# The unit makes the file system read-only apart from $STATE, so a different
# queue_dir needs a drop-in.
queue_dir=$(config_value queue_dir)
if [ -n "$queue_dir" ] && [ "${queue_dir%/}" != "$STATE" ]; then
	install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" "$queue_dir"
	install -d -m 0755 "$DROPIN_DIR"
	printf '[Service]\nReadWritePaths=%s\n' "$queue_dir" >"$DROPIN"
	say "queue_dir is $queue_dir, allowed it in $DROPIN"
else
	rm -f "$DROPIN"
	rmdir "$DROPIN_DIR" 2>/dev/null || true # keeps your own drop-ins
fi

# 6. Service
if [ -n "$new_config" ]; then
	[ -z "$have_systemd" ] || systemctl daemon-reload
	cat <<EOF

Next steps:
  1. Edit $CONFIG: your agents and LAPIs, and "listen". It starts as
     127.0.0.1:8081, which only agents on this host can reach. For agents on
     other machines, use this host's LAN or VPN address.
  2. Put each password in its own file in $ETC, e.g.
       printf '%s' 'the-password' > $ETC/agent-1.password
  3. Run this script again. It fixes file permissions, checks the config
     and starts the service.
EOF
	exit 0
fi
if [ -z "$have_systemd" ]; then
	rm -f "$BIN.prev"
	say "files installed; start $BIN -c $CONFIG with your own service manager"
	exit 0
fi

systemctl daemon-reload
systemctl enable --quiet lapi-relay.service
# On stop the old version spends up to shutdown_grace delivering what it can;
# the rest stays queued on disk for the new one.
systemctl restart lapi-relay.service || true
sleep 3 # a crash by now shows as failed or activating (Restart=)
if systemctl is-active --quiet lapi-relay.service; then
	rm -f "$BIN.prev"
	listen=$(config_value listen)
	say "lapi-relay $new_version is running on ${listen:-127.0.0.1:8081}"
	case ${listen:-127.0.0.1:8081} in
	127.* | localhost:* | "[::1]:"*)
		say "that is loopback: only agents on this host can connect (change \"listen\" for others)" ;;
	esac
	exit 0
fi

journalctl --no-pager -u lapi-relay.service -n 15 >&2 || true
[ -n "$old_version" ] || die "lapi-relay did not start; see journalctl -u lapi-relay"
echo "error: $new_version did not start; putting $old_version back" >&2
mv -f "$BIN.prev" "$BIN"
[ ! -f "$tmp/unit.prev" ] || cp -p "$tmp/unit.prev" "$UNIT"
systemctl daemon-reload
systemctl restart lapi-relay.service || true
sleep 3
if systemctl is-active --quiet lapi-relay.service; then
	die "rolled back to $old_version, which is running again"
fi
die "rolled back to $old_version, but it is not running either; see journalctl -u lapi-relay"
