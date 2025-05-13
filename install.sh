#!/usr/bin/bash

test `whoami` = root || {
  echo "run install script as root" >&2
  exit 1
}

set -e

SCRIPT_DIR=$(realpath `dirname "${BASH_SOURCE[0]}"`)
FAILSAFE_PATH="$SCRIPT_DIR"/work/failsafe.nft
QFW_FAILSAFE_PATH="/rw/config/qubes-firewall.d/01-dynamic-firewall-failsafe.nft"

cd "$SCRIPT_DIR"
python3 << __EOF__
import importlib, sys
exitcode = 0

required_modules = [
  "requests",
  "jinja2",
  "qubesagent",
  "qubesdb",
  "qubesadmin",
]

for m in required_modules:
  if importlib.util.find_spec(m) is None:
    print("missing module:", m, file=sys.stderr)
    exitcode = 1
sys.exit(exitcode)
__EOF__

touch clients
mkdir -p work
python3 "$SCRIPT_DIR"/main.py fail render-print >"$FAILSAFE_PATH" 2>/dev/null || :
grep -q -e "table ip custom-dynamic" "$FAILSAFE_PATH" || {
  echo "failed to generate fail-safe nft." >&2
  exit 1
}
chmod +x "$FAILSAFE_PATH"
mkdir -p `dirname "$QFW_FAILSAFE_PATH"`
ln -sfn "$FAILSAFE_PATH" "$QFW_FAILSAFE_PATH"

cat > /etc/systemd/system/dynamic-firewall-init.service << __EOF__
[Unit]
Description=Set dynamic firewall to a safe state during system initialization
# qubes-network.service is what configures forwarding
Before=qubes-network.service
After=qubes-iptables.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f "$FAILSAFE_PATH"

[Install]
WantedBy=multi-user.target
__EOF__

cat > /etc/systemd/system/dynamic-firewall.service << __EOF__
[Unit]
Description=Firewall with custom dynamic rules
After=dynamic-firewall-init.service

[Service]
Type=exec
ExecStart=/usr/bin/python3 "$SCRIPT_DIR"/main.py s1 do refresh save render-activate wait loop
WorkingDirectory=$SCRIPT_DIR

[Install]
WantedBy=multi-user.target
__EOF__

systemctl daemon-reload
systemctl enable dynamic-firewall-init.service
systemctl enable dynamic-firewall.service
systemctl start dynamic-firewall.service
systemctl mask qubes-firewall.service
QUBES_FW_PID=$(ps --no-headers -C qubes-firewall -o pid | tail -n 1)
test "$QUBES_FW_PID" && kill $QUBES_FW_PID || :
sleep 0.1

readarray -t QUBES_FW_TABLES < <( nft list tables | grep " qubes-firewall$" )
for table in "${QUBES_FW_TABLES[@]}" ; do
  nft delete $table
done

echo installed OK >&2
