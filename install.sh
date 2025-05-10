#!/usr/bin/bash

test `whoami` = root || {
    echo "run install script as root" >&2
    exit 1
}

set -e

SCRIPT_DIR=$(realpath `dirname "${BASH_SOURCE[0]}"`)

cd "$SCRIPT_DIR"
touch clients
mkdir -p work
python3 "$SCRIPT_DIR"/main.py fail render-print >"$SCRIPT_DIR"/work/failsafe.nft 2>/dev/null || :
mkdir -p /rw/config/qubes-firewall.d
cp "$SCRIPT_DIR"/work/failsafe.nft /rw/config/qubes-firewall.d/01-dynamic-firewall-failsafe.nft
chmod +x /rw/config/qubes-firewall.d/01-dynamic-firewall-failsafe.nft

cat > /etc/systemd/system/dynamic-firewall-init.service << __EOF__
[Unit]
Description=Set dynamic firewall to a safe state during system initialization
# qubes-network.service is what configures forwarding
Before=qubes-network.service
After=qubes-iptables.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f "$SCRIPT_DIR"/work/failsafe.nft

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
