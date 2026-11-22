#!/bin/sh
# The target VM's first boot, with its local key: seal the imported door key to this VM's swtpm,
# make the recovery key, write the configuration, move the root to keylocation=prompt, rebuild the
# images without the key, print the pins on the serial console, power off. Test values only.
set -eux
mkdir -p /etc/tailnet-unlock /run/tailnet-unlock
cat >/etc/tailnet-unlock/box.toml <<EOF
[network]
interface = "$(ls /sys/class/net | grep -v '^lo$' | head -n 1)"
match = "mac"

[door]
port = 2222
recovery = "uplink"
key_source = "import"
recovery_key_source = "import"

[tailnet]
enabled = false
EOF
cp /opt/tailnet-unlock/keyholder.pub /etc/tailnet-unlock/delivery_keys
cp /opt/tailnet-unlock/operator.pub /etc/tailnet-unlock/operator_keys
tailnet-unlock door-keygen --import /opt/tailnet-unlock/door_key --replace
tailnet-unlock door-keygen --recovery --import /opt/tailnet-unlock/recovery_key --replace
zfs set keylocation=prompt rpool
rm -f /etc/zfs/rpool.key
update-initramfs -u -k all
echo "TU-PINS $(tailnet-unlock pins | tr '\n' '|')" >/dev/ttyS0
systemctl disable tailnet-unlock-firstboot.service
rm -f /etc/systemd/system/multi-user.target.wants/tailnet-unlock-firstboot.service
echo "TU-FIRSTBOOT done" >/dev/ttyS0
systemctl poweroff
