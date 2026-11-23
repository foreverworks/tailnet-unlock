#!/bin/sh
# The tailnet variant's first boot (firstboot.sh with the tailnet door): seal the imported door
# key to this VM's swtpm, make the recovery key, write a configuration with tailnet.enabled = true
# and the test control server, trust the test CA, enrol the unlock node with the pre-auth key from
# the key disk (the volume labelled TUKEY: the CA, the control server's URL and the key), move the
# root to keylocation=prompt, rebuild the images without the local key, print the enrolment and the
# pins on the serial console, power off. Test values only.
set -eux
# a failed step must not leave the VM running for the harness to time out on
finished=0
trap '[ "$finished" = 1 ] || { echo "TU-FIRSTBOOT failed" >/dev/ttyS0; systemctl poweroff; }' EXIT
mkdir -p /etc/tailnet-unlock /run/tailnet-unlock /run/tukey
mount -o ro /dev/disk/by-label/TUKEY /run/tukey 2>/dev/null || mount -o ro LABEL=TUKEY /run/tukey
install -m 0644 /run/tukey/ca.pem /usr/local/share/ca-certificates/tailnet-unlock-test.crt
update-ca-certificates
control=$(cat /run/tukey/control_url)
# the unit starts after the local file systems only: wait for the uplink and the control server
tries=0
until curl -fsS --cacert /run/tukey/ca.pem "$control/health" >/dev/null; do
	tries=$((tries + 1))
	[ "$tries" -lt 120 ] || exit 1
	sleep 2
done
cat >/etc/tailnet-unlock/box.toml <<TOML
[network]
interface = "$(ls /sys/class/net | grep -v '^lo$' | head -n 1)"
match = "mac"

[door]
port = 2222
recovery = "uplink"
key_source = "import"
recovery_key_source = "import"

[tailnet]
enabled = true
login_server = "$control"
TOML
cp /opt/tailnet-unlock/keyholder.pub /etc/tailnet-unlock/delivery_keys
cp /opt/tailnet-unlock/operator.pub /etc/tailnet-unlock/operator_keys
tailnet-unlock door-keygen --import /opt/tailnet-unlock/door_key --replace
tailnet-unlock door-keygen --recovery --import /opt/tailnet-unlock/recovery_key --replace
# the key reaches enroll as a root-only file in tmpfs; enroll shreds it
install -m 0600 /run/tukey/authkey /run/tu-authkey
umount /run/tukey
zfs set keylocation=prompt rpool
rm -f /etc/zfs/rpool.key
tailnet-unlock enroll --auth-key-file /run/tu-authkey --no-rebuild >/run/tu-enroll.json
echo "TU-ENROLL $(tr -d '\n' </run/tu-enroll.json)" >/dev/ttyS0
update-initramfs -u -k all
tailnet-unlock verify >/dev/ttyS0 2>&1 || echo "TU-VERIFY failed $?" >/dev/ttyS0
echo "TU-PINS $(tailnet-unlock pins | tr '\n' '|')" >/dev/ttyS0
systemctl disable tailnet-unlock-firstboot.service
rm -f /etc/systemd/system/multi-user.target.wants/tailnet-unlock-firstboot.service
finished=1
echo "TU-FIRSTBOOT done" >/dev/ttyS0
systemctl poweroff
