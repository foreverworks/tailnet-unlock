#!/bin/sh
# Runs inside the builder VM (Debian 13's cloud image, booted with cloud-init's NoCloud seed): writes
# the target disk /dev/vdb as DESIGN.md 15.2 lays it out, a 512 MiB ESP, a 1 GiB ext4 /boot and an
# encrypted rpool on the rest, with Debian 13 from trixie main and contrib and tailnet-unlock from
# the repository archive on the seed. Every secret here is a made-up test value from the seed.
set -eux
# Everything mounts inside a private mount namespace: a service that starts meanwhile and has its
# own namespace would otherwise copy the pool's mounts, and the pool could not be exported.
if [ -z "${TU_PRIVATE_NS-}" ]; then
	TU_PRIVATE_NS=1
	export TU_PRIVATE_NS
	exec unshare --mount --propagation private sh "$0"
fi
seed=/run/tailnet-unlock-seed
mkdir -p "$seed"
mount -o ro /dev/disk/by-label/CIDATA "$seed" 2>/dev/null || mount -o ro LABEL=CIDATA "$seed"
. "$seed/vars.sh"

export DEBIAN_FRONTEND=noninteractive
sed -i 's/^Components: main$/Components: main contrib/' /etc/apt/sources.list.d/debian.sources
apt-get update
# headers for the kernel that is running (the cloud image boots a -cloud-amd64 kernel), so dkms
# builds the module `modprobe zfs` needs
apt-get install -y --no-install-recommends "linux-headers-$(uname -r)" zfs-dkms zfsutils-linux \
	debootstrap gdisk parted dosfstools e2fsprogs
modprobe zfs

disk=/dev/vdb
sgdisk --zap-all "$disk"
sgdisk -n1:1M:+512M -t1:EF00 -n2:0:+1G -t2:8300 -n3:0:0 -t3:BF00 "$disk"
partprobe "$disk"; udevadm settle
mkfs.vfat -F32 -n ESP "${disk}1"
mkfs.ext4 -q -L boot "${disk}2"
printf '%s' "$TEST_PASSPHRASE" >/run/rpool.key
zpool create -f -o ashift=12 -O encryption=on -O keyformat=passphrase \
	-O keylocation=file:///run/rpool.key -O compression=lz4 -O acltype=posixacl -O xattr=sa \
	-O mountpoint=none -R /mnt rpool "${disk}3"
zfs create -o mountpoint=/ -o canmount=noauto rpool/ROOT
zfs create -o mountpoint=/ rpool/ROOT/debian
zpool set bootfs=rpool/ROOT/debian rpool
mkdir -p /mnt/boot && mount "${disk}2" /mnt/boot
mkdir -p /mnt/boot/efi && mount "${disk}1" /mnt/boot/efi

debootstrap --components=main,contrib trixie /mnt http://deb.debian.org/debian
cp /etc/apt/sources.list.d/debian.sources /mnt/etc/apt/sources.list.d/
# the cloud image's mirror lists do not exist in the new root: use the mirrors themselves
sed -i "s#mirror+file:/*etc/apt/mirrors/debian.list#http://deb.debian.org/debian#; s#mirror+file:/*etc/apt/mirrors/debian-security.list#http://deb.debian.org/debian-security#" \
	/mnt/etc/apt/sources.list.d/debian.sources
rm -f /mnt/etc/apt/sources.list
for d in dev proc sys run; do mount --rbind "/$d" "/mnt/$d" && mount --make-rslave "/mnt/$d"; done
install -D -m 0600 /run/rpool.key /mnt/etc/zfs/rpool.key
cat >/mnt/etc/fstab <<EOF
LABEL=boot /boot ext4 defaults 0 2
LABEL=ESP /boot/efi vfat umask=0077 0 1
EOF
printf 'tu-test\n' >/mnt/etc/hostname
mkdir -p /mnt/opt/tailnet-unlock
tar -xf "$seed/repo.tar" -C /mnt/opt/tailnet-unlock
cp "$seed/firstboot.sh" "$seed/vars.sh" /mnt/opt/tailnet-unlock/
cp "$seed"/test-keys/* /mnt/opt/tailnet-unlock/ 2>/dev/null || :

chroot /mnt /bin/sh -eux <<'EOF'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends linux-image-amd64 linux-headers-amd64 zfs-dkms \
	zfs-initramfs zfsutils-linux grub-efi-amd64 dropbear-bin tpm2-tools \
	libtss2-tcti-device0t64 python3 openssh-server busybox initramfs-tools systemd-sysv
/opt/tailnet-unlock/tools/install-tree /
zfs set keylocation=file:///etc/zfs/rpool.key rpool
echo 'GRUB_CMDLINE_LINUX="console=ttyS0,115200 root=ZFS=rpool/ROOT/debian"' \
	>/etc/default/grub.d/tailnet-unlock-test.cfg
echo 'GRUB_TERMINAL=serial' >>/etc/default/grub.d/tailnet-unlock-test.cfg
grub-install --target=x86_64-efi --efi-directory=/boot/efi --removable --no-nvram
cat >/etc/grub.d/42_tailnet_unlock_test <<'GRUB'
#!/bin/sh
# a second entry for scenario T28: the same kernel with break=mount
. /usr/lib/grub/grub-mkconfig_lib
kernel=$(ls /boot/vmlinuz-* | sort -V | tail -n 1)
version=${kernel#/boot/vmlinuz-}
cat <<ENTRY
menuentry "tailnet-unlock break=mount" {
	search --no-floppy --label boot --set=root
	linux /vmlinuz-$version console=ttyS0,115200 root=ZFS=rpool/ROOT/debian break=mount
	initrd /initrd.img-$version
}
ENTRY
GRUB
chmod 0755 /etc/grub.d/42_tailnet_unlock_test
sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
update-grub
mkdir -p /root/.ssh && chmod 0700 /root/.ssh
cp /opt/tailnet-unlock/harness_ssh.pub /root/.ssh/authorized_keys
cp /opt/tailnet-unlock/firstboot.sh /usr/local/sbin/tailnet-unlock-firstboot
cat >/etc/systemd/system/tailnet-unlock-firstboot.service <<'UNIT'
[Unit]
Description=tailnet-unlock test: seal the door to this VM's TPM, then power off
ConditionPathExists=/etc/zfs/rpool.key
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/bin/sh /usr/local/sbin/tailnet-unlock-firstboot
StandardOutput=journal+console
UNIT
cat >/etc/systemd/system/tailnet-unlock-report.service <<'UNIT'
[Unit]
Description=tailnet-unlock test: print this boot's record on the serial console
After=local-fs.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo "TU-SCENARIO boot.json $(cat /run/tailnet-unlock/boot.json 2>/dev/null)" >/dev/ttyS0'
UNIT
systemctl enable tailnet-unlock-firstboot.service tailnet-unlock-report.service ssh.service
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf /etc/systemd/system/tailnet-unlock-firstboot.service \
	/etc/systemd/system/multi-user.target.wants/
update-initramfs -u -k all
EOF
for d in dev proc sys run; do umount -R -l "/mnt/$d"; done
umount /mnt/boot/efi /mnt/boot
cd /
sync
# the event daemon and anything else that may hold the pool open
systemctl stop zfs-zed.service zfs-mount.service zfs-share.service 2>&1 || :
for _ in 1 2 3 4 5; do
	zpool export rpool && break
	sleep 3
done
if zpool list rpool >/dev/null 2>&1; then
	set +x
	echo "DIAG: the pool is still busy"
	zpool status rpool || :
	zfs list -r -o name,mounted,mountpoint rpool || :
	for p in /proc/[0-9]*; do
		ls -l "$p/cwd" "$p/root" "$p/fd" 2>/dev/null | grep -E ' /mnt|/dev/vdb|rpool' | sed "s#^#$p: #" || :
	done
	ps -eo pid,comm,args | grep -i "zfs\|zed\|zpool\|dkms" | grep -v grep || :
	echo "DIAG: end"
	set -x
	zpool export -f rpool
fi
echo "TU-PROVISION done"
# the log is tailed to the console: give the tail time to print the line before the power goes
sleep 5
poweroff
