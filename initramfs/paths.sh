# shellcheck shell=sh
# Fixed paths inside the initramfs. The door and the boot scripts source this file. Nothing here
# comes from the environment, so an SSH client can change none of it.
# shellcheck disable=SC2034 # each script uses a different subset
TU_LIB=/usr/lib/tailnet-unlock
TU_RUN=/tailnet-unlock/run
TU_ETC=/etc/tailnet-unlock
TU_CONF=/conf/tailnet-unlock.conf
TU_RECORD_DIR=/run/tailnet-unlock
TU_BOOT_ID_FILE=/proc/sys/kernel/random/boot_id
TU_CMDLINE=/proc/cmdline
TU_CONSOLE=/dev/console
TU_TPM_DEVICE=/dev/tpmrm0
TU_TCTI=device:/dev/tpmrm0
TU_ZFS=zfs
TU_ROOT_WAIT_SECONDS=600
TU_TICK=1
TU_MINUTE=60
TU_INITRAMFS_FUNCTIONS=/scripts/functions
TU_NET_CONF_DIR=/run
TU_PANIC_DELAY=10
TU_REBOOT=reboot
TU_SYSRQ=/proc/sysrq-trigger
TU_KERNEL_PANIC=/proc/sys/kernel/panic
