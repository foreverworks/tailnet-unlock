# Changelog

All notable changes are listed here, newest first. The versions follow [semantic
versioning](https://semver.org); until 1.0, a minor release may change behaviour.

## 0.1.0

The first release: the box side, for Debian 13 with root on ZFS, the `tpm` profile and
initramfs-tools.

### Added

- The uplink door: a minimal SSH server in the initramfs, on the machine's own address, whose only
  commands are `status` and `unlock <boot id>` (the key on stdin). `door-keygen` makes or imports its
  key and seals it to the TPM; `door-keygen --recovery` makes the recovery door's key, stored unsealed
  on purpose. The panic handler wipes the door before a shell can open.
- The tailnet door: `enroll --auth-key-file` gives the door its own Tailscale node, `<host>-unlock`,
  whose state is sealed by the TPM through `tailscaled --encrypt-state`. The same door answers on
  the tailnet and on the uplink.
- `verify` reads every initramfs image and reports what is wrong with it, `status` shows what the last
  boot did and what is enrolled, and `disable --tailnet` takes the node back out.
- `render-initramfs`, `pins`, `fingerprint` and `seal`, the building blocks the above use.
- One Debian package, `tailnet-unlock_0.1.0_all.deb`: the hook and boot scripts, the door, the ZFS
  key-loading extension and the command. A dpkg trigger rebuilds the initramfs images when
  `tailscaled` changes and never fails the upgrade. The package refuses to be removed or purged
  while the box unlocks through its door, and conflicts with `dropbear-initramfs`.
- Release assets: the package, a source archive and `SHA256SUMS`, with build provenance. The package
  is reproducible: the same commit gives the same bytes.

### Not in this release

Delivery of the key by a keyholder after an approval (`deliver`, `watch`, approvers), the safe test
reboot (rehearsal, `commit`), `rotate`, `reseal`, `enroll --rekey`, `--import-dropbear-initramfs`, the
keyholder package and single-file program, dracut for Debian 14, the `measured` profile, and LUKS. A
person or a script unlocks through the door with plain `ssh`. The README lists the limits, and
section 16 of the design tracks every feature.
