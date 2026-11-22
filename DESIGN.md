# tailnet-unlock: design

Status: design, reviewed and re-reviewed (section 19). Milestone M1's building blocks are built and
tested in a Debian 13 container, including one real boot under QEMU TCG; the VM scenarios that need
KVM are written and not yet run (section 16). Versions were read at their sources on 2026-11-21
(section 17).

## 1. Summary

A Debian machine whose root file system is encrypted cannot boot on its own unless the key is stored
next to the disk, which defeats the encryption. tailnet-unlock keeps the key off the machine and
makes the early-boot prompt reachable from anywhere on a tailnet:

- The initramfs starts a small SSH server (the **door**) and a Tailscale node of its own (the
  **unlock node**, `<host>-unlock`), so the door answers on the uplink and on the tailnet, behind NAT
  included.
- The door's identity, its SSH host key and the unlock node's state, is **sealed to the machine's
  TPM**. A copy of the disk or of `/boot` holds only ciphertext that no other TPM can open, so it can
  neither join the tailnet nor present the door's sealed host key.
- The root key arrives over SSH, from an operator at a terminal or from a **keyholder** that sends it
  only after a pluggable **approver** says yes for this one boot. There is no hands-off mode built in.
- The door shuts down before the real system starts; the system's own Tailscale node then comes up as
  usual.

ZFS native encryption is the first backend. LUKS fits the same design with a different backend
(section 11). A TPM 2.0 is a hard requirement.

## 2. The problem

A headless box (a rented server, a machine in a closet, a box behind a home router) with an encrypted
root stops at a prompt after every reboot: power cuts, kernel updates, a provider's maintenance. The
usual options each give something up:

| Option | Boots unattended | A stolen disk stays closed | A stolen machine stays closed | Works behind NAT |
|---|---|---|---|---|
| Key file in the initramfs | yes | no | no | n/a |
| TPM auto-unlock (Clevis, systemd-cryptenroll) | yes | yes | no, it boots itself | n/a |
| dropbear-initramfs and a typed key | no | yes | yes | no |
| Network-bound unlock (Tang, Mandos) | yes, while the server answers | yes | depends on where it is booted | only with extra plumbing |
| **tailnet-unlock** | only through an approval, which a consumer may automate | yes | yes, unless an approver says yes | yes |

The remaining gap with plain dropbear-initramfs is identity: its SSH host key sits unencrypted on
`/boot`, so anyone with a copy of `/boot` who can get on the network path can impersonate the
prompt and collect the key. Putting a tailnet node into the initramfs makes that worse unless the node
state is protected too, because the copy could then join the tailnet from anywhere.

## 3. Goals and non-goals

Goals:

1. A box with an encrypted ZFS root reboots and is unlocked remotely, without its key on any of its
   disks, over the tailnet or its uplink.
2. A copy of the disks, or of `/boot` alone, cannot join the tailnet as the unlock node and cannot
   present the door's sealed host key.
3. The key is delivered only to a door presenting the pinned sealed key, and only after an approval
   bound to one boot. The approval mechanism is the consumer's: a hook with a small contract, never a
   dependency.
4. Every failure falls through to something that still works where the box allows it: the uplink
   door, the recovery door where it is enabled and reachable, the console. A box behind NAT whose TPM
   failed needs its console; nothing in this design changes that. Kernel, initramfs and Tailscale
   updates need no manual step in the default profile.
5. One switch turns the tailnet door off and leaves the uplink door and the console.
6. A stranger with a Debian box and a tailnet (Tailscale or headscale) can install it, on a fresh
   install or an existing box, in an afternoon.

Non-goals:

- Protecting a running machine: memory, DMA, cold boot, or root on the running system.
- Defending against whoever controls the hardware's firmware (a hostile vendor, a provider who
  reflashes firmware).
- Automatic unlock without an approval. The project ships no approver that says yes by itself.
- Changing the TPM's owner, endorsement or lockout authorizations. Section 8.6 gives the hardening an
  owner should do by hand; `verify` reads that state and warns, and never changes it.
- Machines without a TPM 2.0, and virtual TPMs whose state travels with the machine's snapshots (a
  copy of the snapshot is a copy of the TPM, so sealing protects nothing there).
- Installing Debian, or running an installer on the tailnet.
- Network or iSCSI roots, Wi-Fi uplinks, and IPv6-only uplinks in the first releases.
- Tailscale SSH in the initramfs (decision D5).
- TPM 1.2.

## 4. Terms

| Term | Meaning |
|---|---|
| Box | The machine with the encrypted root. |
| initramfs | The small file system the kernel runs first, before the real root is mounted; it is where the root gets unlocked. |
| Tailnet | A private network of devices joined through Tailscale or a headscale server. |
| TPM | The Trusted Platform Module: a chip (or a firmware function) on the motherboard that can encrypt small secrets so that only this machine can decrypt them. |
| Door | The SSH server in the initramfs. Every login runs one forced command that can report status or accept a key, nothing else. |
| Sealed door key | The door's ed25519 SSH host key, sealed to the TPM. Keyholders pin it. |
| Recovery door | The same SSH server presenting a second, unsealed host key, used only when the sealed key does not unseal and recovery is enabled. Automated delivery refuses it by default. |
| Unlock node | The door's own tailnet node, `<host>-unlock`, tagged `tag:unlock`, persistent, separate from the box's own node. |
| Keyholder | Any machine that holds root keys and delivers them: an operator's laptop, a CI job, a small home server. |
| Key source | A command on the keyholder that prints one box's root key. |
| Approver | A command on the keyholder that decides whether one delivery may happen. |
| Watcher | A keyholder job that notices a box waiting at its door and starts a delivery. |
| Profile | Which boot state the sealed door key is bound to: `tpm` (default) or `measured`. |

## 5. Architecture

```
            box (early boot)                               keyholder
 +-------------------------------------------+     +-----------------------------+
 | initramfs-tools                           |     | tailnet-unlock watch        |
 |  init-premount/tailnet-unlock             |     |   reads `tailscale status`  |
 |   - TPM driver, uplink network            |     | tailnet-unlock deliver      |
 |   - unseal door key (tpm2-tools)          |     |   1. door status (pinned)   |
 |   - dropbear on uplink and 127.0.0.1      |<----+   2. approver hook  ------->+--> your approval
 |   - tailscaled --encrypt-state,           | SSH |   3. key source hook ------>+--> your secret store
 |     userspace networking (unlock node)    |     |   4. unlock <boot_id>       |
 |  zfs decrypt_fs                           |     |   5. audit line             |
 |   - load-key extension waits for the key  |     +-----------------------------+
 |  init-bottom/tailnet-unlock               |
 |   - stop tailscaled, dropbear; wipe       |     operator terminal
 +-------------------------------------------+     |  tailnet-unlock unlock <host>
            |                                       |  or plain `ssh -p 2222 root@...`
            v                                       +-----------------------------
 real root mounts; the box's own tailscaled and sshd start as usual
```

The tailnet carries the connection; the pinned SSH host key authenticates the door; the authorized SSH
keys authenticate the keyholder. Neither side trusts the control plane for authentication.

## 6. Threat model

### 6.1 Assets

1. The root key (the ZFS wrapping key). Never stored on the box, never in the TPM.
2. The sealed door key. Whoever presents it is believed to be the box's genuine initramfs.
3. The unlock node's state (machine and node private keys). Whoever holds it can appear on the
   tailnet as `<host>-unlock`.
4. The approval. Whoever forges or replays one can make a keyholder send the key.

### 6.2 Adversaries and what the design does

| Adversary | `tpm` profile (default) | `measured` profile | What it does not defend |
|---|---|---|---|
| **Stolen disk, or a copy** (a returned disk, a provider snapshot, a backup of `/boot`, a pulled `/boot`) | Defended. The sealed door key and the node state open only on this TPM, so the copy cannot unseal them, cannot join the tailnet, cannot present the sealed key. The root stays encrypted; the key was never on the disk. | Same. | The recovery door's key is on `/boot` unsealed, so a copy of `/boot` can present the recovery door to anyone who reaches it (section 9). An imported door key (section 8.1) also exists wherever its owner provisioned it; that store is part of the door's trust. |
| **Stolen whole machine** | Partly. The thief can boot any system on the machine and unseal the door identity, or boot the genuine door at a new site. The root key is not on the machine, so the root opens only if an approver says yes. The approval request includes the endpoints the keyholder sees for the unlock node and whether the reboot was planned (section 10.4). | The sealed key unseals only under the genuine boot chain, so it cannot be extracted under another system. The genuine chain still boots at the thief's site, so the approval remains the defense. | An approver who says yes to an unplanned reboot. The endpoints are a hint for a person, not a proof of location: on a relayed path they are what the node reports, and `site_match` is then always `unverified`. |
| **Evil maid on `/boot` or the ESP** (brief physical access, or a provider's rescue system, used to modify the initramfs and leave) | **Not defended.** The `tpm` profile binds to the TPM, not to what booted, so a modified initramfs unseals the door key, receives the key on the next approved unlock and can leak it. | Partly. A modified boot chain changes PCR 4, the sealed key does not unseal, and the keyholder refuses a door that does not present it. Such a chain lands in recovery on purpose: with recovery off (the default under `measured`) the box waits for its console; with recovery on, an operator who sends the key to the recovery door hands it to the modified chain. So `measured` does not close the gap by itself: it closes it only together with recovery off, or an operator who never trusts what the door says about itself. The modified chain can still join the tailnet (its node state is not under the PCR policy). | Firmware implants (PCRs 0 and 2 are off by default). A bus interposer on a discrete TPM: the door key is unsealed in an encrypted session, but Tailscale's node-state unseal runs without one (`feature/tpm/tpm.go`, read at v1.104.7), so an interposer can read the node identity. An attacker who can reset a discrete TPM without resetting the CPU and replay the expected measurements: PCR reset-and-replay is not stopped. |
| **Compromised tailnet peer** (any device on the tailnet that is not a keyholder) | Defended. The policy lets only keyholders and operators reach the door's port; `tag:unlock` reaches nothing. A peer that reaches the door anyway needs an authorized SSH key, and cannot present the sealed key. | Same. | Denial of service by a peer the policy wrongly allows. |
| **Hostile control plane** (the coordination server, or a headscale administrator) | Defended for confidentiality: it can add peers, reroute, show forged endpoints, and see metadata, but SSH runs end to end with a pinned host key, so it can neither collect the key nor pose as the door. | Same. | Denial of service, and metadata (when boxes reboot and unlock). |
| **Network attacker on the uplink path** | Defended by the pinned sealed key, as above. | Same. | Denial of service; the recovery door caveat above. |
| **Replay** | A recorded SSH session is useless (fresh session keys). An approval is bound to one request id, one boot id, one door key and an expiry, and is used once (section 10.3); the keyholder enforces all of that except the boot id, which the door checks too. An old `/boot` image presents a door key the keyholder stopped pinning at the last rotation, and its unlock node was deleted then. | Same; an old image also needs its old boot chain. | A root key learned once keeps working against any disk copy taken before `rotate`. `zfs change-key` rewraps, but ZFS's master key changes only by re-encrypting the data (send and receive into a new encryption root). |

Out of scope, said plainly: root on the running box (it holds the unlocked data and can rewrite the
initramfs); a compromised keyholder (it holds the keys, and the approval binding is enforced on its
side); an approver who approves the wrong thing; anyone who can cut the network, who can keep the box
locked (the console still works).

### 6.3 The boundary in one sentence

In the default `tpm` profile the root stays closed to whoever takes the disks or a copy of them, and a
whole machine opens only with an approval; the `measured` profile, with recovery left off, adds
protection against a modified boot chain.

## 7. The boot flow

### 7.1 initramfs-tools first, dracut second

Debian 13.8 ("trixie", the current stable) builds its initramfs with initramfs-tools 0.148.4: the
kernel package `linux-image-6.12.117+deb13-amd64` depends on `initramfs-tools`, then on any
`linux-initramfs-tool`. OpenZFS's Debian packaging (`zfs-initramfs` 2.3.9 in trixie's `contrib`
component, 2.4.4 in trixie-backports `contrib`) and `cryptsetup-initramfs` 2.7.5 ship their boot
integration for initramfs-tools, and OpenZFS offers the extension point this design uses
(`/etc/zfs/initramfs-tools-load-key.d/`).

Debian 14 ("forky", testing) is moving: its kernel package `linux-image-7.3.4+deb14-amd64` now
depends on `dracut` first (dracut 112 in forky, 106 in trixie). So the core logic lives in
builder-neutral POSIX shell under `/usr/lib/tailnet-unlock/initramfs/`, initramfs-tools gets thin hook
and boot scripts in the first release, and a dracut module follows before Debian 14 is released
(milestone M5). Until then, Debian 14 boxes and test runs install initramfs-tools explicitly.

### 7.2 Build time (on the running system, at every `update-initramfs`)

The hook `/usr/share/initramfs-tools/hooks/tailnet-unlock`:

1. Runs `tailnet-unlock render-initramfs`, which validates `/etc/tailnet-unlock/box.toml` and prints
   the shell assignments the boot scripts read (`conf/tailnet-unlock.conf` inside the image). The
   configuration has one source; the image carries a value derived from it at each build.
2. Copies in `dropbear` (from `dropbear-bin`) with what it needs to look up its one user: a
   `/etc/passwd` holding only `root:x:0:0:root:/root:/bin/sh`, `/etc/nsswitch.conf` with
   `passwd: files`, and glibc's `libnss_files`, as Debian's own dropbear-initramfs hook does. The
   initramfs has no other user, so every door login is `root`, confined by its forced command.
3. Copies in `tailscaled` (not the `tailscale` CLI, decision D21), the `tpm2_*` tools the unseal needs
   and the TSS device transport library they load at run time, the CA bundle, the TPM drivers
   (`tpm_tis`, `tpm_crb`, where they are modules), and the uplink NIC's driver, read from
   `/sys/class/net/<uplink>/device/driver/module` at each build.
4. Copies in the door material: the sealed door key container (`tpm` profile; under `measured` it
   stays on the ESP, section 8.3), the recovery door key if enabled, the unlock node's sealed state,
   and `/root/.ssh/authorized_keys` (directory 0700, file 0600, as dropbear requires), rendered from two
   plain lists so that no line can lack its options:

   ```
   # from /etc/tailnet-unlock/delivery_keys: automation, no terminal
   restrict,command="/usr/lib/tailnet-unlock/door delivery" ssh-ed25519 AAAA... keyholder
   # from /etc/tailnet-unlock/operator_keys: people, who need a terminal for the no-echo prompt
   no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="/usr/lib/tailnet-unlock/door operator" ssh-ed25519 AAAA... alice
   ```

   `restrict` would also forbid the terminal a person types into, so operator lines name the
   forbidden features one by one instead. The role (`delivery` or `operator`) comes from this file,
   never from the client.
5. Checks `tailscaled --version` against the floor (Tailscale 1.86, where `--encrypt-state` arrived on
   Linux).
6. **Never fails the build** (decision D18). Each part degrades on its own, loudly:
   - tailnet parts missing or unusable (no tailscaled, below the floor, no sealed state): the image
     is built without the tailnet door, and the uplink door stays;
   - `/boot` too small for the tailnet parts: before it copies tailscaled, the hook compares the free
     space on the file system that holds `/boot` with what the image will need (the current image for
     this kernel, which `update-initramfs` keeps until the new one is complete, plus half of
     tailscaled's size, the zstd estimate of 7.4, plus 16 MiB). When it does not fit, the image is
     built without the tailnet door (`boot-space`, with both numbers in the warning), and the uplink
     door stays. A full `/boot` never fails the build because of tailnet-unlock;
   - the sealed door key container missing or unreadable: the image carries only the recovery door,
     where enabled;
   - dropbear missing or the configuration invalid: the image carries no door, and the console stays.

   Each degradation prints `W: tailnet-unlock: <what and why>` during the build, is recorded in the
   image (the door's `status` reports it), and makes `tailnet-unlock verify` exit non-zero. A
   post-update hook (`/etc/initramfs/post-update.d/tailnet-unlock`) prints one summary line per image.
   A kernel package's configure step never fails because of tailnet-unlock, and a degraded image
   never goes unreported.

The image is written with `UMASK=0077`, because it holds the recovery door key unsealed when recovery
is enabled.

OpenZFS's own hook copies `/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock` (shipped by this
package) into the image.

### 7.3 Boot time

1. **init-top**: initramfs-tools' `init` has already mounted `devpts` on `/dev/pts` (it does so in
   0.148.4), which dropbear needs for the operator's terminal; the premount script mounts it if it is
   missing. udev starts as usual.
2. **init-premount/tailnet-unlock** (never blocks the boot): mounts `devpts` if it is missing, mounts a
   private tmpfs (mode 0700) at `/tailnet-unlock/run`, inside the initramfs root and not under `/run`,
   because initramfs-tools moves `/run` into the real system (every file written there is 0600), and
   starts the **supervisor** (`/usr/lib/tailnet-unlock/supervise`) in the background, recording its
   PID. Everything long runs in the supervisor (decision D32):
   1. Loads the TPM driver and waits up to 10 seconds for `/dev/tpmrm0` (the kernel's resource
      manager).
   2. Brings up the uplink with initramfs-tools' `configure_networking` from the rendered `IP=` and
      `BOOTIF=` (DHCP or static, matched by MAC so interface names do not matter), and writes
      `/etc/resolv.conf` from the DHCP answer or the configured resolvers.
   3. Unseals the door key into the tmpfs (section 8.4). On failure it records why and, if the
      recovery door is enabled, uses the recovery key instead. A failure is not final: while the
      seal result is not `ok`, the container is there and the TPM device is present, the supervisor's
      loop asks again (a backoff from 2 to 60 seconds), because a TPM that is slow or busy at boot
      would otherwise pin the whole boot to the recovery key. When it unseals, the supervisor
      records `seal ok` and the sealed role, stops dropbear and starts it again with the sealed key.
   4. Starts dropbear in the foreground of its own child process, so the supervisor holds its PID:
      `dropbear -F -E -r <key> -p 127.0.0.1:<port> -p <uplink address>:<port> -s -j -k -I 600 -P <tmpfs>/dropbear.pid`
      (`-p [address:]port` may repeat; `-s` refuses passwords, `-j -k` refuse forwarding, `-I` ends
      idle sessions). `127.0.0.1` serves the tailnet path; the uplink address is the one
      `configure_networking` set. Under the recovery key, the `127.0.0.1` listener is left out unless
      `door.recovery = "uplink+tailnet"`. dropbear never generates keys on its own here (no `-R`).
      As soon as dropbear has written its PID file, the supervisor deletes the plaintext door key:
      dropbear 2025.89 keeps its host key in memory and does not read the file again for new
      connections (checked in M1), so from then on the unsealed key exists only inside dropbear.
      Neither daemon's output is kept: dropbear logs every connection, and a scan of the uplink
      could otherwise fill the 16 MiB tmpfs that holds the door's state (the supervisor's console
      lines say what happened). Every write to that state goes through one function that reports
      failure; the supervisor says so on the console, and a supervisor that cannot record its own
      PID refuses to run, since init-bottom could never stop it.
   5. If the tailnet door is on (`tailnet.enabled`), starts
      `tailscaled --state=<tmpfs copy of the sealed state> --encrypt-state --tun=userspace-networking
      --socket=<tmpfs>/tailscaled.sock --no-logs-no-support`. The state already holds the login, the
      tags and `WantRunning`, so no `tailscale up` runs at boot. In userspace networking, tailscaled's
      netstack hands inbound TCP for the node's own tailnet address to `127.0.0.1:<port>`
      (`wgengine/netstack/netstack.go`, read at v1.104.7), which is where dropbear listens. If the
      state does not unseal, tailscaled exits with `failed to unseal state file` and the console says
      the tailnet door is down; the uplink door keeps working.
   6. Prints one summary to the console: profile, seal result, uplink address, unlock node name, the
      fingerprint of the key the door presents (sealed or recovery), the boot id.
   7. **Supervises** both daemons until it is told to stop: every 2 seconds it checks each child PID,
      and a daemon that has exited is started again after a backoff that doubles from 1 to 30
      seconds and resets after a minute of uptime. A dropbear restart unseals the door key again,
      since its plaintext was deleted in step 4; a tailscaled restart starts from the same sealed
      state copy. Each restart is printed on the console and counted, and the door's `status`
      reports the counts (`restarts`). A daemon that cannot start at all (the unseal now fails, the
      binary is gone) is retried at the longest backoff and reported, never given up on silently.
      The supervisor's TERM handling is the one place that stops the daemons and wipes (step 5 and
      the exit paths below). It stops them from the PIDs it holds in memory as well as from the
      state files. The handler only records the request and the supervisor stops at its next
      safe point (never between starting a daemon and holding its PID), and the scripts read files
      with `head`, not `read`: busybox 1.38 (Debian 14) spins in `read` once the shell has caught a
      signal. Neither a missing record nor a restart in progress leaves an orphan. A PID is
      only signalled while the process's command line still names the daemon (`dropbear`,
      `tailscaled`, `supervise`): PIDs are reused, and a number read from a file may belong to
      something else by then.
3. **ZFS import and key** (OpenZFS's `mountroot`): the pool is imported and `decrypt_fs` sources each
   load-key extension before it prompts. Ours:
   1. If the encryption root's `keylocation` is a file present in the image and no rehearsal is
      pending, returns 1 at once: the local key loads as before.
   2. Records the encryption root's name for the door.
   3. Starts a console prompt in the background (no echo, piped to `zfs load-key`), keeping its PID.
   4. Waits until the key status is `available`, whoever loaded it (the door or the console), then
      ends the console prompt by its PID and returns 0. In a rehearsal (section 13.2) it waits at most
      the configured minutes, then returns 1 so the local key loads.

   A wrong key is not an exit. `zfs load-key` fails, the door answers `wrong-key` (or the console
   asks again), and the wait goes on: only a key that loads, a rehearsal running out, or one of the
   exit paths below ends it.
4. **The door's forced command**, one per SSH session. It reads `SSH_ORIGINAL_COMMAND`, which dropbear
   sets for forced commands, matches it with one `case`, and never evaluates, splits or passes it to a
   shell:

   ```sh
   # /usr/lib/tailnet-unlock/door <delivery|operator>   (the role is set by authorized_keys)
   role=$1
   h='[0123456789abcdef]'
   # shellcheck disable=SC2254 # $h is unquoted on purpose: each one is a bracket expression
   case "${SSH_ORIGINAL_COMMAND-}" in
   status)
       door_status ;;
   "unlock "$h$h$h$h$h$h$h$h-$h$h$h$h-$h$h$h$h-$h$h$h$h-$h$h$h$h$h$h$h$h$h$h$h$h)
       door_unlock "${SSH_ORIGINAL_COMMAND#unlock }" ;;
   '')
       [ "$role" = operator ] || door_refuse bad-command
       door_prompt ;;
   *)
       door_refuse bad-command ;;
   esac
   ```

   In a POSIX `case` pattern the quoted `"unlock "` is literal and each unquoted `$h` is a bracket
   expression listing the sixteen lowercase hex digits (a list, not a range, so no locale can widen
   it), so the second branch matches exactly `unlock ` followed by the 36-character shape of
   `/proc/sys/kernel/random/boot_id`. shellcheck warns about unquoted expansions in a pattern
   (SC2254), which is what this pattern wants, so the warning is disabled with its reason. The
   directive sits in front of the `case` statement, because shellcheck accepts directives only in
   front of complete commands, not in front of one branch (SC1124, checked with shellcheck 0.10.0);
   no other branch expands anything in its pattern.
   `door_refuse` prints its result line and exits, so a delivery key that sends the empty command
   never falls through to `door_prompt`.
   - `status`: prints one JSON line (sealed or recovery key, boot id, profile, seal result, recorded
     degradations, backend, the encryption root it waits for and its `keyformat`, kernel release,
     tailscaled version).
   - `unlock <boot_id>`: refuses unless the boot id is this boot's; waits up to 10 minutes for the
     encryption root to be named; then pipes at most 512 bytes of stdin into
     `zfs load-key -L prompt <encryption root>`, which reads key material from a stdin that is not a
     terminal. The key touches no file and no command line. Prints one JSON result line (`loaded`,
     `wrong-key`, `not-waiting`, `boot-mismatch`, `bad-command`) and exits 0, 1, 2, 3 or 4.
   - the empty command, for `operator` keys only (a person typing `ssh -p 2222 root@web-1-unlock`):
     asks for the key with echo off on the terminal, reads one line, so the newline is never part of
     the key, then loads it as `unlock` does, without the boot id check, since the person is there.
     A `raw` key cannot be typed; the prompt says so.
   - **The key on the wire** is the key's bytes with no framing and no trailing newline. The keyholder
     strips exactly one trailing newline from a key source's output for `passphrase` and `hex` keys,
     refuses any other line break in them, and for `raw` keys sends exactly 32 bytes or refuses. What
     libzfs does, read in OpenZFS 2.3.9 (`lib/libzfs/libzfs_crypto.c`, `get_key_material_raw`, used
     for `-L prompt` when stdin is not a terminal): a `passphrase` or `hex` key is the first line read
     with `getline`, with one trailing newline trimmed, so a stray newline is tolerated and anything
     after the first line is silently ignored; a `raw` key is read as up to 33 bytes and
     `validate_key` refuses anything but 32 ("Raw key too long"), so a raw key with a trailing newline
     does not load. The door passes the bytes through unchanged (at most 512). The M1 tests check the
     door against a stand-in that follows this source; the KVM scenario T22 checks it against the real
     module.
5. The root mounts. **init-bottom/tailnet-unlock** sends TERM to the supervisor, which stops tailscaled
   with SIGTERM (so the control plane sees the unlock node go offline at once) and waits up to 10
   seconds before SIGKILL, stops dropbear by its PID, deletes the door material and exits. If the
   supervisor has not exited after 15 seconds, init-bottom kills it and does the same itself from the
   recorded PIDs. It then unmounts the tmpfs, and flushes the uplink address it set,
   so the real system's network manager starts clean. It leaves one non-secret record,
   `/run/tailnet-unlock/boot.json` (who unlocked this boot: sealed door, recovery door, console or
   local key; the profile; the seal result; any degradation), which `status` and `commit` read on the
   running system.
6. initramfs-tools switches to the real root and frees the initramfs. The box's own tailscaled starts
   its own node; the unlock node stays offline until the next boot.

**Exit paths, and the wipe on each** (decision D26). Once the supervisor runs, a boot leaves the
waiting initramfs by exactly one of these paths, and each one wipes the door material: it stops both
daemons, overwrites and deletes the plaintext door key if it is still a file, the copy of the node
state in the tmpfs, the unseal work directories and the initramfs's copy of the recovery key, and
removes the daemons' socket and PID files. It does not delete the sealed container, the
`authorized_keys`, the configuration or the public half of any key: they are public or sealed, and
the same bytes are on `/boot` in the image itself, so deleting the copy inside the running
initramfs protects nothing. The recovery key is the one secret in the image, and it is on `/boot`
as well (section 9): its copy is wiped for tidiness, not as a boundary.

1. **The root mounts** (step 5): init-bottom stops the supervisor, whose TERM handler wipes.
2. **`panic()`**, which initramfs-tools calls for every failure it does not handle itself (a pool that
   does not import, a root that does not mount, no `init` on the root) and for `break=`. In
   initramfs-tools 0.148.4, `panic()` in `scripts/functions` tests `panic=` first: when it is set,
   it sleeps, then reboots or halts and exits (lines 48 to 71), **before** it reaches
   `run_scripts /scripts/panic` (line 73). A `panic=` on the command line therefore means no panic
   script runs, and the door, tailscaled and the files in the tmpfs stay live through the sleep. So
   neither profile sets `panic=`, and the two take different branches inside our panic script,
   `/scripts/panic/tailnet-unlock`:
   - **`tpm`**: the script sends TERM to the supervisor, wipes whatever is left from the recorded
     PIDs, and returns; `panic()` then opens its shell for the person at the console. If that
     person leaves the shell, the boot goes on without a door: the console prompt remains.
   - **`measured`**: the UKI's embedded command line carries `tailnet-unlock.noshell`. The script
     ignores INT, QUIT, TSTP, HUP and TERM from its first statement, wipes, prints why, waits 10 seconds so the reason can
     be read on the console, runs `reboot -f`, then `echo b > /proc/sysrq-trigger` should that
     return, then sleeps forever. It never returns, so `panic()` never reaches its shell. The script
     takes this branch when the rendered profile is `measured` or the word is on the command line,
     so an image built without a valid configuration still keeps the shell shut. It decides this
     from `/proc/cmdline` before it sources anything, and a shared file that is missing or will not
     source (`paths.sh`, `lib.sh`, the configuration) counts as noshell too: the script then wipes
     without the library (it kills the PIDs the state files hold and empties the state directory),
     reboots and never returns, so a damaged image cannot be turned into a shell beside the door. The supervisor
     also sets `/proc/sys/kernel/panic` to 10 under `measured`, so a kernel panic reboots instead of
     hanging (a hang opens no shell either; the reboot only saves a trip to the power switch).
3. **A failure inside our premount script** before the supervisor starts: its own cleanup removes
   what it wrote, and the boot goes on without a door.
4. **`zfsdebug=1`** (OpenZFS's `scripts/zfs`, 2.3.9): after the root is mounted and before
   init-bottom runs, it waits for ENTER and runs `/bin/sh` directly on `c`, without `panic()` and
   without any panic script, while the door material is still live. Under `measured` the word is a
   command line override, which changes PCR 12 (section 8.2), so a boot that carries it never
   unsealed the door key and has nothing to hand out. Under `tpm` nothing stops it: it is a shell
   beside the unsealed door, the same boundary as `break=`, since a person at the console can unseal
   the `tpm` profile's key with the tools in the image anyway.

A failed `zfs load-key` is not on this list: it is not an exit (step 3 above).

**Under `measured` there is no initramfs shell at all.** `break=`, `zfsdebug=1`, `init=` or any
other override cannot be added without changing PCR 12, which keeps the sealed key shut, and every
`panic()` ends in our script's reboot. The price: a genuine boot whose pool does not import (a
damaged pool, a missing disk) reboots about every 10 seconds plus the boot time, in a loop, with no
shell to repair it from. The way out is outside the initramfs: the provider's rescue system (or any
other boot medium) to import and repair the pool, or, when an older boot entry still imports, that
entry in the boot menu (choosing an entry is not an edit). Under `tpm`, a person at the console can
still reach a shell with `break=`; that person could unseal the `tpm` profile's key anyway, which is
that profile's boundary.

### 7.4 Tailscale in early boot

- **Userspace networking** (decision D3): no `/dev/net/tun`, no netfilter rules, nothing left in the
  kernel at the handover, nothing to collide with the real system's `tailscale0`.
- **Persistent, not ephemeral** (decision D4): an ephemeral node disappears after it goes offline, so
  every boot would need a fresh auth key, which would have to sit on `/boot` and would let a copy join.
  The unlock node is enrolled once from the running system and its state is reused at every boot.
  Tailscale disables key expiry by default for a device tagged at its first authentication
  (Tailscale's tags documentation), so the node does not expire while it sits offline.
- **Its own node, never the box's**: the box's node carries the box's grants, which the initramfs must
  never hold. The unlock node's name is derived (`<host>-unlock` unless configured) and keyholders pin
  it by node id, so a name Tailscale reserves after a re-enrollment never matters.
- **The state directory is tmpfs only**: tailscaled may update its state while it runs; the copy lives
  in the tmpfs and is discarded at the handover. Nothing in the state needs to persist between boots
  for a tagged node; with Tailnet Lock, the node fetches the lock state again at each boot (scenario
  T19 checks this).
- **No log upload** (`--no-logs-no-support`), no Tailscale SSH, no accepted routes or DNS settings
  (set in the node's preferences at enrollment).
- **Control plane reachability**: the CA bundle is copied in, and Tailscale falls back to its built-in
  bootstrap resolution when DNS fails. A clock far in the past breaks TLS to the control plane; the
  uplink door does not depend on the clock.
- **headscale**: `tailnet.login_server` names it; nothing else changes.
- **Size**: measured from Tailscale's own 1.104.7 amd64 tarball on 2026-11-21: `tailscaled` is 43.9 MB
  (21.5 MB at zstd level 9), the `tailscale` CLI 34.3 MB (16.7 MB at zstd level 9). The image carries
  tailscaled only (D21); `enroll` checks `/boot` has room for every installed kernel's image, and the
  hook checks again at every build and degrades the image instead of failing it (7.2, step 6).

### 7.5 Tailnet policy

Three roles: `tag:unlock` (the doors), `tag:keyholder` (delivering machines), and a group of operators.
The example ships as `examples/policy.hujson` with policy tests:

```hujson
{
  "groups": {
    "group:unlock-operators": ["someone@example.com"],
  },
  "tagOwners": {
    "tag:unlock":    ["autogroup:admin"],
    "tag:keyholder": ["autogroup:admin"],
  },
  "grants": [
    // Operators and keyholders reach the door's port, nothing else on it.
    {"src": ["group:unlock-operators", "tag:keyholder"], "dst": ["tag:unlock"], "ip": ["tcp:2222"]},
    // No grant names tag:unlock as a source: a door reaches nothing.
  ],
  "tests": [
    {"src": "tag:keyholder", "accept": ["tag:unlock:2222"]},
    {"src": "tag:unlock", "deny": ["tag:keyholder:22", "tag:keyholder:2222"]},
  ],
}
```

Notes the README repeats: a policy that still allows everything to everything defeats `tag:unlock`
reaching nothing. The watcher needs to see the box's own node too, so give the keyholder at least one
grant to it. With Tailnet Lock, the enrollment auth key must be signed (`tailscale lock sign`). headscale
takes the equivalent `acls` rules, and the VM suite checks the same rules live against it (T20).

## 8. Sealing

### 8.1 What is sealed, by whom

| Secret | Sealed by | Policy | Where it lives |
|---|---|---|---|
| Unlock node state | Tailscale's own `--encrypt-state` | None: a transient SRK from the standard ECC P-256 template under the owner hierarchy, no authorization policy, unsealed without a session (`feature/tpm/tpm.go`, read at v1.104.7) | `/var/lib/tailnet-unlock/tailnet/unlock.state`, copied into each image |
| Sealed door key | tailnet-unlock, with `tpm2-tools` | The profile's PCR policy (8.2) | `tpm`: the container `/var/lib/tailnet-unlock/door/door.tpm/`, copied into each image. `measured`: on the ESP (8.3) |
| Recovery door key | Not sealed, by design (section 9) | None | `/var/lib/tailnet-unlock/door/recovery_host_key`, 0600, copied into each image when recovery is enabled |

**Where the door key comes from** (decision D23): `door.key_source = "generate"` (the default) makes it
on the box with `dropbearkey -t ed25519` in a tmpfs, seals it, and deletes the plaintext; the pin is
printed afterwards. Every command that makes or converts a plaintext key refuses while a swap area that can
reach a disk is active (`/proc/swaps`): a tmpfs page, like the memory of the process holding the key,
can be written to swap. A zram device is RAM and does not count. The tool says so and asks for
`swapoff -a` for the time it takes, or, for a box where that is unsafe, `--allow-swap`: it prints a
warning and ends its output with a comment line saying the key was made with swap active, which
`enroll` keeps with the pins and in the box's state. (The other
option, piping the key from `dropbearkey` straight into `tpm2_create`, would avoid the file but not
the key in memory, and would not cover an imported key; the refusal covers every path.) `"import"` takes a key the consumer provisions from its own secret store
(`tailnet-unlock enroll --door-key-file -` reads an ed25519 private key in OpenSSH or dropbear format on
stdin, converted with `dropbearconvert`), seals it the same way and deletes the plaintext; its pin is
known in advance. For the door key, both sources end in the same sealed container and the same kind of
pin. With `import`, the consumer's store is part of the door's trust. `door.recovery_key_source` takes
the same two values for the recovery key (`enroll --recovery-key-file -` reads it the same way), but
the recovery key is never sealed, whichever its source: it is stored unsealed by design (section 9),
0600, with its public half beside it, and its pin is printed (or, imported, known in advance). "The
same sealed container" holds for the door key alone.

Why two sealing mechanisms (decision D6): Tailscale's sealing is maintained upstream, handles
tailscaled's own writes and state format changes, and has no PCR policy. The door key is the one that
authenticates the box, so it is the one that carries the measured policy. A tampered boot chain that
still joins the tailnet reaches nothing and cannot present the sealed key.

The door key is an ed25519 dropbear key (about 83 bytes), which fits the TPM's 128-byte limit for
sealed data, so no wrapping key is needed. tailnet-unlock creates its primary key transient at each use
from the TCG SRK template's algorithms and attributes (ECC P-256, AES-128-CFB, the same kind of key
Tailscale's sealing creates): no persistent handle is created or reused and no NV index is defined, so
it never collides with other users of the TPM and leaves nothing behind (decision D8).

Requirements on the TPM: TPM 2.0, an owner hierarchy usable with an empty authorization (the default,
and what Tailscale's sealing needs too), and for `measured` an active SHA-256 PCR bank.

### 8.2 Profiles and PCRs

**`tpm` (default).** No PCRs. The door key opens on this TPM whatever booted. Kernel, initramfs,
boot loader and firmware updates never require a re-seal. Boundary: the first row of the threat
table, not the evil maid row.

**`measured`.** Requires UEFI, systemd-boot and a unified kernel image (UKI: kernel, initrd and command
line in one PE file, built by `ukify`; systemd-boot 257.13 and systemd-ukify 257.13 are in trixie).
The door key is sealed to:

| PCR | What it holds | Why |
|---|---|---|
| 4 | Every EFI image the firmware loads: systemd-boot, the UKI, and the kernel image the stub loads | Any change to the loader, kernel, initrd or embedded command line changes it. The firmware measures each image before it runs it, so this holds with Secure Boot on or off. |
| 7 | Secure Boot state, keys and the authorities that verified each image | Notices Secure Boot being turned off or keys being changed. With Secure Boot off it still records that state. |
| 12 | systemd-stub's command line overrides, credentials and add-ons | Must hold its expected value: an edited command line (`break=premount`, `init=/bin/sh`) cannot reach a shell inside a genuine initramfs and unseal from there. `loader.conf` gets `editor no`. |
| 0, 2 (opt-in) | Firmware code and option ROMs | Off by default: every firmware update would change them. |

Under `measured` the recovery door is off by default (section 9), and the UKI's command line carries
`tailnet-unlock.noshell` and never `panic=` (section 7.3, exit paths).

GRUB is not supported in `measured` (decided in review, section 19): GRUB measures every command it
runs into PCR 8 and every file it reads into PCR 9, and predicting those across `update-grub` means
simulating its script interpreter. GRUB users get the `tpm` profile.

### 8.3 The container, and where the measured one lives

`door.tpm` is a directory, because the initramfs's shell cannot parse a structured file safely. It is
written next to its final place and renamed into it, so a reader never sees half of one:

| File | Content |
|---|---|
| `format` | The text `tailnet-unlock door 1` |
| `profile` | `tpm` or `measured` |
| `public` | The sealed object's `TPM2B_PUBLIC`, as `tpm2_create -u` writes it |
| `private` | Its `TPM2B_PRIVATE`, as `tpm2_create -r` writes it |
| `branches` | `measured` only: one line per policy branch, `pcr sha256:4,7,12 <n>` or `resets <count> <n>` |
| `branch.<n>.digest` | `measured` only: that branch's 32-byte policy digest, which `PolicyOR` needs at unseal |
| `pin` | The door key's public half in OpenSSH format, what keyholders pin |

A secret sealed to a measurement of the initramfs cannot sit inside that initramfs: the measurement
would include the secret. Under `measured` the container lives on the ESP
(`<ESP>/tailnet-unlock/door.tpm/`); the initramfs mounts the ESP read-only by the partition UUID
recorded at build time, copies the container into its tmpfs, and unmounts it.

### 8.4 The tpm2-tools sequence

Option names as in tpm2-tools 5.7 (trixie); M1 checks each against the installed version. Every
command runs with `TPM2TOOLS_TCTI=device:/dev/tpmrm0`, `-Q`, `umask 077`, and its context files in the
tmpfs.

The primary key, at sealing and at every unseal (same template, so the same key):

```
tpm2_createprimary -Q -C o -g sha256 -G ecc256:aes128cfb \
  -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda|restricted|decrypt' \
  -c primary.ctx
```

Sealing under `tpm`, on the running system:

```
tpm2_create -Q -C primary.ctx -g sha256 -a 'fixedtpm|fixedparent|userwithauth|noda' \
  -i door_key -u door.tpm/public -r door.tpm/private
```

Sealing under `measured`: one trial session per branch, then `PolicyOR` when there are two or more
(the TPM's `PolicyOR` needs at least two; with one branch, its digest is the policy):

```
tpm2_startauthsession -Q -S trial.ctx                                # a trial session
tpm2_policypcr -Q -S trial.ctx -l sha256:4,7,12 -f branch.1.pcrs -L branch.1.digest
tpm2_flushcontext trial.ctx
# the optional one-boot relaxation (section 8.5):
tpm2_startauthsession -Q -S trial.ctx
tpm2_policycountertimer -Q -S trial.ctx -L branch.2.digest --eq resets=<next boot's count>
tpm2_flushcontext trial.ctx
tpm2_startauthsession -Q -S trial.ctx
tpm2_policyor -Q -S trial.ctx -L policy.digest -l sha256:branch.1.digest,branch.2.digest
tpm2_flushcontext trial.ctx
tpm2_create -Q -C primary.ctx -g sha256 -a 'fixedtpm|fixedparent|adminwithpolicy|noda' \
  -L policy.digest -i door_key -u door.tpm/public -r door.tpm/private
```

`-f branch.<n>.pcrs` holds the expected PCR values (the current or the predicted ones), so a branch
can be built for a boot chain that has not booted yet.

Unsealing in the initramfs, always in a session salted with the primary key and with response
encryption on, so the door key does not cross the bus to a discrete TPM in clear:

```
tpm2_load -Q -C primary.ctx -u door.tpm/public -r door.tpm/private -c door.ctx
# tpm:
tpm2_startauthsession -Q --hmac-session -c primary.ctx -S s.ctx
# measured:
tpm2_startauthsession -Q --policy-session -c primary.ctx -S s.ctx
tpm2_policypcr -Q -S s.ctx -l sha256:4,7,12            # the TPM compares its current values
tpm2_policyor -Q -S s.ctx -l sha256:branch.1.digest,branch.2.digest   # two or more branches
# both:
tpm2_sessionconfig -Q s.ctx --enable-encrypt
tpm2_unseal -Q -c door.ctx -p session:s.ctx -o /tailnet-unlock/run/door_key
tpm2_flushcontext -Q s.ctx; tpm2_flushcontext -Q -t
```

Checked against tpm2-tools 5.7 in M1: every option above exists under these names, `tpm2_create -i -`
reads the sealed data on stdin (so the plaintext never needs a file of its own), and the TPM refuses
129 bytes of sealed data and takes 128 (an ed25519 dropbear key is 83). `tpm2_flushcontext` takes a
session's context file, but it refuses a saved object context ("Argument neither a session nor a
transient"), so objects are flushed with `-t`, and after every step that loads one: each tool loads
the saved contexts again, and a TPM without a resource manager (swtpm in the tests) runs out of
object slots otherwise. Through `/dev/tpmrm0` the kernel's resource manager shows each connection
only its own objects, so `-t` never reaches another user's and changes nothing there.

A `resets` branch is tried in a fresh session (`tpm2_policycountertimer --eq resets=<n>` instead of
`tpm2_policypcr`) when the PCR branch fails. This protects the door key only: Tailscale's unseal of the
node state runs without a session.

### 8.5 Updates without lockout

Under `tpm` nothing is re-sealed, ever. Under `measured`:

1. **Policy shape**: one `PolicyPCR` branch after a boot, the current chain; up to eight branches
   joined by `PolicyOR` around an update.
2. **Before an update reboots**: a kernel-install plugin, ordered after the plugin that places the new
   UKI on the ESP, predicts the next boot's PCR 4 by replaying this boot's event log
   (`/sys/kernel/security/tpm0/binary_bios_measurements`) with the new UKI's Authenticode digest (and
   the embedded kernel's) in place of the current ones; PCRs 7 and 12 must stay as they are. It then
   re-seals the door key (the running system can unseal it, since it runs the current chain) under
   `PolicyOR(current, predicted)`. The old kernel keeps booting if the new one fails. `update-initramfs`
   on a systemd-boot box goes through kernel-install too, so the same plugin covers it.
3. **After a successful boot**: a unit on the running system re-seals to the chain that just booted and
   drops the other branches.
4. **When the predictor cannot predict** (an event it does not recognise, a firmware update, a Secure
   Boot database update that changes PCR 7), it says so and does nothing silently: the next boot cannot
   unseal, so it lands on the recovery door if enabled, or on the console; or the owner opts in to a
   **one-boot relaxation**: `tailnet-unlock reseal --next-boot-only` adds a branch bound by
   `PolicyCounterTimer` to the TPM's reset count of the next boot, with no PCRs. That boot is protected
   at the `tpm` level only, then step 3 closes the branch. It is never automatic.
5. **A wrong prediction never hangs the box**: the sealed key does not unseal and the door falls
   through as in section 9.
6. `tailnet-unlock verify --next-boot` checks, before a planned reboot, that the default boot entry's
   predicted values satisfy the sealed policy.

Whether the predictor is ours or `systemd-pcrlock` is decided when M6 starts (section 19).
systemd-pcrlock does this prediction with a policy kept in an NV index; systemd 262.2 still marks it
"This component is experimental and subject to change without advance notice."

### 8.6 TPM hardening the owner should do by hand

tailnet-unlock does not change TPM authorizations (a non-goal); `verify` reads them and warns.

1. **Read the TPM's state first**: `tpm2_getcap properties-variable` (`ownerAuthSet`,
   `endorsementAuthSet`, `lockoutAuthSet`, `disableClear`, `inLockout`) and
   `tpm2_getcap handles-persistent`. A second-hand machine can carry an earlier owner's provisioning:
   persistent objects, NV indices, a lockout authorization set to a value nobody knows. tailnet-unlock
   creates no persistent objects, so existing ones do not collide with it; an unknown lockout
   authorization only blocks step 3 until the TPM is cleared from the firmware.
2. **Keep the owner hierarchy's authorization empty**: tailnet-unlock and Tailscale's sealing both
   create their primary key under it.
3. **A TPM the OS can clear without anyone at the box**: with an empty lockout authorization, root on
   the running system can clear the TPM (`tpm2_clear`); and a firmware whose Physical Presence
   Interface is set not to prompt lets the OS queue a clear for the next boot. Either one destroys the
   door: not the data, and not the secrecy of anything. To make a clear need someone at the box: set a
   random lockout authorization (`tpm2_changeauth -c lockout`) and keep it with the keyholder, not on
   the box; set `disableClear` (`tpm2_clearcontrol -C l s`), so the OS cannot clear even with that
   authorization; in the firmware, require confirmation for TPM operations the OS requests, and set a
   firmware setup password.
4. **Firmware updates** can change PCRs 0, 2 and 7 and, on some machines, reset a firmware TPM.
   Under `measured`, plan them with section 8.5 step 4.

### 8.7 What sealing never covers

The TPM never holds the root key (decision D9). Losing the TPM (cleared, failed, replaced with the
motherboard) loses the door, never the data: the box boots through the recovery door where enabled and
reachable, or the console, and `tailnet-unlock enroll --replace` makes a new door.

## 9. Fallbacks

The rule: every failure falls through to something that still works where the box allows it, never to
a wait that nobody at a console could end.

| Failure | Tailnet door | Uplink door | Console |
|---|---|---|---|
| None | sealed key | sealed key | always |
| Sealed key does not unseal (TPM cleared or failed, a firmware change, a `measured` mismatch, a modified boot chain) | recovery key only with `recovery = "uplink+tailnet"` and the node state still unsealing; otherwise down | recovery key with `recovery = "uplink"` or `"uplink+tailnet"`; nothing with `"off"` | always |
| Node state does not unseal | down | sealed key | always |
| Control plane or DERP unreachable, DNS broken, clock wrong | down | sealed key | always |
| Uplink down, or the box behind NAT | as above | unreachable | always |
| An image degraded at build time (section 7.2) | as recorded | as recorded | always |

There is no row for "no TPM": `enroll` refuses a box without a TPM 2.0 (decision D30).

**The recovery door** (decision D16). A second ed25519 key, generated at enrollment (or imported) and
**kept unsealed on `/boot`**, so a copy of `/boot` can present it. The door presents it only when the
sealed key did not unseal, and its fingerprint is different, so a client knows which one answered.

- `door.recovery`: `"off"`, `"uplink"` or `"uplink+tailnet"`. Default `"uplink"` under `tpm`, where a
  cleared TPM must not strand a headless box that has an uplink. Default `"off"` under `measured`,
  because a modified boot chain lands in recovery on purpose, and a recovery door would hand the key
  to it. It is never offered over the tailnet unless set to `"uplink+tailnet"`.
- **Never trust what the door says about itself.** A modified initramfs can print any reason for being
  in recovery ("the TPM was cleared", "a firmware update"). Confirm the reason out of band: you cleared
  the TPM yourself, you updated the firmware yourself, the provider's console shows it.
- **Manual unlock**: `tailnet-unlock unlock --recovery <host>` prints that this is the recovery door
  and asks the operator to type the host name before it sends.
- **Automated delivery refuses the recovery door by default** (decision D25). A consumer that sets
  `allow_recovery_delivery = true` gets requests with `door.role = "recovery"` (section 10.3), and the
  approver must answer with `"recovery_acknowledged": true`. A consumer's approver should allow that
  only behind a separate, explicit human approval that names the recovery door.

**Console.** The load-key extension always runs a console prompt beside the door. A headless box is
recovered through whatever console the owner has: a provider's KVM or serial console, a rescue system,
or a person on site. For a box behind NAT whose TPM failed, the console is the only way back.

**The recovery passphrase is the root key.** ZFS native encryption allows one wrapping key per
encryption root, so a separate recovery passphrase cannot exist for the same root. The README
therefore recommends a root key in a form a person can type at a console: `keyformat=passphrase` with
a generated passphrase of at least 128 bits (decision D22), kept in at least two places that do not
depend on the box. LUKS has real key slots and gets a separate recovery passphrase (section 11).

## 10. Key delivery

### 10.1 The door protocol

Two calls over SSH as `root`, both through the forced command (section 7.3, step 4): `status`, then
`unlock <boot_id>` with the key on stdin. The keyholder runs OpenSSH's client with
`StrictHostKeyChecking=yes`, a known-hosts file generated from one pin at a time (the sealed pin; the
recovery pin only where 10.2 step 2 allows it, and for `unlock --recovery`), so a session that
connects proves which key the door presented, `HostKeyAlgorithms=ssh-ed25519`,
`IdentitiesOnly=yes` and `BatchMode=yes`. A keyholder in userspace networking (a CI job, say) reaches the
tailnet door through `ProxyCommand=tailscale nc %h %p`. The door listens on its own port (2222 by
default, decision D17), so its key never collides with the real sshd's in a known-hosts file.

### 10.2 `deliver`, step by step

`tailnet-unlock deliver <host> --reason planned|unplanned|manual [--by <who>]`:

1. Takes the per-host lock in the keyholder's state directory; a second delivery for the same host
   exits at once. Watchers on several keyholders are the consumer's to coordinate (run one per host
   set).
2. Waits up to `door_wait_minutes` (default 30) for any configured door (tailnet by node id, uplink by
   address) to answer `status` through a known-hosts file that holds the **sealed pin alone**. A door
   that fails that host key check is tried with a known-hosts file holding the recovery pin alone
   only when `allow_recovery_delivery = true`; otherwise the delivery ends ("recovery door, manual
   only"). **The door's role is the key the SSH client verified** (decision D31), never what the
   door reports: `door.role` is `"sealed"` when the session verified against the sealed pin and
   `"recovery"` when it verified against the recovery pin. A copy of `/boot` holds the recovery key
   unsealed and can answer `status` with `"key": "sealed"`; the keyholder ignores that field for
   every decision, and a door whose reported key differs from the verified one is refused and the
   mismatch audited.
3. Builds the approval request (10.3) from the verified role, the door's status, the keyholder's view
   of the unlock node (10.4), the reason and the host's history.
4. Runs the approver with the request on stdin. No approver configured means refused. For
   `door.role = "recovery"` the keyholder refuses any approval that lacks
   `"recovery_acknowledged": true`, whatever its `decision` says.
5. On approval, reads `status` again, through the same single-pin known-hosts file, and checks the same
   boot id and the same door key.
6. Runs the key source, normalises its output (10.6) and pipes it straight into `unlock <boot_id>`.
   The key is never in an argument, an environment variable, a log line or a file the keyholder
   writes.
7. Waits for the box's own node to come online (the boot went on) and writes one audit line (10.8).

Exit codes say what happened: delivered, refused, timed out, door not found, wrong key.

### 10.3 The approver contract

An approver is any executable, configured as an argument list (never run through a shell). It gets one
JSON request on stdin, must print one JSON response on stdout, and exit 0. Anything else (a non-zero
exit, no output, malformed output, a different request id, a response after `expires_at`, the
timeout, default 15 minutes, after which it is killed) is a refusal. It never sees the key.

Request:

```json
{
  "schema": "tailnet-unlock.approval-request/1",
  "request_id": "0b9d1c6e7a2f4e1d9c3b5a7e8f60d4c2",
  "created_at": "2026-11-21T10:02:11Z",
  "expires_at": "2026-11-21T10:17:11Z",
  "host": "web-1",
  "reason": {"kind": "unplanned", "started_by": null, "note": null},
  "door": {
    "role": "sealed",
    "kind": "tailnet",
    "address": "web-1-unlock",
    "port": 2222,
    "host_key_sha256": "SHA256:3mR5pW2s1wIhX9fK0EXAMPLEONLYq7Vb8nJ4tYc6uZo"
  },
  "boot": {
    "boot_id": "6f1c2b3a-0d4e-4c5f-9a8b-7e6d5c4b3a21",
    "kernel": "6.12.117+deb13-amd64",
    "profile": "tpm",
    "seal": "ok",
    "degraded": [],
    "backend": "zfs",
    "waiting_for": "rpool",
    "keyformat": "passphrase",
    "tailscaled": "1.104.7"
  },
  "network": {
    "path": "direct",
    "observed_endpoint": "198.51.100.7:41641",
    "relay": null,
    "reported_endpoints": ["198.51.100.7:41641", "192.0.2.10:41641"],
    "expected": ["198.51.100.0/24"],
    "site_match": "yes"
  },
  "history": {"last_unlock_at": "2026-11-14T03:10:42Z"}
}
```

`door.role` is `"sealed"` or `"recovery"`, set from the host key the keyholder's SSH client verified
(10.2 step 2). Everything under `boot` is what the door says about itself: an approver shows it to a
person and never treats it as evidence.

Response:

```json
{
  "schema": "tailnet-unlock.approval-response/1",
  "request_id": "0b9d1c6e7a2f4e1d9c3b5a7e8f60d4c2",
  "decision": "approve",
  "by": "alice, key SHA256:pQ8EXAMPLEONLYa1b2c3d4e5f6g7h8i9j0k",
  "note": "kernel update this morning"
}
```

For `door.role = "recovery"`, an approval also needs `"recovery_acknowledged": true`, and is only
asked for at all when `allow_recovery_delivery = true`.

**Binding, and who enforces it.** The request id is random (128 bits) and recorded as used once a
delivery ends; the response must name it; `expires_at` bounds it; `door.role` comes from the verified
host key, never from the door's report; step 5 of `deliver` rechecks the boot id and the door key; the
recovery gate is checked before the approver runs; a recovery approval without
`"recovery_acknowledged": true` is refused. All of that is enforced by the keyholder. The door enforces two things only: the authorized SSH key and its role, and that
`unlock` names this boot's id. A keyholder that skips its checks, or a compromised one, can send the
key anyway.

A consumer with its own approval service writes a small approver that calls it and prints the response.
Nothing in tailnet-unlock knows about that service.

### 10.4 What the keyholder knows about the unlock node

The watcher and `deliver` read the keyholder's own `tailscale status --json` (decision D12): each
peer's `Online`, `LastSeen`, `CurAddr` (the address the keyholder's WireGuard session actually talks
to, when the path is direct), `Relay`, and `Addrs` (the endpoints the node reports). No API token is
needed, and it works the same with headscale.

`network.path` is `"direct"` or `"relayed"`. On a direct path, `observed_endpoint` is an address the
keyholder exchanged packets with, and `site_match` is `"yes"` or `"no"` against `expected_endpoints`.
On a relayed path, `observed_endpoint` is null, only the node's own reports remain (a modified client
can invent them), and `site_match` is always `"unverified"`, whatever the reports say. The request
shows endpoints; it does not prove where the door is.

### 10.5 Built-in approvers, and a complete one that needs nothing but SSH

Built in: `deny` (what an empty setting means), `tty` (used by the interactive `unlock`: shows the
request and asks the operator to type the host name) and `ssh`, below. There is deliberately no
approver that says yes on its own.

**The SSH approver.** The approval is an SSH login by a person, ideally with a FIDO2 security key, so a
touch is the approval.

Setup on the keyholder:

```
# a dedicated account whose only purpose is to approve
useradd --system --create-home unlock-approve
# in ~unlock-approve/.ssh/authorized_keys, one line per person, the options followed by that
# person's public key (a security key made with `ssh-keygen -t ed25519-sk`):
restrict,pty,command="tailnet-unlock approver ssh respond --as alice" <alice's ed25519-sk public key>
```

```
# /etc/ssh/sshd_config.d/tailnet-unlock-approve.conf: lets the forced command read which key logged in
Match User unlock-approve
    ExposeAuthInfo yes
```

In `keyholder.toml`:

```toml
[defaults]
approver = ["tailnet-unlock", "approver", "ssh", "request"]
# optional: anything that tells a person a request is waiting (mail, a push service). Empty here.
notify = []
```

Flow:

1. `deliver` runs `tailnet-unlock approver ssh request`, which writes the request to
   `/var/lib/tailnet-unlock/keyholder/approvals/pending/<request_id>.json` (readable by the
   `unlock-approve` account), runs `notify` if set, and waits.
2. The operator runs `ssh -t unlock-approve@keyholder` and touches the key. The forced command lists
   pending requests, prints the one chosen in full (host, reason, door and its role, what the door
   says about itself, endpoints, site match), and asks for the host name to approve or `no` to refuse.
   A recovery request says so first and asks separately.
3. It writes `decided/<request_id>.json` with `by` set to the name from the line (`--as alice`) and the
   fingerprint of the key that logged in, read from the file `$SSH_USER_AUTH` names, which sshd provides
   only with `ExposeAuthInfo yes`. It exits.
4. The waiting approver reads the decision, prints the response, and exits 0. Timeout or refusal: no
   key is sent.

Nothing in this example leaves SSH, and the same pattern works with an approver on another machine:
the hook can `ssh` there instead of writing a local spool.

### 10.6 The key source contract

An argument list per host, run without a shell, that prints the key on stdout and exits 0, for example
`["pass", "show", "unlock/web-1"]`, `["sops", "--decrypt", "--extract", "[\"root_key\"]", "web-1.yaml"]`,
or `["cat", "/srv/keys/web-1.key"]` on an encrypted keyholder disk. At most 513 bytes are read. For
`passphrase` and `hex` keys (the door's `status` reports the `keyformat`) exactly one trailing newline
is removed; a `raw` key must be exactly 32 bytes. The result goes into the SSH session's stdin and
nowhere else.

### 10.7 The watcher and the alarm

`tailnet-unlock watch` makes one pass and exits, for a timer, cron or a scheduled CI job (or loops with
`--every`). Each pass reads `tailscale status --json` once, and for each configured host:

| Box's own node | Unlock node | Action |
|---|---|---|
| online | offline | nothing |
| offline | online | the box waits at its door: start `deliver --reason unplanned`, unless a planned marker (`tailnet-unlock planned <host> --by <who> --for 30m`) makes it `planned` |
| online | online | **alarm**: read again after 60 seconds; if it persists, act on `on_alarm`. Something is using the unlock identity while the box runs. |
| offline | offline | nothing (the box is down or between states) |

The uplink door is probed too for hosts that have one, so a box whose tailnet door is down is still
found.

`on_alarm = "alert" | "expire"` (decision D24). `alert`, the default, runs the `alarm` hook. `expire`
also expires the unlock node's key through the control plane's API (which needs an API credential with
device write access): it stops a cloned identity at once, and also takes away the tailnet door at the
next genuine reboot until a re-enrollment, which strands a box behind NAT. Neither deletes the node.
An enrollment shows the unlock node online for a few seconds while the box runs; a watcher pass in that
window raises the alarm once, as it should.

### 10.8 Audit

One JSON line per delivery attempt on stdout and in `/var/log/tailnet-unlock/audit.jsonl`: time,
host, request id, reason, door and its role, door key fingerprint, boot id, path and endpoints, the
approver's decision and `by`, the result. Never the key. A test greps every log the suite produces for
the key bytes (section 15).

## 11. LUKS

LUKS fits the same design; only the backend that turns a key into an unlocked root changes:

- `root.backend = "luks"`: the door's `unlock` writes the key to cryptsetup-initramfs's askpass FIFO,
  the mechanism Debian's `cryptroot-unlock` uses, for every device waiting with the same key.
- LUKS has key slots, so a recovery passphrase is a slot of its own, independent of the delivered key.
- A TPM token for the root (`systemd-cryptenroll --tpm2-device`) must not be enrolled as well: it would
  unlock without any approval and change the boundary to "a stolen machine boots itself".
- ZFS on LUKS: deliver to LUKS, leave ZFS unencrypted inside.

It is milestone M7, after the ZFS backend is proven.

## 12. Packaging and configuration

### 12.1 Packages

One source package, three binary packages, `Architecture: all`:

| Package | Contents | Depends |
|---|---|---|
| `tailnet-unlock` | initramfs-tools hook and scripts (including `scripts/panic`), the door command, the ZFS load-key extension, the box CLI, the dpkg trigger, the `prerm` guard | `python3-tailnet-unlock`, `initramfs-tools`, `dropbear-bin`, `tpm2-tools`, `tailscale (>= 1.86)` (from Tailscale's own apt repository), `zfs-initramfs` (Debian `contrib`) for the ZFS backend; Conflicts: `dropbear-initramfs` (decision D2) |
| `tailnet-unlock-keyholder` | `deliver`, `unlock`, `watch`, approvers, examples | `python3-tailnet-unlock`, `openssh-client` |
| `python3-tailnet-unlock` | the Python package both use | `python3 (>= 3.13)` |

For keyholders that are not Debian (a laptop, a CI image): a single-file zipapp,
`tailnet-unlock-keyholder.pyz`, attached to each release; the code uses the standard library only.

Distribution: `.deb` files and the zipapp as GitHub release assets with checksums for 0.x; an apt
repository once there are users who ask.

A dpkg trigger on `/usr/sbin/tailscaled` rebuilds every initramfs when the Tailscale package changes,
so each image carries the tailscaled the system runs, and `verify` reads each image's version against
the floor, older kernels' images included. The trigger never fails its package (decision D18): its
script runs `update-initramfs -u -k all`, reports a failure on stderr with a `W: tailnet-unlock:` line
and in the record `verify` reads, and exits 0. A Tailscale upgrade that cannot rebuild an image
leaves that image with the older tailscaled and a warning, never a half-configured package.

**Removal guard** (decision D29): while the box is enrolled (a sealed door exists and the encryption
root's `keylocation` is `prompt`), `prerm` refuses `remove` and `purge`, saying to run
`tailnet-unlock disable` first: removing the hooks would leave the next initramfs without a door.
Upgrades are not affected.

### 12.2 Files

| Path | What |
|---|---|
| `/etc/tailnet-unlock/box.toml` | Box configuration |
| `/etc/tailnet-unlock/delivery_keys` | Keyholder keys, plain; the hook adds `restrict` and the `delivery` forced command |
| `/etc/tailnet-unlock/operator_keys` | People's keys, plain; the hook adds the `no-*` options and the `operator` forced command |
| `/var/lib/tailnet-unlock/door/` | `door.tpm/` (the container, section 8.3), `recovery_host_key` (0600) and its `.pub` |
| `/var/lib/tailnet-unlock/tailnet/unlock.state` | The unlock node's state, sealed by tailscaled |
| `/var/lib/tailnet-unlock/pins.toml` | Public: what keyholders pin (sealed and recovery fingerprints, node id, addresses) |
| `/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock` | The ZFS load-key extension |
| `/etc/tailnet-unlock/keyholder.toml` | Keyholder configuration (or `$XDG_CONFIG_HOME/tailnet-unlock/keyholder.toml`) |
| `/var/lib/tailnet-unlock/keyholder/` | Locks, planned markers, used request ids, the SSH approver's spool |

### 12.3 `box.toml`

```toml
[root]
backend = "zfs"            # "zfs"; "luks" from M7

[door]
port = 2222
key_source = "generate"    # or "import": `enroll --door-key-file -` reads a key you provision
# recovery = "uplink"      # "off", "uplink" or "uplink+tailnet";
                           # unset: "uplink" under the tpm profile ("off" under measured, once built)
recovery_key_source = "generate"
idle_timeout_seconds = 600

[network]
mode = "dhcp"              # "dhcp" or "static"
interface = "eno1"         # or match = "mac", which reads the MAC at each build
# address = "192.0.2.10/24"
# gateway = "192.0.2.1"
# dns = ["192.0.2.53"]
flush_on_handover = true

[tailnet]
enabled = true             # the one switch for the tailnet door (goal 5)
login_server = ""          # empty: Tailscale; or "https://headscale.example.com"
hostname = ""              # empty: "<host>-unlock"
tags = ["tag:unlock"]

[seal]
profile = "tpm"            # "tpm"; "measured" is refused until it is built (M6)

[rehearsal]
minutes = 10               # set by `enroll`, cleared by `commit`
```

`tailnet.enabled = false`: the next build carries no Tailscale, the door answers on the uplink alone,
and `tailnet-unlock disable --tailnet` deletes the sealed state (and the node, given API access).

### 12.4 `keyholder.toml`

```toml
[defaults]
ssh_key = "/etc/tailnet-unlock/keyholder/id_ed25519"
approver = ["tailnet-unlock", "approver", "ssh", "request"]
approval_timeout_seconds = 900
door_wait_minutes = 30
alarm = ["logger", "-t", "tailnet-unlock", "alarm"]
on_alarm = "alert"                     # or "expire"
allow_recovery_delivery = false

[hosts.web-1]
node = "web-1"                         # the box's own tailnet node
key_command = ["pass", "show", "unlock/web-1"]
expected_endpoints = ["198.51.100.0/24"]

[hosts.web-1.door]                     # pasted from the box's pins.toml
port = 2222
door_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEONLYdoorkey"
recovery_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEONLYrecoverykey"
unlock_node_id = "nEXAMPLE1CNTRL"
uplink = "192.0.2.10"
```

### 12.5 Commands

Box: `enroll`, `commit`, `status`, `verify [--next-boot]`, `reseal [--profile P] [--next-boot-only]`,
`rotate`, `disable [--tailnet|--local-key|--console]`, `door-keygen` and `seal` (the M1 building
blocks `enroll` later calls), `render-initramfs` (used by the hook).

Keyholder: `pins add <pins.toml>`, `unlock <host> [--recovery]`, `deliver <host>`, `watch`,
`planned <host>`, `approver {ssh,tty,deny} ...`, `audit`.

## 13. Installing

### 13.1 Prerequisites

Debian 13 with initramfs-tools and the `contrib` component enabled (for `zfs-initramfs`), root on ZFS
with native encryption, a TPM 2.0 visible as `/dev/tpmrm0` (a hard requirement; a virtual TPM only if
its state does not travel with the machine's snapshots), Tailscale 1.86 or later or a headscale server,
a wired IPv4 uplink, room on `/boot`, and, before the last step, a keyholder with the root key in a key
source and a backup of the key that does not depend on the box.

### 13.2 An existing box (the main path)

Every step leaves a box that boots:

1. Install Tailscale and `tailnet-unlock`. Nothing changes at boot yet: no config, no door.
2. Write `box.toml`, `delivery_keys` and `operator_keys` (`enroll --import-dropbear-initramfs` carries
   over the authorized keys of an existing dropbear-initramfs setup; its host keys sat in plain text on
   `/boot` and are not reused).
3. `tailnet-unlock enroll --auth-key-file <file>`: checks the prerequisites; generates (or imports,
   `--door-key-file -`) and seals the door key; generates (or imports, `--recovery-key-file -`) the
   recovery key if recovery is enabled, and stores it unsealed; enrolls the unlock node
   with a second tailscaled (`--encrypt-state`, userspace networking, its own socket and state) from a
   single-use, pre-authorized, tagged, non-ephemeral auth key read from the file (`--auth-key=file:`),
   checks the state is sealed, stops it; turns rehearsal on; rebuilds every initramfs and reads each
   back; prints `pins.toml`. The auth key file is deleted. The box still boots with its local key.
4. On the keyholder: `tailnet-unlock pins add pins.toml`, set the host's key source. If the box has a
   local key file, `tailnet-unlock enroll --rekey --sink <command>` can move to a fresh key, handing it
   to your secret store on stdin.
5. Rehearsal reboot: the box waits up to `rehearsal.minutes` at its door; the keyholder runs
   `deliver web-1 --reason planned`. If the delivery works, the boot used it; if not, the local key boots
   the box when the time is up. `tailnet-unlock status` says which one unlocked this boot.
6. `tailnet-unlock commit`: refuses unless this boot was unlocked through the sealed door. Then sets
   `keylocation=prompt`, deletes the local key file, rebuilds every initramfs, and checks that no current
   image holds the key and every image holds the door.
7. Reboot. From now on the current key lives only with the keyholder.

**What `commit` cannot undo.** While the key lived on the box, it was copied into every initramfs on
`/boot` and into the root's own file. `commit` removes the current copies only. Older copies survive in
ZFS snapshots of the dataset that held the key file, in backups of `/boot` or of the root, and in freed
blocks on `/boot`'s file system and on disks replaced since. Anyone holding one of those, and a copy of
the disks, can open them. `zfs change-key` (or `enroll --rekey`) gives the pool a new wrapping key, so
an old key no longer opens the current pool on its own; but ZFS's master key, which encrypts the data,
never changes without re-encrypting the data (send and receive into a new encryption root), so an old
key together with an old disk copy still yields that master key. Treat the key-on-box era as exposed:
rekey, destroy the snapshots and backups you can, and re-encrypt if the old copies may have left your
hands.

A box that prompts on the console today skips the local-key fallback: its rehearsal is the console.

### 13.3 A fresh install

Recommended: install as usual with a key file, boot once, and follow 13.2. That path is tested on the
real hardware before the key leaves the box.

For image builders: create the pool with `keylocation=prompt`, generate the key on the installer and
put it in the key source, and run `tailnet-unlock enroll` in the target's chroot on the target machine
(the TPM and the network must be the target's) with the `tpm` profile. `measured` can only be chosen
after the first boot, since it seals to the chain that boots. A fresh install avoids the key-on-box era
entirely.

### 13.4 Leaving

`disable --local-key` reads the key on stdin, writes it to a key file, sets `keylocation` back and
rebuilds every image without the door. `disable --console` keeps `prompt` and removes the door. Both
print the unlock node's id to delete, or delete it with API access. After `disable`, the package can be
removed. `rotate` replaces the door key, the recovery key and the unlock node, and prints new pins; the
old node is deleted, so an old `/boot` image stops working.

## 14. Code

- **POSIX sh in the initramfs** and in the initramfs-tools hook, because busybox's shell is all there
  is at boot. Kept small: network, unseal, starting and stopping two daemons, the door, the load-key
  extension, the panic cleanup. Checked with `shellcheck --shell=sh` (POSIX as the target) and run under
  busybox's `sh` in tests.
- **Python everywhere else**: configuration, rendering, enrollment, sealing orchestration, the PCR
  predictor, the keyholder, approvers, the watcher. Python 3.13, the `python3` of Debian 13 (3.13.5),
  with `tomllib` in the standard library; tests run on the newest stable Python too (3.15.2 today).
  Standard library only, so the keyholder ships as one file. TypeScript was the alternative: it would
  add a Node runtime to every box and every keyholder for no gain here.
- **Fully typed** (decision D14): every function, argument and return annotated; `mypy --strict
  --python-version 3.13` with `disallow_any_explicit = true` and `warn_unused_ignores = true`; no
  `Any` escape hatches; a `# type: ignore[code]` only with its reason on the same line, enforced by a
  check. Untrusted input (configuration, approver output, door status, `tailscale status`) enters as
  `object` and is narrowed by validating functions into `TypedDict`s or frozen dataclasses. All of it
  runs in pre-commit and in CI as failing checks.
- **Pure functions and explicit state**: no classes with behaviour; data is `TypedDict` or frozen
  dataclasses; decisions (policy shape, approval checks, watcher actions, prediction) are pure
  functions of their inputs, and effects (TPM, SSH, subprocesses, files) sit at the edge, so the
  decisions are unit-tested without a TPM or a network.
- `ruff` (target `py313`) for lint and formatting, `pytest` for tests.

Layout (what M1 built, then what later milestones add):

```
initramfs/        POSIX sh: door, supervise, unseal, lib.sh, paths.sh (fixed paths), hook,
                  init-premount, init-bottom, panic, zfs-load-key, post-update, conf-umask
src/tailnet_unlock/
                  config, render, authorized_keys, doorkey, tpm, container, seal, cli;
                  keyholder/: pins (the role from the verified key), approval (the contract),
                  keymaterial, doorstatus. Later: predict, enroll, door_client, deliver,
                  approvers/, watch, audit
tools/            install-tree (puts the files where the package will), check_ignores.py
tests/unit/       pytest: the pure functions, the harness's command lines
tests/shell/      the door, the panic script and the load-key extension under dash and busybox
tests/tpm/        door-keygen, seal and unseal against swtpm; the supervisor with dropbear
tests/initramfs/  real images from mkinitramfs, the degraded builds, the door run from an image
tests/vm/         the harness, one TCG boot, the KVM scenarios and the guest's provisioning
tests/container/  the Debian 13 test image (packages from Debian itself)
examples/         box.toml; later keyholder.toml, policy.hujson, approver scripts
debian/           packaging (M4)
```

`make test` runs every tier but the KVM one in the test container, with one command; `make lint
unit` is what CI's check job runs.

## 15. Test plan

### 15.1 What runs where

| Run | Trigger | What | Where |
|---|---|---|---|
| Local | every commit | `make test`: in the Debian 13 test container, `shellcheck --shell=sh`, `mypy --strict --python-version 3.13`, `ruff` (target `py313`), the ignore-with-reason check, the unit and shell tests, swtpm and dropbear, real images, one TCG boot; `make vm-test` for the KVM scenarios | the developer's machine with docker; a Debian host with KVM for the VM scenarios |
| Check | every push and pull request | **one job**: `shellcheck --shell=sh` on `initramfs/`, `mypy --strict --python-version 3.13`, `ruff` (target `py313`), the ignore-with-reason check, and the unit tests (busybox-sh tests included) on the newest stable Python | GitHub-hosted runner |
| Weekly | a schedule, once a week | the full matrix: unit tests on Python 3.13 through the newest stable; the container tiers of `make test` on Debian 13 and 14; from M4, package build, `lintian`, install and purge on Debian 13 and 14; the VM scenarios on Debian 13 and 14 against headscale; plus the next Python pre-release, allowed to fail | GitHub-hosted runners (Linux runners expose `/dev/kvm`) |
| Release | a version tag | the full matrix and the VM scenarios on every supported Debian release (13 and 14), all required, plus the VM scenarios against a throwaway Tailscale tailnet (an OAuth client in the repository's secrets, scoped to auth keys for a test tag); then the release assets are built | GitHub-hosted runners |
| Hardware | before each release, by hand | the scenarios that need real hardware on one machine with a discrete TPM and one with a firmware TPM; results in the release notes | the maintainer's machines |

Every workflow job runs on GitHub-hosted runners. Secrets are never available to pull requests from
forks. Debian 14 runs use initramfs-tools until the dracut module (M5).

### 15.2 The VM harness

- **Host side**: QEMU (10.0.13 in Debian 13, 11.1.3 in trixie-backports) with OVMF (2025.02 in
  Debian 13, with and without Secure Boot variables) and swtpm (0.10.2 upstream; 0.7.1 in Debian 13)
  as a TPM 2.0 per VM:
  `swtpm socket --tpm2 --tpmstate dir=<vm>/tpm --ctrl type=unixio,path=<vm>/swtpm.sock` and
  `-chardev socket,id=chrtpm,path=<vm>/swtpm.sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0`
  on a `q35` machine, with `OVMF_CODE_4M.fd` and a per-VM copy of `OVMF_VARS_4M.fd`, a virtio disk and
  a virtio-net NIC. The harness records the versions it ran with. Plain QEMU rather than Incus keeps it
  the same on a hosted runner and a laptop; Incus (7.0, the active LTS line, 7.0.2 in trixie-backports;
  6.0.4 in trixie) can run it locally through its `tpm` device.
- **Serial console**: `-serial` to a socket the harness drives; the guest boots with
  `console=ttyS0,115200`, served by the 8250 UART driver built into Debian's kernel. Every console
  scenario (prompts, the fallback, the boot summary) goes through it.
- **Guest layout**: GPT with a 512 MiB ESP (vfat), a 1 GiB `/boot` (ext4) and `rpool` on the rest:
  `zpool create -o ashift=12 -O encryption=on -O keyformat=passphrase -O keylocation=prompt
  -O compression=lz4 -O acltype=posixacl -O xattr=sa -O mountpoint=none rpool <disk>-part3`, the root
  in `rpool/ROOT/debian` mounted at `/`, following the OpenZFS "Debian Root on ZFS" guide with `/boot` on
  ext4 instead of a boot pool. The encryption root is `rpool`. Packages from trixie `main` and
  `contrib`.
- **Boot loader**: for `tpm`, GRUB for EFI (`grub-efi-amd64`) with Secure Boot off, reading `/boot`, the
  common Debian layout. For `measured` (M6), systemd-boot with UKIs on a 1 GiB ESP, Secure Boot off and
  on (our own keys enrolled in the VM's variables).
- **Building the image**: inside a builder VM booted from Debian's official 13 cloud image, which
  installs `zfs-dkms` and writes the target disk, so the CI host needs no ZFS module. Cached by the hash
  of its inputs, since building the ZFS module takes minutes.
- **Without KVM**: `make tcg` boots Debian's kernel with an image built in the test container under
  TCG, on SeaBIOS, with swtpm on `tpm-tis`, a virtio NIC matched by MAC and no disk: the unseal from
  the VM's own TPM, the uplink, the sealed door's `status`, and the panic script wiping the door
  before the shell when initramfs-tools gives up waiting for the root. It takes about a minute. Do
  not pass `rootdelay=` there: initramfs-tools 0.148.4 sleeps that long before init-premount even
  starts.
- **Network**: M1 uses QEMU user networking with a forwarded port standing in for the uplink. From M2,
  an isolated test network carries headscale 0.29.7 (in a container, with its embedded DERP), so the
  suite needs no internet and no account.
- **The keyholder** runs in the harness itself, from M2 with its own tailscaled in userspace networking.

### 15.3 Scenarios

| # | Scenario | Passes when |
|---|---|---|
| T1 | Boot, unlock by hand through the door (M1: uplink; M2: tailnet) | the root mounts; the unlock node goes offline before the box's own node comes up |
| T2 | Boot, the watcher finds it, the SSH approver approves | delivered; the audit line is complete, `by` names the key that logged in |
| T3 | Approver refuses; approver times out | nothing is sent; the box keeps waiting; the console still works |
| T4 | Control plane unreachable | the uplink door unlocks |
| T5 | The disk image copied to a second VM with its own swtpm | no unlock node connects; the sealed key is not presented; only the recovery door answers, on the uplink only; `deliver` refuses it |
| T6 | A copy of `/boot` searched for secrets | no node key, machine key or sealed door key in plain text (searched for the known test values); the recovery key is there, as documented |
| T7 | TPM cleared (swtpm state reset) | `tpm`: recovery door on the uplink and the console; `unlock --recovery` works; `enroll --replace` restores the door |
| T8 | Another system booted on the same VM and TPM | `tpm`: it can unseal the door key (the documented boundary); `measured`: it cannot |
| T9 | `measured`: a modified initramfs; an edited command line (`break=premount`, `zfsdebug=1`); a genuine chain whose pool import is made to fail | the modified chain and the edited line do not unseal the sealed key and get no recovery door (off by default); `deliver` refuses them. On the failed import, the panic script's wipe line appears on the serial console, the door stops answering and the unlock node goes offline before the reset; the box reboots about every 10 seconds plus the boot time; no shell opens at any point, also with INT sent on the console |
| T10 | Kernel update and reboot (`measured`) | the predicted branch unseals; a forced misprediction falls through as section 9 says, never a hang |
| T11 | Tailscale package upgrade | every initramfs rebuilt by the trigger; `verify` reads the floor in each |
| T12 | An approval for boot A replayed on boot B | refused (boot id) |
| T13 | Unlock node online while the box runs | `on_alarm = "alert"`: the hook runs once; `"expire"`: the node's key is expired, the node is kept |
| T14 | Every log, console capture, audit file and CI log | the key bytes appear nowhere |
| T15 | `tailnet.enabled = false` | no Tailscale in any image; the uplink door alone |
| T16 | Rehearsal and commit on a box with a local key | a failed delivery still boots with the local key; `commit` refuses until a door unlock happened |
| T17 | `disable --local-key`; removal before and after `disable` | the box boots unattended again with no door; `prerm` refuses removal while enrolled and allows it after |
| T18 | A degraded build (tailscaled removed; `/boot` too small for tailscaled; then the door container removed) | the kernel package configures; the image keeps the uplink door (`boot-space` names both sizes), then the recovery door; `verify` exits non-zero; the door's `status` names the degradation; a Tailscale upgrade whose rebuild fails still configures |
| T19 | Tailnet Lock on, enrollment with a signed auth key, the state directory in tmpfs only | the unlock node comes up and is reachable at every boot |
| T20 | The example policy loaded into headscale | a peer that is neither keyholder nor operator cannot reach the door's port; the door reaches nothing; a keyholder reaches only the door's port |
| T21 | `door.key_source = "import"` and `door.recovery_key_source = "import"` | the imported door key is sealed, its pin matches the one known in advance, no plaintext copy remains on the box; the imported recovery key is stored unsealed (0600) and its pin matches the one known in advance |
| T22 | Door command grammar | anything but `status`, `unlock <uuid>` and, for operator keys, the empty command is refused; a raw key with a trailing newline and a passphrase with one are both handled as section 7.3 says |
| T23 | LUKS backend (M7), dracut module (M5) | T1 to T22 and T24 to T28 again for each |
| T24 | A recovery delivery: `allow_recovery_delivery = true`, the TPM cleared | an approval without `"recovery_acknowledged": true` is refused and no key is sent; with it, the key reaches the recovery door; with the setting false, the approver is never asked |
| T25 | A copy of `/boot` booted on another TPM, with a door changed to report `"key": "sealed"` | the sealed pin fails host key verification; with `allow_recovery_delivery = false` the delivery ends at the gate; with it true, the request says `"role": "recovery"`; the false report is refused and audited |
| T26 | dropbear killed, then tailscaled killed, while the box waits | the supervisor starts each again within its backoff and prints it on the console; `status` counts the restarts; the restarted door presents the same sealed key; the boot then unlocks |
| T27 | A wrong key through the door, then at the console | the door answers `wrong-key` and the wait goes on; the console asks again; the right key then unlocks |
| T28 | `tpm`: `panic()` reached through `break=mount` and through a pool import made to fail | the panic script stops the supervisor and wipes before the shell opens (no dropbear or tailscaled process, no door material in the tmpfs); leaving the shell continues the boot with the console prompt only |

## 16. Milestones

| Milestone | Delivers | Done when |
|---|---|---|
| M0 | This design | reviewed (section 19) |
| M1 | The uplink door (built, KVM scenarios pending; below): a minimal `door-keygen` and `seal` (`tpm` profile, `generate` and `import`), the `door.tpm` container, the initramfs-tools hook and scripts, the door command and its grammar, the ZFS load-key extension, the recovery door, the panic cleanup, the console path, `unlock` by hand; the VM harness with QEMU, OVMF, swtpm and the serial console (no headscale yet) | T1 (uplink), T3 (by hand), T5 (uplink part), T6, T7, T14, T21, T16 (the local key fallback), T22, T26 (dropbear), T27, T28 pass |
| M2 | The tailnet door: enrollment, tailscaled in the initramfs, headscale in the harness, the policy example and its tests | T1, T4, T5, T6, T15, T19, T20, T26 (tailscaled) pass |
| M3 | Delivery: `deliver`, the approver contract, `tty` and `ssh` approvers, key sources, boot binding, the recovery gate, the role from the verified key, audit, `watch`, `on_alarm` | T2, T3, T12, T13, T14, T24, T25 pass |
| M4 | Lifecycle and packaging: `enroll`, rehearsal, `commit`, `rotate`, `disable`, `verify`, the trigger, the degraded build, the removal guard, the `.deb` packages, the zipapp; release 0.1 after the release run and the hardware smoke test | T1 to T22 and T24 to T28 (`tpm`) pass on headscale and on a Tailscale tailnet |
| M5 | The dracut module, for Debian 14 | T23 (dracut) |
| M6 | The `measured` profile (systemd-boot and UKI) | T8, T9, T10 pass, Secure Boot on and off |
| M7 | The LUKS backend | T23 (LUKS) |

Order after 0.1: M5, then M6, then M7 (section 19).

Until M6 is built, `seal.profile = "measured"` is refused by the configuration: an image sealed under
it has no door, so accepting it would leave a box that reboots forever on an initramfs panic.

**Where M1 stands.** Built and passing in the Debian 13 test container: `door-keygen` and `seal`
(`generate` and `import`, the recovery key's import), the container, the unseal, the door and its
grammar under dash and busybox, the supervisor with its restarts, the panic script on both branches,
the load-key extension with the console prompt and the rehearsal limit, the hook with every
degradation, the boot scripts, and one real boot under TCG (section 15.2). The process-level and
TCG tests cover the door halves of T1, T5, T7, T21, T22, T26, T27 and T28. What remains for M1 is
the KVM run of `tests/vm/test_scenarios.py` (T1, T3, T5, T6, T7, T14, T21, T22, T27, T28 against a
ZFS root), which needs a host with `/dev/kvm`, QEMU, OVMF (`OVMF_CODE_4M.fd`, `OVMF_VARS_4M.fd`),
swtpm, about 20 GB of disk for the cached images, and access to cloud.debian.org and
deb.debian.org for the first build; and T16's local-key half, which needs `enroll` (M4).

## 17. Versions, read 2026-11-21

| Component | Version | Source |
|---|---|---|
| Debian stable | 13.8 "trixie" | `deb.debian.org/debian/dists/stable/Release` |
| Debian kernel | 6.12.117+deb13 (trixie); 7.3.4+deb14 (forky) | packages.debian.org |
| Tailscale | 1.104.7 (released 2026-11-12); `--encrypt-state` on Linux since 1.86, opt-in again since 1.92.5 | `pkgs.tailscale.com/stable`, GitHub releases, Tailscale's secure node state storage page |
| dropbear | 2026.94 upstream; 2025.89-1~deb13u1 in trixie (`dropbear-bin`) | GitHub `mkj/dropbear` releases; Debian madison |
| tpm2-tools | 5.8 upstream; 5.7-1 in trixie | GitHub `tpm2-software/tpm2-tools` releases; Debian madison |
| systemd | 262.2 upstream; 257.13-1~deb13u1 in trixie (also `systemd-boot`, `systemd-ukify`) | GitHub `systemd/systemd` releases; Debian madison; `man/experimental.xml` at v262.2 |
| OpenZFS | 2.4.4 upstream; 2.3.9 in trixie `contrib`, 2.4.4 in trixie-backports `contrib` | GitHub `openzfs/zfs` releases; Debian madison |
| initramfs-tools | 0.148.4 in trixie; 0.151 in forky | Debian madison; `init` and `scripts/functions` at 0.148.4 |
| dracut | 106-6 in trixie; 112-8 in forky | Debian madison |
| cryptsetup-initramfs | 2.7.5 in trixie | Debian madison |
| Python | 3.13.5 in trixie; 3.15.2 upstream | Debian madison; endoflife.date |
| swtpm | 0.10.2 upstream; 0.7.1 in trixie | GitHub `stefanberger/swtpm` releases; Debian madison |
| QEMU | 10.0.13 in trixie; 11.1.3 in trixie-backports | Debian madison |
| OVMF | 2025.02-8+deb13u1 in trixie | Debian madison |
| Incus | 7.0.2 (the active LTS line, 7.0), also in trixie-backports; 7.6.0 the newest feature release; 6.0.4 in trixie | GitHub `lxc/incus` releases; Debian madison |
| headscale | 0.29.7 | GitHub `juanfont/headscale` releases |
| mypy, ruff, pytest, pre-commit | 2.4.1, 0.17.6, 9.2.0, 4.7.0 | PyPI |
| shellcheck | 0.11.0 upstream (0.10.0 in trixie) | GitHub `koalaman/shellcheck` releases |

Box packages depend on what Debian stable ships, plus Tailscale from its own repository; development
tools are pinned to the upstream versions above in pre-commit and CI.

## 18. Decisions

| # | Decision | Reason |
|---|---|---|
| D1 | initramfs-tools first, a dracut module before Debian 14 | trixie's kernel prefers initramfs-tools and OpenZFS ships its integration and load-key extension point there; forky's kernel now prefers dracut. |
| D2 | Our own early-boot SSH server from `dropbear-bin`; Conflicts with `dropbear-initramfs` | The host key must be unsealed before the server starts; dropbear-initramfs starts its server with keys read from `/boot`. Two servers on one port would fight. |
| D3 | tailscaled in userspace networking | No tun device, no firewall rules, nothing left in the kernel at handover; netstack hands inbound tailnet TCP to `127.0.0.1`. |
| D4 | A persistent, tagged, separate unlock node | Ephemeral would need a fresh auth key at every boot, on `/boot`; separate keeps the box's grants out of the initramfs; tagged nodes do not expire by default. |
| D5 | The tailnet carries the connection, a pinned SSH host key authenticates; no Tailscale SSH | A compromised peer or control plane can route traffic but cannot present the sealed key; Tailscale SSH would make the control plane the authenticator. |
| D6 | Node state sealed by Tailscale's `--encrypt-state`; the door key sealed by tailnet-unlock | Tailscale's sealing is maintained upstream but has no PCR policy and no encrypted session; the door key carries authentication, so it carries the measured policy and the encrypted unseal. |
| D7 | Two profiles, `tpm` by default and `measured` for systemd-boot with a UKI | `tpm` never needs a re-seal; only `measured` resists a modified boot chain, it needs prediction that only a UKI makes tractable, and it closes the gap only with recovery off. |
| D8 | A transient primary from the TCG SRK template; no persistent handles, no NV indices | Never collides with other users of the TPM, leaves nothing to clean up. |
| D9 | The root key is never on the box or in the TPM | A stolen machine never unlocks itself; losing the TPM loses the door, not the data. |
| D10 | Deliveries only after an approval bound to one request, one boot and one door key; fail closed | A stolen machine runs the genuine door; approvals must not be replayable. The keyholder enforces the binding; the door checks the boot id. |
| D11 | Approver and key source are executables with a JSON contract | Any approval system or secret store plugs in without becoming a dependency, and is testable alone. |
| D12 | The watcher reads the keyholder's own `tailscale status --json` | No API token, works with headscale, and shows the observed endpoint on a direct path. |
| D13 | POSIX sh only in the initramfs, Python 3.13 elsewhere, standard library only | busybox has no Python; Debian 13's python3 is one dependency and has `tomllib`; TypeScript would need a Node runtime everywhere. |
| D14 | Python fully typed: `mypy --strict`, `disallow_any_explicit`, ignores only with a reason, `TypedDict` or frozen dataclasses for data; initramfs shell under `shellcheck --shell=sh`; all failing checks in pre-commit and CI | Security code whose decisions are pure functions should be checked by machine, not by review alone. |
| D15 | TOML configuration, validated by Python and rendered into each initramfs at build time | One source of truth; the keyholder's configuration is nested; a rendered copy can never go stale. |
| D16 | Recovery door: `"uplink"` by default under `tpm`, `"off"` under `measured`, over the tailnet only when set; its key unsealed on `/boot`, said plainly | A cleared TPM must not strand a headless box with an uplink; under `measured` a recovery door would hand the key to a modified chain. |
| D17 | The door on its own port, 2222 by default | Its host key never collides with the real sshd's in a known-hosts file. |
| D18 | The hook never fails the build; each missing part degrades the image loudly (tailnet door, then sealed door, then any door), recorded and reported by `verify` | A kernel package's configure must not fail because of this project, and a degraded image must never go unnoticed. |
| D19 | `.deb` packages plus a standard-library zipapp for keyholders | Debian boxes get dependencies and triggers; keyholders run anywhere Python runs. |
| D20 | QEMU, OVMF and swtpm with headscale for the VM scenarios; a throwaway Tailscale tailnet before releases | Reproducible without an account; the real control plane is still checked before anyone installs a release. |
| D21 | The initramfs carries tailscaled only, not the CLI | Size: the 1.104.7 CLI is 34.3 MB (16.7 MB at zstd level 9) per image, about 50 MB on `/boot` with three kernels. Nothing in the boot flow needs it: tailscaled starts from its saved preferences, the door's `status` does not report connection state, and keyholders read the node's state from their side. Attack surface is not the reason: the CLI is not a daemon. |
| D22 | Recommend a root key a person can type (`keyformat=passphrase`, at least 128 bits), backed up off the box | ZFS has one wrapping key per encryption root, so the console fallback types the same key; losing it loses the data. |
| D23 | Door key source `generate` or `import`, both sealed the same way | Consumers that already keep host keys in their own secret store can pin them in advance; the default keeps the plaintext from ever leaving the box. |
| D24 | `on_alarm` is `alert` or `expire`, default `alert` | Expiring stops a cloned identity but strands a box behind NAT at its next genuine reboot; the safe generic default alerts, a consumer that prefers expiry sets it. |
| D25 | Automated delivery refuses the recovery door unless `allow_recovery_delivery = true` and the approver acknowledges the recovery role | The recovery key is on `/boot` in plain text; sending to it must be a separate, explicit human decision. |
| D26 | Door material wiped on every exit path; no initramfs shell under `measured` (`tailnet-unlock.noshell` in the UKI command line, and our panic script wipes, then reboots and never returns); never `panic=` | A shell inside a genuine initramfs, after the unseal, would hand out the sealed key; under `measured` that is the attack the profile exists to stop. `panic=` would deny the shell too, but initramfs-tools 0.148.4 then reboots before any panic script runs, so nothing would wipe. |
| D27 | Separate delivery keys (`restrict`) and operator keys (`no-port-forwarding,no-agent-forwarding,no-X11-forwarding`); the role set by the key line | People need a terminal for the no-echo prompt; automation needs nothing, so it gets nothing. |
| D28 | CI: one check job on every push and pull request; the full matrix weekly; releases gated by the full matrix and the VM scenarios on Debian 13 and 14; no GitHub-hosted job while the repository is private | Fast feedback for each change, the expensive runs where they matter, and nothing spent on hosted runners before the project is public. |
| D29 | `prerm` refuses removal while the box is enrolled | Removing the hooks would leave the next initramfs without a door. |
| D30 | TPM 2.0 is a hard requirement; no mode without it | Without a TPM the door's identity is plain text on `/boot`, which is the problem this project exists to fix. |
| D31 | The keyholder derives the door's role only from the host key its SSH client verified, one pin per known-hosts file; the recovery pin is used only with `allow_recovery_delivery = true` or `unlock --recovery` | A copy of `/boot` holds the recovery key unsealed and can report anything about itself, including "sealed". |
| D32 | A supervisor in the initramfs owns both daemons: it starts them, restarts them with a backoff, and is the one place that stops them and wipes | A door that dies while the box waits would otherwise strand a headless box until someone reaches its console; one owner of the PIDs makes every exit path wipe the same way. |

## 19. Review outcomes

The first review (2026-11-21) settled the open questions of the first draft:

| # | Question | Outcome |
|---|---|---|
| O1 | Who predicts PCRs under `measured` | Decided when M6 starts: systemd-pcrlock if it is no longer marked experimental, otherwise our own predictor for PCR 4 in the UKI path only. |
| O2 | GRUB under `measured` | Not supported; GRUB users get `tpm`. Evil-maid resistance needs systemd-boot with a UKI. |
| O3 | Recovery door default | `"uplink"` under `tpm`, `"off"` under `measured`, over the tailnet only when set (D16), automated delivery gated (D25). |
| O4 | Expire on alarm | A setting, `on_alarm`, default `alert` (D24). |
| O5 | An approver that says yes by itself | Not shipped. |
| O6 | Node state under the `measured` policy | No: Tailscale's own sealing stays; the boundary is written in section 6.2. |
| O7 | Distribution | Release assets with checksums for 0.x; an apt repository later. |
| O8 | Order of M5 to M7 | M5 (dracut), then M6 (`measured`), then M7 (LUKS). |
| O9 | Default door port | 2222. |

A security re-review (2026-11-21) found five gaps, fixed in this revision before any code:

| # | Finding | Outcome |
|---|---|---|
| R1 | With `panic=` set, initramfs-tools 0.148.4 reboots before `/scripts/panic` runs, so under `measured` nothing wiped | No `panic=` in either profile; our panic script wipes and, under `measured`, reboots itself and never returns (7.3, exit paths; D26; T9, T28) |
| R2 | The keyholder could take the door's role from the door's own report | The role is the pinned key the SSH client verified, one pin per known-hosts file (10.2; D31; T25) |
| R3 | The recovery acknowledgement was not in the enforced list, and the recovery key's import had no flag | Refused without it (10.2 step 4, 10.3; T24); `--recovery-key-file -`, and the recovery key is never sealed (8.1; T21) |
| R4 | A dropbear or tailscaled that dies while the box waits stayed dead | A supervisor restarts both with a backoff (7.3 step 2; D32; T26), and a wrong key is shown not to be an exit (T27) |
| R5 | A full `/boot`, or a failing Tailscale trigger, could fail a package | The hook degrades to the uplink door (`boot-space`), and the trigger always exits 0 (7.2, 12.1; T18) |

A security review of M1 (2026-11-21) found these, fixed in code with tests:

| # | Finding | Outcome |
|---|---|---|
| S1 | dropbear's log in the 16 MiB state tmpfs could be filled from the network | No daemon output is kept; every state write reports failure and the callers say so (7.3 step 2.4) |
| S2 | The panic script could be signalled, or fail open, before it was ready | Signals ignored from the first statement; `noshell` read from `/proc/cmdline` first; a file that will not source means noshell (7.3, exit paths) |
| S3 | A stop during a start, or an unrecorded PID, left a daemon running; a reused PID could be signalled | The supervisor stops from memory and files, defers TERM during a start, and signals a PID only when its command line names the daemon (7.3 step 2.7) |
| S4 | A plaintext key could reach swap | Key making refuses while swap is active (8.1) |
| S5 | One transient TPM failure kept the whole boot on the recovery key | The supervisor retries the unseal and moves the door to the sealed key (7.3 step 2.3) |
| S6 | The wipe list claimed more than the code did | The list now says what is wiped and why the rest is not (7.3, exit paths) |
| S7 | Smaller: the stored public half of a key was not checked against its seed; a host name could start with `-`; door status and key files were read without a cap; a failed recovery key write left plaintext | Each is checked or capped at its source, with a test |

### Open questions from M1

| # | Question | Recommendation |
|---|---|---|
| Q1 | A `raw` root key at the operator prompt: the door answers `bad-command` after saying the key cannot be typed | Keep the five results; a sixth (`cannot-type`) adds a code no keyholder acts on |
| Q2 | Objects are flushed with `tpm2_flushcontext -t`, safe only through a resource manager | Keep, and have `enroll` refuse any TCTI but `device:/dev/tpmrm0` on a box |
| Q3 | The plaintext door key is deleted once dropbear has loaded it, which relies on dropbear 2025.89 not reading the file again; a restart unseals again | Keep; the supervisor test fails if a dropbear upgrade starts reading the file per connection |
| Q4 | The panic script keys `noshell` off the rendered profile or `tailnet-unlock.noshell`; under `measured` the UKI must carry the word | Keep both, and have M6's `verify` check the word is in every UKI's embedded command line |
| Q5 | The weekly and release jobs use `ubuntu-latest` with nested KVM for the VM scenarios | Keep while the repository is public and hosted runners are free; revisit if runs flake |

## 20. Prior art

- Debian's `dropbear-initramfs` with `cryptroot-unlock`, and OpenZFS's `zfsunlock`: the remote prompt
  this builds on, without a tailnet and with the host key in plain text on `/boot`.
- Clevis with its TPM2 and Tang pins, and `systemd-cryptenroll`: automatic unlock bound to a TPM or a
  network server, without a person in the loop.
- Mandos: network unlock for Debian servers with approval delays, on the local network.
- Tailscale's secure node state storage (`--encrypt-state`): the sealing this design reuses for the
  node state.
- systemd's measured boot tools (`systemd-measure`, `systemd-pcrlock`, signed PCR policies): the model
  for `measured`, and possibly its implementation.
