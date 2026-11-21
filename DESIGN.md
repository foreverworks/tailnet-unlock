# tailnet-unlock: design

Status: design, for review. Nothing described here is built yet. Versions were read at their sources on
2026-11-21 (section 17); the build re-reads them when it starts.

## 1. Summary

A Debian machine whose root file system is encrypted cannot boot on its own unless the key is stored
next to the disk, which defeats the encryption. tailnet-unlock keeps the key off the machine and
makes the early-boot prompt reachable from anywhere on a tailnet:

- The initramfs starts a small SSH server (the **door**) and a Tailscale node of its own (the
  **unlock node**, `<host>-unlock`), so the door answers on the uplink and on the tailnet, behind NAT
  included.
- The door's identity, its SSH host key and the unlock node's state, is **sealed to the machine's
  TPM**. A copy of the disk or of `/boot` holds only ciphertext that no other TPM can open, so it can
  neither join the tailnet nor pose as the machine.
- The root key arrives over SSH, from an operator at a terminal or from a **keyholder** that sends it
  only after a pluggable **approver** says yes for this one boot.
- The door shuts down before the real system starts; the system's own Tailscale node then comes up as
  usual.

ZFS native encryption is the first backend. LUKS fits the same design with a different backend
(section 11).

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
| **tailnet-unlock** | after an approval, which can be automated | yes | yes, unless an approver says yes | yes |

The remaining gap with plain dropbear-initramfs is identity: its SSH host key sits unencrypted on
`/boot`, so anyone with a copy of `/boot` who can get on the network path can impersonate the
prompt and collect the key. Putting a tailnet node into the initramfs makes that worse unless the node
state is protected too, because the copy could then join the tailnet from anywhere.

## 3. Goals and non-goals

Goals:

1. A box with an encrypted ZFS root reboots and is unlocked remotely, without its key on any of its
   disks, over the tailnet or its uplink.
2. A copy of the disks, or of `/boot` alone, cannot join the tailnet as the unlock node and cannot
   present the door's host key.
3. The key is delivered only to the genuine door (pinned host key) and only after an approval bound to
   one boot. The approval mechanism is the consumer's: a hook with a small contract, never a
   dependency.
4. No step locks the owner out: every failure falls through to a door that still works (the recovery
   door, the console), and a kernel, initramfs or Tailscale update needs no manual step.
5. One switch turns the tailnet door off and leaves the uplink door and the console.
6. A stranger with a Debian box and a tailnet (Tailscale or headscale) can install it, on a fresh
   install or an existing box, in an afternoon.

Non-goals:

- Protecting a running machine: memory, DMA, cold boot, or root on the running system.
- Defending against whoever controls the hardware's firmware (a hostile vendor, a provider who
  reflashes firmware).
- Automatic unlock without an approval. The project ships no approver that says yes by itself
  (open question O5).
- Managing the TPM's owner, endorsement or lockout authorizations. The README recommends hardening;
  the tool only needs the owner hierarchy usable with an empty authorization, as Tailscale does.
- Installing Debian, or running an installer on the tailnet.
- Network or iSCSI roots, Wi-Fi uplinks, and IPv6-only uplinks in the first releases.
- Tailscale SSH in the initramfs (decision D5).
- TPM 1.2.

## 4. Terms

| Term | Meaning |
|---|---|
| Box | The machine with the encrypted root. |
| Door | The SSH server in the initramfs. Every login runs one forced command that can report status or accept a key, nothing else. |
| Door key | The door's ed25519 SSH host key, sealed to the TPM. Keyholders pin it. |
| Recovery door | The same SSH server presenting a second, unsealed host key, used only when the door key does not unseal. Automated delivery never uses it. |
| Unlock node | The door's own tailnet node, `<host>-unlock`, tagged `tag:unlock`, persistent, separate from the box's own node. |
| Keyholder | Any machine that holds root keys and delivers them: an operator's laptop, a CI job, a small home server. |
| Key source | A command on the keyholder that prints one box's root key. |
| Approver | A command on the keyholder that decides whether one delivery may happen. |
| Watcher | A keyholder job that notices a box waiting at its door and starts a delivery. |
| Profile | Which boot state the door key is sealed to: `tpm` (default) or `measured`. |

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
            |                                       |  or plain `ssh -p 2222 ...`
            v                                       +-----------------------------
 real root mounts; the box's own tailscaled and sshd start as usual
```

The tailnet carries the connection; the pinned SSH host key authenticates the door; the authorized SSH
keys authenticate the keyholder. Neither side trusts the control plane for authentication.

## 6. Threat model

### 6.1 Assets

1. The root key (the ZFS wrapping key). Never stored on the box, never in the TPM.
2. The door key. Whoever presents it is believed to be the box's genuine initramfs.
3. The unlock node's state (machine and node private keys). Whoever holds it can appear on the
   tailnet as `<host>-unlock`.
4. The approval. Whoever forges or replays one can make a keyholder send the key.

### 6.2 Adversaries and what the design does

| Adversary | `tpm` profile (default) | `measured` profile | What it does not defend |
|---|---|---|---|
| **Stolen disk, or a copy** (a returned disk, a provider snapshot, a backup of `/boot`, a pulled `/boot`) | Defended. The door key and the node state are sealed by this TPM, so the copy cannot unseal them, cannot join the tailnet, cannot present the door key. The root stays encrypted; the key was never on the disk. | Same. | A copy of `/boot` holds the recovery door's key in plain text (section 9): someone on the box's network path could present the recovery door. Automation refuses it; a human must not send a key there without knowing why. |
| **Stolen whole machine** | Partly. The thief can boot any system on the machine and unseal the door identity, or boot the genuine door at a new site. The root key is not on the machine, so the root opens only if an approver says yes. The approval request shows the endpoint the unlock node connects from against the box's expected site, and whether the reboot was planned. | The door key unseals only under the genuine boot chain, so it cannot be extracted under another system. The genuine chain still boots at the thief's site, so the approval remains the defense. | An approver who says yes to an unplanned reboot from an unknown endpoint. The endpoint is a hint, not a proof: a direct path shows the address the keyholder actually talks to, a relayed path only what the node reports (section 10.4). |
| **Evil maid on `/boot` or the ESP** (brief physical access, or a provider's rescue system, used to modify the initramfs and leave) | **Not defended.** The `tpm` profile binds to the TPM, not to what booted, so a modified initramfs unseals the door key, receives the key on the next approved unlock and can leak it. | Defended for the door key: a modified boot chain changes PCR 4, the door key does not unseal, and the keyholder refuses a door that does not present it. The modified initramfs can still join the tailnet (open question O6) and can show the recovery door, which automation refuses. | Firmware implants (PCRs 0 and 2 are off by default), a hardware interposer on the TPM bus (mitigated: unseal uses an encrypted session), and an operator talked into using the recovery door. |
| **Compromised tailnet peer** (any device on the tailnet that is not a keyholder) | Defended. The policy lets only keyholders and operators reach the door's port; `tag:unlock` reaches nothing. A peer that reaches the door anyway needs an authorized SSH key, and cannot pose as the door without the door key. | Same. | Denial of service by a peer the policy wrongly allows. |
| **Hostile control plane** (the coordination server, or a headscale administrator) | Defended for confidentiality: it can add peers, reroute, show forged endpoints, and see metadata, but SSH runs end to end with a pinned host key, so it can neither collect the key nor pose as the door. | Same. | Denial of service, and metadata (when boxes reboot and unlock). |
| **Network attacker on the uplink path** | Defended by the pinned door key, as above. | Same. | Denial of service; the recovery door caveat above. |
| **Replay** | A recorded SSH session is useless (fresh session keys). An approval is bound to one request id, one boot id, one door key and an expiry, and is used once (section 10.3). An old `/boot` image presents a door key the keyholder stopped pinning at the last rotation, and its unlock node was deleted then. | Same; an old image also needs its old boot chain. | A root key learned once keeps working against any disk copy taken before `rotate`. `zfs change-key` rewraps, but ZFS's master key changes only by re-encrypting the data (send and receive into a new encryption root). |

Out of scope, said plainly: root on the running box (it holds the unlocked data and can rewrite the
initramfs); a compromised keyholder (it holds the keys); an approver who approves the wrong thing;
anyone who can cut the network, who can keep the box locked (the console still works).

### 6.3 The boundary in one sentence

In the default `tpm` profile the root stays closed to whoever takes the disks or a copy of them, and a
whole machine opens only with an approval; the `measured` profile adds protection against a modified
boot chain.

## 7. The boot flow

### 7.1 initramfs-tools first, dracut second

Debian 13.8 ("trixie", the current stable) builds its initramfs with initramfs-tools 0.148.4: the
kernel package `linux-image-6.12.117+deb13-amd64` depends on `initramfs-tools`, then on any
`linux-initramfs-tool`. OpenZFS's Debian packaging (`zfs-initramfs` 2.3.9 in trixie, 2.4.4 in
trixie-backports) and `cryptsetup-initramfs` 2.7.5 ship their boot integration for initramfs-tools,
and OpenZFS offers the extension point this design uses (`/etc/zfs/initramfs-tools-load-key.d/`).

Debian 14 ("forky", testing) is moving: its kernel package `linux-image-7.3.4+deb14-amd64` now
depends on `dracut` first (dracut 112 in forky, 106 in trixie). So the core logic lives in builder
neutral POSIX shell under `/usr/lib/tailnet-unlock/initramfs/`, initramfs-tools gets thin hook and
boot scripts in the first release, and a dracut module follows before Debian 14 is released
(milestone M5).

### 7.2 Build time (on the running system, at every `update-initramfs`)

The hook `/usr/share/initramfs-tools/hooks/tailnet-unlock`:

1. Runs `tailnet-unlock render-initramfs`, which validates `/etc/tailnet-unlock/box.toml` and prints
   the shell assignments the boot scripts read (`conf/tailnet-unlock.conf` inside the image). The
   configuration has one source; the image carries a value derived from it at each build.
2. Copies in: `dropbear` (from `dropbear-bin`), `tailscaled` (not the `tailscale` CLI, decision D21),
   the few `tpm2_*` tools the unseal needs and the TSS device transport library they load at run
   time, the CA bundle, and the TPM drivers (`tpm_tis`, `tpm_crb`), plus the uplink NIC's driver,
   read from `/sys/class/net/<uplink>/device/driver/module` at each build.
3. Copies in the door material: the sealed door key (`tpm` profile; in `measured` it stays on the ESP,
   section 8.3), the recovery door key if enabled, the unlock node's sealed state, and
   `authorized_keys`, each line rewritten with `restrict,command="/usr/lib/tailnet-unlock/door"` so
   no key can be listed without its forced command.
4. Checks `tailscaled --version` against the floor (Tailscale 1.86, where `--encrypt-state` arrived on
   Linux) and fails if older.
5. Fails the build, saying why, if anything above is missing (decision D18). initramfs-tools then
   keeps the previous image for that kernel. An image is either complete or not written.

The image is written with `UMASK=0077`, though nothing in it is useful without this TPM.

OpenZFS's own hook copies `/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock` (shipped by this
package) into the image.

### 7.3 Boot time

1. **init-top**: initramfs-tools starts udev as usual.
2. **init-premount/tailnet-unlock** (never blocks the boot; everything long runs in the background):
   1. Loads the TPM driver and waits up to 10 seconds for `/dev/tpmrm0` (the kernel's resource
      manager).
   2. Brings up the uplink with initramfs-tools' `configure_networking` from the rendered `IP=` and
      `BOOTIF=` (DHCP or static, matched by MAC so interface names do not matter), and writes
      `/etc/resolv.conf` from the DHCP answer or the configured resolvers.
   3. Mounts a private tmpfs (mode 0700) at `/tailnet-unlock/run`, inside the initramfs root and not
      under `/run`, because initramfs-tools moves `/run` into the real system.
   4. Unseals the door key into that tmpfs (section 8). On failure it records why and, if the recovery
      door is enabled, uses the recovery key instead.
   5. Starts dropbear on `127.0.0.1:<port>` (the tailnet path) and `<uplink address>:<port>`, keys
      only, no forwarding (`-s -j -k`), an idle limit of 10 minutes, the PID kept in the tmpfs.
   6. If the tailnet door is on (`tailnet.enabled`), starts
      `tailscaled --state=<tmpfs copy of the sealed state> --encrypt-state --tun=userspace-networking
      --socket=<tmpfs>/tailscaled.sock --no-logs-no-support`. The state already holds the login, the
      tags and `WantRunning`, so no `tailscale up` runs at boot. In userspace networking, tailscaled's
      netstack hands inbound TCP for the node's own tailnet address to `127.0.0.1:<port>`
      (`wgengine/netstack/netstack.go`, read at v1.104.7), which is where dropbear listens. If the
      state does not unseal, tailscaled exits with `failed to unseal state file` and the console says
      the tailnet door is down; the uplink door keeps working.
   7. Prints one summary to the console: profile, seal result, uplink address, unlock node name, the
      fingerprint of the key the door presents (door or recovery), the boot id.
3. **ZFS import and key** (OpenZFS's `mountroot`): the pool is imported and `decrypt_fs` sources each
   load-key extension before it prompts. Ours:
   1. If the encryption root's `keylocation` is a file present in the image and no rehearsal is
      pending, returns 1 at once: the local key loads as before.
   2. Records the encryption root's name for the door.
   3. Starts a console prompt in the background (no echo, piped to `zfs load-key`), keeping its PID.
   4. Waits until the key status is `available`, whoever loaded it (the door or the console), then
      ends the console prompt by its PID and returns 0. In a rehearsal (section 13.2) it waits at most
      the configured minutes, then returns 1 so the local key loads.
4. **The door's forced command** (`/usr/lib/tailnet-unlock/door`, one per SSH session) dispatches on
   `SSH_ORIGINAL_COMMAND`, which dropbear sets for forced commands:
   - `status`: prints one JSON line (door or recovery key, boot id from
     `/proc/sys/kernel/random/boot_id`, profile, seal result, backend, the encryption root it waits
     for, kernel release, tailscaled version).
   - `unlock <boot_id>`: refuses if the boot id is not this boot's; waits up to 10 minutes for the
     encryption root to be named; then pipes at most 512 bytes of stdin into
     `zfs load-key -L prompt <encryption root>`, which reads key material from a stdin that is not a
     terminal, whatever the key format. The key touches no file and no command line. Prints one JSON
     result line (`loaded`, `wrong-key`, `not-waiting`, `boot-mismatch`) and exits 0, 1, 2 or 3.
   - nothing (a person typing `ssh -p 2222 unlock@host`): prompts for the key with no echo, then as
     `unlock`, without the boot id check, since the person is there.
5. The root mounts. **init-bottom/tailnet-unlock** stops tailscaled with SIGTERM (so the control plane
   sees the unlock node go offline at once) and waits up to 10 seconds before SIGKILL, stops dropbear
   by its PID, deletes the door material, unmounts the tmpfs, and flushes the uplink address it set,
   so the real system's network manager starts clean. It leaves one non-secret record,
   `/run/tailnet-unlock/boot.json` (who unlocked this boot: door, recovery door, console or local key;
   the profile; the seal result), which `status` and `commit` read on the running system.
6. initramfs-tools switches to the real root and frees the initramfs. The box's own tailscaled starts
   its own node; the unlock node stays offline until the next boot.

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
- **Read-only state in practice**: tailscaled may update its state while it runs; the copy lives in the
  tmpfs and is discarded at the handover. Nothing in the state needs to persist between boots for a
  tagged node.
- **No log upload** (`--no-logs-no-support`), no Tailscale SSH, no accepted routes or DNS settings
  (set in the node's preferences at enrollment).
- **Control plane reachability**: the CA bundle is copied in, and Tailscale falls back to its built-in
  bootstrap resolution when DNS fails. A clock far in the past breaks TLS to the control plane; the
  uplink door does not depend on the clock.
- **headscale**: `tailnet.login_server` names it; nothing else changes.
- **Size**: Tailscale's own tarball for 1.104.7 (amd64) is 41 MB compressed with both binaries. The
  image carries tailscaled only; M2 measures the real growth per image, and `enroll` checks `/boot`
  has room for every installed kernel.

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
takes the equivalent `acls` rules.

## 8. Sealing

### 8.1 What is sealed, by whom

| Secret | Sealed by | Policy | Where it lives |
|---|---|---|---|
| Unlock node state | Tailscale's own `--encrypt-state` | None: a transient SRK from the standard ECC P-256 template under the owner hierarchy, no authorization policy (`feature/tpm/tpm.go`, read at v1.104.7) | `/var/lib/tailnet-unlock/tailnet/unlock.state`, copied into each image |
| Door key | tailnet-unlock, with `tpm2-tools` | The profile's PCR policy (8.2) | `tpm`: `/var/lib/tailnet-unlock/door/door.tpm`, copied into each image. `measured`: on the ESP (8.3) |
| Recovery door key | Not sealed, by design (section 9) | None | `/var/lib/tailnet-unlock/door/recovery_host_key`, 0600, copied into each image |

Why two mechanisms (decision D6): Tailscale's sealing is maintained upstream, handles tailscaled's own
writes and state format changes, and has no PCR policy. The door key is the one that authenticates the
box, so it is the one that carries the measured policy. A tampered boot chain that still joins the
tailnet reaches nothing and cannot present the door key.

The door key is an ed25519 dropbear key (about 83 bytes), which fits the TPM's 128-byte limit for
sealed data, so no wrapping key is needed. tailnet-unlock creates its primary key transient at each use
from the same standard SRK template Tailscale uses: no persistent handle is created or reused and no NV
index is defined, so it never collides with other users of the TPM and leaves nothing behind
(decision D8). Unseal runs in a salted session with parameter encryption, so the key does not cross
the bus to a discrete TPM in clear.

Requirements on the TPM: TPM 2.0, an owner hierarchy usable with an empty authorization (the default,
and what Tailscale's sealing needs too), and for `measured` an active SHA-256 PCR bank.

### 8.2 Profiles and PCRs

**`tpm` (default).** No PCRs. The door key opens on this TPM whatever booted. Kernel, initramfs,
boot loader and firmware updates never require a re-seal and never lock the owner out. Boundary: the
first row of the threat table, not the evil maid row.

**`measured`.** Requires UEFI, systemd-boot and a unified kernel image (UKI: kernel, initrd and command
line in one PE file, built by `ukify`; systemd-boot 257.13 and systemd-ukify 257.13 are in trixie).
The door key is sealed to:

| PCR | What it holds | Why |
|---|---|---|
| 4 | Every EFI image the firmware loads: systemd-boot, the UKI, and the kernel image the stub loads | Any change to the loader, kernel, initrd or embedded command line changes it. The firmware measures each image before it runs it, so this holds with Secure Boot on or off. |
| 7 | Secure Boot state, keys and the authorities that verified each image | Notices Secure Boot being turned off or keys being changed. With Secure Boot off it still records that state. |
| 12 | systemd-stub's command line overrides, credentials and add-ons | Must hold its expected value: an edited command line (`break=premount`, `init=/bin/sh`) cannot reach a shell inside a genuine initramfs and unseal from there. `loader.conf` gets `editor no`. |
| 0, 2 (opt-in) | Firmware code and option ROMs | Off by default: every firmware update would change them. |

GRUB is not supported in `measured` (open question O2): GRUB measures every command it runs into
PCR 8 and every file it reads into PCR 9, and predicting those across `update-grub` means simulating its
script interpreter. GRUB users get the `tpm` profile.

### 8.3 Where the measured blob lives

A secret sealed to a measurement of the initramfs cannot sit inside that initramfs: the measurement
would include the secret. In `measured`, the sealed door key lives on the ESP
(`<ESP>/tailnet-unlock/door.tpm`); the initramfs mounts the ESP read-only by the partition UUID recorded
at build time, reads it, and unmounts it.

### 8.4 Updates without lockout

In `tpm` nothing is re-sealed, ever. In `measured`:

1. **Policy shape**: `PolicyOR` of up to eight `PolicyPCR` branches. After a boot it has one branch, the
   current chain.
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
   Boot database update that changes PCR 7), it says so and does nothing silently: the next boot lands
   on the recovery door, or the owner opts in to a **one-boot relaxation**:
   `tailnet-unlock reseal --next-boot-only` adds a branch bound by `PolicyCounterTimer` to the TPM's
   reset count of the next boot, with no PCRs. That boot is protected at the `tpm` level only, then
   step 3 closes the branch. It is never automatic.
5. **A wrong prediction never hangs the box**: the door key does not unseal, the door falls through to
   the recovery door and the console (section 9).
6. `tailnet-unlock verify --next-boot` checks, before a planned reboot, that the default boot entry's
   predicted values satisfy the sealed policy.

Whether the predictor is ours or `systemd-pcrlock` is open question O1: systemd-pcrlock does this
prediction with a policy kept in an NV index, and its manual page in systemd 262 still says
"this command is experimental for now".

### 8.5 What sealing never covers

The TPM never holds the root key (decision D9). Losing the TPM (cleared, failed, replaced with the
motherboard) loses the door, never the data: the box boots through the recovery door or the console,
and `tailnet-unlock enroll --replace` makes a new door.

## 9. Fallbacks

The rule: every failure falls through to something that still works, never to a wait that nobody can
end.

| Failure | Tailnet door | Uplink door | Console |
|---|---|---|---|
| None | door key | door key | always |
| Door key does not unseal (TPM cleared, failed, or `measured` mismatch) | Recovery key, only if tailscaled's state still unsealed | Recovery key, if `door.recovery = true` | always |
| Node state does not unseal | down | door key | always |
| Control plane or DERP unreachable, DNS broken, clock wrong | down | door key | always |
| Uplink down or behind NAT | as above | unreachable | always |
| No TPM at all | not built | door key is plain, as dropbear-initramfs today, and `enroll` refuses it unless `--no-tpm` is given | always |

**Recovery door** (decision D16, open question O3). A second ed25519 key, generated at enrollment and
kept unsealed. The door presents it only when the door key did not unseal, and its fingerprint is
different, so a client knows which one answered. `deliver` refuses a recovery door outright; only
`tailnet-unlock unlock --recovery <host>` sends to it, after printing why the door is in recovery and
asking the operator to type the host name. Intended uses: the owner cleared the TPM, updated firmware,
or replaced the board.

**Console.** The load-key extension always runs a console prompt beside the door. A headless box is
recovered through whatever console the owner has: a provider's KVM or serial console, a rescue system,
or a person on site.

**The recovery passphrase is the root key.** ZFS native encryption allows one wrapping key per
encryption root, so a separate recovery passphrase cannot exist for the same root. The README
therefore recommends a root key in a form a person can type at a console: `keyformat=passphrase` with
a generated passphrase of at least 128 bits (decision D22). The delivery path does not care about the
format. LUKS has real key slots and gets a separate recovery passphrase (section 11).

## 10. Key delivery

### 10.1 The door protocol

Two calls over SSH, both through the forced command (section 7.3, step 4): `status`, then
`unlock <boot_id>` with the key on stdin. The keyholder runs OpenSSH's client with
`StrictHostKeyChecking=yes`, a known-hosts file generated from its pins, `HostKeyAlgorithms=ssh-ed25519`,
`IdentitiesOnly=yes` and `BatchMode=yes`. A keyholder in userspace networking (a CI job, say) reaches the
tailnet door through `ProxyCommand=tailscale nc %h %p`. The door listens on its own port (2222 by
default, decision D17), so its key never collides with the real sshd's in a known-hosts file.

### 10.2 `deliver`, step by step

`tailnet-unlock deliver <host> --reason planned|unplanned|manual [--by <who>]`:

1. Takes the per-host lock in the keyholder's state directory; a second delivery for the same host
   exits at once. Watchers on several keyholders are the consumer's to coordinate (run one per host
   set).
2. Waits up to `door_wait_minutes` (default 30) for any configured door (tailnet by node id, uplink by
   address) to answer `status` with the **pinned door key**. A door presenting the recovery key ends
   the delivery: "recovery door, manual only".
3. Builds the approval request (10.3) from the door's status, the keyholder's view of the unlock node
   (10.4), the reason and the host's history.
4. Runs the approver with the request on stdin. No approver configured means refused.
5. On approval, reads `status` again and checks the same boot id and the same door key.
6. Runs the key source and pipes its output straight into `unlock <boot_id>`. The key is never in an
   argument, an environment variable, a log line or a file the keyholder writes.
7. Waits for the box's own node to come online (the boot went on) and writes one audit line (10.7).

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
    "backend": "zfs",
    "waiting_for": "rpool/ROOT",
    "tailscaled": "1.104.7"
  },
  "network": {
    "observed_endpoint": "198.51.100.7:41641",
    "relay": null,
    "reported_endpoints": ["198.51.100.7:41641", "192.0.2.10:41641"],
    "expected": ["198.51.100.0/24"],
    "site_match": "yes"
  },
  "history": {"last_unlock_at": "2026-11-14T03:10:42Z"}
}
```

Response:

```json
{
  "schema": "tailnet-unlock.approval-response/1",
  "request_id": "0b9d1c6e7a2f4e1d9c3b5a7e8f60d4c2",
  "decision": "approve",
  "by": "operator key SHA256:pQ8EXAMPLEONLYa1b2c3d4e5f6g7h8i9j0k",
  "note": "kernel update this morning"
}
```

Replay protection: the request id is random (128 bits) and recorded as used once a delivery ends;
the approval names it; step 5 rechecks the boot id and door key, and `unlock` refuses any other boot.
An approval for one boot cannot open another.

A consumer with its own approval service writes a small approver that calls it and prints the response.
Nothing in tailnet-unlock knows about that service.

### 10.4 What the keyholder knows about the unlock node

The watcher and `deliver` read the keyholder's own `tailscale status --json` (decision D12): each
peer's `Online`, `LastSeen`, `CurAddr` (the address the keyholder's WireGuard session actually talks
to, when the path is direct), `Relay`, and `Addrs` (the endpoints the node reports). No API token is
needed, and it works the same with headscale. When the path is direct, `observed_endpoint` is an
address the keyholder exchanged packets with. When it is relayed, the request says so and only the
reported endpoints remain, which a modified client can invent. Approvers that check the site should
treat `site_match` as a hint for a person, not a proof.

### 10.5 Built-in approvers, and a complete one that needs nothing but SSH

Built in: `deny` (what an empty setting means), `tty` (used by the interactive `unlock`: shows the
request and asks the operator to type the host name) and `ssh`, below. There is deliberately no
approver that says yes on its own (open question O5).

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
   pending requests, prints the one chosen in full (host, reason, door, boot, endpoints, site match),
   and asks for the host name to approve or `no` to refuse.
3. It writes `decided/<request_id>.json` with `by` set to the person and the fingerprint of the key
   that logged in, and exits.
4. The waiting approver reads the decision, prints the response, and exits 0. Timeout or refusal: no
   key is sent.

Nothing in this example leaves SSH, and the same pattern works with an approver on another machine:
the hook can `ssh` there instead of writing a local spool.

### 10.6 The key source contract

An argument list per host, run without a shell, that prints the key on stdout and exits 0, for example
`["pass", "show", "unlock/web-1"]`, `["sops", "--decrypt", "--extract", "[\"root_key\"]", "web-1.yaml"]`,
or `["cat", "/srv/keys/web-1.key"]` on an encrypted keyholder disk. At most 512 bytes are read. Its
output goes into the SSH session's stdin and nowhere else.

### 10.7 The watcher and the alarm

`tailnet-unlock watch` makes one pass and exits, for a timer, cron or a scheduled CI job (or loops with
`--every`). Each pass reads `tailscale status --json` once, and for each configured host:

| Box's own node | Unlock node | Action |
|---|---|---|
| online | offline | nothing |
| offline | online | the box waits at its door: start `deliver --reason unplanned`, unless a planned marker (`tailnet-unlock planned <host> --by <who> --for 30m`) makes it `planned` |
| online | online | **alarm**: read again after 60 seconds; if it persists, run the `alarm` hook. Something is using the unlock identity while the box runs. |
| offline | offline | nothing (the box is down or between states) |

The uplink door is probed too for hosts that have one, so a box whose tailnet door is down is still
found.

The alarm action defaults to alerting only. Expiring the unlock node's key on alarm stops a cloned
identity, and also takes away the tailnet door at the next genuine reboot until a re-enrollment, so it
is an explicit option (open question O4). An enrollment shows the unlock node online for a few seconds
while the box runs; a watcher pass in that window raises the alarm once, as it should.

### 10.8 Audit

One JSON line per delivery attempt on stdout and in `/var/log/tailnet-unlock/audit.jsonl`: time,
host, request id, reason, door, door key fingerprint, boot id, endpoints, the approver's decision and
`by`, the result. Never the key. A test greps every log the suite produces for the key bytes
(section 15).

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
| `tailnet-unlock` | initramfs-tools hook and scripts, the door command, the ZFS load-key extension, the box CLI, the dpkg trigger | `python3-tailnet-unlock`, `initramfs-tools`, `dropbear-bin`, `tpm2-tools`, `tailscale (>= 1.86)` (from Tailscale's own apt repository), `zfs-initramfs` for the ZFS backend; Conflicts: `dropbear-initramfs` (decision D2) |
| `tailnet-unlock-keyholder` | `deliver`, `unlock`, `watch`, approvers, examples | `python3-tailnet-unlock`, `openssh-client` |
| `python3-tailnet-unlock` | the Python package both use | `python3 (>= 3.13)` |

For keyholders that are not Debian (a laptop, a CI image): a single-file zipapp,
`tailnet-unlock-keyholder.pyz`, attached to each release; the code uses the standard library only.

Distribution at first: `.deb` files and the zipapp as GitHub release assets with checksums (open
question O7 for an apt repository).

A dpkg trigger on `/usr/sbin/tailscaled` rebuilds every initramfs when the Tailscale package changes,
so each image carries the tailscaled the system runs, and `verify` reads each image's version against
the floor, older kernels' images included.

### 12.2 Files

| Path | What |
|---|---|
| `/etc/tailnet-unlock/box.toml` | Box configuration |
| `/etc/tailnet-unlock/authorized_keys` | Keys that may use the door, plain; the hook adds `restrict` and the forced command |
| `/var/lib/tailnet-unlock/door/` | `door.tpm` (sealed), `door.pub`, `recovery_host_key` (0600), `recovery_host_key.pub` |
| `/var/lib/tailnet-unlock/tailnet/unlock.state` | The unlock node's state, sealed by tailscaled |
| `/var/lib/tailnet-unlock/pins.toml` | Public: what keyholders pin (door and recovery fingerprints, node id, addresses) |
| `/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock` | The ZFS load-key extension |
| `/etc/tailnet-unlock/keyholder.toml` | Keyholder configuration (or `$XDG_CONFIG_HOME/tailnet-unlock/keyholder.toml`) |
| `/var/lib/tailnet-unlock/keyholder/` | Locks, planned markers, used request ids, the SSH approver's spool |

### 12.3 `box.toml`

```toml
[root]
backend = "zfs"            # "zfs"; "luks" from M7

[door]
port = 2222
recovery = true            # the recovery door (section 9)
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
profile = "tpm"            # "tpm" or "measured"

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
alarm_expires_node = false

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
`rotate`, `disable [--tailnet|--local-key|--console]`, `render-initramfs` (used by the hook).

Keyholder: `pins add <pins.toml>`, `unlock <host> [--recovery]`, `deliver <host>`, `watch`,
`planned <host>`, `approver {ssh,tty,deny} ...`, `audit`.

## 13. Installing

### 13.1 Prerequisites

Debian 13 with initramfs-tools, root on ZFS with native encryption, a TPM 2.0 visible as `/dev/tpmrm0`,
Tailscale 1.86 or later (1.104.7 current) or a headscale server, a wired IPv4 uplink, room on `/boot`,
and, before the last step, a keyholder with the root key in a key source.

### 13.2 An existing box (the main path)

Every step leaves a box that boots:

1. Install Tailscale and `tailnet-unlock`. Nothing changes at boot yet: no config, no door.
2. Write `box.toml` and `authorized_keys` (`enroll --import-dropbear-initramfs` carries over the
   authorized keys of an existing dropbear-initramfs setup; its host keys sat in plain text on `/boot`
   and are not reused).
3. `tailnet-unlock enroll --auth-key-file <file>`: checks the prerequisites; generates and seals the
   door key; generates the recovery key; enrolls the unlock node with a second tailscaled
   (`--encrypt-state`, userspace networking, its own socket and state) from a single-use, pre-authorized,
   tagged, non-ephemeral auth key read from the file (`--auth-key=file:`), checks the state is sealed,
   stops it; turns rehearsal on; rebuilds every initramfs and reads each back; prints `pins.toml`. The
   auth key file is deleted. The box still boots with its local key.
4. On the keyholder: `tailnet-unlock pins add pins.toml`, set the host's key source. If the box has a
   local key file, `tailnet-unlock enroll --rekey --sink <command>` can move to a fresh key, handing it
   to your secret store on stdin.
5. Rehearsal reboot: the box waits up to `rehearsal.minutes` at its door; the keyholder runs
   `deliver web-1 --reason planned`. If the delivery works, the boot used it; if not, the local key boots
   the box when the time is up. `tailnet-unlock status` says which one unlocked this boot.
6. `tailnet-unlock commit`: refuses unless this boot was unlocked through the door. Then sets
   `keylocation=prompt`, deletes the local key file, rebuilds every initramfs, and checks that no image
   holds the key and every image holds the door.
7. Reboot. From now on the key lives only with the keyholder.

A box that prompts on the console today skips the local-key fallback: its rehearsal is the console.

### 13.3 A fresh install

Recommended: install as usual with a key file, boot once, and follow 13.2. That path is tested on the
real hardware before the key leaves the box.

For image builders: create the pool with `keylocation=prompt`, generate the key on the installer and
put it in the key source, and run `tailnet-unlock enroll` in the target's chroot on the target machine
(the TPM and the network must be the target's) with the `tpm` profile. `measured` can only be chosen
after the first boot, since it seals to the chain that boots.

### 13.4 Leaving

`disable --local-key` reads the key on stdin, writes it to a key file, sets `keylocation` back and
rebuilds every image without the door. `disable --console` keeps `prompt` and removes the door. Both
print the unlock node's id to delete, or delete it with API access. `rotate` replaces the door key,
the recovery key and the unlock node, and prints new pins; the old node is deleted, so an old `/boot`
image stops working.

## 14. Code

- **POSIX sh in the initramfs** and in the initramfs-tools hook, because busybox's shell is all there
  is at boot. Kept small: network, unseal, starting and stopping two daemons, the door, the load-key
  extension. Checked with `shellcheck --shell=sh` (POSIX as the target) and run under busybox's `sh` in
  tests.
- **Python everywhere else**: configuration, rendering, enrollment, sealing orchestration, the PCR
  predictor, the keyholder, approvers, the watcher. Python 3.13, the `python3` of Debian 13 (3.13.5),
  with `tomllib` in the standard library; CI also runs the current upstream stable, 3.15.2. Standard
  library only, so the keyholder ships as one file. TypeScript was the alternative: it would add a
  Node runtime to every box and every keyholder for no gain here.
- **Fully typed** (decision D14): every function, argument and return annotated; `mypy --strict` with
  `disallow_any_explicit = true` and `warn_unused_ignores = true`; no `Any` escape hatches; a
  `# type: ignore[code]` only with its reason on the same line, enforced by a check. Untrusted input
  (configuration, approver output, door status, `tailscale status`) enters as `object` and is narrowed
  by validating functions into `TypedDict`s or frozen dataclasses. Both run in pre-commit and in CI as
  failing checks.
- **Pure functions and explicit state**: no classes with behaviour; data is `TypedDict` or frozen
  dataclasses; decisions (policy shape, approval checks, watcher actions, prediction) are pure
  functions of their inputs, and effects (TPM, SSH, subprocesses, files) sit at the edge, so the
  decisions are unit-tested without a TPM or a network.
- `ruff` for lint and formatting, `pytest` for tests.

Planned layout:

```
initramfs/        POSIX sh: lib/, door, hook, init-premount, init-bottom, zfs-load-key
src/tailnet_unlock/
                  config, render, seal, predict, enroll, door_client, deliver,
                  approvers/, watch, audit
debian/           packaging
tests/unit/       pytest, busybox-sh tests of initramfs/lib
tests/vm/         the VM harness and its scenarios
examples/         box.toml, keyholder.toml, policy.hujson, approver scripts
```

## 15. Test plan

### 15.1 What runs where

| Suite | Where | When |
|---|---|---|
| Lint: `ruff`, `mypy --strict` (as in section 14), the ignore-with-reason check, `shellcheck --shell=sh` | pre-commit locally; GitHub-hosted runners (the repository will be public, where they are free) | every commit and pull request, failing |
| Unit: pytest on Python 3.13 and 3.15; busybox-sh tests of `initramfs/lib` | GitHub-hosted runners | every commit and pull request |
| Packages: build in a Debian 13 container, `lintian`, install and purge | GitHub-hosted runners | every commit and pull request |
| VM suite (15.2) against headscale | GitHub-hosted Linux runners, which expose `/dev/kvm`; or any Debian 13 host with KVM (`make vm-test`) | pull requests touching `initramfs/`, `src/` or `debian/`; full matrix nightly |
| VM suite against a throwaway Tailscale tailnet | GitHub-hosted runners, with an OAuth client in the repository's secrets scoped to auth keys for a test tag | release tags and manual runs only, never for pull requests from forks |
| Hardware smoke test | one machine with a discrete TPM, one with a firmware TPM | before each release, by hand, results in the release notes |

### 15.2 The VM harness

- QEMU (10.0.13 in Debian 13, 11.1.3 in trixie-backports) with OVMF (2025.02 in Debian 13, with and
  without Secure Boot variables) and swtpm (0.10.2 upstream; 0.7.1 in Debian 13) as a TPM 2.0 per VM.
  The harness records the versions it ran with. Plain QEMU rather than Incus keeps it the same on a
  hosted runner and a laptop; Incus (6.0.4 LTS in trixie, 7.6.0 upstream) can run it locally through its
  `tpm` device.
- The guest: Debian 13.8 with root on ZFS (native encryption), built with mmdebstrap, cached by the hash
  of its inputs, since building the ZFS module takes minutes.
- Control plane: headscale 0.29.7 in a container on an isolated test network, with its embedded DERP,
  so the suite needs no internet and no account.
- The keyholder runs in the harness itself, with its own tailscaled in userspace networking.
- Each scenario drives the VM's serial console, so the console fallback is tested the same way.

### 15.3 Scenarios

| # | Scenario | Passes when |
|---|---|---|
| T1 | Boot, unlock by hand over the tailnet door | the root mounts; the unlock node goes offline before the box's own node comes up |
| T2 | Boot, the watcher finds it, the SSH approver approves | delivered; the audit line is complete |
| T3 | Approver refuses; approver times out | nothing is sent; the box keeps waiting; the console still works |
| T4 | Control plane unreachable | the uplink door unlocks |
| T5 | The disk image copied to a second VM with its own swtpm | no unlock node connects; the door key is not presented; only the recovery door answers; `deliver` refuses it |
| T6 | A copy of `/boot` searched for secrets | no node key, machine key or door key in plain text (searched for the known test values) |
| T7 | TPM cleared (swtpm state reset) | recovery door and console; `unlock --recovery` works; `enroll --replace` restores the door |
| T8 | Another system booted on the same VM and TPM | `tpm`: it can unseal the door key (the documented boundary); `measured`: it cannot |
| T9 | A modified initramfs (`measured`) | the door key does not unseal; `deliver` refuses |
| T10 | Kernel update and reboot (`measured`) | the predicted branch unseals; a forced misprediction lands on the recovery door, never a hang |
| T11 | Tailscale package upgrade | every initramfs rebuilt by the trigger; `verify` reads the floor in each |
| T12 | An approval for boot A replayed on boot B | refused (boot id) |
| T13 | Unlock node online while the box runs | the alarm hook runs, once |
| T14 | Every log, console capture, audit file and CI log | the key bytes appear nowhere |
| T15 | `tailnet.enabled = false` | no Tailscale in any image; the uplink door alone |
| T16 | Rehearsal and commit on a box with a local key | a failed delivery still boots with the local key; `commit` refuses until a door unlock happened |
| T17 | `disable --local-key` | the box boots unattended again with no door |
| T18 | LUKS backend (M7), dracut module (M5) | T1 to T17 again for each |

## 16. Milestones

| Milestone | Delivers | Done when |
|---|---|---|
| M0 | This design | reviewed and the open questions answered |
| M1 | The uplink door: initramfs-tools hook and scripts, the door command, the ZFS load-key extension, the sealed door key (`tpm`), the recovery door, the console path, `unlock` by hand; the VM harness | T1 (uplink), T3, T5 (uplink part), T6, T7, T14 pass |
| M2 | The tailnet door: enrollment, tailscaled in the initramfs, headscale in the harness, the policy example and its tests, the size measurement | T1, T4, T5, T6, T15 pass |
| M3 | Delivery: `deliver`, the approver contract, `tty` and `ssh` approvers, key sources, boot binding, audit, `watch`, the alarm | T2, T3, T12, T13, T14 pass |
| M4 | Lifecycle and packaging: `enroll`, rehearsal, `commit`, `rotate`, `disable`, `verify`, the trigger, the `.deb` packages, the zipapp; release 0.1 after the real-tailnet run and the hardware smoke test | T1 to T17 (`tpm`) pass on headscale and on a Tailscale tailnet |
| M5 | The dracut module, for Debian 14 | T18 (dracut) |
| M6 | The `measured` profile (systemd-boot and UKI) | T8, T9, T10 pass, Secure Boot on and off |
| M7 | The LUKS backend | T18 (LUKS) |

M5 to M7 are independent of each other (order: open question O8).

## 17. Versions, read 2026-11-21

| Component | Version | Source |
|---|---|---|
| Debian stable | 13.8 "trixie" | `deb.debian.org/debian/dists/stable/Release` |
| Debian kernel | 6.12.117+deb13 (trixie); 7.3.4+deb14 (forky) | packages.debian.org |
| Tailscale | 1.104.7 (released 2026-11-12); `--encrypt-state` on Linux since 1.86, opt-in again since 1.92.5 | `pkgs.tailscale.com/stable`, GitHub releases, Tailscale's secure node state storage page |
| dropbear | 2026.94 upstream; 2025.89-1~deb13u1 in trixie (`dropbear-bin`) | GitHub `mkj/dropbear` releases; Debian madison |
| tpm2-tools | 5.8 upstream; 5.7-1 in trixie | GitHub `tpm2-software/tpm2-tools` releases; Debian madison |
| systemd | 262.2 upstream; 257.13-1~deb13u1 in trixie (also `systemd-boot`, `systemd-ukify`) | GitHub `systemd/systemd` releases; Debian madison |
| OpenZFS | 2.4.4 upstream; 2.3.9 in trixie, 2.4.4 in trixie-backports | GitHub `openzfs/zfs` releases; Debian madison |
| initramfs-tools | 0.148.4 in trixie; 0.151 in forky | Debian madison |
| dracut | 106-6 in trixie; 112-8 in forky | Debian madison |
| cryptsetup-initramfs | 2.7.5 in trixie | Debian madison |
| Python | 3.13.5 in trixie; 3.15.2 upstream | Debian madison; endoflife.date |
| swtpm | 0.10.2 upstream; 0.7.1 in trixie | GitHub `stefanberger/swtpm` releases; Debian madison |
| QEMU | 10.0.13 in trixie; 11.1.3 in trixie-backports | Debian madison |
| OVMF | 2025.02-8+deb13u1 in trixie | Debian madison |
| Incus | 7.6.0 upstream; 6.0.4 in trixie | GitHub `lxc/incus` releases; Debian madison |
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
| D5 | The tailnet carries the connection, a pinned SSH host key authenticates; no Tailscale SSH | A compromised peer or control plane can route traffic but cannot present the door key; Tailscale SSH would make the control plane the authenticator. |
| D6 | Node state sealed by Tailscale's `--encrypt-state`; the door key sealed by tailnet-unlock | Tailscale's sealing is maintained upstream but has no PCR policy; the door key carries authentication, so it carries the measured policy. |
| D7 | Two profiles, `tpm` by default and `measured` for systemd-boot with a UKI | `tpm` never needs a re-seal and never locks out; only `measured` stops an evil maid, and it needs prediction that only a UKI makes tractable. |
| D8 | A transient primary from the standard SRK template; no persistent handles, no NV indices | Never collides with other users of the TPM, leaves nothing to clean up, same pattern as Tailscale. |
| D9 | The root key is never on the box or in the TPM | A stolen machine never unlocks itself; losing the TPM loses the door, not the data. |
| D10 | Deliveries only after an approval bound to one request, one boot and one door key; fail closed | A stolen machine runs the genuine door; approvals must not be replayable. |
| D11 | Approver and key source are executables with a JSON contract | Any approval system or secret store plugs in without becoming a dependency, and is testable alone. |
| D12 | The watcher reads the keyholder's own `tailscale status --json` | No API token, works with headscale, and shows the observed endpoint on a direct path. |
| D13 | POSIX sh only in the initramfs, Python 3.13 elsewhere, standard library only | busybox has no Python; Debian 13's python3 is one dependency and has `tomllib`; TypeScript would need a Node runtime everywhere. |
| D14 | Python fully typed: `mypy --strict`, `disallow_any_explicit`, ignores only with a reason, `TypedDict` or frozen dataclasses for data; initramfs shell under `shellcheck --shell=sh`; all failing checks in pre-commit and CI | Security code whose decisions are pure functions should be checked by machine, not by review alone. |
| D15 | TOML configuration, validated by Python and rendered into each initramfs at build time | One source of truth; the keyholder's configuration is nested; a rendered copy can never go stale. |
| D16 | Recovery door on by default, with its own unsealed key, never used by automation | A cleared TPM or a firmware update must not strand a headless box that has an uplink. |
| D17 | The door on its own port, 2222 by default | Its host key never collides with the real sshd's in a known-hosts file. |
| D18 | Fail the initramfs build when anything the door needs is missing or below the floor | An image is either complete or not written; initramfs-tools keeps the previous one. |
| D19 | `.deb` packages plus a standard-library zipapp for keyholders | Debian boxes get dependencies and triggers; keyholders run anywhere Python runs. |
| D20 | QEMU, OVMF and swtpm with headscale for every change; a throwaway Tailscale tailnet before releases | Reproducible without an account; the real control plane is still checked before anyone installs a release. |
| D21 | The initramfs carries tailscaled only, not the CLI | Size; nothing at boot needs the CLI. |
| D22 | Recommend a root key a person can type (`keyformat=passphrase`, at least 128 bits) | ZFS has one wrapping key per encryption root, so the console fallback types the same key. |

## 19. Open questions

Each has a recommendation and what follows from it. The design above assumes the recommendation.

| # | Question | Recommendation | Consequence |
|---|---|---|---|
| O1 | Who predicts PCRs in `measured`: a narrow predictor of our own, or systemd-pcrlock? | Decide when M6 starts: systemd-pcrlock if its manual page no longer calls it experimental (it does in 262), else our own predictor for PCR 4 in the UKI path only. | Our own: more security code to maintain, but small and fully tested. pcrlock: less code, an interface that may still change, and an NV index on the TPM. |
| O2 | Support GRUB in `measured`? | No. GRUB users get `tpm`. | Evil-maid protection requires moving the box to systemd-boot with a UKI. |
| O3 | Recovery door on by default? | Yes, uplink and tailnet, with a distinct key and manual delivery only. | A holder of a `/boot` copy who is on the box's network path can present the recovery door; only the warning and the operator stand in the way. Off: a cleared TPM means a console visit. |
| O4 | On alarm, also expire the unlock node's key? | Alert only by default; expiry as an option. | Expiring stops a cloned identity at once, and also removes the tailnet door at the next genuine reboot until a re-enrollment, which strands a box behind NAT. |
| O5 | Ship an approver that says yes on its own (planned reboot, expected site)? | No, not in 0.x. Consumers who want it write it against the contract. | Every unlock needs a person unless the consumer automates it, which is the safe default for a public tool. |
| O6 | Seal the node state under the `measured` policy too (our own encryption instead of `--encrypt-state`)? | No. | A modified boot chain on the same machine can still join the tailnet as the unlock node; it reaches nothing and cannot present the door key. Doing it ourselves would mean owning Tailscale's state encryption. |
| O7 | Distribution: release assets only, or a signed apt repository? | Release assets with checksums for 0.x; an apt repository once there are users who ask. | Updates are manual until then. |
| O8 | Order of M5 (dracut), M6 (measured), M7 (LUKS) | M5 first, since forky's kernel already prefers dracut; then M6; then M7. | Evil-maid protection waits for the dracut module. |
| O9 | Default door port | 2222. | Users whose firewall allows only 22 must open it or choose 22 and use a known-hosts alias. |

## 20. Prior art

- Debian's `dropbear-initramfs` with `cryptroot-unlock`, and OpenZFS's `zfsunlock`: the remote prompt
  this builds on, without a tailnet and with the host key in plain text on `/boot`.
- Clevis with its TPM2 and Tang pins, and `systemd-cryptenroll`: automatic unlock bound to a TPM or a
  network server, without a person in the loop.
- Mandos: network unlock for Debian servers with approval delays, on the local network.
- Tailscale's secure node state storage (`--encrypt-state`): the sealing this design reuses for the
  node state.
- systemd's measured boot tools (`systemd-measure`, `systemd-pcrlock`, signed PCR policies): the model
  for `measured`, and possibly its implementation (O1).
