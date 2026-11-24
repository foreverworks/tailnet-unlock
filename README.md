# tailnet-unlock

**Unlock the encrypted ZFS root of a remote Debian machine from anywhere on your tailnet, with the
key kept off the machine.**

tailnet-unlock puts a small, locked-down SSH door into early boot and gives it its own place on your
tailnet (Tailscale or headscale), so a box behind a home router with no public address can still ask
for its key after a reboot. The door's identity is sealed to the machine's TPM, so a copied disk
cannot pretend to be your box. The key comes from you, or from a machine you trust after an approval
you control.

> **Status: version 0.1.0, the box side only. Early software, not for a machine you cannot reach.**
> This release sets up and checks the door on one Debian 13 machine with root on ZFS and a TPM:
> the door on the machine's own address (the uplink), the door on your tailnet, `enroll`, `verify`,
> `status`, `disable --tailnet`, and one `.deb` package. You unlock a box through the door with plain
> `ssh`: `status` tells you the boot it is waiting in, and `unlock <boot id>` takes the key on stdin.
> The main branch has the keyholder too, for the next release (0.2.0): `deliver` sends a key after an
> approval, and `watch` notices a box that waits.
> What it does not have yet: the safe test reboot (`rehearsal` and `commit`), `rotate`, `reseal`, dracut for Debian 14, the `measured` profile and LUKS. Those are described in the design and are
> planned, not built. It has not yet been run on real hardware, and it has had no independent
> security audit.
> What is built and what is not is listed in the [table in section 16 of DESIGN.md](DESIGN.md#16-what-is-built-and-planned-and-in-what-order).

**The risk, plainly.** This software runs in early boot, before your system is up, and sits between
you and your encrypted root. A fault in it, in its configuration or in your TPM can leave a remote
box waiting at a prompt that only its console can answer. If you have no console (a provider's KVM
or serial console, a rescue system, a person on site), a mistake can cost you access to the server
and, if you lose the root key, the data on it. Read "If something goes wrong" below before you try
it on anything that matters.

**Terms used throughout:**

- **initramfs**: the small file system Linux runs first, before your real root is mounted. It is where
  the root gets unlocked.
- **tailnet**: your private network of devices joined through Tailscale or a headscale server.
- **TPM**: a chip (or a firmware function) on the motherboard that can encrypt small secrets so that
  only this one machine can decrypt them.

**Before you read on:**

- **You need a TPM 2.0.** It is a hard requirement. Most rented servers expose none, and many virtual
  machines either have none or have a virtual TPM whose state is copied along with the machine's
  snapshots. A TPM that travels with the snapshot protects nothing, so such a machine is not a fit.
- **There is no hands-off mode.** Every unlock is a decision: you type the key, or an approver you
  configure says yes for that one boot. If you need a box that always boots by itself, this is not the
  tool.
- **Turn swap off while the door's keys are made.** A key made on the box exists in plain form for a
  moment, in memory, and memory can be written to a swap disk. The key tools refuse to run while a
  swap area on a disk is active (zram is RAM and does not count; neither does swap that
  `/etc/crypttab` encrypts with a fresh random key at each boot): run `swapoff -a` first. If that is
  unsafe on your box, `--allow-swap` makes the keys anyway, prints a warning, and the output says it
  was used, so the choice stays visible.

## Who this is for

You run Debian on a machine you cannot sit in front of: a dedicated server with a TPM, a box in a
closet at a relative's house, a small machine behind a router you do not control. Its root file system
is encrypted, because a disk that leaves the building should be useless to whoever takes it.

And so every reboot ends at a password prompt that nobody can see. A power cut at 3 a.m., a kernel
update, a provider's maintenance window: the box sits there, waiting for someone at a keyboard that
does not exist.

**Who it is not for.** If the machine has no TPM 2.0, or a virtual one that travels with snapshots,
it cannot work. If you want the box to boot by itself with no one deciding, use TPM auto-unlock
(Clevis, `systemd-cryptenroll`) and accept what it gives up (see "How it compares"). If the box has a
public address and you only need to type a passphrase over SSH, `dropbear-initramfs` is simpler.

## The usual answers, and what they give up

- **Keep the key in the initramfs.** The box boots on its own. So does a stolen disk.
- **Let the TPM unlock the disk** (Clevis, `systemd-cryptenroll`). The box boots on its own. So does a
  stolen machine, all the way to a running system.
- **dropbear-initramfs and type the key over SSH.** Works if the box has a public address you can
  reach, and if you trust a host key that sits in plain text on `/boot`, where anyone with a copy of
  the disk can read it.
- **Behind NAT,** none of the SSH answers reach the box at all.

## What you need

To install on a machine, all of this, on Debian 13 ("trixie"):

- Root on **ZFS with native encryption**, and the `contrib` component enabled in apt (ZFS's initramfs
  support lives there). initramfs-tools is the initramfs generator, as on a default Debian.
- A **TPM 2.0** (`/dev/tpmrm0` exists) with its owner hierarchy left at the default empty password.
- A wired uplink with IPv4.
- For the tailnet door: **Tailscale 1.86 or later**, from [Tailscale's own apt
  repository](https://tailscale.com/kb/1031/install-linux), and an account on a tailnet you control.
  Without it the box still gets the door on its own address.
- A **console** you can reach if something goes wrong: a provider's KVM or serial console, a rescue
  system, or a person on site.
- Room on `/boot`: each initramfs grows by about 22 MB (compressed) for `tailscaled`.

The package depends on `python3` (3.13 or later, the Debian 13 one), `initramfs-tools`,
`dropbear-bin`, `tpm2-tools`, `libtss2-tcti-device0t64` and `zfs-initramfs`, and conflicts with
`dropbear-initramfs`, because two SSH servers cannot share early boot. Everything is free software.

To work on the code or run the checks you also need Python 3.13 or later, `shellcheck`, `dash` or
`busybox`, and for `make test` Docker; see "Run the checks" below.

## Install

Releases are on the [releases page](https://github.com/foreverworks/tailnet-unlock/releases). Each has
the package, the source archive and a `SHA256SUMS` file. Download the `.deb` and `SHA256SUMS` into one
directory, check the package against the sums, and install it with apt, which also pulls in what it
depends on:

```
sha256sum --check --ignore-missing SHA256SUMS
sudo apt install ./tailnet-unlock_0.1.0_all.deb
```

The checksum only tells you that the file is the one the release lists. Where you have the GitHub CLI,
you can also check that GitHub built it from this repository's tagged source:

```
gh attestation verify tailnet-unlock_0.1.0_all.deb --repo foreverworks/tailnet-unlock
```

Installing changes nothing about how the box boots until you configure it. On a box that already has
`/etc/tailnet-unlock/box.toml`, installing or upgrading rebuilds the initramfs images, and so does
every upgrade of Tailscale (a dpkg trigger on `tailscaled`, so each image carries the `tailscaled` the
system runs). A rebuild that fails prints a `W: tailnet-unlock:` line and never fails the package.

**Removing it is refused while the box depends on it.** If a door key exists and an encryption root's
key is asked for at the prompt (`keylocation=prompt`), `apt remove` and `apt purge` stop with a
message, because the next initramfs would have no door. Upgrades are never refused. "Leaving" below
says how to get out. `apt purge` removes `/etc/tailnet-unlock` and `/var/lib/tailnet-unlock`, which
holds the door's sealed key and the node's state: do it only for a box you are done with.

## Set up a box

Do this on a machine you can afford to lose access to, with its console at hand. Each step leaves a
box that still boots the way it did.

1. **Configure.** Copy [`examples/box.toml`](examples/box.toml) to `/etc/tailnet-unlock/box.toml` and
   set the uplink (`network.match` or the address), the door's `port` and whether the tailnet door is
   on. Put the public keys that may unlock in `/etc/tailnet-unlock/delivery_keys` (a keyholder
   machine or script) and `/etc/tailnet-unlock/operator_keys` (people), one per line. The comments in
   the example, and section 12.3 of the design, say what each key does.
2. **Make the door's keys.** Turn swap off first (`swapoff -a`: the key exists in plain form in memory
   for a moment). Then `sudo tailnet-unlock door-keygen`, and `sudo tailnet-unlock door-keygen
   --recovery` if you enabled the recovery door. `tailnet-unlock pins` prints the fingerprints to
   write down and give to whoever will unlock.
3. **Join the tailnet** (skip this if `tailnet.enabled = false`). In the Tailscale admin console,
   make a one-use, pre-approved, non-ephemeral auth key tagged `tag:unlock`, and save it to a file
   in `/run` that only root can read (`/run` is in memory: on ZFS, overwriting a file does not erase
   it). Write a policy where nothing but your keyholders and operators can reach
   the door's port, and the door reaches nothing (section 7.5 of the design has an example). Then
   `sudo tailnet-unlock enroll --auth-key-file <file>`. It starts a second `tailscaled` of its own,
   joins as `<host>-unlock`, checks that the node's state is sealed by the TPM and that it opens again,
   deletes the key file, rebuilds every initramfs and checks each one.
4. **Check.** `sudo tailnet-unlock verify` reads every image in `/boot` and lists what is wrong, if
   anything, and exits with 1 when it finds a problem. `tailnet-unlock status` shows what the last
   boot did and what is enrolled.

At this point the box has a door in its images, but if its root still has a key file, the root unlocks
by itself as before and nobody asks the door anything. **To actually use the door** you move the root
to a prompt: `zfs set keylocation=prompt <encryption root>`, then `update-initramfs -u -k all` and
`tailnet-unlock verify`, which also says when an image still holds a key file. Version 0.1.0 does not do this for you, and does not have the rehearsal that
falls back to the old key if the door fails. So: keep the key file, and a copy of the key somewhere
safe, until you have rebooted once and unlocked through the door yourself. If that goes wrong, the
console prompt takes the same key.

### Unlocking through the door

The box waits in the initramfs, with the door on its own address and on the tailnet, on the port in
`box.toml`. With any key from `delivery_keys` or `operator_keys`:

```
ssh -p <port> root@<address> status                  # shows "boot_id", which key it presents, what it waits for
ssh -p <port> root@<address> unlock <boot_id> < keyfile
```

Check the fingerprint your SSH client shows against the one `tailnet-unlock pins` printed before you
send a key. The door replies with one line of JSON: `loaded`, `wrong-key` (try again), `not-waiting`
or `boot-mismatch`. Send the key only to the sealed door, or to the recovery door when you know why
the box is in recovery (below).

### Delivering the key after an approval

Not in 0.1.0; on the main branch, for 0.2.0. The machine that holds your root keys, the
**keyholder**, runs `tailnet-unlock deliver`: it waits for the box's door, checks the door's pinned
key, asks your **approver**, checks that the same boot still waits, and pipes the key in.

1. Get the program. On Debian it is in the package, next to the box's commands, and needs
   `openssh-client`. Anywhere else, use `tailnet-unlock-keyholder.pyz` from a release (or
   `make pyz`): one file, Python 3.13 or later, nothing to install. The machine's own `tailscale`
   tells it where the door is, if you use the tailnet door. Your policy must let it reach the door's
   port, and give it at least one grant to the box's own node, or it cannot see that the box is up.
2. Make a key for it with `ssh-keygen -t ed25519` (without a passphrase, for automation) and add the
   public half to `/etc/tailnet-unlock/delivery_keys` on the box. That key can ask the door for its
   status and hand it a root key, nothing else. Rebuild the box's images.
3. Copy [`examples/keyholder.toml`](examples/keyholder.toml) to `/etc/tailnet-unlock/keyholder.toml`.
   Paste what `tailnet-unlock pins` prints on the box under `[hosts.<name>.door]`, and set
   `key_command` to whatever prints that box's root key.
4. Set `approver` to a program of yours. It gets the request as JSON on stdin (which box, which door,
   which boot, whether the reboot was planned, where the door seems to be) and prints a decision;
   [`examples/approver.py`](examples/approver.py) is a complete one to adapt. No answer, a wrong
   answer or a late one sends nothing. There is no built-in approver that says yes, and none yet that
   asks over SSH.

```
tailnet-unlock deliver web-1 --reason manual --by alice
tailnet-unlock unlock web-1             # by hand: asks at this terminal, takes a typed key
tailnet-unlock planned web-1 --by alice --for 30m && ssh web-1 systemctl reboot
tailnet-unlock watch                    # one pass, for a timer; --every 60 to keep going
```

`watch` starts a delivery for a box it finds waiting, or runs your `on_waiting` program instead. A
machine that runs only `watch` with that setting needs no SSH key and no root key. It also raises an
alarm when a door's tailnet node is online while its box runs, which should not happen.

`deliver` ends with an exit code that says what happened (0 delivered, 3 refused, 4 no answer in
time, 5 no door, 6 wrong key, 7 not needed, 8 only the recovery door, 9 another delivery runs, 10
failed) and one line of JSON in `audit.jsonl`. Sections 10 and 12.4 of [DESIGN.md](DESIGN.md) have
every option, the two JSON formats and the event `watch` sends.

**Protect the keyholder.** Whoever has root there has your keys: the approval is enforced on that
machine.

## Run the checks

Install `shellcheck` and `dash` (or `busybox`) with your package manager, then, from a checkout:

```
git clone https://github.com/foreverworks/tailnet-unlock
cd tailnet-unlock
python3 -m venv .venv
.venv/bin/pip install mypy==2.4.1 ruff==0.17.6 pytest==9.2.0
PATH=$PWD/.venv/bin:$PATH make check
```

`make check` runs `shellcheck`, `mypy`, `ruff` and the unit and shell tests, and ends with a line
like `... passed in ...s` and no failures. With Docker, `make test` builds a Debian 13 test image and
also runs the TPM tests against swtpm (a software TPM), deliveries through a real SSH server, real `mkinitramfs` images, the package's
install, upgrade, removal and purge with apt, and one real boot under QEMU. Nothing touches the TPM,
the disks or the boot of the machine you run it on. The virtual-machine scenarios that boot a ZFS root
(`make vm-test`) need a host with KVM; CI runs them weekly and before every release.

You can also render the boot configuration the way the initramfs hook does, from
[`examples/box.toml`](examples/box.toml), without installing anything:

```
mkdir -p scratch/etc
cp examples/box.toml scratch/etc/box.toml
ssh-keygen -q -t ed25519 -N '' -C keyholder -f scratch/keyholder
cp scratch/keyholder.pub scratch/etc/delivery_keys
PYTHONPATH=src python3 -m tailnet_unlock render-initramfs \
    --config-dir scratch/etc --out scratch/out --host box --uplink-mac 00:00:5e:00:53:01
cat scratch/out/tailnet-unlock.conf
```

`scratch/out/authorized_keys` holds your key with the options that limit it to the door's one command.
A mistake in `box.toml` stops the command with a message that says what is wrong.

## If something goes wrong

These are the ways back in, in the order to try them.

- **The console is the last way in and always works.** Keep a console you can reach before you change
  anything about early boot: a provider's KVM or serial console, a rescue system, a person on site.
  The boot scripts are written so that when the door cannot start, the console prompt for the root
  key remains. On a box behind NAT whose TPM fails, the console is the only way.
- **Never remove your old way of unlocking until a door unlock has worked.** Version 0.1.0 has no
  rehearsal reboot and no `commit` to enforce this: it is yours to do. Keep the root's key file, and
  a copy of the key elsewhere, until you have rebooted once and unlocked through the door yourself.
- **Back out of the initramfs hook.** The hook only adds files to the initramfs. If a box fails to
  boot with it, boot a rescue system, unlock the root pool, chroot into it, remove the files the
  package installed (`dpkg -L tailnet-unlock` lists them; `apt` will refuse to remove the package
  while the box is enrolled, so remove the hook files by hand: `/usr/share/initramfs-tools/hooks/tailnet-unlock`,
  the scripts named `tailnet-unlock` under `/usr/share/initramfs-tools/scripts/`,
  `/usr/share/initramfs-tools/conf.d/tailnet-unlock`,
  `/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock`,
  `/etc/initramfs/post-update.d/tailnet-unlock` and `/usr/lib/tailnet-unlock`), and run
  `update-initramfs -u -k all` to rebuild without it.
- **The hook never fails a kernel update.** If a part is missing or `/boot` is too small, the build
  prints a `W: tailnet-unlock:` warning and carries on with less (the tailnet door, then the sealed
  door, then any door), and the box still boots through the console prompt. `tailnet-unlock verify`
  reports every image that is not what it should be.
- **If the TPM is cleared or replaced,** the sealed door key cannot be opened. The recovery door
  (below) can answer on the box's own address if you enabled it. Otherwise use the console. No data
  is lost: the disk key was never in the TPM. After you have unlocked once, `tailnet-unlock door-keygen
  --replace` makes a new door key and `tailnet-unlock enroll --replace` a new unlock node.

### Leaving

1. Put the root's key back the way it was: a key file, and `zfs set keylocation=<where it is>` on the
   encryption root. Reboot once and make sure the box unlocks.
2. `sudo tailnet-unlock disable --tailnet` logs the unlock node out, deletes its state and rebuilds
   the images without `tailscaled`. It prints the node's id: delete that node in your Tailscale admin
   console (or with its API) too, because the tool cannot.
3. `sudo apt remove tailnet-unlock`. The removal guard lets it through once no root asks for its key
   at the prompt, and rebuilds the images without the door. `apt purge` also deletes the door's keys
   and the box's configuration.

## What tailnet-unlock is designed to do

1. **Early boot opens a door.** The initramfs brings up the network, starts a minimal SSH server and a
   Tailscale node of its own, `<host>-unlock`. The door answers on your tailnet and on the box's own
   address. Behind NAT, the tailnet is how you reach it. Built: the SSH
   server, the network, and `enroll`, which gives the node its identity.
2. **The door can only do one thing.** Every login runs one command: report its status, or accept a
   key. No shell, no forwarding, keys only. Built.
3. **The door's identity is sealed to the TPM.** Its SSH host key and its tailnet node keys are
   encrypted by the machine's own TPM. They open on this machine and nowhere else. The host key's
   sealing is built; the node keys are sealed by Tailscale's own `--encrypt-state`.
4. **The key stays with you.** It lives on a **keyholder**: your laptop, a CI job, a small server at
   home. You can type it in, or let the keyholder deliver it after an **approver** says yes. You decide
   what an approval is: a touch of your security key over SSH, a button in your own system, anything
   that can run a program. Built for 0.2.0; in 0.1.0 you type or pipe the key through `ssh` yourself.
5. **The door closes before the system starts.** The tailnet node goes offline, the door's keys are
   deleted from early boot's temporary storage, and your system's own Tailscale node comes up as
   usual. Built.

## Why sealing to the TPM matters

Without it, the door's identity is a set of files on `/boot`. Anyone who copies the disk, or just the
`/boot` partition, gets a door that looks exactly like yours: it can join your tailnet as your box and
present your box's SSH host key. The next time something sends the key, it may send it to the copy.

With the identity sealed, the copy holds only ciphertext that your machine's TPM alone can open, so it
can neither join the tailnet nor present the sealed host key your keyholder expects. The keyholder is
designed to send the key only to a door that presents that sealed key, with one exception that stays
yours to make: the recovery door below, which you unlock by hand (`unlock --recovery`, or plain
`ssh`), or automatically only if you turn that on and your approver confirms it.

Because the TPM holds only the door, never the disk key, losing the TPM loses the door and nothing
else. Your data is still yours: you unlock once, at the console or through the recovery door where you
enabled it, and make a new door.

## The recovery door, said plainly

When the sealed host key cannot be opened (you cleared the TPM, a firmware update changed it, the
motherboard was replaced), the box can offer a **recovery door** instead: the same door with a second
host key, so you can still unlock it over the network.

- **That second key is on `/boot` unsealed.** A copy of `/boot` can present the recovery door to anyone
  who can reach it.
- **In the planned `measured` profile, any change to what boots lands the box in recovery, on purpose.** That
  includes a change someone made to `/boot` to steal your key. The default profile is different: its
  sealed key opens whatever boots, so a modified `/boot` opens the sealed door itself (the gap named in
  the security model below), and recovery means the sealed key did not open at all. In both profiles,
  never trust the reason the door prints about itself ("the TPM was cleared"): a tampered door, or a
  copy of `/boot` booted somewhere else, can print anything. Send a key to the recovery door only when
  you know the reason yourself, because you did it or your provider's console shows it.
- Automated delivery refuses the recovery door unless you turn that on and your approver confirms, as
  a separate decision, that it is the recovery door.
- It listens on the box's own address only, never on the tailnet unless you enable that. It is on by
  default in the default profile, and is planned to be off by default in the `measured` profile
  (below).

## What 0.1.0 includes, and what comes later

Each item says whether it exists in the repository today.

- initramfs-tools integration for Debian 13: built. A dracut module for Debian 14: not built.
- The ZFS backend: built. LUKS, with the same door: not built.
- On the box: `door-keygen`, `seal`, `render-initramfs`, `pins`, `fingerprint`, and the lifecycle
  commands `enroll`, `verify`, `status` and `disable --tailnet`: built. The **rehearsal** reboot that
  falls back to your old key if anything goes wrong, `commit`, `rotate`, `reseal`, `enroll --rekey`
  and `disable --local-key`: not built.
- The Debian package, with the trigger that rebuilds images when Tailscale changes and the guard that
  refuses removal while the box depends on it: built, one `.deb` on each release.
- A keyholder: `unlock` for you at a terminal, `deliver` for automation, `watch` to notice a box
  waiting at its door after a reboot nobody planned: built, for 0.2.0. Plain `ssh` does the same job
  by hand.
- A small, documented approver contract (JSON in, JSON out): built, with one approver for a terminal
  and an example to adapt. The complete approver that needs nothing but SSH is still to come.
- An example tailnet policy, with tests, where the door can reach nothing and only your keyholders and
  operators can reach the door: `examples/policy.hujson`, which the VM tests load. Section 7.5 of the
  design explains it.
- Fallbacks: the box's own address when the tailnet is down, the recovery door after a TPM clear
  where you enabled it and can reach it, and the console. For a box behind NAT whose TPM failed, the
  console is the only way back. The uplink door, the recovery door and the console prompt are built.
- A single-file keyholder for machines that are not Debian: built, for 0.2.0.

The container tests and a real boot under QEMU TCG run on every release. The virtual-machine scenarios
that boot a real ZFS root pass in CI (since 2026-11-22). Nothing has yet run on real hardware.

## The security model in plain words

**It is designed to protect your data against:**

- someone who takes the disks, or copies them, or copies `/boot`;
- a device on your tailnet that has been taken over;
- whoever runs the coordination server: it can route traffic, but it cannot read the key or pose as
  your door, because SSH runs end to end and the door's host key is pinned;
- replayed approvals: each approval is for one boot of one door, once, checked by your keyholder.

**It relies on you for:**

- **a stolen whole machine.** The thief can boot it and the door will appear. The key is not on the
  machine, so the root stays closed unless an approver says yes. The approval shows whether the reboot
  was planned and the network endpoints your keyholder sees for the door. Those endpoints are a hint,
  not a proof of where the machine is: on a relayed connection they are only what the door reports.
  Say no to what you do not recognise.

**It does not protect against, by default:**

- **someone who modifies `/boot` and leaves** (an "evil maid", or a hosting provider's rescue system).
  The default profile trusts the TPM, not what booted. The planned `measured` profile, for machines
  with systemd-boot and a unified kernel image, refuses to open the sealed key for a modified boot
  chain, and keeps the recovery door off so the modified chain cannot ask for the key that way. It
  still cannot stop an attacker who tampers with the TPM's wiring on the board.

**It never protects against:** root on the running system, a compromised keyholder, firmware you do
not control, or someone who can cut the network (the console still works).

None of this has had an independent security audit. The problems found while building it, and how
they were fixed, are recorded in section 19 of [DESIGN.md](DESIGN.md).

## Requirements

See "What you need" above. A keyholder needs only Python 3.13 or later and an OpenSSH client, and a
place to keep the key (a password manager, SOPS, a file on an encrypted disk: anything that prints it on
request).

## Back up the root key

The root key is the only key to your data. tailnet-unlock never stores it on the box, and the TPM
never holds it, by design, so nothing on the machine can give it back to you. Keep it in at least two
places that do not depend on the box: your password manager, and an offline copy (on paper, in a safe
place). Use a long generated passphrase rather than raw bytes, so you can type it at a console when
everything else is down. Lose every copy and the data is gone.

## Questions people ask

**Do I still need a console?** Yes, keep one possible (a provider's KVM, a serial console, a person on
site). In normal use you will not touch it, but it is the last fallback, and the only one when the
TPM fails on a box behind NAT.

**What happens after a kernel update?** In the default profile, nothing: the door is rebuilt into the
new initramfs and opens as before. The `measured` profile is planned to re-seal for the new kernel
before you reboot and keep the old kernel working too.

**What if the TPM dies, or I clear it?** The door cannot open its sealed identity, so the box offers
the recovery door on its own address, if enabled, and the console. Unlock once, run
`tailnet-unlock door-keygen --replace` and `tailnet-unlock enroll --replace`, and you have a new door. No data is lost: the TPM never
held the disk key.

**My box is behind NAT. Will this work?** It is designed to, through the tailnet door. The recovery
door listens on the box's own address, which you cannot reach behind NAT, so for a dead TPM you need
the console.

**Does the key go through Tailscale's servers?** No. The tailnet carries an SSH connection, encrypted
end to end between your keyholder and the door. The coordination server sees that two nodes talked.

**Can it unlock without me?** Only if the approver you configure says yes. The project ships
an approver that asks a person at a terminal. If you want unattended unlocks for planned reboots, you write that rule
yourself, against a small contract, and you own the risk.

**Does it work with headscale?** It is designed to. The test plan is to run its virtual machine
scenarios against headscale every week and before every release, once those scenarios exist.

**I use dropbear-initramfs today.** tailnet-unlock replaces it (two SSH servers cannot share early
boot), and the package conflicts with `dropbear-initramfs`, so apt removes it when you install this
one. Copy your authorized keys into `delivery_keys` or `operator_keys` yourself; carrying them over
with `enroll --import-dropbear-initramfs` is planned. Your old host keys are not reused, because
they sat in plain text on `/boot`.

**I keep my host keys in my own secret store.** You can import the door's key instead of letting the
box generate it (`door-keygen --import`). It is sealed to the TPM the same way, and you know its
fingerprint in advance.

**My root key file lived on the box until now. Is that history gone after setup?** No. Deleting the
key file removes the current copies only (the planned `commit` will do the same, and no more). Old copies survive in ZFS snapshots, in backups of `/boot` or of the
root, and in freed disk blocks. Giving the pool a new key (`zfs change-key`) stops an old key from
opening the pool by itself, but the key that actually encrypts your data, ZFS's master key, only
changes if you re-encrypt the data (send and receive it into a new encrypted dataset). Treat the old key
as exposed: rekey, delete the snapshots and backups you can, and re-encrypt if old copies may have left
your hands.

**I set this up and the box did not unlock.** That is why you keep the old key file until a
reboot has been unlocked through the door. The planned rehearsal makes the box wait a few minutes for
a delivery and then boot with its old local key; the waiting-then-fall-back step is in the boot scripts
already, but 0.1.0 has no command that turns it on, so use the console prompt and the key you kept.

## How it compares

- **dropbear-initramfs, `cryptroot-unlock`, `zfsunlock`:** the remote prompt this builds on. tailnet-unlock
  adds the tailnet, a sealed identity, and delivery with approvals.
- **Clevis with Tang, Mandos:** unlock when a server on the network answers. Convenient, and the box
  unlocks wherever that server is reachable, without a person deciding.
- **TPM auto-unlock:** the most convenient, and a stolen machine boots to a running system.

tailnet-unlock sits between them: unattended reboots stay possible through an approver you trust, but
the key never lives on the machine and every unlock is a decision.

## Roadmap

After 0.1.0 the order is: delivery and approvals (the keyholder, built for 0.2.0), then the rehearsal, `commit` and the other lifecycle commands, then dracut for Debian 14, the `measured`
profile, and LUKS. The design, the test plan and the table of what is built are in
[DESIGN.md](DESIGN.md), and every release's changes are in [CHANGELOG.md](CHANGELOG.md).

## Where to ask

Questions, doubts about the design and bug reports are welcome as
[issues](https://github.com/foreverworks/tailnet-unlock/issues). A security problem goes through the
private route in [SECURITY.md](SECURITY.md), not a public issue.

## License

MIT. See [LICENSE](LICENSE).
