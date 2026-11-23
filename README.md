# tailnet-unlock

**Unlock the encrypted ZFS root of a remote Debian machine from anywhere on your tailnet, with the
key kept off the machine.**

tailnet-unlock puts a small, locked-down SSH door into early boot and gives it its own place on your
tailnet (Tailscale or headscale), so a box behind a home router with no public address can still ask
for its key after a reboot. The door's identity is sealed to the machine's TPM, so a copied disk
cannot pretend to be your box. The key comes from you, or from a machine you trust after an approval
you control.

> **Status: unfinished, and not for a machine you cannot reach.** There is no release and no
> package. The repository holds the design ([DESIGN.md](DESIGN.md)) and the first parts of it, with
> their tests: sealing the door's key to the TPM, the door itself, the initramfs hook and the boot
> scripts. The pieces that make it usable are not written yet: `enroll`, the safe test reboot
> (rehearsal), `deliver`, `unlock`, `watch`, `verify`, and the Debian packages. Without them you
> cannot set up a real box end to end. Most of this page describes what is planned, and says so.
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
  swap area on a disk is active (zram is RAM and does not count): run `swapoff -a` first. If that is
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
public address and you only need to type a passphrase over SSH, `dropbear-initramfs` is simpler. Today
it is also not for anyone who needs something that installs and works: see the status above.

## The usual answers, and what they give up

- **Keep the key in the initramfs.** The box boots on its own. So does a stolen disk.
- **Let the TPM unlock the disk** (Clevis, `systemd-cryptenroll`). The box boots on its own. So does a
  stolen machine, all the way to a running system.
- **dropbear-initramfs and type the key over SSH.** Works if the box has a public address you can
  reach, and if you trust a host key that sits in plain text on `/boot`, where anyone with a copy of
  the disk can read it.
- **Behind NAT,** none of the SSH answers reach the box at all.

## What you need

To run what exists today (the checks and a rendering of the boot configuration), on a Linux machine:

- Python 3.13 or later. The tool uses the standard library only.
- To run the checks: `shellcheck`, plus `dash` or `busybox` (the shell tests run under whichever is
  installed, and CI uses both), from your package manager (`apt install shellcheck dash busybox` on
  Debian); and `mypy`, `ruff` and `pytest`, which the next section installs into a virtual
  environment at the versions in [`.github/workflows/check.yml`](.github/workflows/check.yml).
- To run the full local test suite (`make test`): Docker. It builds a Debian 13 test image and runs
  swtpm (a software TPM), dropbear and a real `mkinitramfs` in it. Nothing touches the TPM, the disks
  or the boot of the machine you run it on.

To go further, on a machine you can afford to lose access to: Debian 13 with initramfs-tools, root on
ZFS with native encryption, a TPM 2.0, a console, and the other requirements below. All of it is free
software, and nothing here costs money beyond the machine.

## Try it

There is nothing to install from a release. Work from a checkout of the repository.

**1. Run the checks** (about two minutes). Install `shellcheck` and `dash` (or `busybox`) with your
package manager first, then:

```
git clone https://github.com/foreverworks/tailnet-unlock
cd tailnet-unlock
python3 -m venv .venv
.venv/bin/pip install mypy==2.4.1 ruff==0.17.6 pytest==9.2.0
PATH=$PWD/.venv/bin:$PATH make check
```

The last line should look like `212 passed in 98s`; the count grows as tests are added. `make check` runs
`shellcheck`, `mypy`, `ruff` and the unit and shell tests. With Docker, `make test` also runs the TPM
tests, the image tests and one real boot under QEMU.

**2. Render the boot configuration** the way the initramfs hook does, from the example in
[`examples/box.toml`](examples/box.toml). This writes two files to a scratch directory, and does not
touch the TPM or the machine's boot:

```
mkdir -p scratch/etc
cp examples/box.toml scratch/etc/box.toml
ssh-keygen -q -t ed25519 -N '' -C keyholder -f scratch/keyholder
cp scratch/keyholder.pub scratch/etc/delivery_keys
PYTHONPATH=src python3 -m tailnet_unlock render-initramfs \
    --config-dir scratch/etc --out scratch/out --host box --uplink-mac 00:00:5e:00:53:01
cat scratch/out/tailnet-unlock.conf
```

Expect `TU_BACKEND=zfs`, `TU_PORT=2222`, `TU_UNLOCK_HOSTNAME=box-unlock` and the other values the boot
scripts read. `scratch/out/authorized_keys` holds your key with the options that limit it to the door's
one command. A mistake in `box.toml` stops the command with a message that says what is wrong.

**3. See where the files would go**, without installing anything:

```
sh tools/install-tree scratch/root
```

This copies the hook, the boot scripts, the ZFS key-loading extension and the Python package to the
paths the Debian package will use, under `scratch/root`. Run it with no argument and it installs into
`/`, which belongs in a test virtual machine and nowhere else.

The commands that touch the TPM are `door-keygen` and `seal`. They need a real or software TPM at
`/dev/tpmrm0`, and the tests run them against swtpm. Run them yourself only on a machine you are
prepared to lose access to.

## If something goes wrong

These are the ways back in, in the order to try them. Several belong to parts that are planned, so
read each as what the design promises, not as something to rely on today.

- **The console is the last way in and always works.** Keep a console you can reach before you change
  anything about early boot: a provider's KVM or serial console, a rescue system, a person on site.
  The boot scripts are written so that when the door cannot start, the console prompt for the root
  key remains.
  On a box behind NAT whose TPM fails, the console is the only way.
- **Never remove your old way of unlocking until a door unlock has worked.** The design keeps the
  box's old local key file until a reboot has been unlocked through the door. The safe test reboot
  (rehearsal, then `commit`) that enforces this is not built yet. Until it is, do not delete a local
  key by hand on the strength of this software.
- **Back out of the initramfs hook.** The hook only adds files to the initramfs. If a box fails to
  boot with it, boot a rescue system, unlock the root pool, chroot into it, remove the files that
  `tools/install-tree` lists (`/usr/share/initramfs-tools/hooks/tailnet-unlock`, the scripts under
  `/usr/share/initramfs-tools/scripts/` named `tailnet-unlock`,
  `/usr/share/initramfs-tools/conf.d/tailnet-unlock`,
  `/etc/zfs/initramfs-tools-load-key.d/tailnet-unlock`,
  `/etc/initramfs/post-update.d/tailnet-unlock` and `/usr/lib/tailnet-unlock`), and run
  `update-initramfs -u -k all` to rebuild without it.
- **The hook never fails a kernel update.** If a part is missing or `/boot` is too small, the build
  prints a `W: tailnet-unlock:` warning and carries on with less (the tailnet door, then the sealed
  door, then any door), and the box still boots through the console prompt.
- **If the TPM is cleared or replaced,** the sealed door key cannot be opened. The recovery door (below)
  can answer on the box's own address if you enabled it. Otherwise use the console. No data is lost:
  the disk key was never in the TPM.

## What tailnet-unlock is designed to do

1. **Early boot opens a door.** The initramfs brings up the network, starts a minimal SSH server and a
   Tailscale node of its own, `<host>-unlock`. The door answers on your tailnet and on the box's own
   address. Behind NAT, the tailnet is how you reach it. The SSH server and the network are built;
   the tailnet node's identity is not, because `enroll` is not written.
2. **The door can only do one thing.** Every login runs one command: report its status, or accept a
   key. No shell, no forwarding, keys only. Built.
3. **The door's identity is sealed to the TPM.** Its SSH host key and its tailnet node keys are
   encrypted by the machine's own TPM. They open on this machine and nowhere else. The host key's
   sealing is built; the node keys are sealed by Tailscale's own `--encrypt-state`.
4. **The key stays with you.** It lives on a **keyholder**: your laptop, a CI job, a small server at
   home. You can type it in, or let the keyholder deliver it after an **approver** says yes. You decide
   what an approval is: a touch of your security key over SSH, a button in your own system, anything
   that can run a program. The rules for an approval are written and tested as code; the commands
   that use them are not built.
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
yours to make: the recovery door below, which you unlock by hand (`unlock --recovery`), or
automatically only if you turn that on and your approver confirms it.

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

## What the first release is planned to include

Each item says whether it exists in the repository today.

- initramfs-tools integration for Debian 13: built. A dracut module for Debian 14: not built.
- The ZFS backend: built. LUKS, with the same door: not built.
- A `tailnet-unlock` command on the box: `door-keygen`, `seal`, `render-initramfs`, `pins` and
  `fingerprint` are built. `enroll`, the **rehearsal** reboot that falls back to your old key if
  anything goes wrong, `commit`, `rotate`, `disable` and `verify` are not.
- A keyholder: `unlock` for you at a terminal, `deliver` for automation, `watch` to notice a box
  waiting at its door after a reboot nobody planned. Not built; the door's side of delivery is.
- A small, documented approver contract (JSON in, JSON out): the contract is built as code and
  tests. The complete approver that needs nothing but SSH is not built.
- An example tailnet policy, with tests, where the door can reach nothing and only your keyholders and
  operators can reach the door. Not written.
- Fallbacks: the box's own address when the tailnet is down, the recovery door after a TPM clear
  where you enabled it and can reach it, and the console. For a box behind NAT whose TPM failed, the
  console is the only way back. The uplink door, the recovery door and the console prompt are built.
- Debian packages, and a single-file keyholder for machines that are not Debian. Not built.

Nothing in this list has yet run on real hardware, and the virtual machine scenarios that boot a real
ZFS root are written and have not been run.

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

## Requirements (planned)

- Debian 13 with initramfs-tools, and the `contrib` archive component enabled (ZFS lives there).
- Root on ZFS with native encryption. LUKS comes later.
- A TPM 2.0 (`/dev/tpmrm0` exists), with its owner hierarchy left at the default empty authorization.
  No TPM, no tailnet-unlock.
- Tailscale 1.86 or later on the box, or a headscale server.
- A wired uplink with IPv4.
- Room on `/boot`: each initramfs grows by about 22 MB (compressed) for `tailscaled`. The build checks
  before it writes, and leaves the tailnet door out of an image that would not fit.
- A keyholder: any machine with Python 3.13 or later and an SSH client, and a place to keep the key
  (a password manager, SOPS, a file on an encrypted disk: anything that prints it on request).

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
`tailnet-unlock enroll --replace` (planned), and you have a new door. No data is lost: the TPM never
held the disk key.

**My box is behind NAT. Will this work?** It is designed to, through the tailnet door. The recovery
door listens on the box's own address, which you cannot reach behind NAT, so for a dead TPM you need
the console.

**Does the key go through Tailscale's servers?** No. The tailnet carries an SSH connection, encrypted
end to end between your keyholder and the door. The coordination server sees that two nodes talked.

**Can it unlock without me?** Only if the approver you configure says yes. The project will ship
approvers that ask a person. If you want unattended unlocks for planned reboots, you write that rule
yourself, against a small contract, and you own the risk.

**Does it work with headscale?** It is designed to. The test plan is to run its virtual machine
scenarios against headscale every week and before every release, once those scenarios exist.

**I use dropbear-initramfs today.** tailnet-unlock replaces it (two SSH servers cannot share early
boot). `enroll` is planned to carry over your authorized keys. Your old host keys are not reused,
because they sat in plain text on `/boot`.

**I keep my host keys in my own secret store.** You can import the door's key instead of letting the
box generate it (`door-keygen --import`). It is sealed to the TPM the same way, and you know its
fingerprint in advance.

**My root key file lived on the box until now. Is that history gone after setup?** No. `commit`
removes the current copies only. Old copies survive in ZFS snapshots, in backups of `/boot` or of the
root, and in freed disk blocks. Giving the pool a new key (`zfs change-key`) stops an old key from
opening the pool by itself, but the key that actually encrypts your data, ZFS's master key, only
changes if you re-encrypt the data (send and receive it into a new encrypted dataset). Treat the old key
as exposed: rekey, delete the snapshots and backups you can, and re-encrypt if old copies may have left
your hands.

**I set this up and the box did not unlock.** That is what the rehearsal is for: during setup, the box
waits a few minutes for a delivery and then boots with its old local key. You only remove the local key
(`commit`) after a reboot that the door actually unlocked. The waiting-then-fall-back step is built
into the boot scripts; the commands that start and end a rehearsal are not.

## How it compares

- **dropbear-initramfs, `cryptroot-unlock`, `zfsunlock`:** the remote prompt this builds on. tailnet-unlock
  adds the tailnet, a sealed identity, and delivery with approvals.
- **Clevis with Tang, Mandos:** unlock when a server on the network answers. Convenient, and the box
  unlocks wherever that server is reachable, without a person deciding.
- **TPM auto-unlock:** the most convenient, and a stolen machine boots to a running system.

tailnet-unlock sits between them: unattended reboots stay possible through an approver you trust, but
the key never lives on the machine and every unlock is a decision.

## Roadmap

The order is: the tailnet door and its enrollment, delivery and approvals, then the lifecycle
commands and packaging for a first release on Debian 13 with ZFS. After that come dracut for Debian
14, the `measured` profile, and LUKS. The design, the test plan and the table of what is built are in
[DESIGN.md](DESIGN.md).

## Where to ask

Questions, doubts about the design and bug reports are welcome as
[issues](https://github.com/foreverworks/tailnet-unlock/issues). A security problem goes through the
private route in [SECURITY.md](SECURITY.md), not a public issue.

## License

MIT. See [LICENSE](LICENSE).
