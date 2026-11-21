# tailnet-unlock

**Reboot your encrypted Debian box from anywhere, without leaving its key on the machine.**

tailnet-unlock is designed to put a small, locked-down SSH door into early boot and give it its own
place on your tailnet, so the box can ask for its key over Tailscale (or headscale) even when it sits
behind a home router with no public address. The door's identity is to be sealed to the machine's TPM,
so that a copied disk cannot pretend to be your box. The key is to come from you, or from a machine you
trust after an approval you control.

> **Status: design, not yet usable.** This repository holds the design ([DESIGN.md](DESIGN.md)) and
> nothing you can install yet. Everything below describes what is planned. Read it, question it, open
> an issue. The first release will cover Debian 13 with an encrypted ZFS root.

**Three words used throughout:**

- **initramfs**: the small file system Linux runs first, before your real root is mounted. It is where
  the root gets unlocked.
- **tailnet**: your private network of devices joined through Tailscale or a headscale server.
- **TPM**: a chip (or a firmware function) on the motherboard that can encrypt small secrets so that
  only this one machine can decrypt them.

**Two things to know before you read on:**

- **You need a TPM 2.0.** It is a hard requirement. Most rented servers expose none, and many virtual
  machines either have none or have a virtual TPM whose state is copied along with the machine's
  snapshots. A TPM that travels with the snapshot protects nothing, so such a machine is not a fit.
- **There is no hands-off mode.** Every unlock is a decision: you type the key, or an approver you
  configure says yes for that one boot. If you need a box that always boots by itself, this is not the
  tool.

## Who this is for

You run Debian on a machine you cannot sit in front of: a dedicated server with a TPM, a box in a
closet at a relative's house, a small machine behind a router you do not control. Its root file system
is encrypted, because a disk that leaves the building should be useless to whoever takes it.

And so every reboot ends at a password prompt that nobody can see. A power cut at 3 a.m., a kernel
update, a provider's maintenance window: the box sits there, waiting for someone at a keyboard that
does not exist.

## The usual answers, and what they give up

- **Keep the key in the initramfs.** The box boots on its own. So does a stolen disk.
- **Let the TPM unlock the disk** (Clevis, `systemd-cryptenroll`). The box boots on its own. So does a
  stolen machine, all the way to a running system.
- **dropbear-initramfs and type the key over SSH.** Works if the box has a public address you can
  reach, and if you trust a host key that sits in plain text on `/boot`, where anyone with a copy of
  the disk can read it.
- **Behind NAT,** none of the SSH answers reach the box at all.

## What tailnet-unlock will do

1. **Early boot opens a door.** The initramfs brings up the network, starts a minimal SSH server and a
   Tailscale node of its own, `<host>-unlock`. The door answers on your tailnet and on the box's own
   address. Behind NAT, the tailnet is how you reach it.
2. **The door can only do one thing.** Every login runs one command: report its status, or accept a
   key. No shell, no forwarding, keys only.
3. **The door's identity is sealed to the TPM.** Its SSH host key and its tailnet node keys are
   encrypted by the machine's own TPM. They open on this machine and nowhere else.
4. **The key stays with you.** It lives on a **keyholder**: your laptop, a CI job, a small server at
   home. You can type it in, or let the keyholder deliver it after an **approver** says yes. You decide
   what an approval is: a touch of your security key over SSH, a button in your own system, anything
   that can run a program.
5. **The door closes before the system starts.** The tailnet node goes offline, the door's keys are
   deleted from early boot's temporary storage, and your system's own Tailscale node comes up as usual.

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
- **In the `measured` profile, any change to what boots lands the box in recovery, on purpose.** That
  includes a change someone made to `/boot` to steal your key. The default profile is different: its
  sealed key opens whatever boots, so a modified `/boot` opens the sealed door itself (the gap named in
  the security model below), and recovery means the sealed key did not open at all. In both profiles,
  never trust the reason the door prints about itself ("the TPM was cleared"): a tampered door, or a
  copy of `/boot` booted somewhere else, can print anything. Send a key to the recovery door only when
  you know the reason yourself, because you did it or your provider's console shows it.
- Automated delivery refuses the recovery door unless you turn that on and your approver confirms, as
  a separate decision, that it is the recovery door.
- It listens on the box's own address only, never on the tailnet unless you enable that. It is on by
  default in the default profile and off by default in the `measured` profile (below).

## What you will get

- initramfs-tools integration for Debian 13 (a dracut module follows for Debian 14).
- The ZFS backend first; LUKS later, with the same door.
- A `tailnet-unlock` command on the box: `enroll`, a **rehearsal** reboot that falls back to your old
  key if anything goes wrong, `commit`, `rotate`, `disable`, `verify`.
- A keyholder: `unlock` for you at a terminal, `deliver` for automation, `watch` to notice a box
  waiting at its door after a reboot nobody planned.
- A small, documented approver contract (JSON in, JSON out) and a complete approver that needs nothing
  but SSH.
- An example tailnet policy, with tests, where the door can reach nothing and only your keyholders and
  operators can reach the door.
- Fallbacks: the box's own address when the tailnet is down, the recovery door after a TPM clear
  where you enabled it and can reach it, and the console. For a box behind NAT whose TPM failed, the
  console is the only way back.
- Debian packages, and a single-file keyholder for machines that are not Debian.

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

## Requirements (planned)

- Debian 13 with initramfs-tools, and the `contrib` archive component enabled (ZFS lives there).
- Root on ZFS with native encryption. LUKS comes later.
- A TPM 2.0 (`/dev/tpmrm0` exists), with its owner hierarchy left at the default empty authorization.
  No TPM, no tailnet-unlock.
- Tailscale 1.86 or later on the box, or a headscale server.
- A wired uplink with IPv4.
- Room on `/boot`: each initramfs grows by about 22 MB (compressed) for `tailscaled`. `enroll` checks
  before it writes.
- A keyholder: any machine with Python 3.13 or later and an SSH client, and a place to keep the key
  (a password manager, SOPS, a file on an encrypted disk: anything that prints it on request).

## Back up the root key

The root key is the only key to your data. tailnet-unlock never stores it on the box, and the TPM
never holds it, by design, so nothing on the machine can give it back to you. Keep it in at least two
places that do not depend on the box: your password manager, and an offline copy (on paper, in a safe
place). Use a long generated passphrase rather than raw bytes, so you can type it at a console when
everything else is down. Lose every copy and the data is gone.

## Questions people ask

**Do I still need a console?** Not for normal use. Keep one possible (a provider's KVM, a serial
console, a person on site): it is the last fallback, and the only one when the TPM fails on a box
behind NAT.

**What happens after a kernel update?** In the default profile, nothing: the door is rebuilt into the
new initramfs and opens as before. The `measured` profile is planned to re-seal for the new kernel
before you reboot and keep the old kernel working too.

**What if the TPM dies, or I clear it?** The door cannot open its sealed identity, so the box offers
the recovery door on its own address, if enabled, and the console. Unlock once, run
`tailnet-unlock enroll --replace`, and you have a new door. No data is lost: the TPM never held the
disk key.

**My box is behind NAT. Will this work?** Yes, through the tailnet door. The recovery door listens on
the box's own address, which you cannot reach behind NAT, so for a dead TPM you need the console.

**Does the key go through Tailscale's servers?** No. The tailnet carries an SSH connection, encrypted
end to end between your keyholder and the door. The coordination server sees that two nodes talked.

**Can it unlock without me?** Only if the approver you configure says yes. The project will ship
approvers that ask a person. If you want unattended unlocks for planned reboots, you write that rule
yourself, against a small contract, and you own the risk.

**Does it work with headscale?** It is designed to. The test plan is to run its virtual machine
scenarios against headscale every week and before every release, once those scenarios exist and the
project is public.

**I use dropbear-initramfs today.** tailnet-unlock replaces it (two SSH servers cannot share early
boot). `enroll` is planned to carry over your authorized keys. Your old host keys are not reused,
because they sat in plain text on `/boot`.

**I keep my host keys in my own secret store.** You can import the door's key instead of letting the
box generate it. It is sealed to the TPM the same way, and you know its fingerprint in advance.

**My root key file lived on the box until now. Is that history gone after setup?** No. `commit`
removes the current copies only. Old copies survive in ZFS snapshots, in backups of `/boot` or of the
root, and in freed disk blocks. Giving the pool a new key (`zfs change-key`) stops an old key from
opening the pool by itself, but the key that actually encrypts your data, ZFS's master key, only
changes if you re-encrypt the data (send and receive it into a new encrypted dataset). Treat the old key
as exposed: rekey, delete the snapshots and backups you can, and re-encrypt if old copies may have left
your hands.

**I set this up and the box did not unlock.** That is what the rehearsal is for: during setup, the box
waits a few minutes for a delivery and then boots with its old local key. You only remove the local key
(`commit`) after a reboot that the door actually unlocked.

## How it compares

- **dropbear-initramfs, `cryptroot-unlock`, `zfsunlock`:** the remote prompt this builds on. tailnet-unlock
  adds the tailnet, a sealed identity, and delivery with approvals.
- **Clevis with Tang, Mandos:** unlock when a server on the network answers. Convenient, and the box
  unlocks wherever that server is reachable, without a person deciding.
- **TPM auto-unlock:** the most convenient, and a stolen machine boots to a running system.

tailnet-unlock sits between them: unattended reboots stay possible through an approver you trust, but
the key never lives on the machine and every unlock is a decision.

## Roadmap

Design (now), then the door on the box's own address, the tailnet door, delivery and approvals,
packaging and a first release for Debian 13 with ZFS, then dracut for Debian 14, the `measured`
profile, and LUKS. Details and the test plan are in [DESIGN.md](DESIGN.md).

## License

MIT. See [LICENSE](LICENSE).
