# tailnet-unlock

**Reboot your encrypted Debian box from anywhere, without leaving its key on the machine.**

tailnet-unlock puts a small, locked-down SSH door into early boot and gives it its own place on your
tailnet, so the box asks for its key over Tailscale (or headscale) even when it sits behind a home
router with no public address. The door's identity is sealed to the machine's TPM, so a copied disk
cannot pretend to be your box. The key comes from you, or from a machine you trust after an approval
you control.

> **Status: design, not yet usable.** This repository holds the design ([DESIGN.md](DESIGN.md)) and
> nothing you can install yet. Read it, question it, open an issue. The first release will cover
> Debian 13 with an encrypted ZFS root.

## Who this is for

You run Debian on a machine you cannot sit in front of: a rented server, a box in a closet at a
relative's house, a small machine behind a router you do not control. Its root file system is
encrypted, because a disk that leaves the building should be useless to whoever takes it.

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

## What tailnet-unlock does

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
   wiped from memory, and your system's own Tailscale node comes up as usual.

## Why sealing to the TPM matters

Without it, the door's identity is a set of files on `/boot`. Anyone who copies the disk, or just the
`/boot` partition, gets a door that looks exactly like yours: it can join your tailnet as your box and
present your box's SSH host key. The next time something sends the key, it may send it to the copy.

With the identity sealed, the copy holds ciphertext that only your machine's TPM can open. It cannot
join the tailnet. It cannot present the host key your keyholder expects, and your keyholder will not
send the key to anything else.

And because the TPM holds only the door, never the disk key, losing the TPM loses the door and nothing
else. Your data is still yours: you unlock once at the console or through the recovery door, and make
a new door.

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
- Fallbacks that never strand you: the uplink when the tailnet is down, a recovery door when the TPM
  is cleared, the console always.
- Debian packages, and a single-file keyholder for machines that are not Debian.

## The security model in plain words

**It protects your data against:**

- someone who takes the disks, or copies them, or copies `/boot`;
- a device on your tailnet that has been taken over;
- whoever runs the coordination server: it can route traffic, but it cannot read the key or pose as
  your door, because SSH runs end to end and the door's host key is pinned;
- replayed approvals: each approval is for one boot of one door, once.

**It relies on you for:**

- **a stolen whole machine.** The thief can boot it and the door will appear. The key is not on the
  machine, so the root stays closed unless an approver says yes. The approval shows where the door is
  connecting from and whether the reboot was planned. Say no to what you do not recognise.

**It does not protect against, by default:**

- **someone who modifies `/boot` and leaves** (an "evil maid", or a hosting provider's rescue system).
  The default profile trusts the TPM, not what booted. The `measured` profile, planned for machines
  with systemd-boot and a unified kernel image, closes this gap.

**It never protects against:** root on the running system, a compromised keyholder, firmware you do
not control, or someone who can cut the network (the console still works).

## Requirements (planned)

- Debian 13 with initramfs-tools.
- Root on ZFS with native encryption. LUKS comes later.
- A TPM 2.0 (`/dev/tpmrm0` exists), with its owner hierarchy left at the default empty authorization.
- Tailscale 1.86 or later on the box (1.104.7 is current), or a headscale server.
- A wired uplink with IPv4.
- Room on `/boot`: each initramfs grows by the size of `tailscaled`. `enroll` checks before it writes.
- A keyholder: any machine with Python 3.13 or later and an SSH client, and a place to keep the key
  (a password manager, SOPS, a file on an encrypted disk: anything that prints it on request).

## Questions people ask

**Do I still need a console?** Not for normal use. Keep one possible (a provider's KVM, a serial
console, a person on site): it is the last fallback, and the only one when the TPM fails on a box
behind NAT.

**What happens after a kernel update?** In the default profile, nothing: the door is rebuilt into the
new initramfs and opens as before. The `measured` profile re-seals for the new kernel before you reboot
and keeps the old kernel working too.

**What if the TPM dies, or I clear it?** The door cannot open its identity, so the box offers the
recovery door (on its own address) and the console. Unlock once, run `tailnet-unlock enroll
--replace`, and you have a new door. No data is lost: the TPM never held the disk key.

**My box is behind NAT. Will this work?** Yes, through the tailnet door. The recovery door listens on
the box's own address too, which you cannot reach behind NAT, so for a dead TPM you need the console.

**Does the key go through Tailscale's servers?** No. The tailnet carries an SSH connection, encrypted
end to end between your keyholder and the door. The coordination server sees that two nodes talked.

**Can it unlock without me?** Only if the approver you configure says yes. The project ships approvers
that ask a person. If you want unattended unlocks for planned reboots, you write that rule yourself,
against a small contract, and you own the risk.

**Does it work with headscale?** It is designed to, and the test suite runs against headscale on every
change.

**I use dropbear-initramfs today.** tailnet-unlock replaces it (two SSH servers cannot share early
boot). `enroll` can carry over your authorized keys. Your old host keys are not reused, because they sat
in plain text on `/boot`.

**What key format should my root use?** Any works for delivery. For the console fallback, a long
generated passphrase you can type is easier to type at a console than 64 hex characters.

**I set this up and the box did not unlock.** That is what the rehearsal is for: during setup, the box
waits a few minutes for a delivery and then boots with its old local key. You only remove the local key
(`commit`) after a reboot that the door actually unlocked.

## How it compares

- **dropbear-initramfs, `cryptroot-unlock`, `zfsunlock`:** the remote prompt this builds on. tailnet-unlock
  adds the tailnet, a sealed identity, and delivery with approvals.
- **Clevis with Tang, Mandos:** unlock when a server on the network answers. Convenient, and the box
  unlocks wherever that server is reachable, without a person deciding.
- **TPM auto-unlock:** the most convenient, and a stolen machine boots to a running system.

tailnet-unlock sits between them: unattended reboots stay possible, but the key never lives on the
machine and every unlock is a decision.

## Roadmap

Design (now), then the uplink door, the tailnet door, delivery and approvals, packaging and a first
release for Debian 13 with ZFS, then dracut for Debian 14, the `measured` profile, and LUKS. Details and
the test plan are in [DESIGN.md](DESIGN.md).

## License

MIT. See [LICENSE](LICENSE).
