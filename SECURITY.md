# Security policy

tailnet-unlock sits in early boot and handles the key that opens an encrypted root, so a
vulnerability here matters. Thank you for reporting one responsibly.

## State of the software

tailnet-unlock is unfinished and has no release. The door, the sealing of its key to the TPM, the
initramfs hook and the boot scripts exist and are tested in a Debian 13 container; the commands that
set up and run a real box end to end do not (see [README.md](README.md) and section 16 of
[DESIGN.md](DESIGN.md)). It has had no independent security audit. Do not rely on it to protect, or
to keep you able to reach, a machine you cannot get to by other means.

Because it runs in early boot, a fault can leave a remote machine waiting at a prompt. Keep a
console (a provider's KVM or serial console, a rescue system, a person on site), test on a machine
you can afford to lose access to first, and keep at least two copies of the root key that do not
depend on the box. The way back in for each failure is described in the README under "If something
goes wrong".

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting instead:

1. Open this repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Describe what you found, how to reproduce it, and what an attacker gains.

Only the maintainers can read the report. We aim to acknowledge it within a week and to tell you what
we plan to do about it. Please give us a reasonable time to fix the problem before you disclose it.

## What is in scope

- The initramfs scripts (`initramfs/`): the door, the supervisor, the unseal step, the panic handler
  and the hook that builds the image.
- The command line tool and its Python package (`src/tailnet_unlock/`): configuration, rendering,
  sealing, key handling and the keyholder side of the approval.
- The way the door key, the root key and the approval are handled: anything that leaks a key, accepts
  a forged or replayed approval, lets an unauthorised party present the door's identity, or leaves a
  box unable to boot when it should have a way in.
- The test and CI workflows, where they could leak secrets or run untrusted code.

## What is out of scope

The threat model, with its adversaries, what the design defends and what it says it does not, is in
section 6 of [DESIGN.md](DESIGN.md). Behaviour that section lists as not defended (for example an evil
maid modifying `/boot` under the default `tpm` profile, root on the running box, or a compromised
keyholder) is a known limit, not a vulnerability. If you think a limit is described wrongly, that is
worth reporting.

Vulnerabilities in Tailscale, headscale, dropbear, the Linux kernel or other software we build on
belong with their own projects.
