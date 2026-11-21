# The test image: Debian 13 with the packages the box uses, taken from Debian itself (the design's
# choice), plus Tailscale from its own repository and the Python development tools from PyPI.
# Base: the official debian:trixie image, digest read on 2026-11-21. The weekly run also builds it
# on debian:forky@sha256:15f483ba923e165dde04ac535be6f479a62008ae5fefb42fed21896288ce447a (read the
# same day), where initramfs-tools is installed explicitly until the dracut module (M5).
ARG BASE=debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6
FROM ${BASE}

ARG TAILSCALE_VERSION=1.104.7
ARG SUITE=trixie
ARG MYPY_VERSION=2.4.1
ARG RUFF_VERSION=0.17.6
ARG PYTEST_VERSION=9.2.0

ENV DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8

# contrib carries zfs-initramfs. INITRD=No keeps the kernel's own postinst from building an image we
# would throw away; the tests build theirs.
RUN sed -i 's/^Components: main$/Components: main contrib/' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && INITRD=No apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg jq \
      busybox dash shellcheck \
      initramfs-tools linux-image-amd64 kmod zstd cpio \
      dropbear-bin \
      tpm2-tools libtss2-tcti-swtpm0t64 libtss2-tcti-device0t64 swtpm swtpm-tools \
      zfs-initramfs zfsutils-linux \
      openssh-client \
      python3 python3-venv \
      qemu-system-x86 qemu-utils ovmf \
 && rm -rf /var/lib/apt/lists/*

# Tailscale from its own apt repository, as the box installs it.
RUN curl -fsSL https://pkgs.tailscale.com/stable/debian/${SUITE}.noarmor.gpg \
      -o /usr/share/keyrings/tailscale-archive-keyring.gpg \
 && curl -fsSL https://pkgs.tailscale.com/stable/debian/${SUITE}.tailscale-keyring.list \
      -o /etc/apt/sources.list.d/tailscale.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends "tailscale=${TAILSCALE_VERSION}" \
 && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/dev \
 && /opt/dev/bin/pip install --no-cache-dir \
      "mypy==${MYPY_VERSION}" "ruff==${RUFF_VERSION}" "pytest==${PYTEST_VERSION}"

ENV PATH=/opt/dev/bin:$PATH
WORKDIR /src
