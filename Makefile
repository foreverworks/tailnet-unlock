# Every tier, locally, with one command: `make test` (needs rootless or rootful docker).
# Inside the test container (or any Debian 13 host with the same packages) the tiers run alone:
#   make lint unit          what CI's check job runs, on any machine with dash and busybox
#   make tpm initramfs      swtpm, dropbear and mkinitramfs; the test container only
#   make tcg                one real boot of the image under QEMU TCG with swtpm (about 1 minute)
#   make vm-test            the VM scenarios on a host with KVM, QEMU, OVMF and swtpm

PYTHON ?= python3
BUILD_ARGS ?=
IMAGE ?= tailnet-unlock-test:$(shell sha256sum tests/container/Dockerfile | cut -c1-12)
DOCKER ?= docker
RUN = $(DOCKER) run --rm -e TU_TEST_CONTAINER=1 -v "$(CURDIR)":/src -w /src
SHELL_SCRIPTS = initramfs/door initramfs/supervise initramfs/unseal initramfs/lib.sh \
	initramfs/paths.sh initramfs/init-premount initramfs/init-bottom initramfs/panic \
	initramfs/zfs-load-key initramfs/hook initramfs/post-update tools/install-tree
PYTEST = $(PYTHON) -m pytest -p no:cacheprovider

.PHONY: test lint unit tpm initramfs tcg vm-test image check

check: lint unit

lint:
	shellcheck --shell=sh $(SHELL_SCRIPTS)
	$(PYTHON) -m mypy
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) tools/check_ignores.py

unit:
	$(PYTEST) tests/unit tests/shell

tpm:
	TU_TEST_CONTAINER=1 $(PYTEST) tests/tpm

initramfs:
	TU_TEST_CONTAINER=1 $(PYTEST) tests/initramfs

tcg:
	TU_TEST_CONTAINER=1 TU_TCG=1 $(PYTEST) tests/vm/test_tcg_smoke.py

vm-test:
	$(PYTEST) tests/vm/test_scenarios.py

image:
	$(DOCKER) build -q $(BUILD_ARGS) -t $(IMAGE) tests/container >/dev/null

test: image
	$(RUN) $(IMAGE) make lint unit tpm
	$(RUN) --privileged $(IMAGE) make initramfs tcg
