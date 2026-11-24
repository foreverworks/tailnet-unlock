# Every tier, locally, with one command: `make test` (needs rootless or rootful docker).
# Inside the test container (or any Debian 13 host with the same packages) the tiers run alone:
#   make lint unit          what CI's check job runs, on any machine with dash and busybox
#   make tpm initramfs      swtpm, dropbear and mkinitramfs; the test container only
#   make delivery           deliveries end to end with dropbear and OpenSSH; the test container only
#   make deb                build the .deb and install, upgrade, remove and purge it; the test container only
#   make pyz                build the keyholder's single file into dist/, on any machine
#   make tcg                one real boot of the image under QEMU TCG with swtpm (about 1 minute)
#   make vm-test            the uplink VM scenarios on a host with KVM, QEMU, OVMF and swtpm
#   make vm-tailnet-test    the tailnet VM scenarios: the same host plus openssl and 10.0.2.2 on lo

PYTHON ?= python3
BUILD_ARGS ?=
IMAGE ?= tailnet-unlock-test:$(shell sha256sum tests/container/Dockerfile | cut -c1-12)
DOCKER ?= docker
RUN = $(DOCKER) run --rm -e TU_TEST_CONTAINER=1 -v "$(CURDIR)":/src -w /src
SHELL_SCRIPTS = initramfs/door initramfs/supervise initramfs/unseal initramfs/lib.sh \
	initramfs/paths.sh initramfs/init-premount initramfs/init-bottom initramfs/panic \
	initramfs/zfs-load-key initramfs/hook initramfs/post-update tools/install-tree \
	tools/build-deb packaging/postinst packaging/prerm packaging/postrm
PYTEST = $(PYTHON) -m pytest -p no:cacheprovider

.PHONY: test lint unit tpm delivery initramfs deb pyz tcg vm-test vm-tailnet-test image check

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

delivery:
	TU_TEST_CONTAINER=1 $(PYTEST) tests/delivery

initramfs:
	TU_TEST_CONTAINER=1 $(PYTEST) tests/initramfs

deb:
	TU_TEST_CONTAINER=1 $(PYTEST) tests/package

# the keyholder's single file, for machines that are not Debian
pyz:
	$(PYTHON) tools/build_pyz.py dist

tcg:
	TU_TEST_CONTAINER=1 TU_TCG=1 $(PYTEST) tests/vm/test_tcg_smoke.py

vm-test:
	$(PYTEST) tests/vm/test_scenarios.py

vm-tailnet-test:
	$(PYTEST) tests/vm/test_tailnet_scenarios.py

image:
	$(DOCKER) build -q $(BUILD_ARGS) -t $(IMAGE) tests/container >/dev/null

test: image
	$(RUN) $(IMAGE) make lint unit tpm delivery
	$(RUN) $(IMAGE) make deb
	$(RUN) --privileged $(IMAGE) make initramfs tcg
