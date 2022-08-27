# Using an older version of rust so LLVM 13 is used by both rustc and cargo-bpf
RUST_VERSION=1.56
RUSTUP=rustup run $(RUST_VERSION)

.PHONY: install
install:
	rustup install $(RUST_VERSION)

.PHONY: clean-probes
clean-probes:
	cd probes && $(RUSTUP) cargo clean

.PHONY: clean-agent
clean-agent:
	$(RUSTUP) cargo clean

.PHONY: clean
clean: clean-probes clean-agent

.PHONY: build-probes
build-probes:
	cd probes && $(RUSTUP) cargo bpf build --target-dir=../target

build-agent:
	$(RUSTUP) cargo build

.PHONY: build
build: build-probes build-agent

.PHONY: release
release: clean build

.PHONY: run
run:
	sudo target/debug/netmon $(INTERFACE)