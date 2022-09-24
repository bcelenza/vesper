# Using an older version of rust so LLVM 13 is used by both rustc and cargo-bpf
RUST_VERSION=1.59
RUSTUP=rustup run $(RUST_VERSION)

.PHONY: install
install:
	rustup install $(RUST_VERSION)
	$(RUSTUP) cargo install cargo-bpf --no-default-features --features=llvm13,command-line

.PHONY: clean-probes
clean-probes:
	cd probes && $(RUSTUP) cargo clean

.PHONY: clean-agent
clean-agent:
	$(RUSTUP) cargo clean

.PHONY: clean
clean: clean-probes clean-agent

.PHONY: lint
lint:
	$(RUSTUP) cargo clippy

.PHONY: build-probes
build-probes:
	cd probes && $(RUSTUP) cargo bpf build --target-dir=../target

.PHONY: build-agent
build-agent:
	$(RUSTUP) cargo build

.PHONY: build
build: build-probes build-agent

.PHONY: test-agent
test-agent:
	$(RUSTUP) cargo test

.PHONY: test-probes
test-probes:
	cd probes && $(RUSTUP) cargo test

.PHONY: test
test: test-probes test-agent

.PHONY: release
release: clean test build

.PHONY: run
run:
	sudo target/debug/vesper -i $(INTERFACE) -l debug