# Using an older version of rust so LLVM 13 is used by both rustc and cargo-bpf
RUST_VERSION=1.56
RUSTUP=rustup run $(RUST_VERSION)
CARGO_HOME=/home/$(USERNAME)

.PHONY: install
install:
	rustup install $(RUST_VERSION)

.PHONY: build-probes
build-probes:
	cd probes && $(RUSTUP) cargo bpf build --target-dir=../target

build-userspace:
	$(RUSTUP) cargo build

.PHONY: build
build: build-probes build-userspace

.PHONY: test
test:
	$(RUSTUP) cargo test -- --nocapture

.PHONY: run
run:
	sudo target/debug/netmon