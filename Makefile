# Using an older version of rust so LLVM 13 is used by both rustc and cargo-bpf
RUST_VERSION=1.56
RUSTUP=rustup run $(RUST_VERSION)

.PHONY: install
install:
	rustup install $(RUST_VERSION)

.PHONY: clean
clean:
	$(RUSTUP) cargo clean && cd probes && $(RUSTUP) cargo clean

.PHONY: build-probes
build-probes:
	cd probes && $(RUSTUP) cargo bpf build --target-dir=../target

build-userspace:
	$(RUSTUP) cargo build

.PHONY: build
build: build-probes build-userspace

.PHONY: run
run:
	sudo target/debug/netmon $(INTERFACE)