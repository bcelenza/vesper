.PHONY: install
install:
	cargo install cargo-bpf --no-default-features --features=llvm13,command-line

.PHONY: clean-probes
clean-probes:
	cd probes && cargo clean

.PHONY: clean-agent
clean-agent:
	$(RUSTUP) cargo clean

.PHONY: clean
clean: clean-probes clean-agent

.PHONY: lint
lint:
	cargo clippy

.PHONY: build-probes
build-probes:
	cd probes && cargo bpf build --target-dir=../target

.PHONY: build-agent
build-agent:
	cargo build

.PHONY: build
build: build-probes build-agent

.PHONY: test-agent
test-agent:
	cargo test

.PHONY: test-probes
test-probes:
	cd probes && cargo test

.PHONY: test
test: test-probes test-agent

.PHONY: release
release: clean test build

.PHONY: run
run:
	sudo target/debug/vesper -i $(INTERFACE) -l debug