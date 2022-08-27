# Netmon

## Prerequisities

* Rust (any version)
* LLVM 13

## Getting Started

1. Clone the repository.
2. Install the `cargo-bpf` utility: `cargo install cargo-bpf`
3. Run `make install`

This will install Rust 1.56 so that LLVM 13 is used by both `rustc` and cargo-bpf, which is needed for BPF probes to work. ([Read More](https://github.com/foniod/redbpf#valid-combinations-of-rust-and-llvm-versions))

## Build and Run

Run `make build` to build both the probe and the userspace binary, or `make build-probe` / `make build-userspace` separately.

You can run the application with:

```
INTERFACE=<interface name, e.g., en0> make run
```