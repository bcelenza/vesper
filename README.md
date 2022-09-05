# Vesper

A security-focused telemetry agent written in Rust using [eBPF](https://ebpf.io/).

## Why?

This project is all about getting deeper in the Rust language and exposing myself to eBPF. It's purely for educational purposes.

## Design Goals

1. Security: It should go without saying. Although eBPF has [mechanisms to protect against unsafe programs](https://ebpf.io/what-is-ebpf#verification), we should consider security at every step of the pipeline.
2. Simplicity: Focus the agent's features on getting and exposing the data. Don't add features that could be done better by another application (e.g., log offload to the cloud).
3. Performance: Keep the packet data path as fast as possible.

## Feature Goals

* Telemetry
  * Data flow statistics for TCP and UDP
  * Protocol-specific diagnostic information (e.g., TCP retransmits)
  * DNS query and response data 
  * TLS negotiation information
* Output
  * JSON logging
  * [CIM](https://www.dmtf.org/standards/cim)-compliant data format
* Configuration
  * Ignore traffic from specific sources/destinations (ideally by CIDR)
  * Attach to multiple network interfaces

## Building From Source

### Prerequisities

* Rust (any version)
* LLVM 13

### Getting Started

1. Clone the repository.
2. Run `make install`

This will install Rust 1.59 so that LLVM 13 is used by both `rustc` and cargo-bpf, which is needed for BPF probes to work. ([Read More](https://github.com/foniod/redbpf#valid-combinations-of-rust-and-llvm-versions))

### Build and Run

Run `make build` to build both the probe and the agent binary, or `make build-probe` / `make build-agent` separately.

You can run the application with:

```
INTERFACE=<interface name, e.g., en0> make run
```