_This project is an educational endeavor and is not intended to be production ready. Interested in using this? [Let me know](mailto:bcelenza@gmail.com)._

# Vesper

A security-focused telemetry agent written in Rust using [eBPF](https://ebpf.io/).

## What's provided?

The goal of vesper is to provide _transparency_ around what a host is doing, who it's talking to, and how it's communicating.

All events emitted by Vesper will contain at least 3 entries:

* `time`: The time the agent processed the event, in ISO 8601 format.
* `type`: The type of event. See the types table below.
* `event`: The event details.

The event details will have at least one key that matches the event type.

### Event Types

| Type | Description |
|-|-|
| `DnsQuery` | A Domain Name System (DNS) query. |
| `DnsResponse` | A Domain Name System (DNS) response. |
| `TlsClientHello` | The [Client Hello](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2) portion of a Transport Layer Security (TLS) handshake. |
| `TlsServerHello` | The [Server Hello](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.3) portion of a Transport Layer Security (TLS) handshake. |
| `TlsCertificate` | The [Server Certificate](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.2) portion of a Transport Layer Security (TLS) handshake (TLSv1.2 or lower only). |

### Examples

#### DNS Query and Response

Vesper can provide information about what DNS queries have been made from the host, who responded, and what that response was:

```json
// DNS query made by the host
{
    "time":"2022-09-19T14:41:27.127059667+00:00",
    "type":"DnsQuery",
    "event":{
        "DnsQuery":{
            "source": {"ip":"192.168.109.2","port":54329},
            "destination":{"ip":"192.168.109.1","port":53},
            "id":57975,
            "questions":[
                {"type":"A","name":"connectivity-check.ubuntu.com"}
            ]
        }
    }
}

// Subsequent response received by the host
{
    "time":"2022-09-19T14:41:27.175101163+00:00",
    "type":"DnsResponse",
    "event":{
        "DnsResponse":{
            "source":{"ip":"192.168.109.1","port":53},
            "destination":{"ip":"192.168.109.2","port":54329},
            "id":57975,
            "status":"NoError",
            "authoritative":false,
            "recursive":true,
            "questions":[
                {"type":"A","name":"connectivity-check.ubuntu.com"}
            ],
            "answers":[
                {"type":"A","name":"connectivity-check.ubuntu.com","value":"35.224.170.84"},
                {"type":"A","name":"connectivity-check.ubuntu.com","value":"35.232.111.17"},
                {"type":"A","name":"connectivity-check.ubuntu.com","value":"34.122.121.32"}
            ]
        }
    }
}
```

#### TLS Negotiation

Vesper monitors all TCP traffic to look for packet signatures that match TLS negotiations. It currently provides information for the TLS [Client Hello](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2) and [Server Hello](https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.3) events. If you have a specific compliance need for TLS and cipher usage (e.g., TLS 1.2+ only with FIPS 140-2 ciphers), Vesper can monitor and report on what's actually being used:

```json
// TLS client hello made by the host
{
    "time":"2022-09-19T14:41:24.894583531+00:00",
    "type":"TlsClientHello",
    "event":{
        "TlsClientHello":{
            "source":{"ip":"192.168.109.2","port":33182},
            "destination":{"ip":"35.186.227.140","port":443},
            "version":"TLSv1_2",
            "ciphers":[
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                "TLS_RSA_WITH_AES_256_CBC_SHA"
            ],
            "extensions":[
                { "ServerNameIndicator": ["foo.bar.com"] },
            ]
        }
    }
}

// TLS server hello made by the remote host
{
    "time":"2022-09-19T14:41:24.896369601+00:00",
    "type":"TlsServerHello",
    "event":{
        "TlsServerHello":{
            "source":{"ip":"35.186.227.140","port":443},
            "destination":{"ip":"192.168.109.2","port":33182},
            "version":"TLSv1_2",
            "cipher":"TLS_AES_128_GCM_SHA256"
        }
    }
}
```

If the server is negotiation TLS with a version less than 1.3, Vesper will show the certificate information and remaining validity:

```json
{
  "time": "2022-10-23T16:41:40.356350846+00:00",
  "type": "TlsCertificate",
  "event": {
    "TlsCertificate": {
      "source": { "ip": "20.189.173.12", "port": 443 },
      "destination": { "ip": "192.168.109.2", "port": 52560 },
      "certificate_chain": [
        {
          "issuer": {
            "country": "US",
            "organization": "Microsoft Corporation",
            "organizational_unit": "",
            "common_name": "Microsoft Azure TLS Issuing CA 06"
          },
          "common_name": "*.events.data.microsoft.com",
          "subject_alternative_names": [
            "*.events.data.microsoft.com",
            "events.data.microsoft.com",
            "*.pipe.aria.microsoft.com",
            "pipe.skype.com",
            "*.pipe.skype.com",
            "*.mobile.events.data.microsoft.com",
            "mobile.events.data.microsoft.com",
            "*.events.data.msn.com",
            "events.data.msn.com",
            "*.events.data.msn.cn",
            "events.data.msn.cn",
            "oca.microsoft.com",
            "watson.microsoft.com",
            "*.vortex.data.microsoft.com",
            "vortex.data.microsoft.com"
          ],
          "validity": {
            "not_before": "Sep  8 21:29:54 2022 GMT",
            "not_after": "Sep  3 21:29:54 2023 GMT",
            "remaining": {
              "days": 315,
              "seconds": 17294
            }
          }
        },
        {
          "issuer": {
            "country": "US",
            "organization": "DigiCert Inc",
            "organizational_unit": "www.digicert.com",
            "common_name": "DigiCert Global Root G2"
          },
          "common_name": "Microsoft Azure TLS Issuing CA 06",
          "subject_alternative_names": [],
          "validity": {
            "not_before": "Jul 29 12:30:00 2020 GMT",
            "not_after": "Jun 27 23:59:59 2024 GMT",
            "remaining": {
              "days": 613,
              "seconds": 26299
            }
          }
        }
      ]
    }
  }
}

```

## Design Goals

1. Simplicity: Focus the agent's features on getting and exposing the data. Don't add features that could be done better by another application (e.g., log offload to the cloud).
2. Performance: Keep the packet data path as fast as possible.

## Feature Goals

* Telemetry
  * Data flow statistics for TCP and UDP
  * Protocol-specific diagnostic information (e.g., TCP retransmits)
  * DNS query and response data
  * TLS negotiation information
* Configuration
  * Ignore traffic from specific sources/destinations (ideally by domain or CIDR)
  * Attach to multiple network interfaces
  * Pick and choose what data to collect
  * Policies for higher-level logging (e.g., TLS version, ciphers)

## Building From Source

### Prerequisities

* Rust (any version)
* LLVM 13, clang 13, pkg-config
* libssl-dev or openssl-dev

If you're on unbutu, you can install the required system libraries via:

```bash
apt install build-essential \
    libclang-13-dev \
    libclang-common-13-dev \
    libssl-dev \
    pkg-config
```

### Getting Started

1. Clone the repository.
2. Run `make install`

### Build and Run

Run `make build` to build both the probe and the agent binary, or `make build-probes` / `make build-agent` separately.

You can run the application with:

```
INTERFACE=<interface name, e.g., en0> make run
```
