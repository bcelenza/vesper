#![no_std]
#![no_main]

use core::mem::{self, MaybeUninit};
use memoffset::offset_of;
use probes::{common::{IPv6Address, SocketAddress, SocketPair}, network::{ExpectedTcpFrame, PacketMetadataKey}};
use redbpf_probes::socket_filter::prelude::*;
use probes::network::{PacketMetadata, Protocol, TrafficClass};

program!(0xFFFFFFFE, "GPL");

/// Packet Metadata contains information about packets transiting the network.
/// This is used in user space for further packet processing.
#[map(link_section = "maps/packet_metadata")]
static mut PACKET_METADATA: HashMap<PacketMetadataKey, PacketMetadata> = HashMap::with_max_entries(1024);

/// Expected TCP frames contains information about what TCP segment to expect next
/// in the event an application message (e.g., TLS) is split across multiple TCP segments.
// TODO: This will likely contain orphans due to false positive packet signature matches. Sweeper?
#[map(link_section = "maps/expected_tcp_frames")]
static mut EXPECTED_TCP_FRAMES: HashMap<SocketPair, ExpectedTcpFrame> = HashMap::with_max_entries(1024);

/// Filter packets from the network, categorizing and sending to user space for processing.
#[socket_filter]
pub fn filter_network(skb: SkBuff) -> SkBuffResult {
    let packet_size = unsafe { (*skb.skb).len as usize };

    // We'll need the ethernet header length to determine offsets down the line.
    let eth_hdr_len = mem::size_of::<ethhdr>();

    // Only IP packets supported at the moment.
    let eth_proto = skb.load::<__be16>(offset_of!(ethhdr, h_proto))? as u32;
    if eth_proto != ETH_P_IP {
        return Ok(SkBuffAction::Ignore);
    }

    // Capture the IP protocol (e.g., TCP, UDP), and exit if it's not one
    // we support.
    let raw_ip_proto = skb.load::<__u8>(eth_hdr_len + offset_of!(iphdr, protocol))? as u64;
    let ip_proto = Protocol::from_u64(raw_ip_proto);
    if ip_proto == Protocol::UNKNOWN {
        return Ok(SkBuffAction::Ignore)
    }

    let mut ip_hdr = unsafe { MaybeUninit::<iphdr>::zeroed().assume_init() };
    ip_hdr._bitfield_1 = __BindgenBitfieldUnit::new([skb.load::<u8>(eth_hdr_len)?]);
    // TODO: Actual IPv6 support
    if ip_hdr.version() != 4 {
        return Ok(SkBuffAction::Ignore);
    }

    let ip_hdr_len = ((skb.load::<u8>(eth_hdr_len)? & 0x0F) << 2) as usize;
    let ip_total_len = skb.load::<__u16>(eth_hdr_len + offset_of!(iphdr, tot_len))?;
    let ip_id = skb.load::<__u16>(eth_hdr_len + offset_of!(iphdr, id))?;

    // Note: TCP and UDP ports are at the same offsets (bytes 0-1, 2-3 in the header)
    let src = SocketAddress::new(
        IPv6Address::from_v4u32(skb.load::<__be32>(eth_hdr_len + offset_of!(iphdr, saddr))?),
        skb.load::<__be16>(eth_hdr_len + ip_hdr_len + offset_of!(tcphdr, source))?,
    );
    let dest = SocketAddress::new(
        IPv6Address::from_v4u32(skb.load::<__be32>(eth_hdr_len + offset_of!(iphdr, daddr))?),
        skb.load::<__be16>(eth_hdr_len + ip_hdr_len + offset_of!(tcphdr, dest))?,
    );

    // Attempt to classify the traffic
    let mut class: TrafficClass = TrafficClass::UNCLASSIFIED;

    // TODO: Doesn't account for DNS over other ports, overly simplistic.
    let socket_pair = SocketPair{src, dest};
    if src.port == 53 || dest.port == 53 {
        class = TrafficClass::DNS;
    } else {
        if ip_proto == Protocol::TCP {
            let tcp_hdr_len = ((skb.load::<u8>(eth_hdr_len + ip_hdr_len as usize + 12)? >> 4) << 2) as u16;
            let tcp_data_len = ip_total_len - ip_hdr_len as u16 - tcp_hdr_len;
            let seq_num: u32 = skb.load(eth_hdr_len + ip_hdr_len + offset_of!(tcphdr, seq))?;
            // If we're expecting this sequence number, we can optimistically classify.
            if let Some(expected_frame) = unsafe { EXPECTED_TCP_FRAMES.get(&socket_pair) } {
                if seq_num == expected_frame.sequence_num {
                    // If we were expecting this sequence number, we know its class.
                    class = TrafficClass::from_u64(expected_frame.class);

                    // Are we still expecting more?
                    let needed = expected_frame.payload_bytes_needed - tcp_data_len;
                    if needed > 0 {
                        // Replace the expected frame with the next one.
                        unsafe {
                            EXPECTED_TCP_FRAMES.set(&socket_pair, &ExpectedTcpFrame{
                                payload_bytes_needed: needed,
                                sequence_num: seq_num + tcp_data_len as u32,
                                class: expected_frame.class,
                            });
                        }
                    } else {
                        // No more needed, drop the expectation
                        unsafe {
                            EXPECTED_TCP_FRAMES.delete(&socket_pair);
                        }
                    }
                } else {
                    printk!("Unexpected TCP frame receieved: expected=%u, received=%u", expected_frame.sequence_num, seq_num);
                }
            } else {
                // Maybe the start of a TLS message?
                let tls_start = eth_hdr_len + ip_hdr_len + tcp_hdr_len as usize;
                let content_type: u8 = skb.load(tls_start)?;
                let record_version: u16 = skb.load(tls_start + 1)?;
                if content_type == 0x16
                    // Record version should be one of:
                    // SSLv3 (0x0300), TLS 1.0 (0x0301), TLS 1.1 (0x0302), TLS 1.2 (0x0303), TLS 1.3 (0x0304)
                    // Note: During Client Hello, version is always specified as 0x0301.
                    && (record_version == 0x0300 || record_version == 0x0301 || record_version == 0x0302 || record_version == 0x0303 || record_version == 0x0304)
                {
                    class = TrafficClass::TLS;

                    let tls_total_len: u16 = skb.load::<__u16>(tls_start + 3)?;
                    // The amount of TLS data from this packet is the total TCP data length minus the TLS header.
                    let tls_segment_len = tcp_data_len - 5;
                    // If the payload length is less than what the TLS record header says, we know we've got a
                    // fragmented message.
                    if tls_total_len > tls_segment_len {
                        let needed = tls_total_len - tls_segment_len;
                        unsafe {
                            EXPECTED_TCP_FRAMES.set(&socket_pair, &ExpectedTcpFrame{
                                payload_bytes_needed: needed,
                                sequence_num: seq_num + tcp_data_len as u32,
                                class: class.to_u64(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Add the packet metadata to the map for user space.
    if class != TrafficClass::UNCLASSIFIED {
        unsafe {
            let metadata = PacketMetadata{
                src,
                dest,
                length: packet_size,
                protocol: raw_ip_proto,
                class: class.to_u64(),
            };

            let key = PacketMetadataKey {
                socket_pair,
                id: ip_id,
            };
            PACKET_METADATA.set(&key, &metadata);
            return Ok(SkBuffAction::SendToUserspace);
        }
    }

    Ok(SkBuffAction::Ignore)
}