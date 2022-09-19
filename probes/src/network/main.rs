#![no_std]
#![no_main]

use core::mem::{self, MaybeUninit};
use memoffset::offset_of;
use probes::common::{SocketAddress, IPv6Address};
use redbpf_probes::socket_filter::prelude::*;
use probes::network::{PacketMetadata, Protocol, TrafficClass};

program!(0xFFFFFFFE, "GPL");

/// Packet Metadata contains information about packets transiting the network.
/// This is used in user space for further packet processing.
#[map(link_section = "maps/packet_metadata")]
static mut PACKET_METADATA: HashMap<u16, PacketMetadata> = HashMap::with_max_entries(1024);

/// Filter packets from the network, categorizing 
#[socket_filter]
pub fn filter_network(skb: SkBuff) -> SkBuffResult {
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

    let ip_id = skb.load::<__u16>(eth_hdr_len + offset_of!(iphdr, id))?;

    // TODO: Actual IPv6 support
    if ip_hdr.version() != 4 {
        return Ok(SkBuffAction::Ignore);
    }

    // Note: TCP and UDP ports are at the same offsets (bytes 0-1, 2-3 in the header)
    let ip_hdr_len = ((skb.load::<u8>(eth_hdr_len)? & 0x0F) << 2) as usize;
    let src = SocketAddress::new(
        IPv6Address::from_v4u32(skb.load::<__be32>(eth_hdr_len + offset_of!(iphdr, saddr))?),
        skb.load::<__be16>(eth_hdr_len + ip_hdr_len + offset_of!(tcphdr, source))?,
    );
    let dst = SocketAddress::new(
        IPv6Address::from_v4u32(skb.load::<__be32>(eth_hdr_len + offset_of!(iphdr, daddr))?),
        skb.load::<__be16>(eth_hdr_len + ip_hdr_len + offset_of!(tcphdr, dest))?,
    );

    // Attempt to classify the traffic
    let mut class: TrafficClass = TrafficClass::UNCLASSIFIED;
    // TODO: Doesn't account for DNS over other ports, overly simplistic.
    if src.port == 53 || dst.port == 53 {
        class = TrafficClass::DNS;
    } else {
        // Maybe TLS?
        // compute the start of the TLS payload
        let tcp_len = ((skb.load::<u8>(eth_hdr_len + ip_hdr_len as usize + 12)? >> 4) << 2) as usize;
        let tls = eth_hdr_len + ip_hdr_len + tcp_len;
        let content_type: u8 = skb.load(tls)?;
        let record_version: u16 = skb.load(tls + 1)?;
        if content_type == 0x16 
            // Record version should be one of:
            // SSLv3 (0x0300), TLS 1.0 (0x0301), TLS 1.1 (0x0302), TLS 1.2 (0x0303), TLS 1.3 (0x0304)
            // Note: During Client Hello, version is always specified as 0x0301.
            && (record_version == 0x0300 || record_version == 0x0301 || record_version == 0x0302 || record_version == 0x0303 || record_version == 0x0304) 
        {
            class = TrafficClass::TLS;
        }
    }
   
    // Add the packet metadata to the map for user space.
    if class != TrafficClass::UNCLASSIFIED {
        unsafe {
            let metadata = PacketMetadata::new(
                src,
                dst,
                (*skb.skb).len as usize,
                raw_ip_proto,
                class.to_u64(),
            );

            // TODO: Come up with a more unique key. This will eventually collide, even though
            // the user space program is keeping up in most cases.
            // Probably a 5-tuple of (src_ip, src_port, dst_ip, dst_port, ip id).
            PACKET_METADATA.set(&ip_id, &metadata);
            return Ok(SkBuffAction::SendToUserspace);
        }
    }

    Ok(SkBuffAction::Ignore)
}