#![no_std]
#![no_main]

use core::mem::{self, MaybeUninit};
use memoffset::offset_of;
use probes::common::{SocketAddress, IPv6Address};
use redbpf_probes::socket_filter::prelude::*;
use probes::network::{PacketMetadata, Protocol, TrafficClass};

program!(0xFFFFFFFE, "GPL");

/// Packet Metadata contains information about packets transiting the network.
/// This is used in user space for further packet processing and (future, #5) flow stats.
#[map(link_section = "maps/packet_metadata")]
static mut PACKET_METADATA: PerfMap<PacketMetadata> = PerfMap::with_max_entries(10240);

/// Filter packets from the network, categorizing 
#[socket_filter]
pub fn filter_network(skb: SkBuff) -> SkBuffResult {
    // We'll need the ethernet header length to determine offsets down the line.
    let eth_len = mem::size_of::<ethhdr>();

    // Only IP packets supported at the moment.
    let eth_proto = skb.load::<__be16>(offset_of!(ethhdr, h_proto))? as u32;
    if eth_proto != ETH_P_IP {
        return Ok(SkBuffAction::Ignore);
    }

    // Capture the IP protocol (e.g., TCP, UDP), and exit if it's not one 
    // we support.
    let raw_ip_proto = skb.load::<__u8>(eth_len + offset_of!(iphdr, protocol))? as u64;
    let ip_proto = Protocol::from_u64(raw_ip_proto);
    if ip_proto == Protocol::UNKNOWN {
        return Ok(SkBuffAction::Ignore)
    }

    let mut ip_hdr = unsafe { MaybeUninit::<iphdr>::zeroed().assume_init() };
    ip_hdr._bitfield_1 = __BindgenBitfieldUnit::new([skb.load::<u8>(eth_len)?]);

    // TODO: Actual IPv6 support
    if ip_hdr.version() != 4 {
        return Ok(SkBuffAction::Ignore);
    }

    let ihl = ip_hdr.ihl() as usize;

    // Note: TCP and UDP ports are at the same offsets (bytes 0-1, 2-3 in the header)
    let src = SocketAddress::new(
        IPv6Address::from_v4u32(skb.load::<__be32>(eth_len + offset_of!(iphdr, saddr))?),
        skb.load::<__be16>(eth_len + ihl * 4 + offset_of!(tcphdr, source))?,
    );
    let dst = SocketAddress::new(
        IPv6Address::from_v4u32(skb.load::<__be32>(eth_len + offset_of!(iphdr, daddr))?),
        skb.load::<__be16>(eth_len + ihl * 4 + offset_of!(tcphdr, dest))?,
    );

    let mut class: TrafficClass = TrafficClass::UNCLASSIFIED;

    // Attempt to classify the traffic
    // TODO: Doesn't account for DNS over other ports, overly simplistic.
    if src.port == 53 || dst.port == 53 {
        class = TrafficClass::DNS;
    }

    // Add the packet metadata to the map for user space.
    unsafe {
        PACKET_METADATA.insert(skb.skb as *mut __sk_buff, &PacketMetadata::new(
            src,
            dst,
            (*skb.skb).len as usize,
            raw_ip_proto,
            class.to_u64(),
        ));
    }

    // If the traffic was classified, send to user space for processing.
    if class != TrafficClass::UNCLASSIFIED {
        return Ok(SkBuffAction::SendToUserspace);
    }

    Ok(SkBuffAction::Ignore)
}