#![no_std]
#![no_main]

use core::mem::{self, MaybeUninit};
use memoffset::offset_of;
use probes::common::{SocketAddress, IPv6Address};
use redbpf_probes::socket_filter::prelude::*;

program!(0xFFFFFFFE, "GPL");

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
    let ip_proto = skb.load::<__u8>(eth_len + offset_of!(iphdr, protocol))? as u32;
    if ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP {
        return Ok(SkBuffAction::Ignore);
    }

    let mut ip_hdr = unsafe { MaybeUninit::<iphdr>::zeroed().assume_init() };
    ip_hdr._bitfield_1 = __BindgenBitfieldUnit::new([skb.load::<u8>(eth_len)?]);

    // TODO: Actual IPv6 support
    if ip_hdr.version() != 4 {
        return Ok(SkBuffAction::Ignore);
    }

    let ihl = ip_hdr.ihl() as usize;
    let src = SocketAddress::new(
        IPv6Address::from_v4u32(skb.load::<__be32>(eth_len + offset_of!(iphdr, saddr))?),
        skb.load::<__be16>(eth_len + ihl * 4 + offset_of!(tcphdr, source))?,
    );
    let dst = SocketAddress::new(
        IPv6Address::from_v4u32(skb.load::<__be32>(eth_len + offset_of!(iphdr, daddr))?),
        skb.load::<__be16>(eth_len + ihl * 4 + offset_of!(tcphdr, dest))?,
    );

    if ip_proto == IPPROTO_TCP {
        let mut tcp_hdr = unsafe { MaybeUninit::<tcphdr>::zeroed().assume_init() };
        tcp_hdr._bitfield_1 = __BindgenBitfieldUnit::new([
            skb.load::<u8>(eth_len + ihl * 4 + offset_of!(tcphdr, _bitfield_1))?,
            skb.load::<u8>(eth_len + ihl * 4 + offset_of!(tcphdr, _bitfield_1) + 1)?,
        ]);
    }

    if ip_proto == IPPROTO_UDP && (src.port == 53 || dst.port == 53) {
        return Ok(SkBuffAction::SendToUserspace);
    }

    Ok(SkBuffAction::Ignore)
}