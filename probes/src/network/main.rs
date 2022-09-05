#![no_std]
#![no_main]

use probes::common::{SocketAddress, IPv6Address};
use probes::network::{PacketMetadata, TrafficClass};
use redbpf_probes::xdp::prelude::*;
use redbpf_probes::xdp::{XdpContext, XdpAction};

program!(0xFFFFFFFE, "GPL");

/// A map that contains metadata and optional payload for packets.
#[map(link_section = "maps/message")]
static mut messages: PerfMap<PacketMetadata> = PerfMap::with_max_entries(10240);

/// Filter packets from the network, categorizing 
#[xdp]
pub fn filter_network(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };
    let transport = ctx.transport()?;
    let data = ctx.data()?;

    let mut class = TrafficClass::UNCLASSIFIED;
    let mut pass_payload = false;

    // If the packet is DNS, add packet information for user space.
    // TODO: This is likely over-simplistic given other examples in the wild.
    if transport.source() == 53 || transport.dest() == 53 {
        class = TrafficClass::DNS;
        pass_payload = true;                
    }

    let metadata = PacketMetadata::new(
        SocketAddress::new(IPv6Address::from_v4u32(ip.saddr), transport.source()),
        SocketAddress::new(IPv6Address::from_v4u32(ip.daddr), transport.dest()),
        ip.protocol as u64,
        data.len(),
        class as u64, 
        pass_payload);

    unsafe {
        let map_data = if pass_payload {
            MapData::with_payload(metadata, data.offset() as u32, ctx.len() as u32)
        } else {
            MapData::new(metadata)
        };
        messages.insert(&ctx, &map_data);
    }                

    Ok(XdpAction::Pass)
}