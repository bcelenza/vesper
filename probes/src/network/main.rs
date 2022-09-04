#![no_std]
#![no_main]

use probes::common::{SocketAddress, IPv6Address};
use probes::network::{PacketMetadata, Protocol};
use redbpf_probes::xdp::prelude::*;
use redbpf_probes::xdp::{XdpContext, XdpAction};

program!(0xFFFFFFFE, "GPL");

/// A map that contains DNS query/response packet data.
#[map(link_section="maps/dns_data")]
static mut dns_data: PerfMap<PacketMetadata> = PerfMap::with_max_entries(1024);

/// A map that contains metadata only for uncategorized packets.
#[map(link_section = "maps/packet_metadata")]
static mut metadata: PerfMap<PacketMetadata> = PerfMap::with_max_entries(10240);

/// Filter packets from the network, categorizing 
#[xdp]
pub fn filter_network(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };
    let transport = ctx.transport()?;
    let data = ctx.data()?;

    let md = PacketMetadata::new(
        SocketAddress::new(IPv6Address::from_v4u32(ip.saddr), transport.source()),
        SocketAddress::new(IPv6Address::from_v4u32(ip.daddr), transport.dest()),
        ip.protocol as u64,
        data.len());

    // If the packet is DNS, add packet information for userspace.
    // TODO: This is likely over-simplistic given other examples in the wild.
    if transport.source() == 53 || transport.dest() == 53 {
        unsafe {
            dns_data.insert(&ctx, 
                &MapData::with_payload(md, 
                        data.offset() as u32, 
                        ctx.len() as u32));
        }                
        return Ok(XdpAction::Pass);
    }

    // Otherwise, add the packet metadata only to the generic map.
    unsafe {
        metadata.insert(&ctx, &MapData::new(md));
    }

    Ok(XdpAction::Pass)
}