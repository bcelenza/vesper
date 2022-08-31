#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
use probes::dns::DNSEvent;

program!(0xFFFFFFFE, "GPL");

#[map(link_section = "maps/dns_query")]
static mut events: PerfMap<DNSEvent> = PerfMap::with_max_entries(1024);

#[xdp("dns_queries")]
pub fn filter_dns(ctx: XdpContext) -> XdpResult {
    let ip = unsafe { *ctx.ip()? };
    let transport = ctx.transport()?;
    let data = ctx.data()?;

    if transport.source() != 53 && transport.dest() != 53 {
        return Ok(XdpAction::Pass);
    }

    let event = DNSEvent {
        saddr: ip.saddr,
        daddr: ip.daddr,
        sport: transport.source(),
        dport: transport.dest(),
    };
    unsafe {
        events.insert(
            &ctx,
            &MapData::with_payload(event, data.offset() as u32, ctx.len() as u32),
        )
    };

    Ok(XdpAction::Pass)
}