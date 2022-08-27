#![no_std]
#![no_main]
use core::mem::{self, MaybeUninit};
use memoffset::offset_of;

use redbpf_probes::socket_filter::prelude::*;

use probes::netmonitor::{SocketAddr, TCPSummary};

#[map(link_section = "maps/established")]
static mut ESTABLISHED: HashMap<(SocketAddr, SocketAddr), u64> = HashMap::with_max_entries(10240);

#[map(link_section = "maps/tcp_summary")]
static mut TCP_SUMMARY: PerfMap<TCPSummary> = PerfMap::with_max_entries(10240);

program!(0xFFFFFFFE, "GPL");
#[socket_filter]
fn measure_tcp_lifetime(skb: SkBuff) -> SkBuffResult {
    let eth_len = mem::size_of::<ethhdr>();
    let eth_proto = skb.load::<__be16>(offset_of!(ethhdr, h_proto))? as u32;
    if eth_proto != ETH_P_IP {
        return Ok(SkBuffAction::Ignore);
    }

    let ip_proto = skb.load::<__u8>(eth_len + offset_of!(iphdr, protocol))? as u32;
    if ip_proto != IPPROTO_TCP {
        return Ok(SkBuffAction::Ignore);
    }

    let mut ip_hdr = unsafe { MaybeUninit::<iphdr>::zeroed().assume_init() };
    ip_hdr._bitfield_1 = __BindgenBitfieldUnit::new([skb.load::<u8>(eth_len)?]);
    if ip_hdr.version() != 4 {
        return Ok(SkBuffAction::Ignore);
    }

    let ihl = ip_hdr.ihl() as usize;
    let src = SocketAddr::new(
        skb.load::<__be32>(eth_len + offset_of!(iphdr, saddr))?,
        skb.load::<__be16>(eth_len + ihl * 4 + offset_of!(tcphdr, source))?,
    );
    let dst = SocketAddr::new(
        skb.load::<__be32>(eth_len + offset_of!(iphdr, daddr))?,
        skb.load::<__be16>(eth_len + ihl * 4 + offset_of!(tcphdr, dest))?,
    );
    let pair = (src, dst);
    let mut tcp_hdr = unsafe { MaybeUninit::<tcphdr>::zeroed().assume_init() };
    tcp_hdr._bitfield_1 = __BindgenBitfieldUnit::new([
        skb.load::<u8>(eth_len + ihl * 4 + offset_of!(tcphdr, _bitfield_1))?,
        skb.load::<u8>(eth_len + ihl * 4 + offset_of!(tcphdr, _bitfield_1) + 1)?,
    ]);

    if tcp_hdr.syn() == 1 {
        unsafe {
            ESTABLISHED.set(&pair, &bpf_ktime_get_ns());
        }
    }

    if tcp_hdr.fin() == 1 || tcp_hdr.rst() == 1 {
        unsafe {
            if let Some(estab_ts) = ESTABLISHED.get(&pair) {
                ESTABLISHED.delete(&pair);
                TCP_SUMMARY.insert(
                    skb.skb as *mut __sk_buff,
                    &TCPSummary {
                        src,
                        dst,
                        duration: bpf_ktime_get_ns() - estab_ts,
                        close_state: if tcp_hdr.fin() == 1 { 1 } else { 2 },
                    },
                );
            }
        }
    }

    Ok(SkBuffAction::Ignore)
}