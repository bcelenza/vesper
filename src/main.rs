use dns_parser::{rdata::RData, Packet, ResourceRecord};
use futures::stream::StreamExt;
use redbpf::xdp;
use redbpf::xdp::MapData;
use std::env;
use std::process;
use std::ptr;
use tokio::signal::ctrl_c;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;
use redbpf::HashMap;

use probes::network::{SocketAddr, TCPSummary};
use probes::dns::DNSEvent;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Setup tracing.
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // Ensure we're running with escalated privileges.
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    // Determine which interface to attach.
    let args: Vec<String> = env::args().collect();
    let iface = match args.get(1) {
        Some(val) => val,
        None => "lo",
    };
    info!("Attaching socket to interface {}", iface);

    // Load the BPF probes,
    let mut raw_fds = Vec::new();
    let mut tcp_loaded = Loader::load(tcp_probe_code()).expect("error loading TCP BPF program");
    for sf in tcp_loaded.socket_filters_mut() {
        if let Ok(sock_raw_fd) = sf.attach_socket_filter(iface) {
            raw_fds.push(sock_raw_fd);
        }
    }
    let mut dns_loaded = Loader::load(dns_probe_code()).expect("error loading DNS BPF program");
    for x in dns_loaded.xdps_mut() {
        x.attach_xdp(iface, xdp::Flags::default()).unwrap();
    }

    // Monitor for events.
    let tcp_event_fut = async {
        while let Some((name, events)) = tcp_loaded.events.next().await {
            match name.as_str() {
                "tcp_summary" => {
                    for event in events {
                        let tcp_summary =
                            unsafe { ptr::read(event.as_ptr() as *const TCPSummary) };
                        info!("{:?}", tcp_summary);
                    }
                }
                _ => {
                    error!("unknown tcp event = {}", name);
                }
            }
        }
    };

    let dns_event_fut = async {
        while let Some((name, events)) = dns_loaded.events.next().await {
            match name.as_str() {
                "dns_query" => {
                    for event in events {
                        let dns_query = unsafe { &*(event.as_ptr() as *const MapData<DNSEvent>) };
                        info!("data: {:?}, payload: {:?}", dns_query.data(), dns_query.payload());
                        match Packet::parse(dns_query.payload()) {
                            Ok(packet) => { info!("{:?}", packet) },
                            Err(err) => { error!("{:?}", err) },
                        };
                    }
                }
                _ => {
                    error!("unknown dns event = {}", name);
                }
            }
        }
    };

    // Monitor for CTRL+C
    let ctrlc_fut = async {
        ctrl_c().await.unwrap();
    };
    tokio::select! {
        _ = tcp_event_fut => {

        }
        _ = dns_event_fut => {

        }
        _ = ctrlc_fut => {
            println!("");
        }
    }

    // Upon exit, print the connections which are still established.
    let estab: HashMap<(SocketAddr, SocketAddr), u64> =
        HashMap::new(tcp_loaded.map("established").unwrap()).unwrap();
    for ((src, dst), _) in estab.iter() {
        info!(
            "{:<21}  →  {:<21} | still established",
            src.to_string(),
            dst.to_string()
        );
    }
}

fn tcp_probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/network/network.elf"
    ))
}

fn dns_probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/dns/dns.elf"
    ))
}