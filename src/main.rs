use futures::stream::StreamExt;
use tracing::info;
use std::env;
use std::process;
use std::ptr;
use tokio::signal::ctrl_c;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;
use redbpf::HashMap;

use probes::network::{SocketAddr, TCPSummary};

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

    // Load the BPF probe.
    let mut raw_fds = Vec::new();
    let mut loaded = Loader::load(probe_code()).expect("error loading BPF program");
    for sf in loaded.socket_filters_mut() {
        if let Ok(sock_raw_fd) = sf.attach_socket_filter(iface) {
            raw_fds.push(sock_raw_fd);
        }
    }

    // Monitor for events.
    let event_fut = async {
        while let Some((name, events)) = loaded.events.next().await {
            match name.as_str() {
                "tcp_summary" => {
                    for event in events {
                        let tcp_summary =
                            unsafe { ptr::read(event.as_ptr() as *const TCPSummary) };
                        info!("{:?}", tcp_summary);
                    }
                }
                _ => {
                    error!("unknown event = {}", name);
                }
            }
        }
    };

    // Monitor for CTRL+C
    let ctrlc_fut = async {
        ctrl_c().await.unwrap();
    };
    tokio::select! {
        _ = event_fut => {

        }
        _ = ctrlc_fut => {
            println!("");
        }
    }

    // Upon exit, print the connections which are still established.
    let estab: HashMap<(SocketAddr, SocketAddr), u64> =
        HashMap::new(loaded.map("established").unwrap()).unwrap();
    for ((src, dst), _) in estab.iter() {
        info!(
            "Still established: src={:?}, dst={:?}", src, dst);
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/network/network.elf"
    ))
}