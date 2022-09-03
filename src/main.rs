use vesper::listeners::dns_listener::DNSConfig;
use vesper::listeners::dns_listener::DNSListener;
use vesper::listeners::network_listener::NetworkConfig;
use vesper::listeners::network_listener::NetworkListener;
use vesper::listeners::listener::Listener;
use std::env;
use std::process;
use tokio::signal::ctrl_c;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;


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

    // Load the eBPF listeners.
    let mut network_listener = NetworkListener::new().expect("cloud not load network probe");
    network_listener.attach(NetworkConfig{ interface: iface.to_string() }).expect("could not attach network probe to interface");
    let mut dns_listener = DNSListener::new().expect("could not load DNS listener");
    dns_listener.attach(DNSConfig { interface: iface.to_string() }).expect("could not attach DNS listener");

    // Monitor for CTRL+C.
    let ctrlc_fut = async {
        ctrl_c().await.unwrap();
    };
    tokio::select! {
        _ = network_listener.listen() => {}
        _ = dns_listener.listen() => {}
        _ = ctrlc_fut => {
            println!("");
        }
    }
}