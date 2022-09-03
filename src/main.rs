use clap::Parser;
use std::process;
use tokio::signal::ctrl_c;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use vesper::listeners::dns_listener::DNSConfig;
use vesper::listeners::dns_listener::DNSListener;
use vesper::listeners::network_listener::NetworkConfig;
use vesper::listeners::network_listener::NetworkListener;
use vesper::listeners::listener::Listener;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CommandArgs {
    /// Name of the interface to attach
    #[clap(short, long, value_parser, default_value = "lo")]
    interface: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Setup tracing.
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // Determine which interface to attach.
    let args = CommandArgs::parse();
    info!("Attaching socket to interface {}", args.interface);

    // Ensure we're running with escalated privileges.
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    // Load the eBPF listeners.
    let mut network_listener = NetworkListener::new().expect("could not load network probe");
    network_listener.attach(NetworkConfig{ interface: args.interface.to_owned() }).expect("could not attach network probe to interface");
    let mut dns_listener = DNSListener::new().expect("could not load DNS listener");
    dns_listener.attach(DNSConfig { interface: args.interface.to_owned() }).expect("could not attach DNS listener");

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