use clap::Parser;
use std::io;
use std::process;
use tokio::signal::ctrl_c;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use vesper::listeners::network::NetworkConfig;
use vesper::listeners::network::NetworkListener;
use vesper::listeners::Listener;
use vesper::processors::{dns::DnsProcessor, tls::TlsProcessor};

#[derive(clap::ValueEnum, Clone, Debug)]
enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct CommandArgs {
    /// Name of the interface to attach
    #[clap(short, long, value_parser, default_value = "lo")]
    interface: String,
    /// The logging level of the agent
    #[clap(short, long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
}


#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Parse CLI arguments
    let args = CommandArgs::parse();

    // Setup tracing.
    let subscriber = FmtSubscriber::builder()
        .with_max_level(match args.log_level {
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        })
        .with_writer(io::stderr)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    // Ensure we're running with escalated privileges.
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use vesper!");
        process::exit(1);
    }

    // Load the eBPF listeners.
    let mut network_listener = NetworkListener::new(DnsProcessor::new(), TlsProcessor::new()).expect("could not load network probe");
    info!("Attaching to network interface {}", args.interface);
    network_listener.attach(NetworkConfig{ interface: args.interface.to_owned() }).expect("could not attach network probe to interface");

    // Monitor for CTRL+C.
    let ctrlc_fut = async {
        ctrl_c().await.unwrap();
    };
    tokio::select! {
        _ = network_listener.listen() => {}
        _ = ctrlc_fut => {
            println!("");
        }
    }
}