use async_trait::async_trait;
use dns_parser::Packet;
use futures::StreamExt;
use redbpf::{Error, load::{Loaded, Loader, LoaderError}, xdp::{self, MapData}};
use tracing::{error, info};

use super::listener::Listener;
use probes::dns::DNSEvent;

pub struct DNSListener {
    _loaded: Loaded,
}

pub struct DNSConfig {
    pub interface: String,
}

#[async_trait]
impl Listener for DNSListener {
    type Config = DNSConfig;

    fn new() -> Result<DNSListener, LoaderError> {
        let loaded = Loader::load(bytecode())?;
        Ok(DNSListener {
            _loaded: loaded,
        })
    }

    fn attach(&mut self, config: DNSConfig) -> Result<(), Error> {
        for x in self._loaded.xdps_mut() {
            x.attach_xdp(&config.interface, xdp::Flags::default())?;
        }
        Ok(())
    }

    async fn listen(&mut self) {
        while let Some((name, events)) = self._loaded.events.next().await {
            match name.as_str() {
                "dns_query" => {
                    for event in events {
                        let dns_query = unsafe { &*(event.as_ptr() as *const MapData<DNSEvent>) };
                        match Packet::parse(dns_query.payload()) {
                            Ok(packet) => { info!("{:?}", packet) },
                            Err(err) => { error!("Could not parse DNS payload: {:?}", err) },
                        };
                    }
                }
                _ => {
                    error!("unknown dns event = {}", name);
                }
            }
        }
    }
}

fn bytecode() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/dns/dns.elf"
    ))
}
