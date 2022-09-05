use async_trait::async_trait;
use dns_parser::Packet;
use futures::StreamExt;
use probes::network::{PacketMetadata, TrafficClass};
use redbpf::{Error, load::{Loaded, Loader, LoaderError}, xdp::{self, MapData}};
use tracing::{error, info};

use super::listener::Listener;

pub struct NetworkListener {
    _loaded: Loaded,
}
pub struct NetworkConfig {
    pub interface: String,
}

#[async_trait]
impl Listener for NetworkListener {
    type Config = NetworkConfig;

    fn new() -> Result<NetworkListener, LoaderError> {
        let loaded = Loader::load(bytecode())?;
        Ok(NetworkListener {
            _loaded: loaded,
        })
    }

    fn attach(&mut self, config: NetworkConfig) -> Result<(), Error> {
        for x in self._loaded.xdps_mut() {
            x.attach_xdp(&config.interface, xdp::Flags::default())?;
        }
        Ok(())
    }

    async fn listen(&mut self) {
        while let Some((name, events)) = self._loaded.events.next().await {
            match name.as_str() {
                "message" => {
                    for event in events {
                        let message = unsafe { &*(event.as_ptr() as *const MapData<PacketMetadata>) };
                        let metadata = message.data();
                        if TrafficClass::from_u64(metadata.class) == TrafficClass::DNS && metadata.has_payload == 1 {
                            match Packet::parse(message.payload()) {
                                Ok(packet) => { info!("metadata={} data={:?}", metadata, packet) },
                                Err(err) => { error!("Could not parse DNS packet: err={:?}, metadata={}", err, metadata) },
                            };
                        } else {
                            info!("metadata={}", metadata);
                        }
                    }
                }
                _ => {
                    error!("unknown network event = {}", name);
                }
            }
        }
    }
}

fn bytecode() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/network/network.elf"
    ))
}