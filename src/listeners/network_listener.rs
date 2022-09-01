use async_trait::async_trait;
use futures::StreamExt;
use probes::network::TCPSummary;
use redbpf::load::{Loaded, Loader, LoaderError};
use std::ptr;
use tracing::{error, info};

use super::listener::Listener;

pub struct NetworkListener {
    _loaded: Loaded,
    _file_descriptors: Option<Vec<i32>>,
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
            _file_descriptors: None,
        })
    }


    fn attach(&mut self, config: NetworkConfig) -> Result<(), Box<dyn std::error::Error>> {
        let mut fds = Vec::new();
        for filter in self._loaded.socket_filters_mut() {
            // TODO: Error handling
            if let Ok(fd) = filter.attach_socket_filter(&config.interface) {
                fds.push(fd);
            }
        }
        self._file_descriptors = Some(fds);
        Ok(())
    }

    async fn listen(&mut self) {
        while let Some((name, events)) = self._loaded.events.next().await {
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
    }
}

fn bytecode() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/network/network.elf"
    ))
}