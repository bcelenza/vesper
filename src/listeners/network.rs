use std::{os::unix::prelude::FromRawFd, io::{Read, ErrorKind}, ptr};

use async_trait::async_trait;
use etherparse::SlicedPacket;
use futures::StreamExt;
use mio::net::UnixStream;
use redbpf::{Error as BpfError, load::{Loaded, Loader, LoaderError}};
use tracing::{error, debug};

use probes::network::{PacketMetadata, TrafficClass};

use crate::{processors::{dns::DnsProcessor, PacketProcessor}};

use super::{Listener, ListenerError};

pub struct NetworkListener {
    _loaded: Loaded,
    _fds: Vec<i32>,
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
            _fds: Vec::new(),
        })
    }

    fn attach(&mut self, config: NetworkConfig) -> Result<(), BpfError> {
        let mut fds: Vec<i32> = Vec::new();
        for filter in self._loaded.socket_filters_mut() {
            let fd = filter.attach_socket_filter(&config.interface)?;
            fds.push(fd);
        }
        self._fds = fds;

        Ok(())
    }

    async fn listen(&mut self) -> Result<(), ListenerError> {
        // Open the unix socket as a stream
        let mut stream = unsafe { UnixStream::from_raw_fd(self._fds[0]) };

        // Process incoming events
        // TODO: It seems completely plausible that the listener may pick up an event from a map
        // before the probe has written all bytes to the socket for a classified packet.
        while let Some((name, events)) = self._loaded.events.next().await {
            match name.as_str() {
                "packet_metadata" => {
                    for event in events {
                        let metadata = unsafe { ptr::read(event.as_ptr() as *const PacketMetadata) };
                        debug!("Received packet metadata: {:?}", metadata);

                        // If the packet was classified, read the payload from the socket and
                        // pass it off to the appropriate processor.
                        let class = TrafficClass::from_u64(metadata.class);
                        if class != TrafficClass::UNCLASSIFIED {
                            // Read raw bytes to the buffer from the stream.
                            let mut buffer: Vec<u8> = vec![0; metadata.length];
                            if let Err(e) = stream.read_exact(&mut buffer) {
                                // EAGAIN expected since stream is non-blocking
                                if e.kind() != ErrorKind::WouldBlock {
                                    error!("Could not read from stream: {}", e);
                                    continue;
                                }
                            }

                            // Parse the packet contents starting with the Ethernet header.
                            let parsed = SlicedPacket::from_ethernet(&buffer);
                            if parsed.is_err() {
                                error!("Could not parse packet: {}", parsed.unwrap_err());
                                continue;
                            }

                            // Determine how to route the packet for processing.
                            let packet = parsed.unwrap();
                            match class {
                                TrafficClass::DNS => {
                                    if let Err(e) = DnsProcessor::process(&packet) {
                                        error!("Cold not process DNS packet: {}", e);
                                    }
                                },
                                _ => error!("Unhandled traffic class: {:?}", class)
                            }
                        }
                    }
                },
                _ => {
                    error!("Unknown probe event: {}", name);
                },
            }
        }
        
        Ok(())
    }
}

fn bytecode() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/network/network.elf"
    ))
}