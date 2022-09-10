use std::{os::unix::prelude::FromRawFd, io::{Read, ErrorKind}};

use async_trait::async_trait;
use etherparse::SlicedPacket;
use etherparse::TransportSlice::{Tcp, Udp};
use mio::{Poll, Events, net::UnixStream, Token, Interest};
use redbpf::{Error as BpfError, load::{Loaded, Loader, LoaderError}};
use tracing::error;

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

    async fn listen(&self) -> Result<(), ListenerError> {
        let mut stream = unsafe { UnixStream::from_raw_fd(self._fds[0]) };
        let mut poll = match Poll::new() {
            Ok(poll) => poll,
            Err(_) => return Err(ListenerError),
        };
        let mut events = Events::with_capacity(1024);

        if poll.registry().register(&mut stream, Token(0), Interest::READABLE).is_err() {
            return Err(ListenerError)
        }


        loop {
            if let Err(e) = poll.poll(&mut events, None) {
                // Catch CTRL+C interrupts and exit the loop
                if e.kind() == ErrorKind::Interrupted {
                    return Ok(());
                } else {
                    error!("Could not poll for events: {}", e);
                    continue;
                }
            }

            for _ in &events {
                // Read raw bytes to the buffer from the stream.
                let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
                if let Err(e) = stream.read_to_end(&mut buffer) {
                    // EAGAIN expected since stream is non-blocking
                    if e.kind() != ErrorKind::WouldBlock {
                        error!("Could not read from stream: {}", e);
                    }
                }

                // Parse the packet contents starting with the Ethernet header.
                let parsed = SlicedPacket::from_ethernet(&buffer);
                if parsed.is_err() {
                    error!("Could not parse packet: {} (packetLen={})", parsed.unwrap_err(), buffer.len());
                    continue;
                }

                // Determine how to route the packet for processing.
                let packet = parsed.unwrap();
                if packet.transport.is_none() {
                    error!("Could not process packet: no transport specified");
                    continue;
                }

                let transport = packet.transport.as_ref().unwrap();
                match transport {
                    Udp(udp) => {
                        if udp.source_port() == 53 || udp.destination_port() == 53 {
                            if let Err(e) = DnsProcessor::process(&packet) {
                                error!("Could not process packet: {}", e);
                            }
                        }
                    },
                    Tcp(tcp) => {
                        if tcp.source_port() == 53 || tcp.destination_port() == 53 {
                            if let Err(e) = DnsProcessor::process(&packet) {
                                error!("Could not process packet: {}", e);
                            }
                        }
                    }
                    _ => error!("Unhandled transport: {:?}", transport),
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