use std::{os::unix::prelude::FromRawFd, io::{Read, ErrorKind, Error}};

use async_trait::async_trait;
use etherparse::{SlicedPacket, InternetSlice};
use mio::{Poll, Events, net::UnixStream, Token, Interest};
use redbpf::{Error as BpfError, load::{Loaded, Loader, LoaderError}, HashMap};
use tracing::{debug, error, info};

use probes::{network::{PacketMetadata, TrafficClass, PacketMetadataKey}, common::{SocketPair, IPv6Address, SocketAddress}};

use crate::{processors::{dns::DnsProcessor, PacketProcessor, tls::TlsProcessor}};

use super::{Listener, ListenerError};

/// Given an expression that returns a Result type, return the value or log the error
/// and continue the loop.
macro_rules! continue_on_err {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(e) => {
                error!("Encountered error: {:?}. Continuing.", e);
                continue;
            }
        }
    };
}

pub struct NetworkListener {
    _loaded: Loaded,
    _fds: Vec<i32>,
    dns_processor: DnsProcessor,
    tls_processor: TlsProcessor,
}
pub struct NetworkConfig {
    pub interface: String,
}


#[derive(Debug)]
enum ParseError<'a> {
    IncompletePacketError(&'a str),
}

const ETH_HDR_LEN: usize = 14;
fn packet_len(buf: &[u8]) -> usize {
    ETH_HDR_LEN + ((buf[ETH_HDR_LEN + 2] as usize) << 8 | buf[ETH_HDR_LEN + 3] as usize)
}

impl NetworkListener {
    pub fn new(dns_processor: DnsProcessor, tls_processor: TlsProcessor) -> Result<NetworkListener, LoaderError> {
        let loaded = Loader::load(bytecode())?;
        Ok(NetworkListener {
            _loaded: loaded,
            _fds: Vec::new(),
            dns_processor,
            tls_processor,
        })
    }
}

#[async_trait]
impl Listener for NetworkListener {
    type Config = NetworkConfig;

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

        // Register the poller to watch for events.
        let mut poll = match Poll::new() {
            Ok(poll) => poll,
            Err(_) => return Err(ListenerError),
        };
        let mut events = Events::with_capacity(1024);
        if poll.registry().register(&mut stream, Token(0), Interest::READABLE).is_err() {
            return Err(ListenerError)
        }

        // Create a reference to the probe's packet metadata map.
        let loaded = & self._loaded;
        let metadata_map = loaded.map("packet_metadata").expect("Could not find packet_metadata map");
        let packet_metadata: HashMap<PacketMetadataKey, PacketMetadata> = HashMap::new(metadata_map).expect("Could not load class map");

        // Process incoming events.
        info!("Listening for network events.");
        loop {
            if let Err(e) = poll.poll(&mut events, None) {
                // Catch CTRL+C interrupts and exit the loop.
                if e.kind() == ErrorKind::Interrupted {
                    return Ok(());
                } else {
                    error!("Could not poll for events: {}", e);
                    continue;
                }
            }

            for _ in events.iter() {
                // Read raw bytes to the buffer from the stream.
                // Before we can read the full packet from the stream, we need to know how much to read.
                // Peek at the packet header to figure out how long it is.
                let peek_len = ETH_HDR_LEN + 4;
                let mut head_buffer = vec![0u8; peek_len];
                let peek_result = match unsafe { libc::recv(self._fds[0], head_buffer.as_mut_ptr() as _, head_buffer.len(), 0x02) } {
                    r if r < 0 => Err(Error::last_os_error()),
                    r => Ok(r as usize),
                };
                if peek_result.is_err() {
                    error!("Could not peek packet header from socket: {}", peek_result.unwrap_err());
                    continue;
                }

                // Determine the packet length from the header.
                let packet_len = packet_len(&head_buffer);

                // Read the full packet from the stream.
                let mut buffer = vec![0u8; packet_len];
                if let Err(e) = stream.read_exact(&mut buffer) {
                    // EAGAIN expected since stream is non-blocking
                    if e.kind() != ErrorKind::WouldBlock {
                        error!("Could not read from stream: {}", e);
                    }
                }

                // Parse the packet contents starting with the Ethernet header.
                let packet = continue_on_err!(SlicedPacket::from_ethernet(&buffer));

                // Get the PacketMetadata from the shared map, then delete it.
                let metadata_key = continue_on_err!(get_metadata_key(&packet));
                let metadata = packet_metadata.get(metadata_key);
                if metadata.is_none() {
                    error!("Could not find metadata for packet with ID {:?}", metadata_key);
                    debug!("Packet: {:?}", packet);
                    continue;
                }
                packet_metadata.delete(metadata_key);

                // Process packet based on how it was classified.
                let class = TrafficClass::from_u64(metadata.unwrap().class);
                match class {
                    TrafficClass::DNS => {
                        if let Err(e) = self.dns_processor.process(&packet) {
                            error!("Could not process DNS packet: {}", e);
                        }
                    },
                    TrafficClass::TLS => {
                        if let Err(e) = self.tls_processor.process(&packet) {
                            error!("Could not process TLS packet: {}", e);
                        }
                    },
                    _ => error!("Unhandled traffic class: {:?}", class)
                }
            }
        }
    }
}

fn get_metadata_key<'a>(packet: &SlicedPacket) -> Result<PacketMetadataKey, ParseError<'a>> {
    if packet.ip.is_none() {
        return Err(ParseError::IncompletePacketError("No IP header"));
    }
    let ip_header = match packet.ip.as_ref().unwrap() {
        InternetSlice::Ipv4(h, _ext) => h,
        _ => panic!("IPv6 not implemented yet."),
    };
    let ports: (u16, u16) = match packet.transport.as_ref().unwrap() {
        etherparse::TransportSlice::Udp(t) => (t.source_port(), t.destination_port()),
        etherparse::TransportSlice::Tcp(t) => (t.source_port(), t.destination_port()),
        _ => panic!("Unhandled transport type."),
    };

    Ok(PacketMetadataKey{
        socket_pair: SocketPair{
            src: SocketAddress::new(IPv6Address::from_v4slice(ip_header.source()), ports.0),
            dest: SocketAddress::new(IPv6Address::from_v4slice(ip_header.destination()), ports.1),
        },
        id: ip_header.identification(),
    })
}

fn bytecode() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/network/network.elf"
    ))
}