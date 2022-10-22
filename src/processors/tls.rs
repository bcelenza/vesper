use std::{error::Error, collections::HashMap};
use std::fmt;

use etherparse::SlicedPacket;
use tls_parser::{TlsMessage, TlsMessageHandshake};
use tracing::{error, debug};
use crate::events::SocketPair;
use crate::events::tls::CertificateEvent;
use crate::events::{Logger, tls::{ClientHelloEvent, ServerHelloEvent}, Event};

use super::PacketProcessor;

#[derive(Debug)]
pub enum TlsProcessorError<'a> {
    ParserError(&'a str),
}

impl std::error::Error for TlsProcessorError<'_> {}

impl fmt::Display for TlsProcessorError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}


pub struct TlsProcessor {
    _payload_buffer: HashMap<SocketPair, Vec<u8>>,
}

impl TlsProcessor {
    pub fn new() -> TlsProcessor {
        TlsProcessor { _payload_buffer: HashMap::with_capacity(1024) }
    }
}

impl Default for TlsProcessor {
    fn default() -> Self {
        TlsProcessor::new()
    }
}

impl PacketProcessor for TlsProcessor {
    fn process(&mut self, packet: &SlicedPacket) -> Result<(), Box<dyn Error>> {
        let mut reassembled_payload: Vec<u8> = Vec::new();

        // If there is any data in the payload buffer for this socket pair, start with it.
        let socket_pair = SocketPair::from_packet(packet)?;
        if self._payload_buffer.contains_key(&socket_pair) {
            reassembled_payload = self._payload_buffer.get(&socket_pair).unwrap().clone();
        }

        // Append the payload from this packet.
        reassembled_payload.extend_from_slice(packet.payload);

        // The TLS message may be fragmented and multi-message.
        match tls_parser::parse_tls_raw_record(&reassembled_payload) {
            Ok((_, ref record)) => {
                match tls_parser::parse_tls_record_with_header(record.data, &record.hdr) {
                    Ok((_, ref messages)) => {
                        // We've found all messages from the (potentially reassembled) payload, clear
                        // out the buffer.
                        self._payload_buffer.remove(&socket_pair);

                        // Process each message independently
                        for message in messages {
                            match message {
                                TlsMessage::Handshake(handshake) => {
                                    match handshake {
                                        TlsMessageHandshake::ClientHello(hello) => {
                                            Logger::log_event(Event::TlsClientHello(ClientHelloEvent::from(packet, hello)?))?;
                                        },
                                        TlsMessageHandshake::ServerHello(hello) => {
                                            Logger::log_event(Event::TlsServerHello(ServerHelloEvent::from(packet, hello)?))?;
                                        },
                                        TlsMessageHandshake::Certificate(certificate) => {
                                            Logger::log_event(Event::TlsCertificate(CertificateEvent::from(packet, certificate)?))?
                                        },
                                        // Everything else we don't care about (yet).
                                        _ => (),
                                    }
                                },
                                // We don't expect anything other than handshakes, since that's what we filter for
                                // in the BPF probe.
                                _ => error!("Unhandled TLS message type: {:?}", message),
                            }
                        }
                    },
                    Err(tls_parser::Err::Incomplete(needed)) => {
                        debug!("Incomplete TLS record. Needed: {:?}", needed);

                        // set payload buffer from reassmbled payload
                        self._payload_buffer.insert(socket_pair, reassembled_payload);
                    },
                    Err(e) => error!("Could not parse TLS record: {}", e),
                }
            },
            Err(tls_parser::Err::Incomplete(needed)) => {
                debug!("Incomplete TLS record. Needed: {:?}", needed);

                // set payload buffer from reassmbled payload
                self._payload_buffer.insert(socket_pair, reassembled_payload);
            },
            Err(e) => error!("Could not parse TLS record: {}", e),
        }
        Ok(())
    }
}
