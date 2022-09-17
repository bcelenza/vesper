use std::error::Error;
use std::fmt;

use etherparse::SlicedPacket;
use tls_parser::{TlsMessage,  TlsRecordType, TlsMessageHandshake};
use tracing::error;
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


pub struct TlsProcessor;

impl PacketProcessor for TlsProcessor {
    fn process(packet: &SlicedPacket) -> Result<(), Box<dyn Error>> {
        let parsed = tls_parser::parse_tls_plaintext(packet.payload);
        match parsed {
            Ok((_, record)) => {
                let record_type = record.hdr.record_type;
                match record_type {
                    TlsRecordType::Handshake => {
                        let message = record.msg.first().unwrap();
                        match message {
                            TlsMessage::Handshake(handshake) => {
                                match handshake {
                                    TlsMessageHandshake::ClientHello(hello) => {
                                        Logger::log_event(Event::TlsClientHello(ClientHelloEvent::from(packet, hello)?))?;
                                    },
                                    TlsMessageHandshake::ServerHello(hello) => {
                                        Logger::log_event(Event::TlsServerHello(ServerHelloEvent::from(packet, hello)?))?;
                                    },
                                    // Everything else we don't care about (yet).
                                    _ => {}, 
                                }
                            },
                            // We don't expect anything other than handshakes, since that's what we filter for
                            // in the BPF probe.
                            _ => error!("Unhandled TLS message type: {:?}", message)
                        }
                    }
                    // We don't expect anything other than handshakes, since that's what we filter for
                    // in the BPF probe.
                    _ => error!("Unhandled TLS record type: {:?}", record)
                }
            },
            Err(e) => {
                error!("Could not parse TLS packet: {:?} (packet={:?})", e, packet);
                return Err(Box::new(TlsProcessorError::ParserError("Could not parse TLS packet")));
            }
        }
        Ok(())
    }
}