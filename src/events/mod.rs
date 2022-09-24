use std::{fmt, time::SystemTime};

use chrono::{DateTime, Utc};
use etherparse::SlicedPacket;
use etherparse::InternetSlice::{Ipv4, Ipv6};
use etherparse::TransportSlice::{Tcp, Udp};
use serde::Serialize;
use serde_json::Error;

use self::tls::ServerHelloEvent;
use self::{dns::{QueryEvent, AnswerEvent}, tls::ClientHelloEvent};

pub mod dns;
pub mod tls;

#[derive(Debug)]
pub enum EventError<'a> {
    TranslationError(&'a str),
}

impl std::error::Error for EventError<'_> {}

impl fmt::Display for EventError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug, Serialize)]
pub enum Event {
    DnsQuery(QueryEvent),
    DnsResponse(AnswerEvent),
    TlsClientHello(ClientHelloEvent),
    TlsServerHello(ServerHelloEvent),
}

impl Event {
    pub fn get_type(&self) -> String {
        match self {
            Self::DnsQuery(_) => String::from("DnsQuery"),
            Self::DnsResponse(_) => String::from("DnsResponse"),
            Self::TlsClientHello(_) => String::from("TlsClientHello"),
            Self::TlsServerHello(_) => String::from("TlsSeverHello"),
        }
    }
}

#[derive(Debug, Eq, Hash, PartialEq, Serialize)]
pub struct SocketAddress {
    ip: String,
    port: u16,
}

#[derive(Eq, Hash, PartialEq)]
pub struct SocketPair {
    source: SocketAddress,
    destination: SocketAddress,
}

impl SocketPair {
    pub fn from_packet<'a>(packet: &SlicedPacket) -> Result<SocketPair, EventError<'a>> {
        let (source_ip, dest_ip) = match packet.ip.as_ref().unwrap() {
            Ipv4(h, _) => (h.source_addr().to_string(), h.destination_addr().to_string()),
            Ipv6(h, _) => (h.source_addr().to_string(), h.destination_addr().to_string()),
        };
        let (source_port, dest_port) = match packet.transport.as_ref().unwrap() {
            Udp(h) => (h.source_port(), h.destination_port()),
            Tcp(h) => (h.source_port(), h.destination_port()),
            _ => return Err(EventError::TranslationError("Unrecognized packet transport"))
        };
        Ok(SocketPair {
            source: SocketAddress { ip: source_ip, port: source_port },
            destination: SocketAddress { ip: dest_ip, port: dest_port },
        })
    }
}

#[derive(Debug, Serialize)]
struct LogEvent {
    time: String,
    r#type: String,
    event: Event,
}

pub struct Logger;

impl Logger {
    pub fn log_event(event: Event) -> Result<(), Error> {
        let now: DateTime<Utc> = SystemTime::now().into();
        let log_event = LogEvent {
            time: now.to_rfc3339(),
            r#type: event.get_type(),
            event,
        };
        println!("{}", serde_json::to_string(&log_event)?);
        Ok(())
    }
}