use etherparse::SlicedPacket;
use serde::Serialize;
use tls_parser::{TlsClientHelloContents, TlsCipherSuite, TlsServerHelloContents, TlsCipherSuiteID};

use super::{SocketAddress, EventError, SocketPair};

#[derive(Debug, Serialize)]
pub enum TlsVersion {
    Unknown,
    SSLv3,
    TLSv1_0,
    TLSv1_1,
    TLSv1_2,
    TLSv1_3,
}

impl From<tls_parser::TlsVersion> for TlsVersion {
    fn from(v: tls_parser::TlsVersion) -> Self {
        match v {
            tls_parser::TlsVersion::Ssl30 => TlsVersion::SSLv3,
            tls_parser::TlsVersion::Tls10 => TlsVersion::TLSv1_0,
            tls_parser::TlsVersion::Tls11 => TlsVersion::TLSv1_1,
            tls_parser::TlsVersion::Tls12 => TlsVersion::TLSv1_2,
            tls_parser::TlsVersion::Tls13 => TlsVersion::TLSv1_3,
            _ => TlsVersion::Unknown,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ClientHelloEvent {
    source: SocketAddress,
    destination: SocketAddress,
    version: TlsVersion,
    ciphers: Vec<String>,
}

impl ClientHelloEvent {
    pub fn from<'a>(packet: &SlicedPacket, t: &TlsClientHelloContents) -> Result<Self, EventError<'a>> {
        let socket_pair = SocketPair::from_packet(packet)?;
        Ok(ClientHelloEvent { 
            source: socket_pair.source, 
            destination: socket_pair.destination,
            version: TlsVersion::from(t.version),
            ciphers: t.ciphers.iter()
                .map(cipher_to_string)
                .collect(),
        })      
    }
}

#[derive(Debug, Serialize)]
pub struct ServerHelloEvent {
    source: SocketAddress,
    destination: SocketAddress,
    version: TlsVersion,
    cipher: String,
}

impl ServerHelloEvent {
    pub fn from<'a>(packet: &SlicedPacket, t: &TlsServerHelloContents) -> Result<Self, EventError<'a>> {
        let socket_pair = SocketPair::from_packet(packet)?;
        Ok(ServerHelloEvent {
            source: socket_pair.source,
            destination: socket_pair.destination,
            version: TlsVersion::from(t.version),
            cipher: cipher_to_string(&t.cipher),
        })
    }
}

#[derive(Debug, Serialize)]
pub struct CipherChangeEvent {
    source: SocketAddress,
    destination: SocketAddress,
    version: TlsVersion,
}

#[derive(Debug, Serialize)]
pub struct AlertEvent {
    source: SocketAddress,
    destination: SocketAddress,
    version: TlsVersion,
}

fn cipher_to_string(id: &TlsCipherSuiteID) -> String {
    match TlsCipherSuite::from_id(id.0) {
        Some(c) => String::from(c.name),
        None => format!("UNKNOWN ({:x})", id.0),
    }
    
}