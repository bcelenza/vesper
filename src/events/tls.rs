use etherparse::SlicedPacket;
use openssl::{x509::X509, nid::Nid};
use serde::Serialize;
use tls_parser::{parse_tls_extensions, TlsClientHelloContents, TlsCipherSuite, TlsServerHelloContents, TlsCipherSuiteID, TlsCertificateContents};
use tracing::{error, warn};

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

impl From<&tls_parser::TlsVersion> for TlsVersion {
    fn from(v: &tls_parser::TlsVersion) -> Self {
        match *v {
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
pub enum TlsExtension {
    ServerNameIndication(Vec<String>),
    SupportedVersions(Vec<TlsVersion>),
}

#[derive(Default)]
struct TlsExtensionFlags {
    pub tls13: bool,
}

struct TlsExtensionParser;
impl TlsExtensionParser {
    pub fn parse<'a>(ext: Option<&[u8]>) -> Result<(TlsExtensionFlags, Vec<TlsExtension>), EventError<'a>> {
        let mut flags: TlsExtensionFlags = TlsExtensionFlags::default();
        let mut extensions: Vec<TlsExtension> = Vec::new();
        if let Some(e) = ext {
            let parsed = parse_tls_extensions(e);
            if parsed.is_err() {
                return Err(EventError::TranslationError("Could not parse TLS extensions"))
            }

            // Parse all extensions, ignoring those we don't care about.
            extensions = parsed.unwrap().1.iter().flat_map(|e| {
                match e {
                    tls_parser::TlsExtension::SNI(sni) => {
                        let names: Vec<String> = sni.iter().map(|s| {
                            let name = String::from_utf8(s.1.to_vec());
                            name.unwrap()
                        }).collect();
                        Some(TlsExtension::ServerNameIndication(names))
                    },
                    tls_parser::TlsExtension::SupportedVersions(sv) => {
                        let versions: Vec<TlsVersion> = sv.iter().map(|v| {
                            // If 1.3 is specified, we mark this as TLS 1.3 in the output.
                            // Flag it here so we can avoid iterating back through these later.
                            if *v == tls_parser::TlsVersion::Tls13 {
                                flags.tls13 = true;
                            }

                            TlsVersion::from(v)
                        }).collect();
                        Some(TlsExtension::SupportedVersions(versions))
                    }
                    _ => None,
                }
            }).collect();
        }
        Ok((flags, extensions))
    }
}

#[derive(Debug, Serialize)]
pub struct ClientHelloEvent {
    source: SocketAddress,
    destination: SocketAddress,
    version: TlsVersion,
    ciphers: Vec<String>,
    extensions: Vec<TlsExtension>,
}

impl ClientHelloEvent {
    pub fn from<'a>(packet: &SlicedPacket, t: &TlsClientHelloContents) -> Result<Self, EventError<'a>> {
        let socket_pair = SocketPair::from_packet(packet)?;
        let (extension_flags, extensions) = TlsExtensionParser::parse(t.ext)?;

        Ok(ClientHelloEvent {
            source: socket_pair.source,
            destination: socket_pair.destination,
            version: if extension_flags.tls13 { TlsVersion::TLSv1_3 } else { TlsVersion::from(&t.version) },
            ciphers: t.ciphers.iter()
                .map(cipher_to_string)
                .collect(),
            extensions,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ServerHelloEvent {
    source: SocketAddress,
    destination: SocketAddress,
    version: TlsVersion,
    cipher: String,
    extensions: Vec<TlsExtension>,
}

impl ServerHelloEvent {
    pub fn from<'a>(packet: &SlicedPacket, t: &TlsServerHelloContents) -> Result<Self, EventError<'a>> {
        let socket_pair = SocketPair::from_packet(packet)?;
        let (extension_flags, extensions) = TlsExtensionParser::parse(t.ext)?;

        Ok(ServerHelloEvent {
            source: socket_pair.source,
            destination: socket_pair.destination,
            version: if extension_flags.tls13 { TlsVersion::TLSv1_3 } else { TlsVersion::from(&t.version) },
            cipher: cipher_to_string(&t.cipher),
            extensions,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Certificate {
    // pub issuer: String,
    pub common_name: String,
    pub subject_alternative_names: Vec<String>,
    // pub signature: String,
}

impl From<X509> for Certificate {
    fn from<'a>(c: X509) -> Self {
        let subject_alternative_names = if let Some(alt_names) = c.subject_alt_names() {
            alt_names.iter().map(|n| String::from(n.dnsname().unwrap())).collect()
        } else {
            Vec::new()
        };
        let common_names: Vec<String> = c.subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .map(|n| String::from_utf8(n.data().as_slice().to_vec()).unwrap())
            .collect();
        if common_names.len() > 1 {
            warn!("Certificate has multiple common names: {:?}", common_names);
        }
        Certificate{
            common_name: common_names.first().unwrap().to_string(),
            subject_alternative_names,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CertificateEvent {
    source: SocketAddress,
    destination: SocketAddress,
    certificate_chain: Vec<Certificate>,
}

impl CertificateEvent {
    pub fn from<'a>(packet: &SlicedPacket, t: &TlsCertificateContents) -> Result<Self, EventError<'a>> {
        let socket_pair = SocketPair::from_packet(packet)?;
        let certificate_chain = t.cert_chain.iter().flat_map(|raw_cert| {
            let cert = X509::from_der(raw_cert.data);
            if cert.is_err() {
                error!("Could not decode X509 certificate: {}", cert.unwrap_err());
                return None;
            }
            Some(Certificate::from(cert.unwrap()))
        }).collect();
        Ok(CertificateEvent {
            source: socket_pair.source,
            destination: socket_pair.destination,
            certificate_chain,
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
        None => format!("UNKNOWN (0x{:x})", id.0),
    }

}