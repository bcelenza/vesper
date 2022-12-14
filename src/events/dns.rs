use dns_parser::Packet as DnsPacket;
use etherparse::SlicedPacket;
use serde::Serialize;

use super::{SocketAddress, EventError, SocketPair};

#[derive(Debug, Serialize)]
pub enum QuestionType {
    A,
    NS,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO ,
    MINFO,
    MX,
    TXT,
    AAAA,
    SRV,
    AXFR,
    MAILB,
    MAILA,
    All,
}

impl From<&dns_parser::QueryType> for QuestionType {
    fn from(t: &dns_parser::QueryType) -> Self {
        match t {
            dns_parser::QueryType::A => QuestionType::A,
            dns_parser::QueryType::NS => QuestionType::NS,
            dns_parser::QueryType::MF => QuestionType::MF,
            dns_parser::QueryType::CNAME => QuestionType::CNAME,
            dns_parser::QueryType::SOA => QuestionType::SOA,
            dns_parser::QueryType::MB => QuestionType::MB,
            dns_parser::QueryType::MG => QuestionType::MG,
            dns_parser::QueryType::MR => QuestionType::MR,
            dns_parser::QueryType::NULL => QuestionType::NULL,
            dns_parser::QueryType::WKS => QuestionType::WKS,
            dns_parser::QueryType::PTR => QuestionType::PTR,
            dns_parser::QueryType::HINFO => QuestionType::HINFO,
            dns_parser::QueryType::MINFO => QuestionType::MINFO,
            dns_parser::QueryType::MX => QuestionType::MX,
            dns_parser::QueryType::TXT => QuestionType::TXT,
            dns_parser::QueryType::AAAA => QuestionType::AAAA,
            dns_parser::QueryType::SRV => QuestionType::SRV,
            dns_parser::QueryType::AXFR => QuestionType::AXFR,
            dns_parser::QueryType::MAILB => QuestionType::MAILB,
            dns_parser::QueryType::MAILA => QuestionType::MAILA,
            dns_parser::QueryType::All => QuestionType::All,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Question {
    r#type: QuestionType,
    name: String,
}

#[derive(Debug, Serialize)]
pub enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    UNKNOWN,
}

impl From<&dns_parser::RData<'_>> for RecordType {
    fn from(t: &dns_parser::RData) -> Self {
        match t {
            dns_parser::RData::A(_) => RecordType::A,
            dns_parser::RData::NS(_) => RecordType::NS,
            dns_parser::RData::CNAME(_) => RecordType::CNAME,
            dns_parser::RData::SOA(_) => RecordType::SOA,
            dns_parser::RData::PTR(_) => RecordType::PTR,
            dns_parser::RData::MX(_) => RecordType::MX,
            dns_parser::RData::TXT(_) => RecordType::TXT,
            dns_parser::RData::AAAA(_) => RecordType::AAAA,
            dns_parser::RData::SRV(_) => RecordType::SRV,
            dns_parser::RData::Unknown(_) => RecordType::UNKNOWN,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Answer {
    r#type: RecordType,
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
pub struct QueryEvent {
    source: SocketAddress,
    destination: SocketAddress,
    id: u16,
    questions: Vec<Question>,
}

impl QueryEvent {
    pub fn from_packet<'a>(ether_packet: &SlicedPacket, dns_packet: &DnsPacket) -> Result<Self, EventError<'a>> {
        let socket_pair = SocketPair::from_packet(ether_packet)?;

        let event = QueryEvent { 
            source: SocketAddress { ip: socket_pair.source.ip, port: socket_pair.source.port }, 
            destination: SocketAddress { ip: socket_pair.destination.ip, port: socket_pair.destination.port }, 
            id: dns_packet.header.id,
            questions: dns_packet.questions.iter().map(|q| 
                Question { r#type: QuestionType::from(&q.qtype), name: q.qname.to_string() }
            ).collect(),
        };

        Ok(event)
    }
}

#[derive(Debug, Serialize)]
pub struct AnswerEvent {
    source: SocketAddress,
    destination: SocketAddress,
    id: u16,
    status: String,
    authoritative: bool,
    recursive: bool,
    questions: Vec<Question>,
    answers: Vec<Answer>,
}

fn record_value(d: &dns_parser::RData) -> String {
    match d {
        dns_parser::RData::A(r) => r.0.to_string(),
        dns_parser::RData::NS(r) => r.to_string(),
        dns_parser::RData::CNAME(r) => r.to_string(),
        dns_parser::RData::SOA(r) => r.primary_ns.to_string(),
        dns_parser::RData::PTR(r) => r.to_string(),
        dns_parser::RData::MX(r) => r.exchange.to_string(),
        dns_parser::RData::TXT(r) => String::from_utf8(r.iter().flat_map(|i| i.to_vec()).collect()).unwrap(),
        dns_parser::RData::AAAA(r) => r.0.to_string(),
        dns_parser::RData::SRV(r) => r.target.to_string() +  ":" + &r.port.to_string(),
        dns_parser::RData::Unknown(_) => String::from(""),
    }
}

impl AnswerEvent {
    pub fn from_packet<'a>(ether_packet: &SlicedPacket, dns_packet: &DnsPacket) -> Result<Self, EventError<'a>> {
        let socket_pair = SocketPair::from_packet(ether_packet)?;
        let event = AnswerEvent {
            source: SocketAddress { ip: socket_pair.source.ip, port: socket_pair.source.port }, 
            destination: SocketAddress { ip: socket_pair.destination.ip, port: socket_pair.destination.port }, 
            id: dns_packet.header.id,
            status: dns_packet.header.response_code.to_string(),
            authoritative: dns_packet.header.authoritative, 
            recursive: dns_packet.header.recursion_available, 
            questions: dns_packet.questions.iter().map(|q| 
                Question { r#type: QuestionType::from(&q.qtype), name: q.qname.to_string() }
            ).collect(), 
            answers: dns_packet.answers.iter().map(|a|
                Answer { r#type: RecordType::from(&a.data), name: a.name.to_string(), value: record_value(&a.data) }
            ).collect(),
        };

        Ok(event)
    }
}