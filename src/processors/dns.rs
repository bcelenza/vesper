use std::error::Error;

use dns_parser::Packet as DnsPacket;
use etherparse::SlicedPacket;
use crate::events::{Logger, dns::{QueryEvent, AnswerEvent}, Event};

use super::PacketProcessor;

pub struct DnsProcessor;

impl PacketProcessor for DnsProcessor {
    fn process(packet: &SlicedPacket) -> Result<(), Box<dyn Error>> {
        let dns_packet = DnsPacket::parse(packet.payload)?;

        if dns_packet.header.query {
            Logger::log_event(Event::DnsQuery(QueryEvent::from_packet(packet, &dns_packet)?))?;
        } else {
            Logger::log_event(Event::DnsAnswer(AnswerEvent::from_packet(packet, &dns_packet)?))?;
        }
        Ok(())
    }
}