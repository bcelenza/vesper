use std::error::Error;

use dns_parser::Packet as DnsPacket;
use etherparse::SlicedPacket;
use crate::events::{Logger, dns::{QueryEvent, AnswerEvent}, Event};

use super::PacketProcessor;

pub struct DnsProcessor;

impl DnsProcessor {
    pub fn new() -> DnsProcessor {
        DnsProcessor{}
    }
}

impl Default for DnsProcessor {
    fn default() -> Self {
        DnsProcessor::new()
    }
}

impl PacketProcessor for DnsProcessor {
    fn process(&mut self, packet: &SlicedPacket) -> Result<(), Box<dyn Error>> {
        let dns_packet = DnsPacket::parse(packet.payload)?;

        if dns_packet.header.query {
            Logger::log_event(Event::DnsQuery(QueryEvent::from_packet(packet, &dns_packet)?))?;
        } else {
            Logger::log_event(Event::DnsResponse(AnswerEvent::from_packet(packet, &dns_packet)?))?;
        }
        Ok(())
    }
}