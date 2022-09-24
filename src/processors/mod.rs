use std::error::Error;

use etherparse::SlicedPacket;

pub mod dns;
pub mod tls;

pub trait PacketProcessor {
    fn process(&mut self, packet: &SlicedPacket) -> Result<(), Box<dyn Error>>;
}