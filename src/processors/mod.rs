use std::error::Error;

use etherparse::SlicedPacket;

pub mod dns;

pub trait PacketProcessor {
    fn process(packet: &SlicedPacket) -> Result<(), Box<dyn Error>>;
}