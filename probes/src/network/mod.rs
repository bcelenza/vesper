use core::fmt;

use super::common::SocketAddress;

/// The IP protocol (TCP or UDP) of a given packet.
#[derive(Debug)]
pub enum Protocol {
    ICMP,
    UDP,
    TCP,
    UNKNOWN,
}

impl Protocol {
    /// Returns a Protocol given its integer representation.
    /// Maps to formal hex representations.
    /// See: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers.
    pub fn from_u64(p: u64) -> Self {
        match p {
            0x01 => Protocol::ICMP,
            0x06 => Protocol::TCP,
            0x11 => Protocol::UDP,
            _ => Protocol::UNKNOWN
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct PacketMetadata {
    pub src: SocketAddress,
    pub dest: SocketAddress,
    pub length: usize,
    pub protocol: u64,
}

impl fmt::Display for PacketMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ src=")?;
        self.src.fmt(f)?;
        write!(f, ", dest=")?;
        self.dest.fmt(f)?;
        write!(f, ", protocol={:?}, length={} }}", Protocol::from_u64(self.protocol), self.length)
    }
}

impl PacketMetadata {
    pub fn new(src: SocketAddress, dest: SocketAddress, protocol: u64, length: usize) -> Self {
        PacketMetadata { 
            src,
            dest,
            length,
            protocol,
        }
    }
}