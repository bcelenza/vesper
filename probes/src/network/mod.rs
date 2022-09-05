use core::fmt;

use super::common::SocketAddress;

/// The IP protocol (e.g., TCP) of a given packet.
/// Maps to formal hex representations, with the exception
/// of UNKNOWN, which maps to the highest value (a reserved
/// number).
/// See: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers.
#[repr(u64)]
#[derive(Debug, PartialEq, Eq)]
pub enum Protocol {
    ICMP = 0x01,
    UDP = 0x06,
    TCP = 0x11,
    UNKNOWN = 0xFF,
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

/// The classification of the traffic, e.g., DNS.
#[repr(u64)]
#[derive(Debug, PartialEq, Eq)]
pub enum TrafficClass {
    UNCLASSIFIED = 0,
    DNS = 1,
}

impl TrafficClass {
    /// Retrurns a TrafficClass given its integer representation.
    pub fn from_u64(c: u64) -> Self {
        match c {
            1 => TrafficClass::DNS,
            _ => TrafficClass::UNCLASSIFIED
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
    pub class: u64,
    pub has_payload: u64,
}

impl fmt::Display for PacketMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ src=")?;
        self.src.fmt(f)?;
        write!(f, ", dest=")?;
        self.dest.fmt(f)?;
        write!(f, ", protocol={:?}, length={}, class={:?}, has_payload={} }}", 
            Protocol::from_u64(self.protocol), 
            self.length,
            TrafficClass::from_u64(self.class),
            self.has_payload)
    }
}

impl PacketMetadata {
    pub fn new(src: SocketAddress, dest: SocketAddress, protocol: u64, length: usize, class: u64, has_payload: bool) -> Self {
        PacketMetadata { 
            src,
            dest,
            length,
            protocol,
            class,
            has_payload: if has_payload { 1 } else { 0 },
        }
    }
}