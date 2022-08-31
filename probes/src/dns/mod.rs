#[repr(C)]
#[derive(Debug)]
pub struct DNSEvent {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
}