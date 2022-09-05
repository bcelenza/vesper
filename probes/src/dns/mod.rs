use crate::common::SocketAddress;

#[repr(C)]
#[derive(Debug)]
pub struct DNSEvent {
    pub src: SocketAddress,
    pub dest: SocketAddress,
}