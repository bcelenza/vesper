use crate::common::SocketAddr;

#[repr(C)]
#[derive(Debug)]
pub struct DNSEvent {
    pub src: SocketAddr,
    pub dest: SocketAddr,
}