use core::fmt;

use super::common::SocketAddr;

#[derive(Copy, Clone)]
pub enum SocketCloseState {
    FIN = 1,
    RST = 2,
}

impl SocketCloseState {
    pub fn from_u64(value: u64) -> SocketCloseState {
        match value {
            1 => SocketCloseState::FIN,
            2 => SocketCloseState::RST,
            _ => panic!("Unknown SocketCloseState: {}", value),
        }
    }
}

impl fmt::Display for SocketCloseState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SocketCloseState::FIN => write!(f, "FIN"),
            SocketCloseState::RST => write!(f, "RST")
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct TCPSummary {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub duration: u64,
    pub close_state: u64,
}

