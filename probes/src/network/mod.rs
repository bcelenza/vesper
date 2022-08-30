use ::core::fmt;
use ::core::mem::transmute;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocketAddr {
    pub addr: u32,
    pub port: u16,
    _padding: u16,
}

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

impl SocketAddr {
    pub fn new(addr: u32, port: u16) -> Self {
        SocketAddr {
            addr,
            port,
            _padding: 0,
        }
    }
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let octets: [u8; 4] = unsafe { transmute::<u32, [u8; 4]>(self.addr) };

        write!(
            f,
            "{:^3}.{:^3}.{:^3}.{:^3}:{:<5}",
            octets[3], octets[2], octets[1], octets[0], self.port
        )
    }
}