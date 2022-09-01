use core::fmt;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocketAddr {
    pub addr: u32,
    pub port: u16,
    _padding: u16,
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
        let octets: [u8; 4] = self.addr.to_ne_bytes();

        write!(
            f,
            "{:^3}.{:^3}.{:^3}.{:^3}:{:<5}",
            octets[3], octets[2], octets[1], octets[0], self.port
        )
    }
}