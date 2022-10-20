use core::fmt;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct IPv6Address {
    pub a: u16,
    pub b: u16,
    pub c: u16,
    pub d: u16,
    pub e: u16,
    pub f: u16,
    pub g: u16,
    pub h: u16,
}

impl IPv6Address {
    /// Converts a given IPv4 address represented as a u32 into an IPv6Address.
    pub fn from_v4u32(address: u32) -> Self {
        IPv6Address::from_v4slice(address.to_be_bytes())
    }

    pub fn from_v4slice(octets: [u8; 4]) -> Self {
        IPv6Address {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            f: 0xffff,
            g: ((octets[0] as u16) << 8) | octets[1] as u16,
            h: ((octets[2] as u16) << 8) | octets[3] as u16,
        }
    }

    /// Returns true if the IPv6Address can be represnted as an IPv4
    pub fn is_v4(&self) -> bool {
        self.a == 0 &&
        self.b == 0 &&
        self.c == 0 &&
        self.d == 0 &&
        self.e == 0 &&
        self.f == 0xffff
    }
}

impl fmt::Display for IPv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_v4() {
            let upper = self.g.to_be_bytes();
            let lower = self.h.to_be_bytes();
            write!(f, "{}.{}.{}.{}", lower[1], lower[0], upper[1], upper[0])
        } else {
            write!(f, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                self.a, self.b, self.c, self.d,
                self.e, self.f, self.g, self.h)
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocketAddress {
    pub address: IPv6Address,
    pub port: u16,
    _padding: u16,
}

impl SocketAddress {
    pub fn new(address: IPv6Address, port: u16) -> Self {
        SocketAddress {
            address,
            port,
            _padding: 0,
        }
    }
}

impl fmt::Display for SocketAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.address.is_v4() {
            self.address.fmt(f)?;
            write!(f, ":{}", self.port)
        } else {
            write!(f, "[")?;
            self.address.fmt(f)?;
            write!(f, "]:{}", self.port)
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SocketPair {
    pub src: SocketAddress,
    pub dest: SocketAddress,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6address_from_v4u32() {
        // 192.168.1.1
        let v4 = 3232235777;

        let address = IPv6Address::from_v4u32(v4);
        let expected = IPv6Address {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            f: 0xffff,
            g: 0xc0a8,
            h: 0x0101,
        };

        assert_eq!(expected, address);
    }

    #[test]
    fn ipv6address_is_ipv4() {
        let address = IPv6Address::from_v4u32(0);
        assert!(address.is_v4());
    }

    #[test]
    fn ipv6address_is_ipv4_false() {
        let address = IPv6Address {
            a: 0x2001,
            b: 0x0db8,
            c: 0xac10,
            d: 0xfe01,
            e: 0,
            f: 0,
            g: 0,
            h: 0,
        };
        assert!(!address.is_v4());
    }
}