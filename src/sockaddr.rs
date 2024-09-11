use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use libc::{in_addr_t, in_port_t, sa_family_t};

/// A parsed sockaddr_* value.
pub(crate) enum SockAddr {
    Inet(SocketAddr),
}

impl std::fmt::Debug for SockAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SockAddr::Inet(v) => std::fmt::Display::fmt(v, f),
        }
    }
}

const SA_FAMILY_LEN: usize = size_of::<sa_family_t>();

impl SockAddr {
    pub(crate) fn read(buf: &[u8]) -> Option<Self> {
        let (family_bytes, rest) = buf.split_at_checked(SA_FAMILY_LEN)?;

        let family = sa_family_t::from_ne_bytes(family_bytes.try_into().unwrap());
        match family as _ {
            libc::AF_INET => Self::read_inet4(rest),
            _ => None,
        }
    }

    fn read_inet4(buf: &[u8]) -> Option<Self> {
        let (port_bytes, rest) = buf.split_at_checked(size_of::<in_port_t>())?;
        let (addr_bytes, _) = rest.split_at_checked(size_of::<in_addr_t>())?;

        let port = in_port_t::from_be_bytes(port_bytes.try_into().unwrap());
        let addr = in_addr_t::from_be_bytes(addr_bytes.try_into().unwrap());
        let ip = Ipv4Addr::from_bits(addr);

        Some(Self::Inet(SocketAddr::new(IpAddr::V4(ip), port)))
    }
}
