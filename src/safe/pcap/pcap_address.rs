use crate::npcap;
// use std::boxed::Box;
use std::error::Error;
use std::fmt;
// use std::result::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use log::debug;
use winapi::ctypes::{c_int};
use winapi::shared::ws2def::{SOCKADDR, ADDRESS_FAMILY, AF_INET, AF_INET6};
use winapi::shared::ws2ipdef::{SOCKADDR_IN6};
use winapi::shared::in6addr::{IN6_ADDR};
use winapi::um::winnt::{CHAR};

pub struct PcapAddress {
    address: IpAddr,
    netmask: Option<IpAddr>,
    broadcast: Option<IpAddr>,
    destination: Option<IpAddr>,
    scope_id: Option<u32>,
}

impl PcapAddress {
    pub fn winapi_sockaddr_to_addr_v4(sockaddr: *mut SOCKADDR) -> Result<IpAddr,Box<Error>> {
        if sockaddr.is_null() {
            return Err("sockaddr.is_null()".into())
        }
        let v4_sockaddr = unsafe { (*sockaddr) };
        let af = v4_sockaddr.sa_family;
        let data = unsafe { &*(&v4_sockaddr.sa_data as *const [i8] as *const [u8]) };

        if  af as c_int == AF_INET {
            let mut bytes: [u8; 4] = Default::default();
            bytes.copy_from_slice(&data[0..4]); // FIXME: Seems like this is inefficient
            let address = IpAddr::V4(Ipv4Addr::from( bytes ));
            return Ok(address);
        } else {
            return Err(format!("winapi_sockaddr_to_addr_v4 not implemented for af type == {}", af).into());
        }
    }

    pub fn winapi_sockaddr_to_addr_v6(v6_sockaddr: *mut SOCKADDR_IN6) -> Result<(IpAddr, u32),Box<Error>> {
        if v6_sockaddr.is_null() {
            return Err("v6_sockaddr.is_null()".into())
        }
        let v6_sockaddr = unsafe { (*v6_sockaddr) };
        let af = v6_sockaddr.sin6_family;

        if af as c_int == AF_INET6 {
            let addr = v6_sockaddr.sin6_addr;
            let scope_id = unsafe { v6_sockaddr.u.sin6_scope_id() };
            let bytes = unsafe { addr.u.Byte() };
            let address = IpAddr::V6(Ipv6Addr::from( *bytes ));
            return Ok((address, *scope_id));
        } else {
            return Err(format!("winapi_sockaddr_to_addr_v6 not implemented for af type == {}", af).into());
        }
    }

    pub fn from_pcap_addr(addr: npcap::pcap_addr) -> Result<Self,Box<Error>> {
        if addr.addr.is_null() {
            return Err("addr.addr.is_null()".into())
        }
        let address = unsafe { (*addr.addr) };
        let af = address.sa_family;
        match af as c_int {
            AF_INET => {
                debug!("convert pcap_addr to address");
                let address = Self::winapi_sockaddr_to_addr_v4(addr.addr)?;
                let netmask = match addr.netmask.is_null() {
                    true => None,
                    false => {
                        debug!("convert pcap_addr to netmask");
                        Some(Self::winapi_sockaddr_to_addr_v4(addr.netmask)?)
                    },
                };
                let broadcast = match addr.broadaddr.is_null() {
                    true => None,
                    fasle => {
                        debug!("convert pcap_addr to broadcast");
                        Some(Self::winapi_sockaddr_to_addr_v4(addr.broadaddr)?)
                    },
                };
                let destination = match addr.dstaddr.is_null() {
                    true => None,
                    fasle => {
                        debug!("convert pcap_addr to destination");
                        Some(Self::winapi_sockaddr_to_addr_v4(addr.dstaddr)?)
                    },
                };

                Ok(Self {
                    address,
                    netmask: netmask,
                    broadcast:broadcast,
                    destination: destination,
                    scope_id: None,
                })
            },
            AF_INET6 => {
                debug!("convert pcap_addr to address");
                let (address, scope_id) = Self::winapi_sockaddr_to_addr_v6(addr.addr as *mut SOCKADDR_IN6)?;
                Ok(Self {
                    address,
                    netmask: None,
                    broadcast: None,
                    destination: None,
                    scope_id: Some(scope_id),
                })
            },
            _ => {
                return Err(format!("from_pcap_addr not implemented for af type == {}", af).into());
            },
        }

        
    }
}

impl fmt::Display for PcapAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(scope_id) = self.scope_id {
            write!(f, "Address:     {}%{}\n", self.address, scope_id)?;
        } else {
            write!(f, "Address:     {}\n", self.address)?;
        }
        if let Some(netmask) = self.netmask {
            write!(f, "      NetMask:     {}\n", netmask)?;
        }
        if let Some(broadcast) = self.broadcast {
            write!(f, "      Broadcast:     {}\n", broadcast)?;
        }
        if let Some(destination) = self.destination {
            write!(f, "      Destination:     {}\n", destination)?;
        }
        Ok(())
    }
}

impl fmt::Debug for PcapAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "    PcapAddress [\n")?;
        if let Some(scope_id) = self.scope_id {
            write!(f, "        Address:     {}%{}\n", self.address, scope_id)?;
        } else {
            write!(f, "        Address:     {}\n", self.address)?;
        }
        if let Some(netmask) = self.netmask {
            write!(f, "        NetMask:     {}\n", netmask)?;
        }
        if let Some(broadcast) = self.broadcast {
            write!(f, "        Broadcast:     {}\n", broadcast)?;
        }
        if let Some(destination) = self.destination {
            write!(f, "        Destination:     {}\n", destination)?;
        }
        write!(f, "    ]\n")
    }
}