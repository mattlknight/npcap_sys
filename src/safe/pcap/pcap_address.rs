use crate::npcap;
// use std::boxed::Box;
use std::error::Error;
use std::fmt;
// use std::result::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use log::debug;
use winapi::ctypes::{c_int};
use winapi::shared::ws2def::{SOCKADDR, ADDRESS_FAMILY, AF_INET, AF_INET6};
use winapi::um::winnt::{CHAR};

pub struct PcapAddress {
    address: IpAddr,
    netmask: IpAddr,
    broadcast: IpAddr,
    destination: IpAddr,
}

impl PcapAddress {
    pub fn winapi_sockaddr_to_addr(sockaddr: *mut SOCKADDR) -> Result<IpAddr,Box<Error>> {
        if sockaddr.is_null() {
            return Err("sockaddr.is_null()".into())
        }
        let sockaddr = unsafe { (*sockaddr) };
        let af = sockaddr.sa_family;
        let data = unsafe { &*(&sockaddr.sa_data as *const [i8] as *const [u8]) };

        match af as c_int {
            AF_INET => {
                let mut bytes: [u8; 4] = Default::default();
                bytes.copy_from_slice(&data[0..4]);
                let address = IpAddr::V4(Ipv4Addr::from( bytes ));
                return Ok(address);
            },
            AF_INET6 => {
                let mut bytes: [u8; 16] = Default::default();
                return Err("Still figuring out how the hell this would work!".into());
                bytes.copy_from_slice(&data[0..8]);
                let address = IpAddr::V6(Ipv6Addr::from( bytes ));
                return Ok(address);
            },
            _ => unimplemented!(),
        }
    }

    pub fn from_pcap_addr(addr: npcap::pcap_addr) -> Result<Self,Box<Error>> {
        debug!("convert pcap_addr to address");
        let address = Self::winapi_sockaddr_to_addr(addr.addr)?;
        debug!("convert pcap_addr to netmask");
        let netmask = Self::winapi_sockaddr_to_addr(addr.netmask)?;
        debug!("convert pcap_addr to broadcast");
        let broadcast = Self::winapi_sockaddr_to_addr(addr.broadaddr)?;
        debug!("convert pcap_addr to destination");
        let destination = Self::winapi_sockaddr_to_addr(addr.dstaddr)?;
        Ok(Self {
            address,
            netmask,
            broadcast,
            destination,
        })
    }
}

impl fmt::Debug for PcapAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "    PcapAddress [\n")?;
        write!(f, "        Address:     {}\n", self.address)?;
        write!(f, "        NetMask:     {}\n", self.netmask)?;
        write!(f, "        Broadcast:   {}\n", self.broadcast)?;
        write!(f, "        Destination: {}\n", self.destination)?;
        write!(f, "    ]\n")
    }
}