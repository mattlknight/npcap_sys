use crate::npcap;
use crate::safe::PcapAddress;
use crate::util::str_from_c_str_ptr;
use log::{debug, error, trace};
// use std::borrow::ToOwned;
// use std::boxed::Box;
use std::error::Error;
use std::fmt;
// use std::string::String;
// use std::vec::Vec;

pub struct PcapDev {
    name: String,
    description: String,
    addresses: Vec<PcapAddress>,
    flags: u32,
}

impl PcapDev {
    pub fn from_pcap_if(dev: npcap::pcap_if_t) -> Result<Self, Box<Error>> {
        trace!("Converting device name to string");
        let name = match dev.name.is_null() {
            true => return Err("Null pointer to dev.name".into()),
            false => str_from_c_str_ptr(dev.name)?,
        };

        trace!("Converting device description to string");
        let description = match dev.description.is_null() {
            true => return Err("Null pointer to dev.description".into()),
            false => str_from_c_str_ptr(dev.description)?,
        };

        debug!("Looping through dev->addresses");
        let mut addresses = Vec::new();
        let mut pcap_if_address = dev.addresses;
        loop {
            if pcap_if_address.is_null() {
                trace!("pcap_if_address.is_null() breaking loop");
                break;
            }

            let this_address = unsafe { (*pcap_if_address) };
            let pcap_addr = match PcapAddress::from_pcap_addr(this_address) {
                Ok(addr) => addr,
                Err(err) => {
                    error!("{:?}", err);
                    break;
                },
            };

            addresses.push(pcap_addr);
            pcap_if_address = this_address.next;
        }

        Ok(Self {
            name: name.to_owned(),
            description: description.to_owned(),
            addresses: addresses,
            flags: dev.flags,
        })
    }
}

impl fmt::Debug for PcapDev {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "PcapDev [\n")?;
        write!(f, "    Name:     {}\n", self.name)?;
        write!(f, "    Description:     {}\n", self.description)?;
        write!(f, "    Addresses:   \n")?;
        for address in &self.addresses {
            write!(f, "{:?}", address)?;
        }
        write!(f, "    Flags: {}\n", self.flags)?;
        write!(f, "]\n")
    }
}