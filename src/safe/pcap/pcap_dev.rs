// use std::borrow::ToOwned;
// use std::boxed::Box;
// use std::string::String;
// use std::vec::Vec;
use crate::npcap;
use crate::safe::PcapAddress;
use crate::util::parse_guid;
use crate::util::{str_from_c_str_ptr, str_from_c_str_buff_u8};
use lazy_static::lazy_static;
use log::{debug, error, trace};
use regex::Regex;
use std::error::Error;
use std::fmt;
use std::mem;
use std::ptr;
use std::ffi::CString;
use winapi::um::winnt::WCHAR;
use winapi::shared::guiddef::GUID;
use winapi::shared::netioapi;
use winapi::shared::winerror::{NO_ERROR};
use winapi::um::stringapiset;

pub const NPF_NAME_PREFIX: &'static str = "\\Device\\NPF_";
pub const CP_UTF8: usize = 65001; // FIXME: Should be in winapi-rs, but isn't
pub const IF_MAX_STRING_SIZE: usize = 256; // FIXME: Should be in winapi-rs, but isn't
pub const NDIS_IF_MAX_STRING_SIZE: usize = IF_MAX_STRING_SIZE; // FIXME: Should be in winapi-rs, but isn't
pub type IF_ALIAS_BUF = [WCHAR; NDIS_IF_MAX_STRING_SIZE + 1];

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

        trace!("Looping through dev->addresses");
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

    pub fn is_loopback(&self) -> bool {
        self.flags as usize & npcap::PCAP_IF_LOOPBACK != 0
    }

    pub fn friendly_name(&self) -> &str {
        let guid = {
            if self.name.starts_with(NPF_NAME_PREFIX) {
                self.name.trim_start_matches(NPF_NAME_PREFIX)
            } else {
                &self.name
            }
        };
        // debug!("guid text == \"{}\"", guid);

        let guid = match parse_guid(guid) {
            Ok(guid) => guid,
            Err(err) => panic!("{:?}", err),
        };
        // let guid_ptr: *const GUID = &guid;
        // debug!("std::mem::size_of::<GUID>(): {}", std::mem::size_of::<GUID>());
        // debug!("Guid Data1: {:X?}", guid.Data1);
        // debug!("Guid Data2: {:X?}", guid.Data2);
        // debug!("Guid Data3: {:X?}", guid.Data3);
        // debug!("Guid Data4: {:X?}", guid.Data4);
        trace!("guid == {:X?}", guid);

        let mut luid = unsafe { mem::zeroed() };
        let result = unsafe { netioapi::ConvertInterfaceGuidToLuid(&guid, &mut luid) };
        if result != NO_ERROR {
            panic!("ConvertInterfaceGuidToLuid() result = {}", result);
        };

        let mut w_alias_buf: IF_ALIAS_BUF = [0; NDIS_IF_MAX_STRING_SIZE + 1];
        let result2 = unsafe { netioapi::ConvertInterfaceLuidToAlias(&luid, w_alias_buf.as_mut_ptr(), NDIS_IF_MAX_STRING_SIZE + 1) };
        if result2 != NO_ERROR {
            panic!("ConvertInterfaceLuidToAlias() result2 = {}", result2);
        };

        let size = unsafe { stringapiset::WideCharToMultiByte(CP_UTF8 as u32, 0, w_alias_buf.as_ptr(), -1, ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut()) };
        if size == 0 {
            panic!("WideCharToMultiByte() size = 0");
        };

        let mut alias_buf = Vec::with_capacity(size as usize); // FIXME: Seems inefficient
        let size = unsafe { stringapiset::WideCharToMultiByte(CP_UTF8 as u32, 0, w_alias_buf.as_ptr(), -1, alias_buf.as_mut_ptr(), size, ptr::null_mut(), ptr::null_mut()) };
        if size == 0 {
            panic!("WideCharToMultiByte() #2 size = 0");
        };

        let bytes: &[u8] = unsafe { &*(alias_buf.as_ref() as *const [i8] as *const [u8]) };

        let c_string = match str_from_c_str_buff_u8(bytes) {
            Ok(c_string) => c_string,
            Err(err) => {
                panic!("str_from_c_str_buff_u8() err = {:?}", err);
            },
        };
        c_string
    }
}

impl fmt::Display for PcapDev {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Name:          {}\n", self.name)?;
        write!(f, "   Description:  {}\n", self.description)?;
        write!(f, "   Alias:        {}\n", self.friendly_name())?;
        if self.is_loopback() {
            write!(f, "   Loopback:     yes\n")?;
        } else {
            write!(f, "   Loopback:     no\n")?;
        }
        for address in &self.addresses {
            write!(f, "    {}", address)?;
        }
        Ok(())
    }
}

impl fmt::Debug for PcapDev {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\n PcapDev [\n")?;
        write!(f, "    Name:     {}\n", self.name)?;
        write!(f, "    Description:     {}\n", self.description)?;
        write!(f, "    Addresses:   \n")?;
        for address in &self.addresses {
            write!(f, "        [\n{}        ],\n", address)?;
        }
        write!(f, "    Flags: {}\n", self.flags)?;
        write!(f, "]\n")
    }
}