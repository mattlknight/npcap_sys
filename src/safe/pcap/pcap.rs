use crate::npcap;
use crate::safe::{ErrBuf, PcapDev};
use crate::util::str_from_c_str_ptr;
// use std::boxed::Box;
// use std::fmt::format;
// use std::vec::Vec;
use std::error::Error;
use log::{debug, error, info, trace};

pub struct Pcap {
    err_buf: ErrBuf,
    pcap_devs: Vec<PcapDev>,
}

impl Pcap {
    pub fn new() -> Self {
        trace!("Pcap::new()");
        Self {
            err_buf: ErrBuf::new(),
            pcap_devs: Vec::new(),
        }
    }

    pub fn get_device_list(&mut self) -> Result<&[PcapDev], Box<Error>> {
        let mut all_devs: *mut npcap::pcap_if_t = std::ptr::null_mut();
        self.err_buf.clear();

        trace!("pcap_findalldevs()");
        let result = unsafe { npcap::pcap_findalldevs(&mut all_devs, self.err_buf.buf_ptr_mut()) };
        
        match result {
            0   => { trace!("pcap_findalldevs() -> 0"); },
            -1  => {
                error!("pcap_freealldevs() -> -1");
                unsafe { npcap::pcap_freealldevs(all_devs) };
                return Err(format!("{}", self.err_buf).into());
            },
            _   => {
                error!("pcap_freealldevs() -> {}", result);
                unsafe { npcap::pcap_freealldevs(all_devs) };
                return Err(format!("{}", self.err_buf).into());
            },
        }

        info!("Identifying interfaces");
        let mut device = all_devs; // Initially set device == start of all_devs
        loop {
            if device.is_null() {
                trace!("device.is_null() breaking loop");
                break;
            }

            let this_device = unsafe { (*device) };
            let pcap_dev = match PcapDev::from_pcap_if(this_device) {
                Ok(dev) => dev,
                Err(err) => {
                    error!("{:?}", err);
                    break;
                },
            };

            self.pcap_devs.push(pcap_dev);
            device = this_device.next;
        }

        trace!("pcap_freealldevs()");
        unsafe { npcap::pcap_freealldevs(all_devs) };
        trace!("C all_devs should be freed");        

        Ok(&self.pcap_devs)
    }
}

