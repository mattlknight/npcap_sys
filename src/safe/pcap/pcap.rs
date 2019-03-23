use crate::npcap;
use crate::safe::{ErrBuf, PcapDev};
use crate::util::str_from_c_str_ptr;
use std::boxed::Box;
use std::vec::Vec;
use log::{debug, error, info, trace};

pub struct Pcap {
    err_buf: ErrBuf,
    pcap_devs: Vec<PcapDev>,
}

impl Pcap {
    pub fn new() -> Self {
        Self {
            err_buf: ErrBuf::new(),
            pcap_devs: Vec::new(),
        }
    }

    pub fn get_device_list(&mut self) -> Result<&[PcapDev], Box<std::error::Error>> {
        let mut all_devs: *mut npcap::pcap_if_t = unsafe { std::mem::uninitialized() };
        let all_devs_ptr: *mut *mut npcap::pcap_if_t = &mut all_devs;
        debug!("{:?}", all_devs);
        debug!("{:?}", all_devs_ptr);

        self.err_buf.clear();

        debug!("\npcap_findalldevs()");
        unsafe { match npcap::pcap_findalldevs(all_devs_ptr, self.err_buf.buf_ptr_mut()) {
            0   => {},
            -1  => panic!("{}", self.err_buf),
            _   => unreachable!(),
        }}

        debug!("{:?}", all_devs);
        debug!("{:?}", all_devs_ptr);


        info!("Looping through devices");
        let mut device = all_devs; // Initially set device == start of all_devs
        loop {
            debug!("{:?}", all_devs);
            debug!("{:?}", all_devs_ptr);
            debug!("{:?}", device);

            if device.is_null() {
                debug!("device.is_null() breaking loop");
                break;
            }
            if all_devs == device {
                debug!("all_devs == device == {:?}", all_devs);
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

        
        debug!("{:?}", all_devs);
        debug!("{:?}", all_devs_ptr);
        debug!("{:?}", device);
        debug!("Freeing device list");
        unsafe { npcap::pcap_freealldevs(all_devs) };

        debug!("All devs should be freed");        

        Ok(&self.pcap_devs)
    }
}

