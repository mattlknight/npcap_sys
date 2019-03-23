//! Safe wrappers to the npcap public API
//! 
use std::fmt;
use crate::npcap;
use crate::util;

/// pcap::errbuf is naturally a c_char string buffer
/// We can force the casting to a u8 when we lend out the ptr to the buffer
// FIXME: This needs sanity checking
pub type ErrBuffCasted = [u8; npcap::PCAP_ERRBUF_SIZE];

pub struct ErrBuf {
    buf: ErrBuffCasted,
}

impl ErrBuf {
    pub fn new() -> Self {
        Self { buf: [0; npcap::PCAP_ERRBUF_SIZE] }
    }

    pub fn buf_ptr(&self) -> *const npcap::errbuf {
        &self.buf as *const[u8; npcap::PCAP_ERRBUF_SIZE] as *const[i8; npcap::PCAP_ERRBUF_SIZE]
    }

    pub fn buf_ptr_mut(&mut self) -> *mut npcap::errbuf {
        &mut self.buf as *mut[u8; npcap::PCAP_ERRBUF_SIZE] as *mut[i8; npcap::PCAP_ERRBUF_SIZE]
    }

    pub fn clear(&mut self) {
        self.buf = [0; npcap::PCAP_ERRBUF_SIZE];
    }
}

impl fmt::Display for ErrBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Leaving commented code here for understanding, we lend out a byte buffer to npcap
        // npcap is expecting a signed c_char array, but still uses valid utf8 nul-terminated strings
        // Instead, we lend out an unsigned byte array, so when npcap fills the buffer, it is still
        // but, it is easier to work with in rust, as we expect it to be valid
        // FIXME: This needs sanity checking
        // let buf_i8 = self.buf_ptr();
        // let buf_u8 = unsafe { &*(buf_i8 as *const[i8] as *const[u8]) };
        let buf_str = util::str_from_c_str_buff_u8(&self.buf[..]).expect("Failed to convert ErrBuf to str while trying to Display");
        write!(f, "({})", buf_str)
    }
}

impl fmt::Debug for ErrBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("ErrBuf [")?;
        self.buf[..].fmt(f)?;
        f.write_str("]")
    }
}