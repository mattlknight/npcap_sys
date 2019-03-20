// MIT License
//
// Copyright (c) 2019 Matthew Knight
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// #include <pcap/export-defs.h>
// #include <pcap/dlt.h>
//
//! Npcap SDK wpcap.lib Bindings
use libc::FILE;
use winapi::ctypes::{c_char, c_int, c_uchar, c_uint, c_void};
use winapi::shared::ws2def::{SOCKADDR};
use winapi::um::winsock2::{timeval};
use super::bpf::{bpf_u_int32, bpf_program};
// use winapi::um::{minwinbase, winsock2};

pub const PCAP_VERSION_MAJOR: usize = 2;
pub const PCAP_VERSION_MINOR: usize = 4;
pub const PCAP_ERRBUF_SIZE: usize = 256;
pub type errbuf = [c_char; PCAP_ERRBUF_SIZE];
STRUCT!{struct pcap_addr {
    next: *mut pcap_addr,
    addr: *mut SOCKADDR,
    netmask: *mut SOCKADDR,
    broadaddr: *mut SOCKADDR,
    dstaddr: *mut SOCKADDR,
}}
STRUCT!{struct pcap {
    _private: [u8; 0], // pcap is a private struct type, not in public api, used via an opaque pointer
}}
pub type pcap_t = pcap;
STRUCT!{struct pcap_if {
    next: *mut pcap_if,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut pcap_addr,
    flags: bpf_u_int32,
}}
pub type pcap_if_t = pcap_if;
STRUCT!{struct pcap_pkthdr {
    ts: timeval,
    caplen: bpf_u_int32,
    len: bpf_u_int32,
}}
pub type pcap_handler = extern fn(user: *mut c_uchar, h: *const pcap_pkthdr, bytes: *const c_uchar) -> c_void;
STRUCT!{struct pcap_stat {
    ps_recv: c_uint,
    ps_drop: c_uint,
    ps_ifdrop: c_uint,
    ps_capt: c_uint,
    ps_sent: c_uint,
    ps_netdrop: c_uint,
}}
ENUM!{enum pcap_direction_t {
    PCAP_D_INOUT = 0,
    PCAP_D_IN,
    PCAP_D_OUT,
}}
#[link(name = "wpcap")]
extern "C" {
    /// get first non-loopback device on that list (from pcap_findalldevs)
    pub fn pcap_lookupdev(errbuf: *mut errbuf) -> *mut c_char;
    /// get network address and network mask for a capture device 
    pub fn pcap_lookupnet(device: *const c_char, netp: *mut bpf_u_int32, maskp: *mut bpf_u_int32, errbuf: *mut errbuf) -> c_int;
    /// get a pcap_t for live capture 
    pub fn pcap_create(source: *const c_char, errbuf: *mut errbuf) -> *mut pcap_t;
    /// set the snapshot length for a not-yet-activated pcap_t for live capture 
    pub fn pcap_set_snaplen(p: *mut pcap_t, snaplen: c_int) -> c_int;
    /// set promiscuous mode for a not-yet-activated pcap_t for live capture 
    pub fn pcap_set_promisc(p: *mut pcap_t, promisc: c_int) -> c_int;
    /// determine whether monitor mode can be set for a pcap_t for live capture 
    pub fn pcap_can_set_rfmon(p: *mut pcap_t) -> c_int;
    /// set monitor mode for a not-yet-activated pcap_t for live capture 
    pub fn pcap_set_rfmon(p: *mut pcap_t, rfmon: c_int) -> c_int;
    /// set read timeout for a not-yet-activated pcap_t for live capture 
    pub fn pcap_set_timeout(p: *mut pcap_t, to_ms: c_int) -> c_int;
    /// set time stamp type for a not-yet-activated pcap_t for live capture 
    pub fn pcap_set_tstamp_type(p: *mut pcap_t, tstamp_type: c_int) -> c_int;
    /// set immediate mode for a not-yet-activated pcap_t for live capture. see [Libpcap Manpage](https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html)
    pub fn pcap_set_immediate_mode(p: *mut pcap_t, mode: c_int) -> c_int;
    /// set buffer size for a not-yet-activated pcap_t for live capture 
    pub fn pcap_set_buffer_size(p: *mut pcap_t, buffer_size: c_int) -> c_int;
    /// set time stamp precision for a not-yet-activated pcap_t for live capture 
    pub fn pcap_set_tstamp_precision(p: *mut pcap_t, tstamp_precision: c_int) -> c_int;
    /// get the time stamp precision of a pcap_t for live capture 
    pub fn pcap_get_tstamp_precision(p: *mut pcap_t) -> c_int;
    /// activate a pcap_t for live capture 
    pub fn pcap_activate(p: *mut pcap_t) -> c_int;
    /// get list of available time stamp types for a not-yet-activated pcap_t for live capture 
    pub fn pcap_list_tstamp_types(p: *mut pcap_t, tstamp_typesp: *mut *mut c_int) -> c_int;
    /// free list of available time stamp types 
    pub fn pcap_free_tstamp_types(tstamp_types: *mut c_int) -> c_void;
    /// get time stamp type corresponding to a name  (man pcap has descriptions swapped with name_to_val)
    pub fn pcap_tstamp_type_val_to_name(name: *const c_char) -> c_int;
    /// get name for a time stamp type  (man pcap has descriptions swapped with val_to_name)
    pub fn pcap_tstamp_type_name_to_val(tstamp_type: c_int) -> *const c_char;
    /// get description for a time stamp type 
    pub fn pcap_tstamp_type_val_to_description(tstamp_type: c_int) -> *const c_char;
    /// Backwards compatibility, open a device for capturing. see [Libpcap Manpage](https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html)
    pub fn pcap_open_live(device: *const c_char, snaplen: c_int, promisc: c_int, to_ms: c_int, errbuf: *mut errbuf) -> *mut pcap_t;
    /// create a ``fake'' pcap_t
    pub fn pcap_open_dead(linktype: c_int, snaplen: c_int) -> *mut pcap_t;
    /// create a ``fake'' pcap_t
    pub fn pcap_open_dead_with_tstamp_precision(linktype: c_int, snaplen: c_int, precision: c_uint) -> *mut pcap_t;
    /// open a pcap_t for a ``savefile'', given a pathname, and specify the precision to provide for packet time stamps 
    pub fn pcap_open_offline_with_tstamp_precision(fname: *const c_char, precision: c_uint, errbuf: *mut errbuf) -> *mut pcap_t;
    /// open a pcap_t for a ``savefile'', given a pathname 
    pub fn pcap_open_offline(fname: *const c_char, errbuf: *mut errbuf) -> *mut pcap_t;
    /// open a pcap_t for a ``savefile'', given a windows osfhandle, and specify the precision to provide for packet time stamps 
    pub fn pcap_hopen_offline_with_tstamp_precision(osfd: isize, precision: c_uint, errbuf: *mut errbuf) -> *mut pcap_t; //osfd is an intptr_t which == isize
    /// open a pcap_t for a ``savefile'', given a windows osfhandle 
    pub fn pcap_hopen_offline(osfd: isize, errbuf: *mut errbuf) -> *mut pcap_t; //osfd is an intptr_t which == isize
    /// close a pcap_t
    pub fn pcap_close(p: *mut pcap_t) -> c_void;
    /// read packets from a pcap_t until an interrupt or error occurs 
    pub fn pcap_loop(p: *mut pcap_t, cnt: c_int, callback: *mut pcap_handler, user: *mut c_uchar) -> c_int;
    /// read a bufferful of packets from a pcap_t open for a live capture or the full set of packets from a pcap_t open for a ``savefile'' 
    pub fn pcap_dispatch(p: *mut pcap_t, cnt: c_int, callback: *mut pcap_handler, user: *mut c_uchar) -> c_int;
    /// read the next packet from a pcap_t without an indication whether an error occurred 
    pub fn pcap_next(p: *mut pcap_t, h: *mut pcap_pkthdr) -> *const c_uchar;
    /// read the next packet from a pcap_t with an error indication on an error 
    pub fn pcap_next_ex(p: *mut pcap_t, pkt_header: *mut *mut pcap_pkthdr, pkt_data: *const *const c_uchar) -> c_int;
    /// prematurely terminate the loop in pcap_dispatch() or pcap_loop() 
    pub fn pcap_breakloop(p: *mut pcap_t) -> c_void;
    /// get capture statistics 
    pub fn pcap_stats(p: *mut pcap_t, ps: *mut pcap_stat) -> c_int;
    /// set filter for a pcap_t
    pub fn pcap_setfilter(p: *mut pcap_t, fp: *mut bpf_program) -> c_int;
    /// specify whether to capture incoming packets, outgoing packets, or both 
    pub fn pcap_setdirection(p: *mut pcap_t, d: pcap_direction_t) -> c_int;
    /// get the state of non-blocking mode for a pcap_t
    pub fn pcap_getnonblock(p: *mut pcap_t, errbuf: *mut errbuf) -> c_int;
    /// set or clear non-blocking mode on a pcap_t
    pub fn pcap_setnonblock(p: *mut pcap_t, nonblock: c_int, errbuf: *mut errbuf) -> c_int;
    /// transmit a packet 
    pub fn pcap_inject(p: *mut pcap_t, buf: *const c_void, size: usize) -> c_int; // size = size_t == architecture uint size == usize
    /// transmit a packet 
    pub fn pcap_sendpacket(p: *mut pcap_t, buf: *const c_uchar, size: c_int) -> c_int; // size = size_t == architecture uint size == usize
    /// get a string for an error or warning status code 
    pub fn pcap_statustostr(error: c_int) -> *const c_char;
    /// convert an errno value to a string
    pub fn pcap_strerror(error: c_int) -> *const c_char;
    /// get libpcap error message text 
    pub fn pcap_geterr(p: *mut pcap_t) -> *mut c_char;
    /// print libpcap error message text 
    pub fn pcap_perror(p: *mut pcap_t, prefix: *const c_char) -> c_void;
    /// compile filter expression to a pseudo-machine-language code program 
    pub fn pcap_compile(p: *mut pcap_t, fp: *mut bpf_program, str_: *const c_char, optimize: c_int, netmask: bpf_u_int32) -> c_int;
    /// Compile a packet filter without the need of opening an adapter.
    pub fn pcap_compile_nopcap(snaplen_arg: c_int, linktype_arg: c_int, program: *mut bpf_program, buf: *mut c_char, optimize: c_int, mask: bpf_u_int32) -> c_int;
    /// free a filter program 
    pub fn pcap_freecode(fp: *mut bpf_program) -> c_void;
    /// apply a filter program to a packet 
    pub fn pcap_offline_filter(fp: *const bpf_program, h: *const pcap_pkthdr, pkt: *const c_uchar) -> c_int;




    /// get a list of devices that can be opened for a live capture
    pub fn pcap_findalldevs(alldevsp: *mut *mut pcap_if_t, errbuf: *mut errbuf) -> c_int;
    /// free list of devices
    pub fn pcap_freedalldevs(alldevsyou: *mut pcap_if_t) -> c_void;
}