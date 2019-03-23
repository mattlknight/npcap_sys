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
// #include <pcap-stdinc.h>
// #include <pcap/bpf.h>
// #include <stdio.h>
// #include <remote-ext.h>
//
//! Npcap SDK wpcap.lib(dll) Public API bindings
//! 
use winapi::ctypes::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use winapi::shared::ws2def::{SOCKADDR};
use winapi::um::winnt::{HANDLE};
use winapi::um::winsock2::{timeval};
use super::bpf::{bpf_u_int32, bpf_program, bpf_insn};
pub const PCAP_ERRBUF_SIZE: usize = 256;
pub type errbuf = [c_char; PCAP_ERRBUF_SIZE];
pub type size_t = usize;
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
STRUCT!{struct pcap_dumper {
    _private: [u8; 0], // pcap_dumper is a private struct type, not in public api, used via an opaque pointer
}}
pub type pcap_dumper_t = pcap_dumper;
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
pub type pcap_handler = extern fn(user: *mut c_uchar, h: *const pcap_pkthdr, bytes: *const c_uchar);
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
STRUCT!{struct pcap_send_queue {
    maxlen: c_uint,
    len: c_uint,
    buffer: *mut c_char,
}}
STRUCT!{struct FILE {
    _private: [u8; 0], // file is windows c runtime specific, used via an opaque pointer
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
    pub fn pcap_free_tstamp_types(tstamp_types: *mut c_int);
    /// get time stamp type corresponding to a name
    pub fn pcap_tstamp_type_name_to_val(name: *const c_char) -> c_int;
    /// get name for a time stamp type
    pub fn pcap_tstamp_type_val_to_name(tstamp_type: c_int) -> *const c_char;
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
    pub fn pcap_close(p: *mut pcap_t);
    /// read packets from a pcap_t until an interrupt or error occurs 
    pub fn pcap_loop(p: *mut pcap_t, cnt: c_int, callback: *mut pcap_handler, user: *mut c_uchar) -> c_int;
    /// read a bufferful of packets from a pcap_t open for a live capture or the full set of packets from a pcap_t open for a ``savefile'' 
    pub fn pcap_dispatch(p: *mut pcap_t, cnt: c_int, callback: *mut pcap_handler, user: *mut c_uchar) -> c_int;
    /// read the next packet from a pcap_t without an indication whether an error occurred 
    pub fn pcap_next(p: *mut pcap_t, h: *mut pcap_pkthdr) -> *const c_uchar;
    /// read the next packet from a pcap_t with an error indication on an error 
    pub fn pcap_next_ex(p: *mut pcap_t, pkt_header: *mut *mut pcap_pkthdr, pkt_data: *const *const c_uchar) -> c_int;
    /// prematurely terminate the loop in pcap_dispatch() or pcap_loop() 
    pub fn pcap_breakloop(p: *mut pcap_t);
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
    pub fn pcap_inject(p: *mut pcap_t, buf: *const c_void, size: size_t) -> c_int;
    /// transmit a packet 
    pub fn pcap_sendpacket(p: *mut pcap_t, buf: *const c_uchar, size: c_int) -> c_int;
    /// get a string for an error or warning status code 
    pub fn pcap_statustostr(error: c_int) -> *const c_char;
    /// convert an errno value to a string
    pub fn pcap_strerror(error: c_int) -> *const c_char;
    /// get libpcap error message text 
    pub fn pcap_geterr(p: *mut pcap_t) -> *mut c_char;
    /// print libpcap error message text 
    pub fn pcap_perror(p: *mut pcap_t, prefix: *const c_char);
    /// compile filter expression to a pseudo-machine-language code program 
    pub fn pcap_compile(p: *mut pcap_t, fp: *mut bpf_program, str_: *const c_char, optimize: c_int, netmask: bpf_u_int32) -> c_int;
    /// Compile a packet filter without the need of opening an adapter.
    pub fn pcap_compile_nopcap(snaplen_arg: c_int, linktype_arg: c_int, program: *mut bpf_program, buf: *mut c_char, optimize: c_int, mask: bpf_u_int32) -> c_int;
    /// free a filter program 
    pub fn pcap_freecode(fp: *mut bpf_program);
    /// apply a filter program to a packet 
    pub fn pcap_offline_filter(fp: *const bpf_program, h: *const pcap_pkthdr, pkt: *const c_uchar) -> c_int;
    /// get link-layer header type for a pcap_t
    pub fn pcap_datalink(p: *mut pcap_t) -> c_int;
    /// FIXME: Missing documentation in Pcap and Libpcap manpages
    pub fn pcap_datalink_ext(p: *mut pcap_t) -> c_int;
    /// get a list of link-layer header types for a device 
    pub fn pcap_list_datalinks(p: *mut pcap_t, dlt_buf: *mut *mut c_int) -> c_int;
    /// set link-layer header type for a device 
    pub fn pcap_set_datalink(p: *mut pcap_t, dlt: c_int) -> c_int;
    /// free list of link-layer header types for a device
    pub fn pcap_free_datalinks(dlt_list: *mut c_int);
    /// get link-layer header type corresponding to a name 
    pub fn pcap_datalink_name_to_val(name: *const c_char) -> c_int;
    /// get name for a link-layer header type 
    pub fn pcap_datalink_val_to_name(dlt: c_int) -> *const c_char;
    /// get description for a link-layer header type 
    pub fn pcap_datalink_val_to_description(dlt: c_int) -> *const c_char;
    /// get the snapshot length for a pcap_t
    pub fn pcap_snapshot(p: *mut pcap_t) -> c_int;
    /// determine whether a ``savefile'' being read came from a machine with the opposite byte order 
    pub fn pcap_is_swapped(p: *mut pcap_t) -> c_int;
    /// get the major version of the file format version for a ``savefile''
    pub fn pcap_major_version(p: *mut pcap_t) -> c_int;
    /// get the minor version of the file format version for a ``savefile''
    pub fn pcap_minor_version(p: *mut pcap_t) -> c_int;
    /// get the FILE\ * for a pcap_t opened for a ``savefile'' 
    pub fn pcap_file(p: *mut pcap_t) -> FILE;
    /// get the file descriptor for a live capture 
    pub fn pcap_fileno(p: *mut pcap_t) -> c_int;
    /// FIXME: Missing documentation in Pcap and Libpcap manpages
    pub fn pcap_wsockinit() -> c_int;
    /// open a pcap_dumper_t for a ``savefile``, given a pathname 
    pub fn pcap_dump_open(p: *mut pcap_t, fname: *const c_char) -> *mut pcap_dumper_t;
    /// open a pcap_dumper_t for a ``savefile``, given a FILE\ *
    pub fn pcap_dump_fopen(p: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;
    /// open a pcap_dumper_t for an existing ``savefile``, given a FILE\ *, assuming parameters match
    pub fn pcap_dump_open_append(p: *mut pcap_t, fname: *const c_char) -> *mut pcap_dumper_t;
    /// get the FILE\ * for a pcap_dumper_t opened for a ``savefile'' 
    pub fn pcap_dump_file(p: *mut pcap_dumper_t) -> *mut FILE;
    /// get current file position for a pcap_dumper_t
    pub fn pcap_dump_ftell(p: *mut pcap_dumper_t) -> c_long;
    /// flush buffered packets written to a pcap_dumper_t to the ``savefile'' 
    pub fn pcap_dump_flush(p: *mut pcap_dumper_t) -> c_int;
    /// close a pcap_dumper_t
    pub fn pcap_dump_close(p: *mut pcap_dumper_t);
    /// write packet to a pcap_dumper_t
    pub fn pcap_dump(user: *mut c_uchar, h: *const pcap_pkthdr, sp: *const c_uchar);
    /// get a list of devices that can be opened for a live capture
    pub fn pcap_findalldevs(alldevsp: *mut *mut pcap_if_t, errbuf: *mut errbuf) -> c_int;
    /// free list of devices
    pub fn pcap_freealldevs(alldevs: *mut pcap_if_t);
    /// get library version string
    pub fn pcap_lib_version() -> *const c_char;
    /// FIXME: Missing documentation in Pcap and Libpcap manpages
    pub fn bpf_filter(f: *const bpf_insn, pkt: *const c_uchar, something: c_uint, something: c_uint) -> c_uint;
    /// FIXME: Missing documentation in Pcap and Libpcap manpages
    pub fn bpf_validate(f: *const bpf_insn, len: c_int) -> c_int;
    /// FIXME: Missing documentation in Pcap and Libpcap manpages
    pub fn bpf_image(f: *const bpf_insn, something: c_int) -> *mut c_char;
    /// FIXME: Missing documentation in Pcap and Libpcap manpages
    pub fn bpf_dump(something: *const bpf_program, something: c_int);
    /// Sets the size of the kernel buffer associated with an adapter.
    pub fn pcap_setbuff(p: *mut pcap_t, dim: c_int) -> c_int;
    /// Sets the working mode of the interface.
    pub fn pcap_setmode(p: *mut pcap_t, mode: c_int) -> c_int;
    /// Sets the minumum amount of data received by the kernel in a single call.
    pub fn pcap_setmintocopy(p: *mut pcap_t, size: c_int) -> c_int;
    /// Returns the handle of the event associated with the interface
    pub fn pcap_getevent(p: *mut pcap_t) -> HANDLE;
    /// Send an OID request to the underlying NDIS drivers
    pub fn pcap_oid_get_request(p: *mut pcap_t, something: bpf_u_int32, something: *mut c_void, something: *mut size_t) -> c_int;
    /// Send an OID request to the underlying NDIS drivers
    pub fn pcap_oid_set_request(p: *mut pcap_t, something: bpf_u_int32, something: *const c_void, something: *mut size_t) -> c_int;
    /// Allocate a send queue as a buffer of memsize bytes.
    pub fn pcap_sendqueue_alloc(memsize: c_uint) -> *mut pcap_send_queue;
    /// Free the allocated send queue
    pub fn pcap_sendqueue_destroy(queue: *mut pcap_send_queue);
    /// adds a packet at the end of the send queue pointed by the queue parameter.
    pub fn pcap_sendqueue_queue(queue: *mut pcap_send_queue, pkt_header: *const pcap_pkthdr, pkt_data: *const c_uchar) -> c_int;
    /// transmits the content of a queue to the wire
    pub fn pcap_sendqueue_transmit(p: *mut pcap_t, queue: *mut pcap_send_queue, sync: c_int) -> c_uint;
    /// extends the pcap_stats() allowing to return more statistical parameters than the old call.
    pub fn pcap_stats_ex(p: *mut pcap_t, pcap_stat_size: *mut c_int) -> *mut pcap_stat;
    /// Sets the size of the buffer that accepts packets from the kernel driver.
    pub fn pcap_setuserbuffer(p: *mut pcap_t, size: c_int) -> c_int;
    /// Save a capture to file.
    pub fn pcap_live_dump(p: *mut pcap_t, filename: *mut c_char, maxsize: c_int, maxpacks: c_int) -> c_int;
    /// Return the status of the kernel dump process, i.e. tells if one of the limits defined with pcap_live_dump() has been reached. 
    pub fn pcap_live_dump_ended(p: *mut pcap_t, sync: c_int) -> c_int;
}
