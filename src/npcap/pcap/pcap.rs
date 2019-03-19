// MIT License
// Copyright (c) 2019 Matthew Knight
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
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
// #include <stdio.h>
//
//! Npcap SDK wpcap.lib Bindings
use libc::FILE;
use winapi::ctypes;
use winapi::shared::{ntdef, ws2def};
// use winapi::um::{minwinbase, winsock2};

pub const PCAP_VERSION_MAJOR: usize = 2;
pub const PCAP_VERSION_MINOR: usize = 4;
pub const PCAP_ERRBUF_SIZE: usize = 256;

pub type errbuf = [ntdef::CHAR; PCAP_ERRBUF_SIZE];
STRUCT!{struct pcap_addr {
    next: *mut pcap_addr,
    addr: *mut ws2def::SOCKADDR,
    netmask: *mut ws2def::SOCKADDR,
    broadaddr: *mut ws2def::SOCKADDR,
    dstaddr: *mut ws2def::SOCKADDR,
}}
STRUCT!{struct pcap {
    _private: [u8; 0], // pcap is a private struct type, not in public api, used via an opaque pointer
}}
pub type pcap_t = pcap;
pub type bpf_u_int32 = ctypes::c_uint;
STRUCT!{struct pcap_if {
    next: *mut pcap_if,
    name: *mut ctypes::c_char,
    description: *mut ctypes::c_char,
    addresses: *mut pcap_addr,
    flags: bpf_u_int32,
}}
pub type pcap_if_t = pcap_if;

#[link(name = "wpcap1")]
extern "C" {
    pub fn pcap_create(source: *const ctypes::c_char, errbuf: *mut errbuf) -> *mut pcap_t;
    pub fn pcap_activate(p: *mut pcap_t) -> ctypes::c_int;
    pub fn pcap_findalldevs(alldevsp: *mut *mut pcap_if_t, errbuf: *mut errbuf) -> ctypes::c_int;
    pub fn pcap_freedalldevs(alldevsyou: *mut pcap_if_t) -> ctypes::c_void;
    pub fn pcap_lookupdev(errbuf: *mut errbuf) -> *mut ctypes::c_char;
    pub fn pcap_open_offline(fname: *const ctypes::c_char, errbuf: *mut errbuf) -> *mut pcap_t;
    pub fn pcap_open_offline_with_tstamp_precision(fname: *const ctypes::c_char, precision: ctypes::c_uint, errbuf: *mut errbuf) -> *mut pcap_t;
    pub fn pcap_fopen_offline(fp: *mut FILE, errbuf: *mut errbuf) -> *mut pcap_t;
    pub fn pcap_fopen_offline_with_tstamp_precision(fp: *mut FILE, precision: ctypes::c_uint, errbuf: *mut errbuf) -> *mut pcap_t;
}