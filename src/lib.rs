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
//! This library provides a Rust interface to the Public API of 
//! [Npcap](https://nmap.org/npcap/), a Windows packet sniffing architecture. Specifically, 
//! it utilizes the public interface provided by wpcap.dll (not Packet.dll). 
//! This library also provides safe wrappers to the unsafe external functions, as well as, 
//! some of the API Documenation from 
//! [Npcap API](https://nmap.org/npcap/guide/npcap-devguide.html#npcap-api) and 
//! [Man Pcap](https://nmap.org/npcap/guide/wpcap/pcap.html). The included documentation is a 
//! snapshot of the current documentation at the time of the writing this library. 
//! For up to date documentation, see [Npcap Guide](https://nmap.org/npcap/guide/). For 
//! legacy documentation or backwards compatible function documentation, see 
//! [Libcap Manpage](https://www.tcpdump.org/manpages/pcap.3pcap.html) and 
//! [Winpcap Docs](https://www.winpcap.org/docs/docs_412/html/group__wpcapfunc.html)
//! 
//! This library depends on Npcap being installed for runtime operation. For compiling this 
//! library, the 
//! [Npcap SDK](https://nmap.org/npcap/guide/npcap-devguide.html#npcap-development) must be 
//! downloaded and extracted first. 
//! Packet.lib and wpcap.lib files must be either copied to the crate root OR their location 
//! can be added to the `%LIB%`/`$Env:LIB` environment variables.
//! For downloading and installing Npcap and/or the SDK, see [Npcap](https://nmap.org/npcap/).
//! 
//! Npcap is NOT open source licensed, see licensing here 
//! [LICENSE](https://raw.githubusercontent.com/nmap/npcap/master/LICENSE) 
//! and at [Npcap](https://nmap.org/npcap/)
//! 
//! Most of the macros, testing code, and syntax patterns are copied from 
//! [Winapi](https://github.com/retep998/winapi-rs). The idea was to make developing with 
//! this library as similar to [Winapi](https://github.com/retep998/winapi-rs) as possible.

#![cfg(windows)]
#![allow(unused, unused_qualifications)] // FIXME: Change to deny
#![warn(unused_attributes)]
#![allow(bad_style, overflowing_literals, unused_macros)]
#![recursion_limit = "2563"]
#![no_std]

//Uncomment as needed or once minimum Rust version is bumped to 1.18
//#![cfg_attr(feature = "cargo-clippy", warn(clippy::pedantic))]
//#![cfg_attr(feature = "cargo-clippy", allow(clippy::absurd_extreme_comparisons, clippy::cast_lossless, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_precision_loss, clippy::cast_ptr_alignment, clippy::cast_sign_loss, clippy::const_static_lifetime, clippy::doc_markdown, clippy::empty_enum, clippy::erasing_op, clippy::excessive_precision, clippy::expl_impl_clone_on_copy, clippy::identity_op, clippy::if_not_else, clippy::many_single_char_names, clippy::module_inception, clippy::cast_possible_truncation, clippy::too_many_arguments, clippy::transmute_int_to_float, clippy::trivially_copy_pass_by_ref, clippy::unreadable_literal, clippy::unseparated_literal_suffix, clippy::used_underscore_binding))]

#[macro_use]
mod macros;

#[cfg(feature = "std")]
extern crate std;

/// Hack for exported macros
#[doc(hidden)]
pub extern crate core as _core;

pub extern crate winapi;
pub extern crate libc;

mod npcap;

pub use npcap::pcap::pcap::*;

#[cfg(feature = "safe")]
pub mod safe;
