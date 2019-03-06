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

#![cfg(windows)]
#![deny(unused, unused_qualifications)]
#![warn(unused_attributes)]
#![allow(bad_style, overflowing_literals, unused_macros)]
#![recursion_limit = "2563"]
#![no_std]
//Uncomment as needed or once minimum Rust version is bumped to 1.18
//#![cfg_attr(feature = "cargo-clippy", warn(clippy::pedantic))]
//#![cfg_attr(feature = "cargo-clippy", allow(clippy::absurd_extreme_comparisons, clippy::cast_lossless, clippy::cast_possible_truncation, clippy::cast_possible_wrap, clippy::cast_precision_loss, clippy::cast_ptr_alignment, clippy::cast_sign_loss, clippy::const_static_lifetime, clippy::doc_markdown, clippy::empty_enum, clippy::erasing_op, clippy::excessive_precision, clippy::expl_impl_clone_on_copy, clippy::identity_op, clippy::if_not_else, clippy::many_single_char_names, clippy::module_inception, clippy::cast_possible_truncation, clippy::too_many_arguments, clippy::transmute_int_to_float, clippy::trivially_copy_pass_by_ref, clippy::unreadable_literal, clippy::unseparated_literal_suffix, clippy::used_underscore_binding))]

#[cfg(feature = "std")]
extern crate std;

/// Hack for exported macros
#[doc(hidden)]
pub extern crate core as _core;


#[cfg(all(windows, feature = "npcap"))]
#[path = "npcap.rs"]
mod npcap;

// Copied directly from https://github.com/retep998/winapi-rs lib.rs and macros.rs
#[macro_use]
mod macros;