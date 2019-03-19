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

// Copied directly from https://github.com/retep998/winapi-rs

#![cfg(all(windows, target_arch = "x86_64"))]
extern crate winapi;
use std::mem::{size_of, align_of};
#[cfg(feature = "bcrypt")] #[test]
fn shared_bcrypt() {
    use winapi::shared::bcrypt::*;
    assert_eq!(size_of::<BCRYPT_KEY_LENGTHS_STRUCT>(), 12);
    assert_eq!(align_of::<BCRYPT_KEY_LENGTHS_STRUCT>(), 4);
    assert_eq!(size_of::<BCRYPT_OID>(), 16);
    assert_eq!(align_of::<BCRYPT_OID>(), 8);
}
