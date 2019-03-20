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
// #include ??? FIXME
use winapi::ctypes::{c_char, c_int, c_uchar, c_uint, c_ushort, c_void};
use core::mem::size_of;

pub const BPF_RELEASE: usize = 199606;
pub type bpf_int32 = c_int;
pub type bpf_u_int32 = c_uint;
pub const BPF_ALIGNMENT: usize = size_of::<bpf_int32>();
STRUCT!{struct bpf_insn {
    code: c_ushort,
    jt: c_uchar,
    jf: c_uchar,
    k: bpf_u_int32,
}}
STRUCT!{struct bpf_program {
    bf_len: c_uint,
    bf_insns: *mut bpf_insn,
}}