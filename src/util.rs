use log::error;
use std::ffi::CStr;

pub fn str_from_c_str_buff_u8(s: &[u8]) -> Result<&str, std::str::Utf8Error> {
    let bytes_ptr = s.as_ptr() as *const _;
    let this_cstr = unsafe { CStr::from_ptr(bytes_ptr) };
    match this_cstr.to_str() {
        Ok(this_str) => Ok(this_str),
        Err(err) => {
            error!("Error converting from C nul-terminated string c_uchar array, into a str");
            Err(err)
        },
    }
}

pub fn str_from_c_str_ptr<'a>(s: *const i8) -> Result<&'a str, std::str::Utf8Error> {
    let this_cstr = unsafe { CStr::from_ptr(s) };
    match this_cstr.to_str() {
        Ok(this_str) => Ok(this_str),
        Err(err) => {
            error!("Error converting from C nul-terminated string ptr, into a str");
            Err(err)
        },
    }
}