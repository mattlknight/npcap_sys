use hex::FromHex;
use lazy_static::lazy_static;
use log::error;
use regex::Regex;
use std::error::Error;
use std::ffi::CStr;
use winapi::shared::guiddef::GUID;

lazy_static!{
    pub static ref RE_GUID: Regex = Regex::new(r"\{?(\w{8})-(\w{4})-(\w{4})-(\w{4})-(\w{12})\}?").expect("Failed to compile GUID Regex");
}

pub fn str_from_c_str_buff_u8(s: &[u8]) -> Result<&str, Box<Error>> {
    let bytes_ptr = s.as_ptr() as *const _;
    let this_cstr = unsafe { CStr::from_ptr(bytes_ptr) };
    match this_cstr.to_str() {
        Ok(this_str) => Ok(this_str),
        Err(err) => {
            error!("Error converting from C nul-terminated string c_uchar array, into a str");
            Err(err.into())
        },
    }
}

pub fn str_from_c_str_ptr<'a>(s: *const i8) -> Result<&'a str, Box<Error>> {
    let this_cstr = unsafe { CStr::from_ptr(s) };
    match this_cstr.to_str() {
        Ok(this_str) => Ok(this_str),
        Err(err) => {
            error!("Error converting from C nul-terminated string ptr, into a str");
            Err(err.into())
        },
    }
}

pub fn parse_guid(text: &str) -> Result<GUID,Box<Error>> {
    if !RE_GUID.is_match(text) {
        return Err(format!("parse_guid(text) \"{}\" does not contain valid GUID text!", text).into());
    }
    if let Some(cap) = RE_GUID.captures(text) {
        if cap.len() != 6 {
            return Err(format!("parse_guid(text) Failed to parse capture groups for \"{}\"", text).into());
        }
        let data_1 = u32::from_str_radix(&cap[1], 16)?;
        let data_2 = u16::from_str_radix(&cap[2], 16)?;
        let data_3 = u16::from_str_radix(&cap[3], 16)?;
        let data_4_p1= <[u8; 2]>::from_hex(&cap[4])?;
        let data_4_p2= <[u8; 6]>::from_hex(&cap[5])?;
        Ok(GUID {
            Data1: data_1,
            Data2: data_2,
            Data3: data_3,
            Data4: [
                    data_4_p1[0], 
                    data_4_p1[1], 
                    data_4_p2[0],
                    data_4_p2[1],
                    data_4_p2[2],
                    data_4_p2[3],
                    data_4_p2[4],
                    data_4_p2[5],
                    ],
        })
    } else {
        return Err(format!("parse_guid(text) Failed to parse capture groups for \"{}\"", text).into());
    }
}