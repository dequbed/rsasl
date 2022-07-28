use crate::gsasl::consts::*;
use base64::{CharacterSet, Config};
use libc::size_t;
use std::mem::ManuallyDrop;

const CONFIG: Config = Config::new(CharacterSet::Standard, true);

pub unsafe fn gsasl_base64_to(
    mut in_0: *const libc::c_char,
    mut inlen: size_t,
    mut out: *mut *mut libc::c_char,
    mut outlen: *mut size_t,
) -> libc::c_int {
    if in_0.is_null() || inlen == 0 || out.is_null() {
        if !out.is_null() {
            *out = std::ptr::null_mut();
        }
        if !outlen.is_null() {
            *outlen = 0;
        }
        return GSASL_OK as libc::c_int;
    }

    let maxlen = inlen * 4 / 3 + 4;
    // make sure we'll have a slice big enough for base64 + padding
    let mut buf = ManuallyDrop::new(Vec::with_capacity(maxlen + 1));
    buf.set_len(maxlen);

    let input = std::slice::from_raw_parts(in_0.cast(), inlen);

    let len = base64::encode_config_slice(input, CONFIG, &mut buf[0..maxlen]);

    buf.set_len(len);
    if !outlen.is_null() {
        *outlen = buf.len();
    }

    buf.push(b'\0');
    *out = buf.as_mut_ptr().cast();

    return GSASL_OK as libc::c_int;
}

pub unsafe fn gsasl_base64_from(
    mut in_0: *const libc::c_char,
    mut inlen: size_t,
    mut out: *mut *mut libc::c_char,
    mut outlen: *mut size_t,
) -> libc::c_int {
    if in_0.is_null() || inlen == 0 || out.is_null() {
        if !out.is_null() {
            *out = std::ptr::null_mut();
        }
        if !outlen.is_null() {
            *outlen = 0;
        }
        return GSASL_OK as libc::c_int;
    }

    let maxlen = inlen * 3 / 4 + 3;
    // make sure we'll have a slice big enough for decoded data
    let mut buf = ManuallyDrop::new(Vec::with_capacity(maxlen + 1));
    buf.set_len(maxlen);

    let input = std::slice::from_raw_parts(in_0.cast(), inlen);

    return if let Ok(len) = base64::decode_config_slice(input, CONFIG, &mut buf[0..maxlen]) {
        buf.set_len(len);
        if !outlen.is_null() {
            *outlen = buf.len();
        }

        buf.push(b'\0');
        *out = buf.as_mut_ptr() as *mut libc::c_char;

        GSASL_OK as libc::c_int
    } else {
        GSASL_BASE64_ERROR as libc::c_int
    };
}