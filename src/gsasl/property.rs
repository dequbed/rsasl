use std::ffi::CString;
use libc::size_t;
use crate::consts::*;
use crate::gsasl::consts::{GSASL_MALLOC_ERROR, GSASL_OK, Gsasl_property};
use crate::Session;

extern "C" {
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong)
     -> *mut libc::c_void;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn rpl_free(ptr: *mut libc::c_void);
}

/* property.c --- Callback property handling.
 * Copyright (C) 2004-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
unsafe fn map(_sctx: &mut Session,
              _prop: Gsasl_property
) -> *mut *mut libc::c_char
{
    todo!();
}

pub unsafe fn gsasl_property_set(mut sctx: &mut Session,
                                            mut prop: Gsasl_property,
                                            mut data: *const libc::c_char)
 -> libc::c_int {
    return gsasl_property_set_raw(sctx, prop, data,
                                  if !data.is_null() {
                                      strlen(data) as usize
                                  } else {
                                      0
                                  });
}

pub unsafe fn gsasl_property_set_raw(mut sctx: &mut Session,
                                                mut prop: Gsasl_property,
                                                mut data: *const libc::c_char,
                                                mut len: size_t)
 -> libc::c_int {
    let bytes = std::slice::from_raw_parts(data as *const u8, len);
    let mut vec = Vec::with_capacity(len);
    vec.extend_from_slice(bytes);
    let cstring = CString::new(vec)
        .expect("gsasl_property_set_raw called with NULL-containing string")
        .into_string()
        .expect("gsasl_propery_set_raw called with non-UTF8 string");
    sctx.set_property_raw(prop, Box::new(cstring));

    return GSASL_OK as libc::c_int;
}
/* *
 * gsasl_property_fast:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 *
 * Retrieve the data stored in the session handle for given property
 * @prop.
 *
 * The pointer is to live data, and must not be deallocated or
 * modified in any way.
 *
 * This function will not invoke the application callback.
 *
 * Return value: Return property value, if known, or NULL if no value
 *   known.
 *
 * Since: 0.2.0
 **/
unsafe fn gsasl_property_fast(sctx: &mut Session,
                                  prop: Gsasl_property)
 -> *const libc::c_char {

    if GSASL_OPENID20_OUTCOME_DATA == prop {
        if let Some(prop) = sctx.get_property::<OPENID20_OUTCOME_DATA>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_OPENID20_REDIRECT_URL == prop {
        if let Some(prop) = sctx.get_property::<OPENID20_REDIRECT_URL>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SAML20_REDIRECT_URL == prop {
        if let Some(prop) = sctx.get_property::<SAML20_REDIRECT_URL>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SAML20_IDP_IDENTIFIER == prop {
        if let Some(prop) = sctx.get_property::<SAML20_IDP_IDENTIFIER>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_CB_TLS_UNIQUE == prop {
        if let Some(prop) = sctx.get_property::<CB_TLS_UNIQUE>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SCRAM_STOREDKEY == prop {
        if let Some(prop) = sctx.get_property::<SCRAM_STOREDKEY>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SCRAM_SERVERKEY == prop {
        if let Some(prop) = sctx.get_property::<SCRAM_SERVERKEY>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SCRAM_SALTED_PASSWORD == prop {
        if let Some(prop) = sctx.get_property::<SCRAM_SALTED_PASSWORD>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SCRAM_SALT == prop {
        if let Some(prop) = sctx.get_property::<SCRAM_SALT>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SCRAM_ITER == prop {
        if let Some(prop) = sctx.get_property::<SCRAM_ITER>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_QOP == prop {
        if let Some(it) = sctx.get_property::<QOP>() {
            let ptr = it.as_ptr();
            println!("ret {:?} @ {:?}", it, ptr);
            ptr
        } else {
            std::ptr::null()
        }
    } else if GSASL_QOPS == prop {
        if let Some(prop) = sctx.get_property::<QOPS>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_DIGEST_MD5_HASHED_PASSWORD == prop {
        if let Some(prop) = sctx.get_property::<DIGEST_MD5_HASHED_PASSWORD>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_REALM == prop {
        if let Some(prop) = sctx.get_property::<REALM>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_PIN == prop {
        if let Some(prop) = sctx.get_property::<PIN>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SUGGESTED_PIN == prop {
        if let Some(prop) = sctx.get_property::<SUGGESTED_PIN>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_PASSCODE == prop {
        if let Some(prop) = sctx.get_property::<PASSCODE>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_GSSAPI_DISPLAY_NAME == prop {
        if let Some(prop) = sctx.get_property::<GSSAPI_DISPLAY_NAME>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_HOSTNAME == prop {
        if let Some(prop) = sctx.get_property::<HOSTNAME>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_SERVICE == prop {
        if let Some(prop) = sctx.get_property::<SERVICE>() {
            prop.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_ANONYMOUS_TOKEN == prop {
        if let Some(prop) = sctx.get_property::<ANONYMOUS_TOKEN>() {
            let cstr = CString::new(prop).unwrap();
            cstr.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_PASSWORD == prop {
        if let Some(prop) = sctx.get_property::<PASSWORD>() {
            let cstr = CString::new(prop).unwrap();
            cstr.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_AUTHZID == prop {
        if let Some(prop) = sctx.get_property::<AUTHZID>() {
            let cstr = CString::new(prop).unwrap();
            cstr.as_ptr()
        } else {
            std::ptr::null()
        }
    } else if GSASL_AUTHID == prop {
        if let Some(prop) = sctx.get_property::<AUTHID>() {
            let cstr = Box::leak(Box::new(CString::new(prop).unwrap()));
            (*cstr).as_ptr()
        } else {
            std::ptr::null()
        }
    } else {
        std::ptr::null()
    }
}

pub unsafe fn gsasl_property_get(sctx: &mut Session,
                                 prop: Gsasl_property
) -> *const libc::c_char
{
    let mut ptr = gsasl_property_fast(sctx, prop);
    if ptr.is_null() {
        let _ = sctx.callback(prop);
        ptr = gsasl_property_fast(sctx, prop);
    }
    ptr
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use super::*;

    #[test]
    fn property_get_set() {
        let mut session = Session::new(None);

        unsafe {
            let ptr = gsasl_property_fast(&mut session, GSASL_QOP);
            assert!(ptr.is_null());
        }
        session.set_property::<QOP>(Box::new(CString::new("testservice").unwrap()));
        let cstr = session.get_property::<QOP>();
        println!("cstr {:?}", cstr);
        assert!(cstr.is_some());
        unsafe {
            let ptr = gsasl_property_fast(&mut session, GSASL_QOP);
            println!("after {:?}", ptr);
            assert!(!ptr.is_null());
            let slc = std::slice::from_raw_parts(ptr as *const u8, 11);
            println!("Manual {}", std::str::from_utf8_unchecked(slc));
            let cstr = CStr::from_ptr(ptr);
            println!("fast {:?} {:?}", cstr, cstr.as_ptr());
            assert_eq!(cstr.to_str().unwrap(), "testservice");
        }
    }
}