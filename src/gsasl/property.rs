use std::any::{Any, TypeId};
use ::libc;
use libc::size_t;
use crate::consts::Property;
use crate::gsasl::consts::{GSASL_MALLOC_ERROR, GSASL_OK, Gsasl_property};
use crate::gsasl::gsasl::{Gsasl, Gsasl_session};
use crate::gsasl_callback;

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
unsafe fn map(mut sctx: *mut Gsasl_session,
                         mut prop: Gsasl_property) -> *mut *mut libc::c_char {
    let mut p: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    if sctx.is_null() { return 0 as *mut *mut libc::c_char }
    match prop as libc::c_uint {
        4 => { p = &mut (*sctx).anonymous_token }
        5 => { p = &mut (*sctx).service }
        6 => { p = &mut (*sctx).hostname }
        1 => { p = &mut (*sctx).authid }
        2 => { p = &mut (*sctx).authzid }
        3 => { p = &mut (*sctx).password }
        8 => { p = &mut (*sctx).passcode }
        10 => { p = &mut (*sctx).pin }
        9 => { p = &mut (*sctx).suggestedpin }
        7 => { p = &mut (*sctx).gssapi_display_name }
        11 => { p = &mut (*sctx).realm }
        12 => { p = &mut (*sctx).digest_md5_hashed_password }
        13 => { p = &mut (*sctx).qops }
        14 => { p = &mut (*sctx).qop }
        15 => { p = &mut (*sctx).scram_iter }
        16 => { p = &mut (*sctx).scram_salt }
        17 => { p = &mut (*sctx).scram_salted_password }
        23 => { p = &mut (*sctx).scram_serverkey }
        24 => { p = &mut (*sctx).scram_storedkey }
        18 => { p = &mut (*sctx).cb_tls_unique }
        19 => { p = &mut (*sctx).saml20_idp_identifier }
        20 => { p = &mut (*sctx).saml20_redirect_url }
        21 => { p = &mut (*sctx).openid20_redirect_url }
        22 => { p = &mut (*sctx).openid20_outcome_data }
        _ => { }
    }
    return p;
}

/* *
 * gsasl_property_free:
 * @sctx: session handle.
 * @prop: enumerated value of %Gsasl_property type to clear
 *
 * Deallocate associated data with property @prop in session handle.
 * After this call, gsasl_property_fast(@sctx, @prop) will always
 * return NULL.
 *
 * Since: 2.0.0
 **/
#[no_mangle]
pub unsafe fn gsasl_property_free(mut sctx: *mut Gsasl_session,
                                             mut prop: Gsasl_property) {
    let mut p: *mut *mut libc::c_char = map(sctx, prop);
    if !p.is_null() {
        rpl_free(*p as *mut libc::c_void);
        *p = 0 as *mut libc::c_char
    };
}

/* *
 * gsasl_property_set:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 * @data: zero terminated character string to store.
 *
 * Make a copy of @data and store it in the session handle for the
 * indicated property @prop.
 *
 * You can immediately deallocate @data after calling this function,
 * without affecting the data stored in the session handle.
 *
 * Return value: %GSASL_OK iff successful, otherwise
 * %GSASL_MALLOC_ERROR.
 *
 * Since: 0.2.0
 **/
pub unsafe fn gsasl_property_set(mut sctx: *mut Gsasl_session,
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

/* *
 * gsasl_property_set_raw:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 * @data: character string to store.
 * @len: length of character string to store.
 *
 * Make a copy of @len sized @data and store a zero terminated version
 * of it in the session handle for the indicated property @prop.
 *
 * You can immediately deallocate @data after calling this function,
 * without affecting the data stored in the session handle.
 *
 * Except for the length indicator, this function is identical to
 * gsasl_property_set.
 *
 * Return value: %GSASL_OK iff successful, otherwise
 * %GSASL_MALLOC_ERROR.
 *
 * Since: 0.2.0
 **/
#[no_mangle]
pub unsafe fn gsasl_property_set_raw(mut sctx: *mut Gsasl_session,
                                                mut prop: Gsasl_property,
                                                mut data: *const libc::c_char,
                                                mut len: size_t)
 -> libc::c_int {
    let mut p: *mut *mut libc::c_char = map(sctx, prop);
    if !p.is_null() {
        rpl_free(*p as *mut libc::c_void);
        if !data.is_null() {
            *p =
                malloc(len.wrapping_add(1) as libc::c_ulong) as
                    *mut libc::c_char;
            if (*p).is_null() { return GSASL_MALLOC_ERROR as libc::c_int }
            memcpy(*p as *mut libc::c_void, data as *const libc::c_void, len as libc::c_ulong);
            *(*p).offset(len as isize) = '\u{0}' as i32 as libc::c_char
        } else { *p = 0 as *mut libc::c_char }
    }
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
#[no_mangle]
pub unsafe fn gsasl_property_fast(mut sctx: *mut Gsasl_session,
                                             mut prop: Gsasl_property)
 -> *const libc::c_char {
    let mut p: *mut *mut libc::c_char = map(sctx, prop);
    if !p.is_null() {
        return *p
    } else {
        std::ptr::null()
    }
}

pub unsafe fn gsasl_property_get(mut sctx: *mut Gsasl_session,
                                 prop: Gsasl_property
) -> *const libc::c_char
{
    let mut p: *const libc::c_char = gsasl_property_fast(sctx, prop);
    if p.is_null() {
        gsasl_callback(0 as *mut Gsasl, sctx, prop);
        p = gsasl_property_fast(sctx, prop)
    }
    return p;
}

pub unsafe fn property_get<'a, P: Property>(session: *mut Gsasl_session) -> Option<&'a P::Item> {
    let sessref = &mut *session;
    if let Some(item) = sessref.get::<P>() {
        return Some(item)
    }

    gsasl_callback(0 as *mut Gsasl, session, P::code());
    sessref.get::<P>()
}

pub unsafe fn property_set<P: Property>(session: *mut Gsasl_session, data: Box<P::Item>)
{
    let sessref = &mut *session;
    sessref.insert::<P>(data);
}

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use crate::consts::{AUTHID, GSASL_AUTHID};
    use crate::gsasl_server_start;
    use super::*;

    #[test]
    fn set_get_property() {
        let gsasl = Gsasl::new().unwrap();
        let mut session: *mut Gsasl_session = std::ptr::null_mut();
        unsafe {
            gsasl_server_start(&gsasl, "PLAIN", &mut session);

            assert!(property_get::<AUTHID>(session).is_none());

            let data = "Hello there I'm a string".to_string();
            println!("Setting data Authid = {:?}", data);
            property_set::<AUTHID>(session, Box::new(data.clone()));

            let out = property_get::<AUTHID>(session);
            assert!(out.is_some());
            assert_eq!(Some(&data), out);
            println!("Getting data Authid =? {:?}", out.unwrap());
        }
    }
}