use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::callback::gsasl_callback;
use crate::gsasl::consts::{GSASL_AUTHID, GSASL_AUTHZID, GSASL_MALLOC_ERROR, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_OK, GSASL_PASSCODE, GSASL_PIN, GSASL_SUGGESTED_PIN, GSASL_VALIDATE_SECURID};
use crate::gsasl::gsasl::{Gsasl, Gsasl_session};
use crate::gsasl::property::{gsasl_property_get, gsasl_property_set};

extern "C" {
    fn malloc(_: size_t) -> *mut libc::c_void;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: size_t)
     -> *mut libc::c_void;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> size_t;
}

/* securid.h --- Prototypes for SASL mechanism SECURID as defined in RFC 2808.
 * Copyright (C) 2002-2021 Simon Josefsson
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
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
pub unsafe fn _gsasl_securid_server_step(sctx: *mut Gsasl_session,
                                         _mech_data: Option<NonNull<()>>,
                                         input: Option<&[u8]>,
                                         output: *mut *mut libc::c_char,
                                         output_len: *mut size_t,
) -> libc::c_int
{
    let input_len = input.map(|i| i.len()).unwrap_or(0);
    let input: *const libc::c_char = input.map(|i| i.as_ptr().cast()).unwrap_or(std::ptr::null());

    let mut authorization_id: *const libc::c_char = 0 as *const libc::c_char;
    let mut authentication_id: *const libc::c_char = 0 as *const libc::c_char;
    let mut passcode: *const libc::c_char = 0 as *const libc::c_char;
    let mut suggestedpin: *const libc::c_char = 0 as *const libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut res: libc::c_int = 0;
    let mut len: size_t = 0;
    if input_len == 0 {
        *output_len = 0 as libc::c_int as size_t;
        *output = 0 as *mut libc::c_char;
        return GSASL_NEEDS_MORE as libc::c_int
    }
    authorization_id = input;
    authentication_id =
        memchr(input as *const libc::c_void, '\u{0}' as i32,
               input_len.wrapping_sub(1)) as *const libc::c_char;
    if !authentication_id.is_null() {
        authentication_id = authentication_id.offset(1);
        passcode =
            memchr(authentication_id as *const libc::c_void, '\u{0}' as i32,
                   input_len.wrapping_sub(strlen(authorization_id))
                            .wrapping_sub(1)
                            .wrapping_sub(1))
                as *const libc::c_char;
        if !passcode.is_null() {
            passcode = passcode.offset(1);
            pin =
                memchr(passcode as *const libc::c_void, '\u{0}' as i32,
                       input_len.wrapping_sub(strlen(authorization_id))
                           .wrapping_sub(1)
                           .wrapping_sub(strlen(authentication_id))
                           .wrapping_sub(1)
                           .wrapping_sub(1))
                    as *mut libc::c_char;
            if !pin.is_null() {
                pin = pin.offset(1);
                if !pin.is_null() && *pin == 0 {
                    pin = 0 as *mut libc::c_char
                }
            }
        }
    }
    if passcode.is_null() {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int
    }
    res = gsasl_property_set(sctx, GSASL_AUTHID, authentication_id);
    if res != GSASL_OK as libc::c_int { return res }
    res = gsasl_property_set(sctx, GSASL_AUTHZID, authorization_id);
    if res != GSASL_OK as libc::c_int { return res }
    res = gsasl_property_set(sctx, GSASL_PASSCODE, passcode);
    if res != GSASL_OK as libc::c_int { return res }
    if !pin.is_null() {
        res = gsasl_property_set(sctx, GSASL_PIN, pin)
    } else {
        res = gsasl_property_set(sctx, GSASL_PIN, 0 as *const libc::c_char)
    }
    if res != GSASL_OK as libc::c_int { return res }
    res = gsasl_callback(0 as *mut Gsasl, sctx, GSASL_VALIDATE_SECURID);
    match res {
        48 => {
            *output =
                strdup(b"passcode\x00" as *const u8 as *const libc::c_char);
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            *output_len =
                strlen(b"passcode\x00" as *const u8 as *const libc::c_char);
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        49 => {
            suggestedpin = gsasl_property_get(sctx, GSASL_SUGGESTED_PIN);
            if !suggestedpin.is_null() {
                len = strlen(suggestedpin)
            } else { len = 0 as libc::c_int as size_t }
            *output_len =
                strlen(b"pin\x00" as *const u8 as
                           *const libc::c_char).wrapping_add(len);
            *output = malloc(*output_len) as *mut libc::c_char;
            if (*output).is_null() {
                return GSASL_MALLOC_ERROR as libc::c_int
            }
            memcpy(*output as *mut libc::c_void,
                   b"pin\x00" as *const u8 as *const libc::c_char as
                       *const libc::c_void,
                   strlen(b"pin\x00" as *const u8 as *const libc::c_char));
            if !suggestedpin.is_null() {
                memcpy((*output).offset(strlen(b"pin\x00" as *const u8 as
                                                   *const libc::c_char) as
                                            isize) as *mut libc::c_void,
                       suggestedpin as *const libc::c_void, len);
            }
            res = GSASL_NEEDS_MORE as libc::c_int
        }
        _ => {
            *output_len = 0 as libc::c_int as size_t;
            *output = 0 as *mut libc::c_char
        }
    }
    return res;
}
