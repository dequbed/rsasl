use crate::gsasl::consts::{
    GSASL_AUTHENTICATION_ERROR, GSASL_AUTHID, GSASL_CRYPTO_ERROR, GSASL_MALLOC_ERROR,
    GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_NO_PASSWORD, GSASL_OK,
};
use crate::gsasl::gl::free::rpl_free;
use crate::gsasl::property::gsasl_property_set;
use crate::gsasl::saslprep::{gsasl_saslprep, Gsasl_saslprep_flags};
use crate::mechanisms::cram_md5::challenge::cram_md5_challenge;
use crate::mechanisms::cram_md5::digest::cram_md5_digest;
use crate::property::Password;
use crate::session::SessionData;
use crate::Shared;
use ::libc;
use libc::{calloc, malloc, memcmp, memcpy, size_t, strdup, strlen};
use std::ffi::CString;
use std::ptr::NonNull;

pub(crate) unsafe fn _gsasl_cram_md5_server_start(
    _ctx: &Shared,
    mech_data: &mut Option<NonNull<()>>,
) -> libc::c_int {
    let mut challenge: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut rc: libc::c_int = 0;
    challenge = malloc(35) as *mut libc::c_char;
    if challenge.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int;
    }
    rc = cram_md5_challenge(challenge);
    if rc != 0 {
        return GSASL_CRYPTO_ERROR as libc::c_int;
    }
    *mech_data = NonNull::new(challenge as *mut ());
    return GSASL_OK as libc::c_int;
}

pub unsafe fn _gsasl_cram_md5_server_step(
    sctx: &mut SessionData,
    mech_data: Option<NonNull<()>>,
    input: Option<&[u8]>,
    output: *mut *mut libc::c_char,
    output_len: *mut size_t,
) -> libc::c_int {
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);

    let input_len = input.map(|i| i.len()).unwrap_or(0);
    let input: *const libc::c_char = input.map(|i| i.as_ptr().cast()).unwrap_or(std::ptr::null());

    let challenge: *mut libc::c_char = mech_data as *mut libc::c_char;
    let mut hash: [libc::c_char; 32] = [0; 32];
    let mut username: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut res: libc::c_int = GSASL_OK as libc::c_int;
    let mut normkey: *mut libc::c_char = 0 as *mut libc::c_char;
    if input_len == 0 {
        *output_len = strlen(challenge) as usize;
        *output = strdup(challenge);
        return GSASL_NEEDS_MORE as libc::c_int;
    }
    if input_len <= (16 * 2) {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
    }
    if *input.offset(input_len.wrapping_sub(16 * 2).wrapping_sub(1) as isize) != ' ' as i8 {
        return GSASL_MECHANISM_PARSE_ERROR as libc::c_int;
    }
    username = calloc(1, input_len.wrapping_sub(16 * 2)) as *mut libc::c_char;
    if username.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int;
    }
    memcpy(
        username as *mut libc::c_void,
        input as *const libc::c_void,
        input_len.wrapping_sub(16 * 2).wrapping_sub(1),
    );
    res = gsasl_property_set(sctx, GSASL_AUTHID, username);
    rpl_free(username as *mut libc::c_void);
    if res != GSASL_OK as libc::c_int {
        return res;
    }

    if let Ok(Some(password)) = sctx.get_property_or_callback::<Password>() {
        let cstr = CString::new(password.as_bytes().to_owned()).unwrap();
        /* FIXME: Use SASLprep here?  Treat string as storage string?
        Specification is unclear. */
        res = gsasl_saslprep(
            cstr.as_ptr(),
            0 as Gsasl_saslprep_flags,
            &mut normkey,
            0 as *mut libc::c_int,
        );
        if res != GSASL_OK as libc::c_int {
            return res;
        }
    } else {
        return GSASL_NO_PASSWORD as libc::c_int;
    }

    cram_md5_digest(
        challenge,
        strlen(challenge) as usize,
        normkey,
        strlen(normkey) as usize,
        hash.as_mut_ptr(),
    );
    rpl_free(normkey as *mut libc::c_void);
    if memcmp(
        &*input.offset(input_len.wrapping_sub(32) as isize) as *const libc::c_char
            as *const libc::c_void,
        hash.as_mut_ptr() as *const libc::c_void,
        2 * 16,
    ) == 0
    {
        res = GSASL_OK as libc::c_int
    } else {
        res = GSASL_AUTHENTICATION_ERROR as libc::c_int
    }
    *output_len = 0 as libc::c_int as size_t;
    *output = 0 as *mut libc::c_char;
    return res;
}
/* cram-md5.h --- Prototypes for CRAM-MD5 mechanism as defined in RFC 2195.
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
#[no_mangle]
pub unsafe fn _gsasl_cram_md5_server_finish(mech_data: Option<NonNull<()>>) {
    let mech_data = mech_data
        .map(|ptr| ptr.as_ptr())
        .unwrap_or_else(std::ptr::null_mut);
    let challenge: *mut libc::c_char = mech_data as *mut libc::c_char;
    rpl_free(challenge as *mut libc::c_void);
}
