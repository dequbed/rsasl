use ::libc;
use crate::gsasl::digest_md5::client::{_gsasl_digest_md5_client_decode, _gsasl_digest_md5_client_encode, _gsasl_digest_md5_client_finish, _gsasl_digest_md5_client_start, _gsasl_digest_md5_client_step};
use crate::gsasl::digest_md5::server::{_gsasl_digest_md5_server_decode, _gsasl_digest_md5_server_encode, _gsasl_digest_md5_server_finish, _gsasl_digest_md5_server_start, _gsasl_digest_md5_server_step};
use crate::gsasl::gsasl::{Gsasl_mechanism, Gsasl_mechanism_functions};

/* mechinfo.c --- Definition of DIGEST-MD5 mechanism.
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
/* Get specification. */
pub static mut gsasl_digest_md5_mechanism: Gsasl_mechanism = Gsasl_mechanism {
    name: b"DIGEST-MD5\x00" as *const u8 as *const libc::c_char,
    client: Gsasl_mechanism_functions {
        init: None,
        done: None,
        start: Some(_gsasl_digest_md5_client_start),
        step: Some(_gsasl_digest_md5_client_step),
        finish: Some(_gsasl_digest_md5_client_finish),
        encode: Some(_gsasl_digest_md5_client_encode),
        decode: Some(_gsasl_digest_md5_client_decode),
    },
    server: Gsasl_mechanism_functions {
        init: None,
        done: None,
        start: Some(_gsasl_digest_md5_server_start),
        step: Some(_gsasl_digest_md5_server_step),
        finish: Some(_gsasl_digest_md5_server_finish),
        encode: Some(_gsasl_digest_md5_server_encode),
        decode: Some(_gsasl_digest_md5_server_decode),
    },
};
