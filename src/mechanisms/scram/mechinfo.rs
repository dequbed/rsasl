use crate::gsasl::gsasl::{Gsasl_mechanism, MechanismVTable};
use crate::mechanisms::scram::client::{_gsasl_scram_client_finish, _gsasl_scram_client_step,
                              _gsasl_scram_sha1_client_start, _gsasl_scram_sha1_plus_client_start, _gsasl_scram_sha256_client_start, _gsasl_scram_sha256_plus_client_start};
use crate::mechanisms::scram::server::{_gsasl_scram_server_finish, _gsasl_scram_server_step,
                              _gsasl_scram_sha1_plus_server_start, _gsasl_scram_sha1_server_start, _gsasl_scram_sha256_plus_server_start, _gsasl_scram_sha256_server_start};

/* mechinfo.c --- Definition of SCRAM mechanism.
 * Copyright (C) 2009-2021 Simon Josefsson
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
pub static mut gsasl_scram_sha1_mechanism: Gsasl_mechanism = Gsasl_mechanism {
    name: "SCRAM-SHA-1",
    client: MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha1_client_start),
        step: Some(_gsasl_scram_client_step),
        finish: Some(_gsasl_scram_client_finish),
        encode: None,
        decode: None,
    },
    server: MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha1_server_start),
        step: Some(_gsasl_scram_server_step),
        finish: Some(_gsasl_scram_server_finish),
        encode: None,
        decode: None,
    },
};

pub static mut gsasl_scram_sha1_plus_mechanism: Gsasl_mechanism = Gsasl_mechanism {
    name: "SCRAM-SHA-1-PLUS",
    client: MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha1_plus_client_start),
        step: Some(_gsasl_scram_client_step),
        finish: Some(_gsasl_scram_client_finish),
        encode: None,
        decode: None,
    },
    server: MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha1_plus_server_start),
        step: Some(_gsasl_scram_server_step),
        finish: Some(_gsasl_scram_server_finish),
        encode: None,
        decode: None,
    },
};

pub static mut gsasl_scram_sha256_mechanism: Gsasl_mechanism = Gsasl_mechanism {
    name: "SCRAM-SHA-256",
    client: MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha256_client_start),
        step: Some(_gsasl_scram_client_step),
        finish: Some(_gsasl_scram_client_finish),
        encode: None,
        decode: None,
    },
    server: MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha256_server_start),
        step: Some(_gsasl_scram_server_step),
        finish: Some(_gsasl_scram_server_finish),
        encode: None,
        decode: None,
    },
};

pub static mut gsasl_scram_sha256_plus_mechanism: Gsasl_mechanism = Gsasl_mechanism {
    name: "SCRAM-SHA-256-PLUS",
    client: MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha256_plus_client_start),
        step: Some(_gsasl_scram_client_step),
        finish: Some(_gsasl_scram_client_finish),
        encode: None,
        decode: None,
    },
    server: MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha256_plus_server_start),
        step: Some(_gsasl_scram_server_step),
        finish: Some(_gsasl_scram_server_finish),
        encode: None,
        decode: None,
    },
};