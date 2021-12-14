use crate::gsasl::external::client::_gsasl_external_client_step;
use crate::gsasl::external::server::_gsasl_external_server_step;
use crate::gsasl::gsasl::{Gsasl_mechanism, MechanismVTable};

/* mechinfo.c --- Definition of EXTERNAL mechanism.
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

pub static mut gsasl_external_mechanism: Gsasl_mechanism = Gsasl_mechanism {
    name: "EXTERNAL",
    client: MechanismVTable {
        init: None,
        done: None,
        start: None,
        step: Some(_gsasl_external_client_step),
        finish: None,
        encode: None,
        decode: None,
    },
    server: MechanismVTable {
        init: None,
        done: None,
        start: None,
        step: Some(_gsasl_external_server_step),
        finish: None,
        encode: None,
        decode: None,
    },
};
