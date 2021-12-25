use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::consts::{AUTHID, AUTHZID, PASSWORD};
use crate::gsasl::consts::{GSASL_MALLOC_ERROR, GSASL_NO_AUTHID, GSASL_NO_PASSWORD, GSASL_OK};
use crate::{Mechanism, MechanismBuilder, RsaslError, SASL, SaslError, Session};
use crate::session::StepResult;
use crate::Step::Done;

extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: size_t)
     -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> size_t;
    fn malloc(_: size_t) -> *mut libc::c_void;
}

/* plain.h --- Prototypes for SASL mechanism PLAIN as defined in RFC 2595.
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
/* client.c --- SASL mechanism PLAIN as defined in RFC 2595, client side.
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
/* Get memcpy, strdup, strlen. */
/* Get malloc, free. */
pub unsafe fn _gsasl_plain_client_step(sctx: &mut Session,
                                       _mech_data: Option<NonNull<()>>,
                                       _input: Option<&[u8]>,
                                       output: *mut *mut libc::c_char,
                                       output_len: *mut size_t
) -> libc::c_int
{
    let authzid = sctx.get_property_or_callback::<AUTHZID>();
    let authid = sctx.get_property_or_callback::<AUTHID>();
    let password = sctx.get_property_or_callback::<PASSWORD>();

    let authzidlen: size_t = if let Some(ref authzid) = authzid {
        authzid.len()
    } else {
        0
    };

    if authid.is_none() {
        return GSASL_NO_AUTHID as libc::c_int
    }
    let authid = authid.unwrap();
    let authidlen = authid.len();

    if password.is_none() {
        return GSASL_NO_PASSWORD as libc::c_int
    }
    let password = password.unwrap();
    let passwordlen = password.len();

    *output_len =
        authzidlen.wrapping_add(1)
            .wrapping_add(authidlen)
            .wrapping_add(1)
            .wrapping_add(passwordlen);

    let mut out = malloc(*output_len) as *mut libc::c_char;
    *output = out;

    if out.is_null() {
        return GSASL_MALLOC_ERROR as libc::c_int
    }

    if let Some(ref authzid) = authzid {
        memcpy(out as *mut libc::c_void,
               authzid.as_ptr() as *const libc::c_void,
               authzid.len());
        out = out.offset(authzid.len() as isize)
    }
    let fresh0 = out;
    out = out.offset(1);
    *fresh0 = '\u{0}' as i32 as libc::c_char;

    memcpy(out as *mut libc::c_void,
           authid.as_ptr() as *const libc::c_void,
           authidlen);
    out = out.offset(authidlen as isize);

    let fresh1 = out;
    out = out.offset(1);
    *fresh1 = '\u{0}' as i32 as libc::c_char;

    memcpy(out as *mut libc::c_void,
           password.as_ptr() as *const libc::c_void,
           passwordlen);
    return GSASL_OK as libc::c_int;
}

#[derive(Copy, Clone, Debug)]
pub struct Plain;

impl MechanismBuilder for Plain {
    fn start(&self, _sasl: &SASL) -> Result<Box<dyn Mechanism>, RsaslError> {
        Ok(Box::new(Plain))
    }
}

impl Mechanism for Plain {
    fn step(&mut self, session: &mut Session, input: Option<&[u8]>) -> StepResult {
        let authzid = session.get_property_or_callback::<AUTHZID>();
        let authzidref: Option<&str> = authzid.as_ref().map(|s| s.as_str());
        let authid = session.get_property_or_callback::<AUTHID>()
            .ok_or(SaslError(GSASL_NO_AUTHID))?;

        let password = session.get_property_or_callback::<PASSWORD>()
            .ok_or(SaslError(GSASL_NO_PASSWORD))?;

        let out = format!("{}\0{}\0{}", authzidref.unwrap_or(""), authid, password);

        Ok(Done(Some(out.into_boxed_str().into_boxed_bytes())))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::consts::{AUTHID, PASSWORD};
    use crate::Session;
    use crate::Step::{Done, NeedsMore};

    #[test]
    fn simple() {
        let mut session = Session::new(None);

        let username = "testuser".to_string();
        assert_eq!(username.len(), 8);
        let password = "secret".to_string();
        assert_eq!(password.len(), 6);

        session.set_property::<AUTHID>(Box::new(username));
        session.set_property::<PASSWORD>(Box::new(password));


        // Do an authentication step. In a PLAIN exchange there is only one step, with no data.
        let mut plain = Plain;
        let step_result = plain.step(&mut session, None).unwrap();

        match step_result {
            Done(Some(buffer)) => {
                // (1) "\0" + (8) "testuser" + (1) "\0" + (6) "secret"
                assert_eq!(buffer.len(), 1 + 8 + 1 + 6);
                let (name, pass) = buffer.split_at(9);
                assert_eq!(name[0], 0);
                assert_eq!(name, b"\0testuser");
                assert_eq!(pass[0], 0);
                assert_eq!(pass, b"\0secret");
                return;
            },
            Done(None) => panic!("PLAIN exchange produced no output"),
            NeedsMore(_) => panic!("PLAIN exchange took more than one step"),
        }
    }
}