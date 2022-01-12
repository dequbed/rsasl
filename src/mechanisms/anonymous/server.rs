use std::io::Write;
use std::ptr::NonNull;
use ::libc;
use libc::size_t;
use crate::gsasl::consts::{GSASL_AUTHENTICATION_ERROR, GSASL_MECHANISM_PARSE_ERROR, GSASL_NEEDS_MORE, GSASL_OK};
use crate::{Mechanism, Mechname, SASLError, validate};
use crate::mechanism::Authentication;
use crate::property::AnonymousToken;
use crate::session::{SessionData, StepResult};
use crate::session::Step::{Done, NeedsMore};
use crate::validate::ANONYMOUS;

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;

impl Authentication for Anonymous {
    fn step(&mut self, session: &mut SessionData, input: Option<&[u8]>, writer: &mut dyn Write) -> StepResult {
        let input = if let Some(buf) = input {
            buf
        } else {
            return Ok(NeedsMore(None));
        };

        if let Ok(input) = std::str::from_utf8(input) {
            /* token       = 1*255TCHAR
             The <token> production is restricted to 255 UTF-8 encoded Unicode
             characters.   As the encoding of a characters uses a sequence of 1
             to 4 octets, a token may be long as 1020 octets. */
            if input.len() == 0 || input.len() > 255 {
                return Err(SASLError::MechanismParseError);
            }

            session.set_property::<AnonymousToken>(Box::new(input.to_string()));
            session.validate(ANONYMOUS)?;

            Ok(Done(None))
        } else {
            Err(SASLError::MechanismParseError)
        }
    }
}

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS_CLIENT};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS_CLIENT))]
pub static ANONYMOUS_SERVER: Mechanism = Mechanism {
    mechanisms: &[Mechname::const_new_unchecked("ANONYMOUS")],
    matches: |name| name.as_str() == "ANONYMOUS",
    start: |_sasl| Ok(Box::new(Anonymous)),
};
