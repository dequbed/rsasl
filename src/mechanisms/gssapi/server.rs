use alloc::io::Read;
use alloc::mem;
use crate::error::SessionError;
use crate::mechanism::{Authentication, MechanismData, State};
use crate::mechanisms::gssapi::properties::{Error, SecurityLayer};
use acid_io::Write;
use core::fmt;
use libgssapi::context::{CtxFlags, SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::oid::{GSS_MECH_KRB5, OidSet};
use crate::prelude::State::Finished;
use crate::session::MessageSent;

#[derive(Debug, Default)]
pub struct Gssapi {
    state: GssapiState,
}

enum GssapiState {
    Initial,
    Pending(ServerCtx),
    Installed(ServerCtx),
    Final(ServerCtx),
    Done(Option<(ServerCtx, bool)>),
    Errored,
}

impl fmt::Debug for GssapiState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GssapiState::Initial => f.write_str("Initial"),
            GssapiState::Pending(_) => f.write_str("Pending"),
            GssapiState::Installed(_) => f.write_str("Installed"),
            GssapiState::Final(_) => f.write_str("Final"),
            GssapiState::Done(Some((_, true))) => f.write_str("Done<Confidentiality>"),
            GssapiState::Done(Some((_, false))) => f.write_str("Done<Integrity>"),
            GssapiState::Done(None) => f.write_str("Done<NoSecurity>"),
            GssapiState::Errored => f.write_str("Errored"),
        }
    }
}

impl Default for GssapiState {
    fn default() -> Self {
        Self::Initial
    }
}

impl Authentication for Gssapi {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        match mem::replace(&mut self.state, GssapiState::Errored) {
            GssapiState::Initial => {
                let mut krb5 = OidSet::new().map_err(Error::Gss)?;
                krb5.add(&GSS_MECH_KRB5).map_err(Error::Gss)?;
                let cred = Cred::acquire(None, None, CredUsage::Accept, Some(&krb5))
                    .map_err(Error::Gss)?;
                let ctx = ServerCtx::new(cred);
                self.state = GssapiState::Pending(ctx);
                self.step(session, input, writer)
            }
            GssapiState::Pending(mut ctx) => {
                let input = input.ok_or(SessionError::InputDataRequired)?;
                if let Some(token) = ctx.step(input).map_err(Error::Gss)? {
                    writer.write_all(&token)?;
                    if ctx.is_complete() {
                        self.state = GssapiState::Installed(ctx);
                    }
                    Ok(State::Running)
                } else {
                    // if no token was produced we're done and immediately produce the token
                    // indicating the installed security layer
                    self.state = GssapiState::Installed(ctx);
                    self.step(session, None, writer)
                }
            }
            GssapiState::Installed(mut ctx) => {
                let ctx_flags = ctx.flags().map_err(Error::Gss)?;
                let mut flags = SecurityLayer::NO_SECURITY_LAYER;
                if ctx_flags.contains(CtxFlags::GSS_C_INTEG_FLAG) {
                    flags |= SecurityLayer::INTEGRITY;
                    if ctx_flags.contains(CtxFlags::GSS_C_CONF_FLAG) {
                        flags |= SecurityLayer::CONFIDENTIALITY;
                    }
                }
                let out_bytes = if flags.bits() > 1 {
                    // TODO: This should come from a call to `GSS_Wrap_size_limit` instead of
                    //       being a static 2^25 - 1
                    [flags.bits(), 0xFF, 0xFF, 0xFF]
                } else {
                    [flags.bits(), 0x00, 0x00, 0x00]
                };
                let wrapped = ctx.wrap(false, &out_bytes).map_err(Error::Gss)?;
                writer.write_all(&wrapped)?;
                self.state = GssapiState::Final(ctx);
                Ok(State::Running)
            }
            GssapiState::Final(mut ctx) => {
                let input = input.ok_or(SessionError::InputDataRequired)?;
                let unwrapped = ctx.unwrap(input).map_err(Error::Gss)?;
                if unwrapped.len() != 4 {
                    Err(Error::BadFinalToken)?;
                }
                let flags = SecurityLayer::from_bits(unwrapped[0]).ok_or(Error::BadFinalToken)?;

                let wrap_state = if flags.contains(SecurityLayer::CONFIDENTIALITY) {
                    Some((ctx, true))
                } else if flags.contains(SecurityLayer::INTEGRITY) {
                    Some((ctx, false))
                } else {
                    None
                };

                self.state = GssapiState::Done(wrap_state);

                Ok(Finished(MessageSent::No))
            }
            _ => Err(SessionError::MechanismDone),
        }
    }

    fn has_security_layer(&self) -> bool {
        // If we're done and have at least integrity protection negotiated we must call wrap/unwrap.
        matches!(self.state, GssapiState::Done(Some(_)))
    }

    fn encode(&mut self, input: &[u8], writer: &mut dyn Write) -> Result<usize, SessionError> {
        match self.state {
            GssapiState::Done(Some((ref mut ctx, encrypt))) => {
                let wrapped = ctx.wrap(encrypt, input).map_err(Error::Gss)?;
                writer.write_all(&wrapped)?;
                Ok(wrapped.len())
            },
            _ => Err(SessionError::NoSecurityLayer)
        }
    }

    fn decode(&mut self, input: &[u8], writer: &mut dyn Write) -> Result<usize, SessionError> {
        match self.state {
            GssapiState::Done(Some((ref mut ctx, _))) => {
                let unwrapped = ctx.unwrap(input).map_err(Error::Gss)?;
                writer.write_all(&unwrapped)?;
                Ok(unwrapped.len())
            },
            _ => Err(SessionError::NoSecurityLayer)
        }
    }
}
