use crate::context::EmptyProvider;
use crate::error::SessionError;
use crate::mechanism::{Authentication, MechanismData, State};
use crate::mechanisms::gssapi::properties::{Error, GssSecurityLayer, SecurityLayer};
use crate::prelude::State::Finished;
use crate::session::MessageSent;
use acid_io::Write;
use alloc::mem;
use core::fmt;
use libgssapi::context::{CtxFlags, SecurityContext, ServerCtx};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::oid::{OidSet, GSS_MECH_KRB5};

#[derive(Debug, Default)]
pub struct Gssapi {
    state: GssapiState,
}

enum GssapiState {
    Initial,
    Pending(ServerCtx),
    Installed(ServerCtx, SecurityLayer),
    Final(ServerCtx, SecurityLayer),
    Done(Option<(ServerCtx, bool)>),
    Errored,
}

impl fmt::Debug for GssapiState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GssapiState::Initial => f.write_str("Initial"),
            GssapiState::Pending(..) => f.write_str("Pending"),
            GssapiState::Installed(..) => f.write_str("Installed"),
            GssapiState::Final(..) => f.write_str("Final"),
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
                let token = ctx.step(input).map_err(Error::Gss)?;
                if ctx.is_complete() {
                    // Query the user for acceptable security layers
                    let mut acceptable = session
                        .maybe_need_with::<GssSecurityLayer, _, _>(&EmptyProvider, |acceptable| {
                            Ok(*acceptable)
                        })?
                        .unwrap_or_default();

                    let ctx_flags = ctx.flags().map_err(Error::Gss)?;

                    if !ctx_flags.contains(CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_CONF_FLAG)
                    {
                        acceptable.set(SecurityLayer::CONFIDENTIALITY, false);
                    }
                    if !ctx_flags.contains(CtxFlags::GSS_C_INTEG_FLAG) {
                        acceptable.set(SecurityLayer::INTEGRITY, false);
                    }

                    // if unsetting all layers not supported or not acceptable leaves us with none,
                    // we error out.
                    if acceptable.is_empty() {
                        return Err(Error::BadContext.into());
                    }

                    self.state = GssapiState::Installed(ctx, acceptable);
                }
                // If an auth exchange token was produced we need to do another loop, otherwise we
                // immediately produce the supported security layer token.
                if let Some(token) = token {
                    writer.write_all(&token)?;
                    Ok(State::Running)
                } else {
                    self.step(session, None, writer)
                }
            }
            GssapiState::Installed(mut ctx, supported) => {
                let out_bytes = if supported
                    .intersects(SecurityLayer::CONFIDENTIALITY | SecurityLayer::INTEGRITY)
                {
                    // TODO: This should come from a call to `GSS_Wrap_size_limit` instead of
                    //       being a static 2^25 - 1
                    [supported.bits(), 0xFF, 0xFF, 0xFF]
                } else {
                    [supported.bits(), 0x00, 0x00, 0x00]
                };
                let wrapped = ctx.wrap(false, &out_bytes).map_err(Error::Gss)?;
                writer.write_all(&wrapped)?;
                self.state = GssapiState::Final(ctx, supported);
                Ok(State::Running)
            }
            GssapiState::Final(mut ctx, supported) => {
                let input = input.ok_or(SessionError::InputDataRequired)?;
                let unwrapped = ctx.unwrap(input).map_err(Error::Gss)?;
                if unwrapped.len() != 4 {
                    Err(Error::BadFinalToken)?;
                }
                let selected = SecurityLayer::from_bits(unwrapped[0]).ok_or(Error::BadFinalToken)?;

                // If the client selected a layer we don't support or accept, error.
                if !selected.intersects(supported) {
                    Err(Error::BadFinalToken)?;
                }

                let wrap_state = if selected.contains(SecurityLayer::CONFIDENTIALITY) {
                    Some((ctx, true))
                } else if selected.contains(SecurityLayer::INTEGRITY) {
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
            }
            _ => Err(SessionError::NoSecurityLayer),
        }
    }

    fn decode(&mut self, input: &[u8], writer: &mut dyn Write) -> Result<usize, SessionError> {
        match self.state {
            GssapiState::Done(Some((ref mut ctx, _))) => {
                let unwrapped = ctx.unwrap(input).map_err(Error::Gss)?;
                writer.write_all(&unwrapped)?;
                Ok(unwrapped.len())
            }
            _ => Err(SessionError::NoSecurityLayer),
        }
    }
}
