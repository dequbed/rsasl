use crate::context::EmptyProvider;
use crate::error::SessionError;
use crate::mechanism::{Authentication, MechanismData, State};
use crate::mechanisms::gssapi::properties::{Error, GssSecurityLayer, GssService, SecurityLayer};
use crate::property::Hostname;
use crate::session::MessageSent;
use acid_io::Write;
use core::fmt;
use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE};

#[derive(Debug, Default)]
pub struct Gssapi {
    state: GssapiState,
}

enum GssapiState {
    Initial,
    Pending(ClientCtx),
    Last(ClientCtx, SecurityLayer),
    Completed(Option<(ClientCtx, bool)>),
    Errored,
}

impl Default for GssapiState {
    fn default() -> Self {
        Self::Initial
    }
}

impl fmt::Debug for GssapiState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initial => f.write_str("Initial"),
            Self::Pending(..) => f.write_str("Pending"),
            Self::Last(..) => f.write_str("Last"),
            Self::Completed(..) => f.write_str("Completed"),
            Self::Errored => f.write_str("Errored"),
        }
    }
}

impl Authentication for Gssapi {
    fn step(
        &mut self,
        session: &mut MechanismData,
        input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> Result<State, SessionError> {
        match core::mem::replace(&mut self.state, GssapiState::Errored) {
            GssapiState::Initial => {
                let mut targ_name = session
                    .need_with::<GssService, _, _>(&EmptyProvider, |service| {
                        Ok(String::from(service))
                    })?;
                targ_name.push('@');
                session.need_with::<Hostname, _, _>(&EmptyProvider, |hostname| {
                    targ_name.push_str(hostname);
                    Ok(())
                })?;
                let target = Name::new(targ_name.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
                    .map_err(Error::Gss)?;

                let mut krb5 = OidSet::new().map_err(Error::Gss)?;
                krb5.add(&GSS_MECH_KRB5).map_err(Error::Gss)?;

                let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&krb5))
                    .map_err(Error::Gss)?;

                self.state = GssapiState::Pending(ClientCtx::new(
                    cred,
                    target,
                    // Allow all flags. Setting them does not mean the final context will provide
                    // them, so this should not be an issue.
                    CtxFlags::all(),
                    Some(&GSS_MECH_KRB5),
                ));

                self.step(session, input, writer)
            }
            GssapiState::Pending(mut ctx) => {
                if let Some(token) = ctx.step(input, None).map_err(Error::Gss)? {
                    if !token.is_empty() {
                        writer.write_all(&token)?;
                    }
                }
                if !ctx.is_complete() {
                    self.state = GssapiState::Pending(ctx);
                    return Ok(State::Running);
                }

                // Request acceptable security layers from the client.
                let acceptable = session
                    .maybe_need_with::<GssSecurityLayer, _, _>(&EmptyProvider, |acceptable| {
                        let flags = ctx.flags().map_err(Error::Gss)?;
                        // If acceptable contains `NO_SECURITY_LAYER` or is empty, which we treat as
                        // the same, our context is always secure enough.
                        if acceptable.is_empty() || acceptable.contains(SecurityLayer::NO_SECURITY_LAYER) {
                            return Ok(*acceptable);
                        }

                        // Else, we check if the least required flag is set.

                        if acceptable.contains(SecurityLayer::INTEGRITY) && flags.contains(CtxFlags::GSS_C_INTEG_FLAG) {
                            return Ok(*acceptable);
                        }

                        let required = CtxFlags::GSS_C_INTEG_FLAG
                            | CtxFlags::GSS_C_MUTUAL_FLAG
                            | CtxFlags::GSS_C_CONF_FLAG;

                        if flags.contains(required) {
                            Ok(*acceptable)
                        } else {
                            Err(Error::BadContext.into())
                        }
                    })?
                    .unwrap_or_default();

                self.state = GssapiState::Last(ctx, acceptable);
                Ok(State::Running)
            }
            GssapiState::Last(mut ctx, acceptable) => {
                let input = input.ok_or(SessionError::InputDataRequired)?;
                let unwrapped = ctx.unwrap(input).map_err(Error::Gss)?;
                if unwrapped.len() != 4 {
                    Err(Error::BadFinalToken)?;
                }

                let supported_sec =
                    SecurityLayer::from_bits(unwrapped[0]).ok_or(Error::BadFinalToken)?;

                // This contains all layers that are supported by the server and acceptable to
                // the user.
                let shared_layers = supported_sec & acceptable;

                let (response, wrap) = if shared_layers.contains(SecurityLayer::CONFIDENTIALITY) {
                    (
                        [SecurityLayer::CONFIDENTIALITY.bits(), 0xFF, 0xFF, 0xFF],
                        Some(true)
                    )
                } else if shared_layers.contains(SecurityLayer::INTEGRITY) {
                    (
                        [SecurityLayer::INTEGRITY.bits(), 0xFF, 0xFF, 0xFF],
                        Some(false)
                    )
                } else if shared_layers.contains(SecurityLayer::NO_SECURITY_LAYER) {
                    (
                        [SecurityLayer::NO_SECURITY_LAYER.bits(), 0x00, 0x00, 0x00],
                        None
                    )
                } else {
                    return Err(Error::BadContext.into());
                };

                let wrapped = ctx.wrap(false, &response).map_err(Error::Gss)?;
                writer.write_all(&wrapped)?;
                self.state = GssapiState::Completed(wrap.map(|e| (ctx, e)));
                Ok(State::Finished(MessageSent::Yes))
            }
            GssapiState::Completed(..) | GssapiState::Errored => Err(SessionError::MechanismDone),
        }
    }

    fn encode(&mut self, input: &[u8], writer: &mut dyn Write) -> Result<usize, SessionError> {
        match self.state {
            GssapiState::Completed(Some((ref mut ctx, encrypt))) => {
                let wrapped = ctx.wrap(encrypt, input).map_err(Error::Gss)?;
                writer.write_all(&wrapped)?;
                Ok(wrapped.len())
            }
            _ => Err(SessionError::NoSecurityLayer),
        }
    }

    fn decode(&mut self, input: &[u8], writer: &mut dyn Write) -> Result<usize, SessionError> {
        match self.state {
            GssapiState::Completed(Some((ref mut ctx, _))) => {
                let unwrapped = ctx.unwrap(input).map_err(Error::Gss)?;
                writer.write_all(&unwrapped)?;
                Ok(unwrapped.len())
            }
            _ => Err(SessionError::NoSecurityLayer),
        }
    }

    fn has_security_layer(&self) -> bool {
        matches!(self.state, GssapiState::Completed(Some(_)))
    }
}
