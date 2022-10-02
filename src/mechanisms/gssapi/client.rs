use acid_io::Write;
use core::fmt;
use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE, OidSet};
use crate::context::EmptyProvider;
use crate::error::SessionError;
use crate::mechanism::{Authentication, MechanismData, State};
use crate::mechanisms::gssapi::properties::{Error, GssSecurityLayer, GssService};
use crate::property::Hostname;
use crate::session::MessageSent;

#[derive(Debug, Default)]
pub struct Gssapi {
    state: GssapiState,
}

enum GssapiState {
    Initial,
    Pending(ClientCtx),
    Last(ClientCtx),
    Completed(ClientCtx, bool),
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
            Self::Errored => f.write_str("Errored")
        }
    }
}

impl Authentication for Gssapi {
    fn step(&mut self, session: &mut MechanismData, input: Option<&[u8]>, writer: &mut dyn Write) -> Result<State, SessionError> {
        match core::mem::replace(&mut self.state, GssapiState::Errored) {
            GssapiState::Initial => {
                let mut targ_name = session.need_with::<GssService, _, _>(&EmptyProvider, |service| Ok(String::from(service)))?;
                targ_name.push('@');
                session.need_with::<Hostname, _, _>(&EmptyProvider, |hostname| {
                    targ_name.push_str(hostname);
                    Ok(())
                })?;
                let target = Name::new(targ_name.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
                    .map_err(Error::Gss)?;
                let mut flags = CtxFlags::GSS_C_INTEG_FLAG | CtxFlags::GSS_C_MUTUAL_FLAG;
                session.maybe_need_with::<GssSecurityLayer, _, _>(&EmptyProvider, |seclayer| if *seclayer {
                    // set mutual authentication, sequence numbering and confidential flags when a
                    // security layer is to be installed.
                    flags |= CtxFlags::GSS_C_SEQUENCE_FLAG | CtxFlags::GSS_C_CONF_FLAG;
                    Ok(())
                } else { Ok(()) })?;
                let mut krb5 = OidSet::new().map_err(Error::Gss)?;
                krb5.add(&GSS_MECH_KRB5).map_err(Error::Gss)?;

                let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&krb5)).map_err(Error::Gss)?;

                self.state = GssapiState::Pending(ClientCtx::new(cred, target, flags, Some(&GSS_MECH_KRB5)));

                self.step(session, input, writer)
            },
            GssapiState::Pending(mut ctx) => {
                if let Some(token) = ctx.step(input, None).map_err(Error::Gss)? {
                    if !token.is_empty() {
                        writer.write_all(&token)?;
                    }
                }
                if ctx.is_complete() {
                    self.state = GssapiState::Last(ctx);
                } else {
                    self.state = GssapiState::Pending(ctx);
                }

                Ok(State::Running)
            },
            GssapiState::Last(mut ctx) => {
                let input = input.ok_or(SessionError::InputDataRequired)?;
                let unwrapped = ctx.unwrap(input).map_err(Error::Gss)?;
                if unwrapped.len() != 4 {
                    Err(Error::BadFinalToken)?;
                }
                let bitmask = unwrapped[0];
                let len1 = unwrapped[1];
                let len2 = unwrapped[2];
                let len3 = unwrapped[3];
                let max_body = u32::from_be_bytes([0,len1,len2,len3]);

                let response = 0u32.to_be_bytes();
                let wrapped = ctx.wrap(false, &response).map_err(Error::Gss)?;
                writer.write_all(&wrapped)?;
                self.state = GssapiState::Completed(ctx, bitmask != 0);
                Ok(State::Finished(MessageSent::Yes))
            }
            GssapiState::Completed(..) | GssapiState::Errored => {
                Err(SessionError::MechanismDone)
            }
        }
    }

    fn encode(&mut self, input: &[u8], writer: &mut dyn Write) -> Result<usize, SessionError> {
        match self.state {
            GssapiState::Completed(ref mut ctx, true) => {
                let wrapped = ctx.wrap(true, input).map_err(Error::Gss)?;
                writer.write_all(&wrapped)?;
                Ok(wrapped.len())
            },
            _ => Err(SessionError::NoSecurityLayer)
        }
    }

    fn decode(&mut self, input: &[u8], writer: &mut dyn Write) -> Result<usize, SessionError> {
        match self.state {
            GssapiState::Completed(ref mut ctx, true) => {
                let unwrapped = ctx.unwrap(input).map_err(Error::Gss)?;
                writer.write_all(&unwrapped)?;
                Ok(unwrapped.len())
            }
            _ => Err(SessionError::NoSecurityLayer)
        }
    }

    fn has_security_layer(&self) -> bool {
        match self.state {
            GssapiState::Completed(_, has_security_layer) => has_security_layer,
            _ => false,
        }
    }
}
