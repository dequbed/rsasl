use crate::callback::{Request, SessionCallback};
use crate::channel_bindings::{ChannelBindingCallback, NoChannelBindings};
use crate::config::{ClientConfig, ClientSide, ConfigSide, SASLConfig, ServerConfig, ServerSide};
use crate::context::Context;
use crate::error::{SASLError, SessionError};
use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use crate::property::{AuthId, AuthzId, Password};
use crate::registry::Mechanism;
use crate::session::{ClientSession, ServerSession, Session, SessionData, Side};
use crate::validate::{NoValidation, Validation};
use crate::{init, registry, session};
use std::marker::PhantomData;
use std::sync::Arc;

#[derive(Debug)]
/// SASL Provider context
///
pub(crate) struct SASL<Side: ConfigSide> {
    config: Arc<SASLConfig<Side>>,
}

#[cfg(feature = "provider")]
/// ### Provider functions
///
/// These methods are only available when compiled with feature `provider`
/// or `provider_base64` (enabled by default).
/// They are mainly relevant for protocol implementations wanting to start an
/// authentication exchange.
impl<Side: ConfigSide> SASL<Side> {
    pub fn new(config: Arc<SASLConfig<Side>>) -> Self {
        Self { config }
    }

    fn get_mechlist(&self, channel_binding_support: bool) -> impl Iterator<Item = &Mechanism> {
        [].iter()
    }

    fn start_suggested_cb<'a, V, CB>(
        &self,
        cb: CB,
        offered: impl Iterator<Item = &'a Mechname>,
    ) -> Result<Session<Side, V, CB>, SASLError>
    where
        CB: ChannelBindingCallback,
        V: Validation,
    {
        todo!()
    }

    fn start_suggested<'a, V: Validation>(
        &self,
        offered: impl Iterator<Item = &'a Mechname>,
    ) -> Result<Session<Side, V, NoChannelBindings>, SASLError> {
        todo!()
    }

    /*
    // FIXME: There need to be two variants of this fn since we have to choose "-PLUS" here. So
    //        we need to be able to supply info of if we'll supply channel binding data already.
    //        (probably just supply the channel binding callback and good enough)
    pub fn client_start_suggested<'a>(
        &self,
        mechs: impl IntoIterator<Item = &'a Mechname>,
    ) -> Result<SessionBuilder, SASLError> {
        mechs
            .into_iter()
            .filter_map(|name| {
                self.client_mech_list().into_iter().find_map(|mech| {
                    if mech.mechanism == name {
                        mech.client(&self)
                            // Option<Result<Session, SASLError>> -> Option<(&Mechanism, Session)>
                            .map(|res| res.ok().map(|auth| (mech, auth)))
                            .flatten()
                    } else {
                        None
                    }
                })
            })
            .max_by(|(a, _), (b, _)| (self.sort_fn)(a, b))
            .map(|(m, auth)| self.new_session(m, auth, Side::Client))
            .ok_or(SASLError::NoSharedMechanism)
    }

    pub fn server_start_suggested<'a>(
        &self,
        mechs: impl IntoIterator<Item = &'a Mechname>,
    ) -> Result<SessionBuilder, SASLError> {
        mechs
            .into_iter()
            .filter_map(|name| {
                self.server_mech_list().into_iter().find_map(|mech| {
                    if mech.mechanism == name {
                        mech.server(&self)
                            .map(|res| res.ok().map(|auth| (mech, auth)))
                            .flatten()
                    } else {
                        None
                    }
                })
            })
            .max_by(|(a, _), (b, _)| (self.sort_fn)(a, b))
            .map(|(m, auth)| self.new_session(m, auth, Side::Server))
            .ok_or(SASLError::NoSharedMechanism)
    }

    #[doc(hidden)]
    #[inline(always)]
    fn start_inner<'a>(
        &self,
        mech: &Mechname,
        mech_list: impl IntoIterator<Item = &'static Mechanism>,
        start: impl Fn(&Mechanism) -> Option<Result<Box<dyn Authentication>, SASLError>>,
        side: Side,
    ) -> Result<SessionBuilder, SASLError> {
        // Using an inverted result to shortcircuit out of `try_fold`: We want to stop looking
        // for mechanisms as soon as we found the first matching one. try_fold stop running as
        // soon as the first `ControlFlow::Break` is found, which for the implementation of `Try` on
        // `Result` is the first `Result::Err`.
        // If no break is encountered the `try_fold` will return `Ok(())` which we can then
        // interpret as this mechanism not being supported.
        let foldout = mech_list.into_iter().try_fold((), move |(), supported| {
            let opt = if supported.mechanism == mech {
                start(supported).map(|res| res.map(|auth| (supported, auth)))
            } else {
                None
            };
            match opt {
                Some(res) => Err(res),
                None => Ok(()),
            }
        });

        match foldout {
            Err(res) => Result::map(res, |(name, auth)| self.new_session(name, auth, side)),
            Ok(()) => Err(SASLError::unknown_mechanism(mech)),
        }
    }

    /// Starts a authentication exchange as a client
    ///
    /// Depending on the mechanism chosen this may need additional data from the application, e.g.
    /// an authcid, optional authzid and password for PLAIN. To provide that data an application
    /// has to either call `set_property` before running the step that requires the data, or
    /// install a callback.
    pub fn client_start(&self, mech: &Mechname) -> Result<SessionBuilder, SASLError> {
        self.start_inner(
            mech,
            self.client_mech_list(),
            |mechanism| mechanism.client(&self),
            Side::Client,
        )
    }

    /// Starts a authentication exchange as the server role
    ///
    /// An application acting as server will most likely need to implement a callback to check the
    /// authentication data provided by the user.
    ///
    /// See [SessionCallback] on how to implement callbacks.
    pub fn server_start(&self, mech: &Mechname) -> Result<SessionBuilder, SASLError> {
        self.start_inner(
            mech,
            self.server_mech_list(),
            |mechanism| mechanism.server(&self),
            Side::Server,
        )
    }

     */
}

pub struct SASLClient {
    inner: SASL<ClientSide>,
}
impl SASLClient {
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self {
            inner: SASL::new(config),
        }
    }

    pub fn start_suggested_cb<'a, CB>(
        &self,
        cb: CB,
        offered: impl Iterator<Item = &'a Mechname>,
    ) -> Result<ClientSession<CB>, SASLError>
    where
        CB: ChannelBindingCallback,
    {
        self.inner.start_suggested_cb(cb, offered)
    }
}
impl SASLClient {
    pub fn start_suggested<'a>(
        &self,
        offered: impl Iterator<Item = &'a Mechname>,
    ) -> Result<ClientSession, SASLError> {
        self.inner.start_suggested(offered)
    }
}

pub struct SASLServer<V = NoValidation> {
    inner: SASL<ServerSide>,
    _validate: PhantomData<V>,
}
impl<V: Validation> SASLServer<V> {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            inner: SASL::new(config),
            _validate: PhantomData,
        }
    }

    /// Return all mechanisms supported by this provider in the current configuration
    ///
    /// The parameter `channel_binding_support` should be set to `true` if the user of the
    /// `SASLServer` can provide channel bindings and will call [`Self::start_suggested_cb`].
    /// It should be set to `false` if channel bindings are not supported or if
    /// [`Self::start_suggested`] is going to be used.
    ///
    /// Setting `channel_binding_support` to `false` will not necessarily disable the use of
    /// channel bindings, as the supplied `SASLConfig` may support channel bindings irrespective
    /// of the protocol crate in use.
    pub fn get_mechlist(&self, channel_binding_support: bool) -> impl Iterator<Item = &Mechanism> {
        self.inner.get_mechlist(channel_binding_support)
    }

    pub fn start_suggested_cb<'a, CB>(
        &self,
        cb: CB,
        offered: impl Iterator<Item = &'a Mechname>,
    ) -> Result<ServerSession<V, CB>, SASLError>
    where
        CB: ChannelBindingCallback,
    {
        self.inner.start_suggested_cb(cb, offered)
    }

    pub fn start_suggested<'a>(
        &self,
        offered: impl Iterator<Item = &'a Mechname>,
    ) -> Result<ServerSession<V>, SASLError> {
        self.inner.start_suggested(offered)
    }
}

/// A [`SessionCallback`] implementation returning preconfigured values
struct CredentialsProvider {
    authid: String,
    authzid: Option<String>,
    password: String,
}
impl SessionCallback for CredentialsProvider {
    fn callback(
        &self,
        _session_data: &SessionData,
        _context: &Context,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        request
            .satisfy::<AuthId>(self.authid.as_str())?
            .satisfy::<Password>(self.password.as_bytes())?;
        if let Some(authzid) = self.authzid.as_deref() {
            request.satisfy::<AuthzId>(authzid)?;
        }
        Ok(())
    }
}
