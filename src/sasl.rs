use crate::callback::{Request, SessionCallback};
use crate::context::Context;
use crate::error::{SASLError, SessionError};
use crate::property::{AuthId, AuthzId, Password};
use crate::session::{ClientSession, ServerSession, Session, SessionBuilder, SessionData, Side};
use std::sync::Arc;
use std::marker::PhantomData;
use crate::{init, registry, session};
use crate::channel_bindings::{ChannelBindingCallback, NoChannelBindings};
use crate::config::{ClientConfig, ClientSide, ConfigSide, SASLConfig, ServerConfig, ServerSide};
use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use crate::registry::Mechanism;
use crate::validate::{NoValidation, Validation};

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

    fn get_mechlist(&self, channel_binding_support: bool) -> impl Iterator<Item=&Mechanism> {
        todo!()
    }

    fn start_suggested_cb<'a, V, CB>(&self, cb: CB, offered: impl Iterator<Item=&'a Mechname>)
        -> Result<Session<V,CB>, SASLError>
        where CB: ChannelBindingCallback
    {
        todo!()
    }

    fn start_suggested<'a, V>(&self, offered: impl Iterator<Item=&'a Mechname>)
        -> Result<Session<V, NoChannelBindings>, SASLError>
    {
        todo!()
    }

    pub fn client_mech_list(&self) -> impl Iterator<Item = &Mechanism> {
        self.config.client_mech_list()
    }

    /// Return all mechanisms supported on the server side by this provider.
    ///
    /// An server allowing client software to "log in" would use this method. A client
    /// application would use [`SASL::client_mech_list()`].
    pub fn server_mech_list(&self) -> impl IntoIterator<Item = &'static Mechanism> + '_ {
        let statics = {
            #[cfg(feature = "registry_static")]
            {
                IntoIterator::into_iter(registry::MECHANISMS)
            }
            #[cfg(not(feature = "registry_static"))]
            {
                IntoIterator::into_iter([])
            }
        };
        let dynamics = {
            #[cfg(feature = "registry_dynamic")]
            {
                self.dynamic_mechs.iter().map(|m| *m)
            }
            #[cfg(not(feature = "registry_dynamic"))]
            {
                (&[]).iter()
            }
        };
        statics
            .chain(dynamics)
            .filter(|mechanism: &&Mechanism| mechanism.server.is_some())
    }

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

    /// Start a new session with the given [`Authentication`] implementation
    ///
    /// This function should rarely be necessary, see [`SASL::client_start`] and
    /// [`SASL::server_start`] for more ergonomic alternatives.
    fn new_session(
        &self,
        mechdesc: &'static Mechanism,
        mechanism: Box<dyn Authentication>,
        side: Side,
    ) -> SessionBuilder {
        SessionBuilder::new(self.callback.clone(), mechanism, *mechdesc, side)
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

    pub fn start_suggested_cb<'a, CB>(&self, cb: CB, offered: impl Iterator<Item=&'a Mechname>)
        -> Result<ClientSession<CB>, SASLError>
        where CB: ChannelBindingCallback
    {
        let session = self.inner.start_suggested_cb(cb, offered)?;
        Ok(ClientSession::new(session))
    }
}
impl SASLClient {
    pub fn start_suggested<'a>(&self, offered: impl Iterator<Item=&'a Mechname>)
        -> Result<ClientSession, SASLError>
    {
        let session = self.inner.start_suggested(offered)?;
        Ok(ClientSession::new(session))
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
    pub fn get_mechlist(&self, channel_binding_support: bool) -> impl Iterator<Item=&Mechanism> {
        self.inner.get_mechlist(channel_binding_support)
    }

    pub fn start_suggested_cb<'a, CB>(&self, cb: CB, offered: impl Iterator<Item=&'a Mechname>)
        -> Result<ServerSession<V, CB>, SASLError>
        where CB: ChannelBindingCallback
    {
        let session = self.inner.start_suggested_cb(cb, offered)?;
        Ok(ServerSession::new(session))
    }

    pub fn start_suggested<'a>(&self, offered: impl Iterator<Item=&'a Mechname>)
        -> Result<ServerSession<V>, SASLError>
    {
        let session = self.inner.start_suggested(offered)?;
        Ok(ServerSession::new(session))
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
