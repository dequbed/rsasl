use crate::callback::{Request, SessionCallback};
use crate::context::Context;
use crate::error::{SASLError, SessionError};
use crate::property::{AuthId, AuthzId, Password};
use crate::session::{SessionBuilder, SessionData, Side};
use std::sync::Arc;
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use crate::{init, registry};
use crate::mechanism::Authentication;
use crate::mechname::Mechname;
use crate::registry::Mechanism;

/// SASL Provider context
///
/// This is the central type required to use SASL both for protocol implementations requiring the
/// use of SASL and for users wanting to provide SASL authentication to such implementations.
///
/// This struct is neither `Clone` nor `Copy`, but all functions required for authentication
/// exchanges only need a non-mutable reference to it. If you want to be able to do several
/// authentication exchanges in parallel, e.g. in a server context, you can wrap it in an
/// [`std::sync::Arc`] to add cheap cloning, or initialize it as a global value.
pub struct SASL {
    pub callback: Arc<dyn SessionCallback>,

    #[cfg(feature = "registry_dynamic")]
    pub(crate) dynamic_mechs: Vec<&'static Mechanism>,
    #[cfg(feature = "registry_static")]
    static_mechs: &'static [Mechanism],

    sort_fn: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,
}

impl SASL {
    pub fn new(callback: Arc<dyn SessionCallback>) -> Self {
        Self {
            callback,

            #[cfg(feature = "registry_dynamic")]
            dynamic_mechs: Vec::new(),

            #[cfg(feature = "registry_static")]
            static_mechs: &registry::MECHANISMS,

            sort_fn: |a, b| a.priority.cmp(&b.priority),
        }
    }

    /// Construct a rsasl context with preconfigured Credentials
    pub fn with_credentials(authid: String, authzid: Option<String>, password: String) -> Self {
        Self::new(Arc::new(CredentialsProvider {
            authid,
            authzid,
            password,
        }))
    }

    /// Initialize this SASL with the builtin Mechanisms
    ///
    /// Calling this function is usually not necessary if you're using the `registry_static`
    /// feature since the builtin mechanisms are registered at compile time then. However the
    /// optimizer may strip modules that it deems are unused so a call may still be necessary but
    /// it then extremely cheap.
    fn init(&mut self) {
        init::register_builtin(self);
    }
}

impl Debug for SASL {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SASL");
        #[cfg(feature = "registry_dynamic")]
        s.field("registered mechanisms", &self.dynamic_mechs);
        #[cfg(feature = "registry_static")]
        s.field("collected mechanisms", &self.static_mechs);
        s.finish()
    }
}

#[cfg(feature = "provider")]
/// ### Provider functions
///
/// These methods are only available when compiled with feature `provider`
/// or `provider_base64` (enabled by default).
/// They are mainly relevant for protocol implementations wanting to start an
/// authentication exchange.
impl SASL {
    /// Return all mechanisms supported on the client side by this provider.
    ///
    /// An interactive client "logging in" to some server application would use this method. The
    /// server application would use [`SASL::server_mech_list()`].
    pub fn client_mech_list(&self) -> impl IntoIterator<Item = &'static Mechanism> + '_ {
        #[cfg(feature = "registry_static")]
        {
            #[cfg(feature = "registry_dynamic")]
            {
                registry::MECHANISMS
                    .into_iter()
                    .chain(self.dynamic_mechs.iter().map(|m| *m))
                    .filter(|mechanism| mechanism.client.is_some())
            }
            #[cfg(not(feature = "registry_dynamic"))]
            {
                registry::MECHANISMS
                    .into_iter()
                    .filter(|mechanism| mechanism.client.is_some())
            }
        }
        #[cfg(all(not(feature = "registry_static"), feature = "registry_dynamic"))]
        {
            self.dynamic_mechs.iter().map(|m| *m)
        }
        #[cfg(not(any(feature = "registry_static", feature = "registry_dynamic")))]
        {
            []
        }
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

    /// Returns whether there is client-side support for the given mechanism.
    ///
    /// You should not call this function to filter supported mechanisms if you intend to start a
    /// session right away since this function only calls `self.client_start()` with the given
    /// Mechanism name and throws away the Session.
    fn client_supports(&self, mech: &Mechname) -> bool {
        self.client_start(mech).is_ok()
    }

    /// Returns whether there is server-side support for the specified mechanism
    ///
    /// You should not call this function to filter supported mechanisms if you intend to start a
    /// session right away since this function only calls `self.server_start()` with the given
    /// Mechanism name and throws away the Session.
    fn server_supports(&self, mech: &Mechname) -> bool {
        self.server_start(mech).is_ok()
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
