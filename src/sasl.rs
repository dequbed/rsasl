use crate::channel_bindings::NoChannelBindings;
use crate::config::SASLConfig;
use core::fmt::{Debug, Formatter};

use crate::mechname::Mechname;

use crate::validate::{NoValidation, Validation};

use crate::alloc::sync::Arc;
use crate::typed::Tagged;

#[derive(Debug)]
/// SASL Client context
///
/// A SASL Client starts authentication using the
pub struct SASLClient<CB = NoChannelBindings> {
    inner: Sasl<NoValidation, CB>,
}

#[allow(dead_code)]
pub struct SASLServer<V: Validation, CB = NoChannelBindings> {
    inner: Sasl<V, CB>,
}

/// SASL Provider context
///
pub struct Sasl<V: Validation = NoValidation, CB = NoChannelBindings> {
    pub(crate) config: Arc<SASLConfig>,
    pub(crate) cb: CB,
    pub(crate) validation: Tagged<'static, V>,
}
impl<V: Validation + Debug, CB: Debug> Debug for Sasl<V, CB> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sasl")
            .field("config", &self.config)
            .field("cb", &self.cb)
            .finish_non_exhaustive()
    }
}

#[cfg(any(feature = "provider", test))]
#[cfg_attr(docsrs, doc(cfg(feature = "provider")))]
#[allow(dead_code)]
mod provider {
    use super::{
        Arc, Mechname, NoChannelBindings, NoValidation, SASLClient, SASLConfig, SASLServer, Sasl,
        Tagged, Validation,
    };
    use crate::channel_bindings::ChannelBindingCallback;
    use crate::error::SASLError;
    use crate::registry::Mechanism;
    use crate::session::{Session, Side};

    /************************************************************
     * CLIENT impls
     ************************************************************/

    impl SASLClient {
        #[must_use]
        pub fn new(config: Arc<SASLConfig>) -> Self {
            Self {
                inner: Sasl::client(config),
            }
        }
    }

    /// ### Provider functions
    ///
    /// These methods are only available when compiled with feature `provider`
    /// or `provider_base64` (enabled by default).
    /// They are mainly relevant for protocol implementations wanting to start an
    /// authentication exchange.
    impl<CB: ChannelBindingCallback> SASLClient<CB> {
        pub fn with_cb(config: Arc<SASLConfig>, cb: CB) -> Self {
            Self {
                inner: Sasl::with_cb(config, cb),
            }
        }

        #[inline(always)]
        /// Starts a authentication exchange as a client
        ///
        /// Depending on the mechanism chosen this may need additional data from the application, e.g.
        /// an authcid, optional authzid and password for PLAIN. This data is provided by the
        /// application via callbacks.
        ///
        /// This is a small wrapper for [`Self::start_suggested_iter`] to keep
        /// backwards-compatability by allowing to pass `&[&Mechname]`, which only implemens
        /// `IntoIterator<Item=&&Mechname>`. Using the `_iter` variant is more efficient if you can
        /// generate direct references to `Mechname`.
        pub fn start_suggested<'a>(
            self,
            offered: impl IntoIterator<Item = &'a &'a Mechname>,
        ) -> Result<Session<NoValidation, CB>, SASLError> {
            self.start_suggested_iter(offered.into_iter().copied())
        }

        /// Starts a authentication exchange as a client
        ///
        /// Depending on the mechanism chosen this may need additional data from the application, e.g.
        /// an authcid, optional authzid and password for PLAIN. This data is provided by the
        /// application via callbacks.
        pub fn start_suggested_iter<'a>(
            self,
            offered: impl IntoIterator<Item = &'a Mechname>,
        ) -> Result<Session<NoValidation, CB>, SASLError> {
            self.inner.client_start_suggested(offered)
        }
    }

    /************************************************************
     * SERVER impls
     ************************************************************/

    impl<V: Validation> SASLServer<V> {
        #[must_use]
        pub fn new(config: Arc<SASLConfig>) -> Self {
            Self {
                inner: Sasl::server(config),
            }
        }
    }
    impl<V: Validation, CB: ChannelBindingCallback> SASLServer<V, CB> {
        pub fn with_cb(config: Arc<SASLConfig>, cb: CB) -> Self {
            Self {
                inner: Sasl::with_cb(config, cb),
            }
        }

        pub fn get_available(&self) -> impl IntoIterator<Item = &Mechanism> {
            self.inner.get_available()
        }

        /// Starts a authentication exchange as the server role
        ///
        /// An application acting as server will most likely need to implement a callback to check the
        /// authentication data provided by the user.
        ///
        /// See [`SessionCallback`](crate::callback::SessionCallback) on how to implement callbacks.
        pub fn start_suggested(self, selected: &Mechname) -> Result<Session<V, CB>, SASLError> {
            self.inner.server_start_suggested(selected)
        }
    }

    /************************************************************
     * SHARED impls
     ************************************************************/

    impl Sasl {
        fn client(config: Arc<SASLConfig>) -> Self {
            Self {
                config,
                cb: NoChannelBindings,
                validation: Tagged(None),
            }
        }
    }
    impl<V: Validation> Sasl<V> {
        fn server(config: Arc<SASLConfig>) -> Self {
            Self {
                config,
                cb: NoChannelBindings,
                validation: Tagged(None),
            }
        }
    }
    impl<CB: ChannelBindingCallback, V: Validation> Sasl<V, CB> {
        fn with_cb(config: Arc<SASLConfig>, cb: CB) -> Self {
            Self {
                config,
                cb,
                validation: Tagged(None),
            }
        }

        fn client_start_suggested<'a>(
            self,
            offered: impl IntoIterator<Item = &'a Mechname>,
        ) -> Result<Session<V, CB>, SASLError> {
            let (mechanism, mechanism_desc) = self.config.select_mechanism(offered)?;
            Ok(Session::new(self, Side::Client, mechanism, *mechanism_desc))
        }

        fn server_start_suggested(self, selected: &Mechname) -> Result<Session<V, CB>, SASLError> {
            let config = self.config.clone();
            let mech = self
                .get_available()
                .find(|mech| mech.mechanism == selected)
                .ok_or(SASLError::NoSharedMechanism)?;
            let auth = mech
                .server(config.as_ref())
                .ok_or(SASLError::NoSharedMechanism)??;
            Ok(Session::new(self, Side::Server, auth, *mech))
        }

        pub fn get_available<'a>(&self) -> impl Iterator<Item = &'a Mechanism> {
            self.config.mech_list().filter(|mech| mech.server.is_some())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_impl_all!(Sasl: Send, Sync);
}
