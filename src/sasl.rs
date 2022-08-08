use crate::channel_bindings::{ChannelBindingCallback, NoChannelBindings};
use crate::config::SASLConfig;

use crate::error::SASLError;

use crate::mechname::Mechname;

use crate::registry::Mechanism;
use crate::session::{Session, Side};
use crate::validate::{NoValidation, Validation};

use std::sync::Arc;

#[derive(Debug)]
/// SASL Client context
///
/// A SASL Client starts authentication using the
pub struct SASLClient<CB = NoChannelBindings> {
    inner: Sasl<NoValidation, CB>,
}

pub struct SASLServer<V: Validation, CB = NoChannelBindings> {
    inner: Sasl<V, CB>,
}

#[derive(Debug)]
/// SASL Provider context
///
pub(crate) struct Sasl<V: Validation = NoValidation, CB = NoChannelBindings> {
    pub(crate) config: Arc<SASLConfig>,
    pub(crate) cb: CB,
    pub(crate) validation: Option<V::Value>,
}

#[cfg(any(feature = "provider", test))]
mod provider {
    use super::*;

    /************************************************************
     * CLIENT impls
     ************************************************************/

    impl SASLClient {
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

        /// Starts a authentication exchange as a client
        ///
        /// Depending on the mechanism chosen this may need additional data from the application, e.g.
        /// an authcid, optional authzid and password for PLAIN. To provide that data an application
        /// has to either call `set_property` before running the step that requires the data, or
        /// install a callback.
        pub fn start_suggested(
            self,
            offered: &[&Mechname],
        ) -> Result<Session<NoValidation, CB>, SASLError> {
            self.inner.client_start_suggested(offered)
        }
    }

    /************************************************************
     * SERVER impls
     ************************************************************/

    impl<V: Validation> SASLServer<V> {
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
            let mut vec: Vec<&Mechanism> = self.inner.get_available().collect();
            vec.as_mut_slice()
                .sort_unstable_by(|a, b| self.inner.config.sort(a, b));
            vec
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
                validation: None,
            }
        }
    }
    impl<V: Validation> Sasl<V> {
        fn server(config: Arc<SASLConfig>) -> Self {
            Self {
                config,
                cb: NoChannelBindings,
                validation: None,
            }
        }
    }
    impl<CB: ChannelBindingCallback, V: Validation> Sasl<V, CB> {
        fn with_cb(config: Arc<SASLConfig>, cb: CB) -> Self {
            Self {
                config,
                cb,
                validation: None,
            }
        }

        fn client_start_suggested(
            self,
            offered: &[&Mechname],
        ) -> Result<Session<V, CB>, SASLError> {
            let (mechanism, mechanism_desc) = self.config.select_mechanism(offered)?;
            let mechanism_desc = *mechanism_desc;
            Ok(Session::new(self, Side::Client, mechanism, mechanism_desc))
        }

        fn server_start_suggested(
            self,
            selected: &Mechname,
        ) -> Result<Session<V, CB>, SASLError> {
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
