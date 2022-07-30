use crate::channel_bindings::{ChannelBindingCallback, NoChannelBindings};
use crate::config::SASLConfig;

use crate::error::SASLError;

use crate::mechname::Mechname;

use crate::registry::{Mechanism, StartFn};
use crate::session::{Session, Side};
use crate::validate::{NoValidation, Validation};

use std::sync::Arc;

#[derive(Debug)]
/// SASL Client context
///
/// A SASL Client starts authentication using the
pub struct SASLClient<CB = NoChannelBindings> {
    inner: SASL<NoValidation, CB>,
}

pub struct SASLServer<V: Validation, CB = NoChannelBindings> {
    inner: SASL<V, CB>,
}

#[derive(Debug)]
/// SASL Provider context
///
pub(crate) struct SASL<V: Validation = NoValidation, CB = NoChannelBindings> {
    pub(crate) config: Arc<SASLConfig>,
    pub(crate) cb: CB,
    pub(crate) validation: Option<V::Value>,
}

#[cfg(feature = "provider")]
mod provider {
    use super::*;

    /************************************************************
     * CLIENT impls
     ************************************************************/

    impl SASLClient {
        pub fn new(config: Arc<SASLConfig>) -> Self {
            Self {
                inner: SASL::client(config),
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
                inner: SASL::with_cb(config, cb),
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
                inner: SASL::server(config),
            }
        }
    }
    impl<V: Validation, CB: ChannelBindingCallback> SASLServer<V, CB> {
        pub fn with_cb(config: Arc<SASLConfig>, cb: CB) -> Self {
            Self {
                inner: SASL::with_cb(config, cb),
            }
        }

        pub fn get_available(&self) -> impl Iterator<Item = &Mechanism> {
            self.inner.get_available()
        }

        /// Starts a authentication exchange as the server role
        ///
        /// An application acting as server will most likely need to implement a callback to check the
        /// authentication data provided by the user.
        ///
        /// See [SessionCallback] on how to implement callbacks.
        pub fn start_suggested(self, offered: &[&Mechname]) -> Result<Session<V, CB>, SASLError> {
            self.inner.server_start_suggested(offered)
        }
    }


    /************************************************************
     * SHARED impls
     ************************************************************/

    impl SASL {
        fn client(config: Arc<SASLConfig>) -> Self {
            Self {
                config,
                cb: NoChannelBindings,
                validation: None,
            }
        }
    }
    impl<V: Validation> SASL<V> {
        fn server(config: Arc<SASLConfig>) -> Self {
            Self {
                config,
                cb: NoChannelBindings,
                validation: None,
            }
        }
    }
    impl<CB: ChannelBindingCallback, V: Validation> SASL<V, CB> {
        fn with_cb(config: Arc<SASLConfig>, cb: CB) -> Self {
            Self {
                config,
                cb,
                validation: None,
            }
        }

        fn start_inner<'a, F>(
            self,
            f: F,
            offered: &[&Mechname],
        ) -> Result<Session<V, CB>, SASLError>
        where
            F: for<'b> Fn(&'b Mechanism) -> Option<StartFn>,
        {
            let config = self.config.clone();
            offered
                .iter()
                .filter_map(|offered_mechname| {
                    let mech = config
                        .mech_list()
                        .find(|avail_mech| avail_mech.mechanism == *offered_mechname);
                    mech.and_then(|mech| {
                        let start = f(&mech)?;
                        let auth = start(config.as_ref(), offered).ok()?;
                        Some((mech, auth))
                    })
                })
                .max_by(|(m, _), (n, _)| (self.config.sorter)(m, n))
                .map_or(Err(SASLError::NoSharedMechanism), |(selected, auth)| {
                    Ok(Session::new(self, Side::Client, auth, selected.clone()))
                })
        }

        fn client_start_suggested<'a>(
            self,
            offered: &[&Mechname],
        ) -> Result<Session<V, CB>, SASLError> {
            self.start_inner(|mech| mech.client, offered)
        }

        fn server_start_suggested<'a>(
            self,
            offered: &[&Mechname],
        ) -> Result<Session<V, CB>, SASLError> {
            self.start_inner(|mech| mech.server, offered)
        }

        pub fn get_available(&self) -> impl Iterator<Item = &Mechanism> {
            // self.config2.available_mechs()
            todo!()
        }
    }
}
