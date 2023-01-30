//! Configuration supplied by the downstream user

use crate::alloc::{boxed::Box, string::String};
use crate::callback::SessionCallback;
use crate::error::SASLError;
use crate::registry::{Mechanism, MechanismIter};
use crate::session::SessionData;
use alloc::sync::Arc;
use core::fmt;

#[doc(inline)]
#[cfg(feature = "config_builder")]
pub use crate::builder::ConfigBuilder;
use crate::mechanism::Authentication;
use crate::mechname::Mechname;

trait ConfigInstance: fmt::Debug + Send + Sync {
    fn get_mech_iter<'a>(&self) -> MechanismIter<'a>;
    fn get_callback(&self) -> &dyn SessionCallback;
    fn select(
        &self,
        cb: bool,
        offered: &mut dyn Iterator<Item = &Mechname>,
    ) -> Result<(Box<dyn Authentication>, &'static Mechanism), SASLError>;
}

#[repr(transparent)]
/// Opaque supplier configuration encoding all details necessary to perform authentication exchanges
///
/// This type contains all user-specified configuration necessary for SASL authentication. It is
/// designed to be passed to a protocol implementation and provide an opaque and abstracted
/// interface to said configuration so that neither side has to expose implementation details.
///
/// Due to the user-supplied config being generic this type is `!Sized`. This means you can only
/// ever hold this type via a pointer indirection (e.g. as `Arc<SASLConfig>`, `Box<SASLConfig>`
/// or `&SASLConfig`).
/// Right now all functions that expect a `SASLConfig` take an `Arc<SASLConfig>`, so the `!Sized`
/// bound has little relevancy in practice.
pub struct SASLConfig {
    inner: dyn ConfigInstance + Send + Sync,
}

impl fmt::Debug for SASLConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(any(test, feature = "provider", feature = "testutils"))]
mod provider {
    use super::{Box, Mechanism, SASLConfig, SASLError, SessionCallback};
    use crate::mechanism::Authentication;
    use crate::mechname::Mechname;

    impl SASLConfig {
        #[inline(always)]
        /// Select the best mechanism of the offered ones.
        pub(crate) fn select_mechanism<'a>(
            &self,
            offered: impl IntoIterator<Item = &'a Mechname>,
        ) -> Result<(Box<dyn Authentication>, &'static Mechanism), SASLError> {
            let cb = self.get_callback().enable_channel_binding();
            self.inner.select(cb, &mut offered.into_iter())
        }

        #[inline(always)]
        pub(crate) fn get_callback(&self) -> &dyn SessionCallback {
            self.inner.get_callback()
        }
    }
}

impl SASLConfig {
    #[inline(always)]
    pub(crate) fn mech_list<'a>(&self) -> impl Iterator<Item = &'a Mechanism> {
        self.inner.get_mech_iter()
    }
}

#[cfg(feature = "config_builder")]
mod instance {
    use super::{
        fmt, Arc, Box, ConfigInstance, Mechanism, MechanismIter, SASLConfig, SASLError,
        SessionCallback, SessionData, String,
    };
    pub use crate::builder::ConfigBuilder;
    use crate::callback::Request;
    use crate::context::Context;
    use crate::error::SessionError;
    use crate::mechanism::Authentication;
    use crate::mechname::Mechname;
    use crate::property::{AuthId, AuthzId, Password};
    use crate::registry::Registry;

    impl SASLConfig {
        fn cast(arc: Arc<dyn ConfigInstance>) -> Arc<Self> {
            unsafe { core::mem::transmute(arc) }
        }

        pub(crate) fn new<CB: SessionCallback + 'static>(
            callback: CB,
            mechanisms: Registry,
        ) -> Result<Arc<Self>, SASLError> {
            let inner = Inner::new(callback, mechanisms)?;
            let outer = Arc::new(inner) as Arc<dyn ConfigInstance>;
            Ok(Self::cast(outer))
        }

        /// Construct a config from a linker-friendly builder
        #[must_use]
        pub const fn builder() -> ConfigBuilder {
            ConfigBuilder::new()
        }

        /// Construct a `SASLConfig` with static credentials
        ///
        /// The `SASLConfig` generated by this method only has a limited number of mechanisms
        /// enabled that can work with just an authorization id, authentication id, and password.
        ///
        /// Depending on the enabled cargo features the available mechanisms are:
        /// - SCRAM-SHA-512
        /// - SCRAM-SHA-1
        /// - PLAIN
        /// - LOGIN (**only enabled if `authzid` is set to `None`!**)
        /// And will be preferred in this order.
        #[allow(clippy::similar_names)]
        pub fn with_credentials(
            authzid: Option<String>,
            authid: String,
            password: String,
        ) -> Result<Arc<Self>, SASLError> {
            struct CredentialsProvider {
                authid: String,
                password: String,
                authzid: Option<String>,
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

            let has_authzid = authzid.is_some();

            let callback = CredentialsProvider {
                authid,
                password,
                authzid,
            };

            Self::builder()
                .with_credentials_mechanisms(has_authzid)
                .with_callback(callback)
        }
    }

    struct Inner {
        cb: bool,
        callback: Box<dyn SessionCallback>,
        mechanisms: Registry,
    }

    impl fmt::Debug for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SASLConfig")
                .field("channel_binding", &self.cb)
                .field("mechanisms", &self.mechanisms)
                .finish()
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    #[cfg(any(feature = "config_builder", feature = "testutils"))]
    impl Inner {
        pub(crate) fn new<CB: SessionCallback + 'static>(
            callback: CB,
            mechanisms: Registry,
        ) -> Result<Self, SASLError> {
            Ok(Self {
                cb: false, // FIXME!
                callback: Box::new(callback),
                mechanisms,
            })
        }
    }

    impl ConfigInstance for Inner {
        fn get_mech_iter<'a>(&self) -> MechanismIter<'a> {
            self.mechanisms.get_mechanisms()
        }

        fn get_callback(&self) -> &dyn SessionCallback {
            self.callback.as_ref()
        }

        fn select(
            &self,
            cb: bool,
            offered: &mut dyn Iterator<Item = &Mechname>,
        ) -> Result<(Box<dyn Authentication>, &'static Mechanism), SASLError> {
            let callback = self.get_callback();
            self.mechanisms.select(cb | self.cb, offered, |acc, mech| {
                callback.prefer(acc, mech)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_impl_all!(SASLConfig: Send, Sync);
}
