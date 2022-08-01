//! Configuration supplied by the downstream user

use crate::alloc::boxed::Box;
use crate::callback::SessionCallback;
use crate::error::SASLError;
use crate::registry::{Mechanism, MechanismIter};
use crate::session::SessionData;
use crate::mechname::Mechname;
use core::cmp::Ordering;
use core::fmt;
use alloc::sync::Arc;

use crate::mechanism::Authentication;

pub(crate) type FilterFn = fn(a: &Mechanism) -> bool;
pub(crate) type SorterFn = fn(a: &Mechanism, b: &Mechanism) -> Ordering;

trait ConfigInstance: fmt::Debug {
    fn get_mech_iter<'a>(&self) -> MechanismIter<'a>;
    fn get_callback(&self) -> &dyn SessionCallback;
    fn sort(&self, left: &Mechanism, right: &Mechanism) -> Ordering;
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
/// or )&SASLConfig`). Right now all functions that expect a `SASLConfig` take an
/// `Arc<SASLConfig>`, so the `!Sized` bound has little relevancy in practice.
pub struct SASLConfig {
    inner: dyn ConfigInstance + Send + Sync,
}
impl fmt::Debug for SASLConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl SASLConfig {
    #[inline(always)]
    /// Select the best mechanism of the offered ones.
    pub(crate) fn select_mechanism(&self, offered: &[&Mechname])
        -> Result<(Box<dyn Authentication>, &Mechanism), SASLError>
    {
        offered
            .iter()
            .filter_map(|offered_mechname| {
                self.mech_list().find(|avail_mech| avail_mech.mechanism == *offered_mechname).and_then(|mech| {
                    let auth = mech.client(self, offered)?.ok()?;
                    Some((auth, mech))
                })
            })
            .max_by(|(_, m), (_, n)| self.inner.sort(m, n))
            .ok_or(SASLError::NoSharedMechanism)
    }

    #[inline(always)]
    pub(crate) fn mech_list<'a>(&self) -> impl Iterator<Item=&'a Mechanism> {
        self.inner.get_mech_iter()
    }

    #[inline(always)]
    pub(crate) fn get_callback(&self) -> &dyn SessionCallback {
        self.inner.get_callback()
    }

    #[inline(always)]
    pub(crate) fn sort(&self, left: &Mechanism, right: &Mechanism) -> Ordering {
        self.inner.sort(left, right)
    }
}

#[cfg(feature = "config_builder")]
mod instance {
    use super::*;
    pub use crate::builder::ConfigBuilder;
    use crate::callback::Request;
    use crate::context::Context;
    use crate::error::SessionError;
    use crate::property::{AuthId, AuthzId, Password};
    use crate::registry::Registry;

    impl SASLConfig {
        fn cast(arc: Arc<dyn ConfigInstance>) -> Arc<Self> {
            unsafe { std::mem::transmute(arc) }
        }

        pub(crate) fn new<CB: SessionCallback + 'static>(
            callback: CB,
            sorter: SorterFn,
            mechanisms: Registry,
        ) -> Result<Arc<Self>, SASLError> {
            let inner = Inner::new(callback, sorter, mechanisms)?;
            let outer = Arc::new(inner) as Arc<dyn ConfigInstance>;
            Ok(Self::cast(outer))
        }

        pub fn builder() -> ConfigBuilder<crate::builder::WantMechanisms> {
            ConfigBuilder::new()
        }

        /// Construct a SASLConfig with static credentials
        ///
        ///
        pub fn with_credentials(
            authzid: Option<String>,
            authid: String,
            password: String,
        ) -> Result<Arc<SASLConfig>, SASLError> {
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

            let callback = CredentialsProvider {
                authid,
                password,
                authzid,
            };

            Self::builder()
                .with_credentials_mechanisms()
                .with_default_sorting()
                .with_callback(callback)
        }
    }


    struct Inner {
        callback: Box<dyn SessionCallback>,
        sorter: SorterFn,
        mechanisms: Registry,
    }

    impl fmt::Debug for Inner {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SASLConfig")
             .field("mechanisms", &self.mechanisms)
             .finish()
        }
    }

    #[cfg(any(feature = "config_builder", feature = "testutils"))]
    impl Inner {
        pub(crate) fn new<CB: SessionCallback + 'static>(
            callback: CB,
            sorter: SorterFn,
            mechanisms: Registry,
        ) -> Result<Self, SASLError> {
            Ok(Self {
                callback: Box::new(callback),
                sorter,
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

        fn sort(&self, left: &Mechanism, right: &Mechanism) -> Ordering {
            (self.sorter)(left, right)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_impl_bounds() {
        static_assertions::assert_impl_all!(SASLConfig: Send, Sync);
    }
}