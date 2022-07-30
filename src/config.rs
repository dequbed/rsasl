//! Configuration supplied by the downstream user

use crate::callback::{Context, Request, SessionCallback};
use crate::error::{SASLError, SessionError};
use crate::property::{AuthId, AuthzId, Password};
use crate::registry::{Mechanism, MechanismIter, Registry};
use crate::session;
use crate::session::SessionData;
use crate::mechname::Mechname;
use std::cmp::Ordering;
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use instance::ConfigInstance;

#[cfg(feature = "config_builder")]
pub use crate::builder::ConfigBuilder;
use crate::mechanism::Authentication;

pub(crate) type FilterFn = fn(a: &Mechanism) -> bool;
pub(crate) type SorterFn = fn(a: &Mechanism, b: &Mechanism) -> Ordering;

#[cfg(feature = "config_builder")]
impl SASLConfig {
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
            .with_default_mechanisms()
            .with_filter(|mechanism| {
                let name = mechanism.mechanism;
                match name.as_str() {
                    "PLAIN" | "LOGIN" => true,
                    n if n.starts_with("SCRAM-") => true,
                    _ => false,
                }
            })
            .with_default_sorting()
            .with_callback(callback)
    }
}

mod instance {
    use std::fmt;
    use crate::callback::SessionCallback;
    use crate::error::SASLError;
    use crate::mechanism::Authentication;
    use crate::mechname::Mechname;
    use crate::registry::{Mechanism, MechanismIter};

    pub(crate) trait ConfigInstance: fmt::Debug {
        fn select_mechanism(&self, offered: &[&Mechname])
            -> Result<(Box<dyn Authentication>, &Mechanism), SASLError>;
        fn get_mech_iter(&self) -> MechanismIter;
        fn get_callback(&self) -> &dyn SessionCallback;
    }
}

#[repr(transparent)]
#[derive(Debug)]
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
    inner: dyn ConfigInstance,
}

impl SASLConfig {
    #[inline]
    /// Select the best mechanism of the offered ones.
    pub fn select_mechanism(&self, offered: &[&Mechname])
        -> Result<(Box<dyn Authentication>, &Mechanism), SASLError>
    {
        self.inner.select_mechanism(offered)
    }

    #[inline]
    pub fn mech_list(&self) -> impl Iterator<Item=&Mechanism> {
        self.inner.get_mech_iter()
    }

    #[inline]
    pub fn get_callback(&self) -> &dyn SessionCallback {
        self.inner.get_callback()
    }
}

#[cfg(feature = "config_builder")]
impl SASLConfig {
    fn cast(arc: Arc<dyn ConfigInstance>) -> Arc<Self> {
        unsafe { std::mem::transmute(arc) }
    }
    pub(crate) fn new<CB: SessionCallback + 'static>(
        callback: CB,
        filter: FilterFn,
        sorter: SorterFn,
        mechanisms: Registry,
    ) -> Result<Arc<Self>, SASLError> {
        let inner = Inner::new(callback, filter, sorter, mechanisms)?;
        let outer = Arc::new(inner) as Arc<dyn ConfigInstance>;
        Ok(Self::cast(outer))
    }
}

struct Inner {
    callback: Box<dyn SessionCallback>,

    filter: FilterFn,
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

impl Inner {
    pub fn mech_list(&self) -> impl Iterator<Item = &Mechanism> {
        self.mechanisms.get_mechanisms()
            .filter(|m| (self.filter)(m))
    }
}

#[cfg(any(feature = "config_builder", feature = "testutils"))]
impl Inner {
    pub(crate) fn new<CB: SessionCallback + 'static>(
        callback: CB,
        filter: FilterFn,
        sorter: SorterFn,
        mechanisms: Registry,
    ) -> Result<Self, SASLError> {
        Ok(Self {
            callback: Box::new(callback),
            filter,
            sorter,
            mechanisms,
        })
    }
}

impl Inner {
    #[cfg(any(feature = "registry_dynamic"))]
    /// Register the builtin mechanisms
    ///
    /// When `registry_static` is enabled this method is a no-op and does not need to be called.
    /// Otherwise this will register all built-in mechanisms via the dynamic registry.
    pub fn register_builtin(&mut self) {
        crate::init::register_builtin(self)
    }

    #[cfg(feature = "registry_dynamic")]
    /// Register a mechanism
    pub fn register(&mut self, mechanism: &'static Mechanism) {
        self.mechanisms.register(mechanism)
    }
}
impl ConfigInstance for Inner {
    fn select_mechanism(&self, offered: &[&Mechname]) -> Result<(Box<dyn Authentication>, &Mechanism), SASLError> {
        todo!()
    }

    fn get_mech_iter(&self) -> MechanismIter {
        self.mechanisms.get_mechanisms()
    }

    fn get_callback(&self) -> &dyn SessionCallback {
        self.callback.as_ref()
    }
}