use crate::alloc::sync::Arc;
use crate::callback::SessionCallback;
use crate::config::SASLConfig;
use crate::error::SASLError;
use crate::registry::Registry;
use core::fmt::{Debug, Formatter};

#[derive(Clone)]
/// Type-checking, complete and linker-friendly builder for [`SASLConfig`](crate::config::SASLConfig)
///
/// Due to `ConfigBuilder` using the `State` generic the compiler can enforce that all required
/// information is provided at compile time.
/// Since the configuration is generated statically with an enforced order unused mechanisms,
/// structs and code can be discarded by the compiler, reducing binary size and compile time.
///
/// Examples:
/// ```
/// # #[cfg(not(miri))]
/// # {
/// # use std::sync::Arc;
/// # use rsasl::callback::SessionCallback;
/// # struct Callback;
/// # impl SessionCallback for Callback {}
/// # impl Callback {
/// # fn new() -> Self { Self }
/// # }
/// use rsasl::config::SASLConfig;
/// let config: Arc<SASLConfig> = SASLConfig::builder()
///     .with_default_mechanisms()
///     .with_callback(Callback::new())
///     .unwrap();
/// # }
/// ```
///
/// Which can be shortened to:
///
/// ```
/// # #[cfg(not(miri))]
/// # {
/// # use std::sync::Arc;
/// # use rsasl::callback::SessionCallback;
/// # struct Callback;
/// # impl SessionCallback for Callback {}
/// # impl Callback {
/// # fn new() -> Self { Self }
/// # }
/// use rsasl::config::SASLConfig;
/// let config: Arc<SASLConfig> = SASLConfig::builder()
///     .with_defaults()
///     .with_callback(Callback::new())
///     .unwrap();
/// # }
/// ```
///
/// If explicit control over the mechanisms that need to be available is required `with_registry`
/// must be used:
///
/// ```
/// # use std::sync::Arc;
/// # use rsasl::callback::SessionCallback;
/// # use rsasl::prelude::{Mechanism, Registry};
/// # struct Callback;
/// # impl SessionCallback for Callback {}
/// # impl Callback {
/// # fn new() -> Self { Self }
/// # }
/// # use rsasl::mechanisms::external::EXTERNAL;
/// # use rsasl::mechanisms::plain::PLAIN;
/// # use rsasl::config::SASLConfig;
/// static MECHANISMS: &[Mechanism] = &[PLAIN, EXTERNAL];
/// let config: Arc<SASLConfig> = SASLConfig::builder()
///     .with_registry(Registry::with_mechanisms(MECHANISMS))
///     .with_callback(Callback::new())
///     .unwrap();
/// ```
///
pub struct ConfigBuilder<State = WantMechanisms> {
    pub(crate) state: State,
}
impl<State: Debug> Debug for ConfigBuilder<State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConfigBuilder<_>")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct WantMechanisms(());
/// `ConfigBuilder` first stage
///
///
impl ConfigBuilder {
    pub(crate) const fn new() -> Self {
        Self {
            state: WantMechanisms(()),
        }
    }

    /// Use the default configuration for each state and only provide a custom callback
    #[must_use]
    pub fn with_defaults(self) -> ConfigBuilder<WantCallback> {
        ConfigBuilder {
            state: WantCallback {
                mechanisms: Registry::default(),
            },
        }
    }

    /// Use a pre-initialized mechanism registry, giving the most control over available mechanisms
    #[must_use]
    pub const fn with_registry(self, mechanisms: Registry) -> ConfigBuilder<WantCallback> {
        ConfigBuilder {
            state: WantCallback { mechanisms },
        }
    }

    /// Make the default set of mechanisms available
    ///
    /// This is equivalent to `Self::with_registry(Registry::default())`. The default set of
    /// mechanisms depends on the enabled cargo features.
    #[must_use]
    pub fn with_default_mechanisms(self) -> ConfigBuilder<WantCallback> {
        self.with_registry(Registry::default())
    }

    pub(crate) fn with_credentials_mechanisms(self, authzid: bool) -> ConfigBuilder<WantCallback> {
        self.with_registry(Registry::credentials(authzid))
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct WantCallback {
    mechanisms: Registry,
}
impl ConfigBuilder<WantCallback> {
    /// Install a callback for querying properties
    pub fn with_callback<CB: SessionCallback + 'static>(
        self,
        callback: CB,
    ) -> Result<Arc<SASLConfig>, SASLError> {
        SASLConfig::new(callback, self.state.mechanisms)
    }
}
