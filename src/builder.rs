use crate::callback::SessionCallback;
use crate::config::{SASLConfig, SorterFn};
use crate::error::SASLError;
use crate::registry::{Mechanism, Registry};
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

#[derive(Clone)]
/// Type-checking and linker-friendly builder for a [`SASLConfig`](crate::config::SASLConfig)
pub struct ConfigBuilder<State = WantMechanisms> {
    pub(crate) state: State,
}
impl<State: Debug> Debug for ConfigBuilder<State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigBuilder<_>")
            .field("state", &self.state)
            .finish()
    }
}

pub(crate) fn default_sorter(a: &Mechanism, b: &Mechanism) -> Ordering {
    a.priority.cmp(&b.priority)
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct WantMechanisms(());
/// ConfigBuilder first stage
///
///
impl ConfigBuilder {
    pub(crate) fn new() -> Self {
        ConfigBuilder {
            state: WantMechanisms(()),
        }
    }

    /// Use the default configuration for each state and only provide a custom callback
    pub fn with_defaults(self) -> ConfigBuilder<WantCallback> {
        ConfigBuilder {
            state: WantCallback {
                mechanisms: Registry::default(),
                sorter: default_sorter,
            },
        }
    }

    /// Use a pre-initialized mechanism registry, giving the most control over available mechanisms
    pub fn with_registry(self, mechanisms: Registry) -> ConfigBuilder<WantSorter> {
        ConfigBuilder {
            state: WantSorter { mechanisms },
        }
    }

    /// Make the default set of mechanisms available
    ///
    /// This is equivalent to `Self::with_registry(Registry::default())`. The default set of
    /// mechanisms depends on the enabled cargo features.
    pub fn with_default_mechanisms(self) -> ConfigBuilder<WantSorter> {
        self.with_registry(Registry::default())
    }

    pub(crate) fn with_credentials_mechanisms(self, authzid: bool) -> ConfigBuilder<WantSorter> {
        self.with_registry(Registry::credentials(authzid))
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct WantSorter {
    mechanisms: Registry,
}
impl ConfigBuilder<WantSorter> {
    /// Use the default mechanisms prioritizations
    ///
    /// This method is required to allow backwards-compatible expansion of the configuration builder
    pub fn with_defaults(self) -> ConfigBuilder<WantCallback> {
        ConfigBuilder {
            state: WantCallback {
                mechanisms: self.state.mechanisms,
                sorter: default_sorter,
            },
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct WantCallback {
    mechanisms: Registry,
    sorter: SorterFn,
}
impl ConfigBuilder<WantCallback> {
    /// Install a callback for querying properties
    pub fn with_callback<CB: SessionCallback + 'static>(
        self,
        callback: CB,
    ) -> Result<Arc<SASLConfig>, SASLError> {
        SASLConfig::new(callback, self.state.sorter, self.state.mechanisms)
    }
}
