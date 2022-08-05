use crate::callback::SessionCallback;
use crate::config::{SASLConfig, SorterFn};
use crate::error::SASLError;
use crate::registry::{Mechanism, Registry};
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

#[derive(Clone)]
/// Type-checking Builder for a [`ClientConfig`](crate::config::ClientConfig) or
/// [`ServerConfig`](crate::config::ServerConfig)
///
/// This builder allows to construct sided [`SASLConfig`]s using the type system to ensure all
/// relevant information is provided.
pub struct ConfigBuilder<State> {
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
impl ConfigBuilder<WantMechanisms> {
    pub(crate) fn new() -> Self {
        ConfigBuilder {
            state: WantMechanisms(()),
        }
    }
    pub fn with_registry(self, mechanisms: Registry) -> ConfigBuilder<WantSorter> {
        ConfigBuilder {
            state: WantSorter { mechanisms },
        }
    }
    pub fn with_default_mechanisms(self) -> ConfigBuilder<WantSorter> {
        self.with_registry(Registry::default())
    }
    pub(crate) fn with_credentials_mechanisms(self) -> ConfigBuilder<WantSorter> {
        self.with_registry(Registry::credentials())
    }

    pub fn with_defaults(self) -> ConfigBuilder<WantCallback> {
        ConfigBuilder {
            state: WantCallback {
                mechanisms: Registry::default(),
                sorter: default_sorter,
            },
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct WantSorter {
    mechanisms: Registry,
}
impl ConfigBuilder<WantSorter> {
    pub fn with_default_sorting(self) -> ConfigBuilder<WantCallback> {
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
    ///
    /// `cbsupport` dicates the availability of channel binding support. See [`CBSupport`] for
    /// available values and their meaning.
    pub fn with_callback<CB: SessionCallback + 'static>(
        self,
        callback: CB,
    ) -> Result<Arc<SASLConfig>, SASLError> {
        SASLConfig::new(
            callback,
            self.state.sorter,
            self.state.mechanisms,
        )
    }
}
