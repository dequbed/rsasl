
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use crate::callback::SessionCallback;
use crate::config::{ClientSide, ConfigSide, SASLConfig, ServerSide};
use crate::error::SASLError;
use crate::registry::Mechanism;

#[derive(Clone)]
/// Type-checking Builder for a [`ClientConfig`](crate::config::ClientConfig) or
/// [`ServerConfig`](crate::config::ServerConfig)
///
/// This builder allows to construct sided [`SASLConfig`]s using the type system to ensure all
/// relevant information is provided.
pub struct ConfigBuilder<Side: ConfigSide, State> {
    side: Side,
    pub(crate) state: State,
}
impl<State: Debug> Debug for ConfigBuilder<ClientSide, State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigBuilder<Client, _>")
         .field("state", &self.state)
         .finish()
    }
}
impl<State: Debug> Debug for ConfigBuilder<ServerSide, State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigBuilder<Server, _>")
         .field("state", &self.state)
         .finish()
    }
}

fn default_filter(_: &&Mechanism) -> bool {
    true
}
fn default_sorter(a: &&Mechanism, b: &&Mechanism) -> Ordering {
    a.priority.cmp(&b.priority)
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct WantMechanisms(());
impl<Side: ConfigSide> ConfigBuilder<Side, WantMechanisms> {
    pub(crate) fn new(side: Side) -> Self {
        ConfigBuilder {
            side,
            state: WantMechanisms(()),
        }
    }
    pub fn with_default_mechanisms(self) -> ConfigBuilder<Side, WantFilter> {
        ConfigBuilder {
            side: self.side,
            state: WantFilter {
                #[cfg(feature = "registry_dynamic")]
                dynamic_mechs: vec![],
            }
        }
    }
    pub fn with_defaults(self) -> ConfigBuilder<Side, WantCallback> {
        ConfigBuilder {
            side: self.side,
            state: WantCallback {
                #[cfg(feature = "registry_dynamic")]
                dynamic_mechs: vec![],
                filter: default_filter,
                sorter: default_sorter,
            }
        }
    }
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct WantFilter {
    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
}
impl<Side: ConfigSide> ConfigBuilder<Side, WantFilter> {
    pub fn with_default_filter(self) -> ConfigBuilder<Side, WantSorter> {
        ConfigBuilder {
            side: self.side,
            state: WantSorter {
                #[cfg(feature = "registry_dynamic")]
                dynamic_mechs: self.state.dynamic_mechs,
                filter: default_filter,
            }
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct WantSorter {
    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
    filter: fn(a: &&Mechanism) -> bool,
}
impl<Side: ConfigSide> ConfigBuilder<Side, WantSorter> {
    pub fn with_default_sorting(self) -> ConfigBuilder<Side, WantCallback> {
        ConfigBuilder {
            side: self.side,
            state: WantCallback {
                #[cfg(feature = "registry_dynamic")]
                dynamic_mechs: self.state.dynamic_mechs,
                filter: self.state.filter,
                sorter: default_sorter,
            }
        }
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct WantCallback {
    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
    filter: fn(a: &&Mechanism) -> bool,
    sorter: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,
}
impl<Side: ConfigSide> ConfigBuilder<Side, WantCallback> {
    pub fn with_callback<CB: SessionCallback + 'static>(self, callback: Box<CB>)
        -> Result<SASLConfig<Side>, SASLError>
    {
        let callback = callback as Box<dyn SessionCallback>;
        SASLConfig::new(
            self.side,
            callback,
            self.state.filter,
            self.state.sorter,
            #[cfg(feature = "registry_dynamic")]
            self.state.dynamic_mechs,
        )
    }
}
