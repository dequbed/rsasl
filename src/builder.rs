use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use crate::callback::SessionCallback;
use crate::channel_bindings::{ChannelBindingCallback, NoChannelBindings};
use crate::registry::Mechanism;
use crate::sasl::SASL;
use crate::validate::Validation;

#[derive(Clone)]
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

fn default_filter(a: &&Mechanism) -> bool {
    true
}
fn default_sorter(a: &&Mechanism, b: &&Mechanism) -> Ordering {
    a.priority.cmp(&b.priority)
}

#[derive(Clone, Debug)]
pub struct WantMechanisms(());
impl ConfigBuilder<WantMechanisms> {
    pub fn with_default_mechanisms(self) -> ConfigBuilder<WantFilter> {
        ConfigBuilder {
            state: WantFilter {
                #[cfg(feature = "registry_dynamic")]
                dynamic_mechs: vec![],
            }
        }
    }
    pub fn with_defaults(self) -> ConfigBuilder<WantCallback> {
        ConfigBuilder {
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
pub struct WantFilter {
    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
}
impl ConfigBuilder<WantFilter> {
    pub fn with_default_filter(self) -> ConfigBuilder<WantSorter> {
        ConfigBuilder {
            state: WantSorter {
                #[cfg(feature = "registry_dynamic")]
                dynamic_mechs: self.state.dynamic_mechs,
                filter: default_filter,
            }
        }
    }
}

#[derive(Clone)]
pub struct WantSorter {
    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
    filter: fn(a: &&Mechanism) -> bool,
}
impl ConfigBuilder<WantSorter> {
    pub fn with_default_sorting(self) -> ConfigBuilder<WantCallback> {
        ConfigBuilder {
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
pub struct WantCallback {
    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
    filter: fn(a: &&Mechanism) -> bool,
    sorter: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,
}
impl ConfigBuilder<WantCallback> {
    pub fn with_callback<CB: SessionCallback + 'static>(self, callback: Arc<CB>)
        -> SASLConfig<WantChannelbindings>
    {
        let callback = callback as Arc<dyn SessionCallback>;
        SASLConfig {
            state: WantChannelbindings {
                callback,
                filter: self.state.filter,
                sorter: self.state.sorter,
                #[cfg(feature = "registry_dynamic")]
                dynamic_mechs: self.state.dynamic_mechs,
            }
        }
    }
}

pub struct WantValidation {
    callback: Arc<dyn SessionCallback>,
    cb_callback: Box<dyn ChannelBindingCallback>,

    filter: fn(a: &&Mechanism) -> bool,
    sorter: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,

    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
}
pub struct SASLConfig<State> {
    state: State,
}
impl<State: Debug> Debug for SASLConfig<State> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigBuilder<_>")
         .field("state", &self.state)
         .finish()
    }
}

pub struct WantChannelbindings {
    callback: Arc<dyn SessionCallback>,

    filter: fn(a: &&Mechanism) -> bool,
    sorter: fn(a: &&Mechanism, b: &&Mechanism) -> Ordering,

    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Vec<&'static Mechanism>,
}

#[cfg(feature = "provider")]
impl SASLConfig<WantChannelbindings> {
    pub fn with_cb_support<CB: ChannelBindingCallback + 'static>(self, cb_callback: Box<CB>)
        -> SASLConfig<WantValidation>
    {
        let cb_callback: Box<dyn ChannelBindingCallback> = cb_callback;
        SASLConfig {
            state: WantValidation {
                callback: self.state.callback,
                cb_callback,
                filter: self.state.filter,
                sorter: self.state.sorter,

                #[cfg(feature = "registry_dynamic")]
                dynamic_mechs: self.state.dynamic_mechs,
            }
        }
    }

    pub fn no_cb_support(self) -> SASLConfig<WantValidation> {
        self.with_cb_support(Box::new(NoChannelBindings))
    }
}

impl SASLConfig<WantValidation> {
    pub fn with_validation<V: Validation>(self) -> SASL {
        todo!()
    }

    pub fn no_validation(self) -> SASL {
        todo!()
    }
}
