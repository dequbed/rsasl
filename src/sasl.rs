use crate::{init, registry, DynCallback, Mechanism, SASL};
use std::cmp::Ordering;
use std::sync::Arc;

impl SASL {
    pub fn build() -> Builder {
        Builder::new()
    }

    pub fn new() -> Self {
        Self {
            callback: None,

            #[cfg(feature = "registry_dynamic")]
            dynamic_mechs: Vec::new(),

            #[cfg(feature = "registry_static")]
            static_mechs: &registry::MECHANISMS,

            sort_fn: |a, b| a.priority.cmp(&b.priority),
        }
    }

    /// Initialize this SASL with the builtin Mechanisms
    ///
    /// Calling this function is usually not necessary if you're using the `registry_static`
    /// feature since the builtin mechanisms are registered at compile time then. However the
    /// optimizer may strip modules that it deems are unused so a call may still be necessary but
    /// it then extremely cheap.
    pub fn init(&mut self) {
        init::register_builtin(self);
    }

    pub fn install_callback(&mut self, callback: Arc<dyn DynCallback + Send + Sync>) {
        self.callback = Some(callback);
    }
}

pub struct Builder {
    callback: Option<Arc<dyn DynCallback + Send + Sync>>,

    #[cfg(feature = "registry_dynamic")]
    dynamic_mechs: Option<Vec<&'static Mechanism>>,

    #[cfg(feature = "registry_static")]
    static_mechs: Option<&'static [Mechanism]>,

    sort_fn: Option<fn(a: &&Mechanism, b: &&Mechanism) -> Ordering>,
}
impl Builder {
    pub fn new() -> Self {
        Self {
            callback: None,
            #[cfg(feature = "registry_dynamic")]
            dynamic_mechs: None,
            #[cfg(feature = "registry_static")]
            static_mechs: None,
            sort_fn: None,
        }
    }
    pub fn finish(self) -> SASL {
        let callback = self.callback;

        #[cfg(feature = "registry_dynamic")]
        let dynamic_mechs = self.dynamic_mechs.unwrap_or_else(Vec::new);
        #[cfg(feature = "registry_static")]
        let static_mechs = self.static_mechs.unwrap_or(&registry::MECHANISMS);

        let sort_fn = self.sort_fn.unwrap_or(|a, b| a.priority.cmp(&b.priority));

        SASL {
            callback,
            sort_fn,

            #[cfg(feature = "registry_dynamic")]
            dynamic_mechs,

            #[cfg(feature = "registry_static")]
            static_mechs,
        }
    }

    #[cfg(feature = "registry_static")]
    pub fn with_static_mechs(mut self, static_mechs: &'static [Mechanism]) -> Self {
        self.static_mechs = Some(static_mechs);
        self
    }
}
