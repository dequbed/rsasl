
use crate::{init, registry, SASL, SessionCallback};

use std::sync::Arc;

impl SASL {
    pub fn new(callback: Arc<dyn SessionCallback>) -> Self {
        Self {
            callback,

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
}