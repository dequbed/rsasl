use crate::{init, registry, SessionCallback, SASL};

use crate::callback::Request;
use crate::context::Context;
use crate::property::{AuthId, AuthzId, Password};
use crate::session::SessionData;
use std::sync::Arc;
use crate::error::SessionError;

pub struct CredentialsProvider {
    authid: String,
    authzid: Option<String>,
    password: String,
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

    /// Construct a rsasl context with preconfigured Credentials
    pub fn with_credentials(authid: String, authzid: Option<String>, password: String) -> Self {
        Self::new(Arc::new(CredentialsProvider {
            authid,
            authzid,
            password,
        }))
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
