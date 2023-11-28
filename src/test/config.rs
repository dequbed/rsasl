//! Mock `SASLConfig` useful for testing
//!

use super::mechanism::{RSASLTEST_CF, RSASLTEST_SF};
use crate::callback::SessionCallback;
pub use crate::callback::{Context, SessionData};
use crate::config::SASLConfig;
use crate::registry::{Mechanism, Registry};
pub use crate::validate::{Validate, ValidationError};
use std::sync::Arc;

struct ClosureSessionCallback<F>(F);

impl<F> SessionCallback for ClosureSessionCallback<F>
where
    F: Fn(&SessionData, &Context, &mut Validate<'_>) -> Result<(), ValidationError>
        + Send
        + Sync
        + 'static,
{
    fn validate(
        &self,
        session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        (self.0)(session_data, context, validate)
    }
}

#[non_exhaustive]
pub struct EmptyCallback;
impl SessionCallback for EmptyCallback {}

static MECHANISMS: [Mechanism; 2] = [RSASLTEST_CF, RSASLTEST_SF];

#[allow(clippy::missing_panics_doc)]
pub fn client_config<CB: SessionCallback + 'static>(cb: CB) -> Arc<SASLConfig> {
    SASLConfig::new(cb, Registry::with_mechanisms(&MECHANISMS))
        .expect("Failed to generate known-good sasl config")
}

#[allow(clippy::missing_panics_doc)]
pub fn server_config<CB: SessionCallback + 'static>(cb: CB) -> Arc<SASLConfig> {
    SASLConfig::new(cb, Registry::with_mechanisms(&MECHANISMS))
        .expect("Failed to generate known-good sasl config")
}
