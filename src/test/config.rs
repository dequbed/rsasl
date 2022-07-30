//! Mock `SASLConfig` useful for testing
//!
use std::sync::Arc;
use crate::builder::{default_filter, default_sorter};
use crate::callback::SessionCallback;
pub use crate::callback::{Context, SessionData};
use crate::config::SASLConfig;
use crate::registry::{Mechanism, Registry};
pub use crate::validate::{Validate, ValidationError};
use super::mechanism::{RSASLTEST_CF, RSASLTEST_SF};

struct ClosureSessionCallback<F>(F);

impl<F> SessionCallback for ClosureSessionCallback<F> where
    F: Fn(&SessionData, &Context, &mut Validate<'_>) -> Result<(), ValidationError> + 'static,
{
    fn validate(&self, session_data: &SessionData, context: &Context, validate: &mut Validate<'_>) -> Result<(), ValidationError> {
        (self.0)(session_data, context, validate)
    }
}

pub struct EmptyCallback;
impl SessionCallback for EmptyCallback {}

static MECHANISMS: [Mechanism; 2] = [RSASLTEST_CF, RSASLTEST_SF];

pub fn client_config<CB: SessionCallback + 'static>(cb: CB) -> Arc<SASLConfig> {
    SASLConfig::new(
        cb,
        default_sorter,
        Registry::with_mechanisms(&MECHANISMS),
    ).expect("Failed to generate known-good sasl config")
}

pub fn server_config<F>(validation: F) -> Arc<SASLConfig>
where
    F: Fn(&SessionData, &Context, &mut Validate<'_>) -> Result<(), ValidationError> + 'static,
{
    SASLConfig::new(
        ClosureSessionCallback(validation),
        default_sorter,
        Registry::with_mechanisms(&MECHANISMS),
    ).expect("Failed to generate known-good sasl config")
}
