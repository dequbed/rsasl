//! Mock `SASLConfig` useful for testing
//!
use crate::builder::{default_filter, default_sorter};
use crate::callback::{Request, SessionCallback};
pub use crate::callback::{Context, SessionData};
use crate::config::SASLConfig;
use crate::error::SessionError;
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

fn client_config() -> SASLConfig {
    SASLConfig::new(
        EmptyCallback,
        default_filter,
        default_sorter,
        Registry::with_mechanisms(&MECHANISMS),
    ).expect("Failed to generate known-good sasl config")
}

fn server_config<F>(validation: F) -> SASLConfig
where
    F: Fn(&SessionData, &Context, &mut Validate<'_>) -> Result<(), ValidationError> + 'static,
{
    SASLConfig::new(
        ClosureSessionCallback(validation),
        default_filter,
        default_sorter,
        Registry::with_mechanisms(&MECHANISMS),
    ).expect("Failed to generate known-good sasl config")
}
