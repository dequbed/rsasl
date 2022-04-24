
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use crate::callback::CallbackError;

#[derive(Debug)]
/// Common mechanism Error type
///
/// Errors such as expected data but none provided are common to all mechanism implementations
/// and thus it's sensible to have a shared type for them. This lends itself better to the
/// generic framework side of rsasl and not so much to the
pub enum MechanismError {
    NeedMoreData,
    Callback(CallbackError),
}

impl Display for MechanismError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedMoreData =>
                f.write_str("mechanism expected input data to be provided this step"),
            Self::Callback(e) => Debug::fmt(e, f),
        }
    }
}

impl Error for MechanismError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Callback(e) => Some(e),
            _ => None,
        }
    }
}