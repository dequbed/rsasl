use thiserror::Error;
use crate::error::{MechanismError, MechanismErrorKind};
use crate::prelude::Property;
use crate::property::SizedProperty;

#[derive(Debug, Error)]
pub enum Error {
    #[error("GSS-API error")]
    Gss(#[source] #[from] libgssapi::error::Error),
    #[error("final token is invalid")]
    BadFinalToken,
}

impl MechanismError for Error {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Protocol
    }
}

pub struct GssService;
impl Property<'_> for GssService {
    type Value = str;
}

/// Should a security layer be installed?
pub struct GssSecurityLayer;
impl SizedProperty<'_> for GssSecurityLayer {
    type Value = bool;
}