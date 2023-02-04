use crate::error::{MechanismError, MechanismErrorKind};
use crate::prelude::Property;
use crate::property::SizedProperty;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("GSS-API error")]
    Gss(
        #[source]
        #[from]
        libgssapi::error::Error,
    ),
    #[error("final token is invalid")]
    BadFinalToken,
    #[error("produced context is not secure enough")]
    BadContext,
}

impl MechanismError for Error {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Protocol
    }
}

#[non_exhaustive]
pub struct GssService;
impl Property<'_> for GssService {
    type Value = str;
}

/// Acceptable security layers
#[non_exhaustive]
pub struct GssSecurityLayer;
impl SizedProperty<'_> for GssSecurityLayer {
    type Value = SecurityLayer;
}

bitflags::bitflags! {
    #[repr(transparent)]
    pub struct SecurityLayer: u8 {
        const NO_SECURITY_LAYER = 0b001;
        const INTEGRITY = 0b010;
        const CONFIDENTIALITY = 0b100;
    }
}

impl Default for SecurityLayer {
    fn default() -> Self {
        Self::all()
    }
}
