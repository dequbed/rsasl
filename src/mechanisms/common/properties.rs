//! Properties and related types that are useful for more than one mechanism.
//!

use crate::property::Property;
use crate::validate::Validation;

#[derive(Debug)]
/// Plaintext credentials
pub struct Credentials {
    /// Authentication ID
    ///
    /// This is usually the "username" to be used, respectively the username that the password
    /// belongs to.
    pub authid: &'static str,
    /// Auth**orization** ID
    ///
    /// Separate from the authid this is the name of the entity to *authorize* as. Not commonly
    /// used.
    pub authzid: Option<&'static str>,
    /// Password
    ///
    /// The password to be used.
    pub password: &'static [u8],
}

pub struct SimpleCredentials;
impl Property for SimpleCredentials {
    type Value = Credentials;
}

pub struct ValidateSimple;
impl Property for ValidateSimple {
    type Value = bool;
}
impl Validation for ValidateSimple {}
