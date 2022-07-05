//! Properties and related types that are useful for more than one mechanism.
//!

use crate::callback::tags;

#[derive(Debug)]
/// Plaintext credentials
pub struct Credentials<'a> {
    /// Authentication ID
    ///
    /// This is usually the "username" to be used, respectively the username that the password
    /// belongs to.
    pub authid: &'a str,
    /// Auth**orization** ID
    ///
    /// Separate from the authid this is the name of the entity to *authorize* as. Not commonly
    /// used.
    pub authzid: Option<&'a str>,
    /// Password
    ///
    /// The password to be used.
    pub password: &'a [u8],
}

pub struct SimpleCredentials;
impl<'a> tags::Type<'a> for SimpleCredentials {
    type Reified = Credentials<'a>;
}

pub struct ValidateSimple;