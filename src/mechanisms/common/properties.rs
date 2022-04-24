//! Properties and related types that are useful for more than one mechanism.
//!

use crate::callback::{Answerable, Question};

#[derive(Debug)]
/// Plaintext credentials
pub struct Credentials {
    /// Authentication ID
    ///
    /// This is usually the "username" to be used, respectively the username that the password
    /// belongs to.
    pub authid: String,
    /// Auth**orization** ID
    ///
    /// Separate from the authid this is the name of the entity to *authorize* as. Not commonly
    /// used.
    pub authzid: Option<String>,
    /// Password
    ///
    /// The password to be used.
    pub password: String,
}

pub struct SimpleCredentials(Option<Credentials>);
impl Question for SimpleCredentials {
    type Params = ();

    fn build(_: Self::Params) -> Self {
        Self(None)
    }
}
impl Answerable for SimpleCredentials {
    type Answer = Credentials;

    fn respond(&mut self, resp: Self::Answer) {
        self.0 = Some(resp);
    }

    fn into_answer(self) -> Option<Self::Answer> {
        self.0
    }
}

pub struct ValidateSimple(Credentials);
impl Question for ValidateSimple {
    type Params = Credentials;

    fn build(params: Self::Params) -> Self {
        Self(params)
    }
}