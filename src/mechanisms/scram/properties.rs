use crate::callback::RequestType;

pub struct ScramSaltedPassword {
    iterations: u32,
    salt: Box<[u8]>,
    password: Box<[u8]>,
}

#[derive(Debug)]
/// SCRAM stored password parameters
///
/// A server SHOULD store users' passwords hashed in a way SCRAM can use and not in plaintext.
///
pub struct ScramPassParams<'a> {
    pub iterations: u32,
    pub salt: &'a [u8],
}

#[derive(Debug)]
pub enum ScramPasswordError {
    /// Password can't possibly be for the current hash function.
    PasswordHashMismatch,
}

pub struct ScramSaltedPasswordQuery;
impl<'a> RequestType<'a> for ScramSaltedPasswordQuery {
    type Answer = (ScramPassParams<'a>, &'a [u8]);
    type Result = Result<(), ScramPasswordError>;
}

pub struct ScramSaltedPasswordQueryClient;

pub struct ScramValidate {
    pub authid: String,
    pub authzid: String,
}