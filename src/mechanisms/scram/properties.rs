use crate::property::{Property, SizedProperty};

/// Iterations of a hash or key derivation algorithm used
pub struct Iterations;
impl SizedProperty<'_> for Iterations {
    type Value = u32;
}

/// The Salt added to the password
pub struct Salt;
impl Property<'_> for Salt {
    type Value = [u8];
}

/// The algorithm name
pub struct AlgorithmName;
impl Property<'_> for AlgorithmName {
    type Value = str;
}

/// Retrieve a stored SCRAM password from persistent storage
///
/// This property is used by SCRAM mechanisms to retrieve the secrets required to authenticate an
/// user.
pub struct ScramStoredPassword<'a> {
    pub iterations: u32,
    pub salt: &'a [u8],
    pub stored_key: &'a [u8],
    pub server_key: &'a [u8],
}
impl<'a> Property<'a> for ScramStoredPassword<'static> {
    type Value = ScramStoredPassword<'a>;
}

/// Callback to store generated keys for future use
///
/// actionable but also satisfiable, depends.
/// This property is used by the SCRAM mechanism on the client side of an authentication, and
/// an action callback for this property will be issued when the server has been authenticated.
/// This allows a client to store the derived keys in a persistent database and use them in
/// future authentication exchanges.
pub struct ScramCachedPassword<'a> {
    pub client_key: &'a [u8],
    pub server_key: &'a [u8],
}
impl<'a> Property<'a> for ScramCachedPassword<'static> {
    type Value = ScramCachedPassword<'a>;
}

/// A salted and hashed password
pub struct SaltedPassword;
impl Property<'_> for SaltedPassword {
    type Value = [u8];
}