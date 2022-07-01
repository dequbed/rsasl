
pub struct ScramSaltedPasswordRef<'a> {
    iterations: u32,
    salt: &'a [u8],
    password: &'a [u8],
}

#[derive(Debug)]
/// SCRAM stored password parameters
///
/// A server SHOULD store users' passwords hashed in a way SCRAM can use and not in plaintext.
///
pub struct ScramPassParams {
    pub iterations: u32,
    pub salt: Box<[u8]>,
}
#[derive(Debug)]
pub struct ScramSaltedPassword {
    pub params: ScramPassParams,
    pub password: Box<[u8]>,
    // TODO: Include the algorithm name dummy
    //          ⇒ crypto_common::AlgorithmName will be useful
}
// TODO: (Feature-gated) Implement serde for these since they are commonly stored?

pub enum ScramSaltedPasswordQuery {
    Q(String),
    A(ScramSaltedPassword),
}

pub enum ScramSaltedPasswordQueryClient {
    Q {
        username: String,
        params: ScramPassParams,
        // TODO: Include the algorithm name dummy
        //          ⇒ crypto_common::AlgorithmName will be useful
    },
    A(Box<[u8]>),
}

pub struct ScramValidate {
    pub authid: String,
    pub authzid: String,
}