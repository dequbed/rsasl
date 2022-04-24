use crate::callback::{Answerable, Question};

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
impl Question for ScramSaltedPasswordQuery {
    type Params = String;

    fn build(params: Self::Params) -> Self {
        Self::Q(params)
    }
}
impl Answerable for ScramSaltedPasswordQuery {
    type Answer = ScramSaltedPassword;

    fn respond(&mut self, resp: Self::Answer) {
        *self = Self::A(resp);
    }

    fn into_answer(self) -> Option<Self::Answer> {
        match self {
            ScramSaltedPasswordQuery::Q(_) => None,
            ScramSaltedPasswordQuery::A(p) => Some(p)
        }
    }
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
impl Question for ScramSaltedPasswordQueryClient {
    type Params = (String, ScramPassParams);

    fn build(params: Self::Params) -> Self {
        Self::Q {
            username: params.0,
            params: params.1,
        }
    }
}
impl Answerable for ScramSaltedPasswordQueryClient {
    type Answer = Box<[u8]>;

    fn respond(&mut self, resp: Self::Answer) {
        *self = Self::A(resp)
    }

    fn into_answer(self) -> Option<Self::Answer> {
        match self {
            Self::A(b) => Some(b),
            Self::Q { .. }  => None,
        }
    }
}

pub struct ScramValidate {
    pub authid: String,
    pub authzid: String,
}
impl Question for ScramValidate {
    type Params = ScramValidate;

    fn build(params: Self::Params) -> Self {
        params
    }
}