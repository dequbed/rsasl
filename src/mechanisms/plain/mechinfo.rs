use crate::error::{MechanismError, MechanismErrorKind};
use crate::mechanisms::plain::{client, server};
use crate::mechname::Mechname;
use crate::registry::Mechanism;
use crate::session::Side;
use std::str::Utf8Error;
use thiserror::Error;

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
/// Mechanism description for PLAIN
///
/// See the [`plain`](super) module documentation for details and usage.
pub static PLAIN: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"PLAIN"),
    priority: 300,
    client: Some(|_sasl, _offered| Ok(Box::new(client::Plain))),
    server: Some(|_sasl| Ok(Box::new(server::Plain))),
    first: Side::Client,
};

#[derive(Debug, Error)]
pub(super) enum PlainError {
    #[error("The given value contains a NULL-byte")]
    ContainsNull,
    #[error("authid and password must not be empty")]
    Empty,
    #[error("invalid format, expected three strings separated by two NULL-bytes")]
    BadFormat,
    #[error("authzid is invalid UTF-8: {0}")]
    BadAuthzid(#[source] Utf8Error),
    #[error("authcid is invalid UTF-8: {0}")]
    BadAuthcid(#[source] Utf8Error),

    #[error("saslprep failed: {0}")]
    Saslprep(
        #[from]
        #[source]
        stringprep::Error,
    ),
}

impl MechanismError for PlainError {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}