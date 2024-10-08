use crate::alloc::boxed::Box;
use crate::error::{MechanismError, MechanismErrorKind};
use crate::mechanisms::plain::{client, server};
use crate::mechname::Mechname;
use crate::registry::{Matches, Mechanism, Named};
use crate::session::Side;
use core::str::Utf8Error;

#[cfg(feature = "std")]
use thiserror::Error;

#[cfg_attr(
    feature = "registry_static",
    linkme::distributed_slice(crate::registry::MECHANISMS)
)]
/// Mechanism description for PLAIN
///
/// See the [`plain`](super) module documentation for details and usage.
pub static PLAIN: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"PLAIN"),
    priority: 300,
    client: Some(|| Ok(Box::new(client::Plain))),
    server: Some(|_sasl| Ok(Box::new(server::Plain))),
    first: Side::Client,
    select: |_| Some(Matches::<Select>::name()),
    offer: |_| true,
};

struct Select;
impl Named for Select {
    fn mech() -> &'static Mechanism {
        &PLAIN
    }
}

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
