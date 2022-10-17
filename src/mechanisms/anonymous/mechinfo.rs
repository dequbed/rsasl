use crate::alloc::boxed::Box;
use crate::mechanisms::anonymous::{client, server};
use crate::mechname::Mechname;
use crate::property::Property;
use crate::registry::{Matches, Mechanism, Named, Selection, Selector};
use crate::session::Side;

/// Anonymous 'trace' token
///
/// A client using the `ANONYMOUS` mechanism may provide 'trace' information to the server.
///
/// Quoting [RFC 4505](https://www.rfc-editor.org/rfc/rfc4505.html) section 2:
///
/// > The trace information, which has no semantical value, should take one of two forms: an
/// > Internet email address, or an opaque string that does not contain the '@' (U+0040) character
/// > and that can be interpreted by the system administrator of the client's domain.
///
/// The form and length of the token provided is not validated by rsasl. By the RFC a string over
/// 255 UTF-8 characters or 1020 bytes in length is invalid, and may not be supported by other
/// SASL implementations.
#[non_exhaustive]
pub struct AnonymousToken;
impl Property<'_> for AnonymousToken {
    type Value = str;
}

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static ANONYMOUS: Mechanism = Mechanism {
    mechanism: Mechname::const_new(b"ANONYMOUS"),
    priority: 100,
    client: Some(|| Ok(Box::new(client::Anonymous))),
    server: Some(|_sasl| Ok(Box::new(server::Anonymous))),
    first: Side::Client,
    select: |_| Some(Matches::<Select>::name()),
    offer: |_| true,
};

struct Select;
impl Named for Select {
    fn mech() -> &'static Mechanism {
        &ANONYMOUS
    }
}