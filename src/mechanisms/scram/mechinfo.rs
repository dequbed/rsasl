use crate::mechanisms::scram::{client, server};
use crate::{Mechanism, Mechname, Side};

const NONCE_LEN: usize = 24;

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SCRAM_SHA1: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"SCRAM-SHA-1"),
    priority: 400,
    client: Some(|_sasl| Ok(Box::new(client::ScramSha1Client::<NONCE_LEN>::new()))),
    server: Some(|_sasl| Ok(Box::new(server::ScramSha1Server::<NONCE_LEN>::new()))),
    first: Side::Client,
};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SCRAM_SHA1_PLUS: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"SCRAM-SHA-1-PLUS"),
    priority: 500,
    client: Some(|_sasl| Ok(Box::new(client::ScramSha1Client::<NONCE_LEN>::new_plus()))),
    server: Some(|_sasl| Ok(Box::new(server::ScramSha1Server::<NONCE_LEN>::new_plus()))),
    first: Side::Client,
};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SCRAM_SHA256: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"SCRAM-SHA-256"),
    priority: 600,
    client: Some(|_sasl| Ok(Box::new(client::ScramSha256Client::<NONCE_LEN>::new()))),
    server: Some(|_sasl| Ok(Box::new(server::ScramSha256Server::<NONCE_LEN>::new()))),
    first: Side::Client,
};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SCRAM_SHA256_PLUS: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"SCRAM-SHA-256-PLUS"),
    priority: 700,
    client: Some(|_sasl| Ok(Box::new(client::ScramSha256Client::<NONCE_LEN>::new_plus()))),
    server: Some(|_sasl| Ok(Box::new(server::ScramSha256Server::<NONCE_LEN>::new_plus()))),
    first: Side::Client,
};
