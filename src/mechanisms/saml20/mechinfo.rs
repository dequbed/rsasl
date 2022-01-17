use crate::{Mechanism, Mechname, Side};
use crate::gsasl::gsasl::{CMechanismStateKeeper, MechanismVTable};
use crate::mechanisms::saml20::client::{_gsasl_saml20_client_finish, _gsasl_saml20_client_start, _gsasl_saml20_client_step};
use crate::mechanisms::saml20::server::{_gsasl_saml20_server_finish, _gsasl_saml20_server_start, _gsasl_saml20_server_step};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SAML20: Mechanism = Mechanism {
    priority: 1000,
    mechanism: &Mechname::const_new_unchecked(b"SAML20"),
    client: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_saml20_client_start),
        step: Some(_gsasl_saml20_client_step),
        finish: Some(_gsasl_saml20_client_finish),
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_saml20_server_start),
        step: Some(_gsasl_saml20_server_step),
        finish: Some(_gsasl_saml20_server_finish),
        encode: None,
        decode: None,
    })),
    first: Side::Client,
};