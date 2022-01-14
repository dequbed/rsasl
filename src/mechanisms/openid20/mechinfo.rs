use crate::{Mechanism, Mechname};
use crate::gsasl::gsasl::{CMechanismStateKeeper, MechanismVTable};
use crate::mechanisms::openid20::client::{_gsasl_openid20_client_finish, _gsasl_openid20_client_start, _gsasl_openid20_client_step};
use crate::mechanisms::openid20::server::{_gsasl_openid20_server_finish, _gsasl_openid20_server_start, _gsasl_openid20_server_step};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static OPENID20: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked("OPENID20"),
    client: Some(|_sasl| CMechanismStateKeeper::new(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_openid20_client_start),
        step: Some(_gsasl_openid20_client_step),
        finish: Some(_gsasl_openid20_client_finish),
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::new(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_openid20_server_start),
        step: Some(_gsasl_openid20_server_step),
        finish: Some(_gsasl_openid20_server_finish),
        encode: None,
        decode: None,
    })),
};
