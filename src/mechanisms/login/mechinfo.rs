use crate::gsasl::gsasl::{CMechanismStateKeeper, MechanismVTable};
use crate::{Mechanism, Mechname};
use crate::mechanisms::login::client::{_gsasl_login_client_finish, _gsasl_login_client_start, _gsasl_login_client_step};
use crate::mechanisms::login::server::{_gsasl_login_server_finish, _gsasl_login_server_start, _gsasl_login_server_step};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static LOGIN: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked("LOGIN"),
    client: Some(|_sasl| CMechanismStateKeeper::new(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_login_client_start),
        step: Some(_gsasl_login_client_step),
        finish: Some(_gsasl_login_client_finish),
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::new(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_login_server_start),
        step: Some(_gsasl_login_server_step),
        finish: Some(_gsasl_login_server_finish),
        encode: None,
        decode: None,
    })),
};
