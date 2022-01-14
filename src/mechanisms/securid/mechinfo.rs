use crate::{Mechanism, Mechname};
use crate::gsasl::gsasl::{CMechanismStateKeeper, MechanismVTable};
use crate::mechanisms::securid::client::{_gsasl_securid_client_finish, _gsasl_securid_client_start, _gsasl_securid_client_step};
use crate::mechanisms::securid::server::_gsasl_securid_server_step;

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SECURID: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked(b"SECURID"),
    priority: 300,
    client: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_securid_client_start),
        step: Some(_gsasl_securid_client_step),
        finish: Some(_gsasl_securid_client_finish),
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: None,
        step: Some(_gsasl_securid_server_step),
        finish: None,
        encode: None,
        decode: None,
    })),
};
