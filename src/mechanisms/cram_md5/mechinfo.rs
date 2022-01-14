use crate::{Mechanism, Mechname};
use crate::gsasl::gsasl::{CMechanismStateKeeper, MechanismVTable};
use crate::mechanisms::cram_md5::client::_gsasl_cram_md5_client_step;
use crate::mechanisms::cram_md5::server::{_gsasl_cram_md5_server_finish, _gsasl_cram_md5_server_start, _gsasl_cram_md5_server_step};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static CRAM_MD5: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked(b"CRAM-MD5"),
    priority: 0,
    client: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: None,
        step: Some(_gsasl_cram_md5_client_step),
        finish: None,
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_cram_md5_server_start),
        step: Some(_gsasl_cram_md5_server_step),
        finish: Some(_gsasl_cram_md5_server_finish),
        encode: None,
        decode: None,
    })),
};