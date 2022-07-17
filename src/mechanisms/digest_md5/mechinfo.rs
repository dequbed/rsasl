use crate::gsasl::gsasl::{CMechanismStateKeeper, MechanismVTable};
use crate::mechanisms::digest_md5::client::{
    _gsasl_digest_md5_client_decode, _gsasl_digest_md5_client_encode,
    _gsasl_digest_md5_client_finish, _gsasl_digest_md5_client_start, _gsasl_digest_md5_client_step,
};
use crate::mechanisms::digest_md5::server::{
    _gsasl_digest_md5_server_decode, _gsasl_digest_md5_server_encode,
    _gsasl_digest_md5_server_finish, _gsasl_digest_md5_server_start, _gsasl_digest_md5_server_step,
};
use crate::mechname::Mechname;
use crate::registry::Mechanism;
use crate::session::Side;

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static DIGEST_MD5: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unvalidated(b"DIGEST-MD5"),
    priority: 0,
    client: Some(|_sasl| {
        CMechanismStateKeeper::build(MechanismVTable {
            init: None,
            done: None,
            start: Some(_gsasl_digest_md5_client_start),
            step: Some(_gsasl_digest_md5_client_step),
            finish: Some(_gsasl_digest_md5_client_finish),
            encode: Some(_gsasl_digest_md5_client_encode),
            decode: Some(_gsasl_digest_md5_client_decode),
        })
    }),
    server: Some(|_sasl| {
        CMechanismStateKeeper::build(MechanismVTable {
            init: None,
            done: None,
            start: Some(_gsasl_digest_md5_server_start),
            step: Some(_gsasl_digest_md5_server_step),
            finish: Some(_gsasl_digest_md5_server_finish),
            encode: Some(_gsasl_digest_md5_server_encode),
            decode: Some(_gsasl_digest_md5_server_decode),
        })
    }),
    first: Side::Server,
};
