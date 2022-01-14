use crate::{Mechanism, Mechname};
use crate::gsasl::gsasl::{CMechanismStateKeeper, MechanismVTable};
use crate::mechanisms::scram::client::{_gsasl_scram_client_finish, _gsasl_scram_client_step, _gsasl_scram_sha1_client_start, _gsasl_scram_sha1_plus_client_start, _gsasl_scram_sha256_client_start, _gsasl_scram_sha256_plus_client_start};
use crate::mechanisms::scram::server::{_gsasl_scram_server_finish, _gsasl_scram_server_step, _gsasl_scram_sha1_plus_server_start, _gsasl_scram_sha1_server_start, _gsasl_scram_sha256_plus_server_start, _gsasl_scram_sha256_server_start};

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SCRAM_SHA1: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked(b"SCRAM-SHA-1"),
    priority: 400,
    client: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha1_client_start),
        step: Some(_gsasl_scram_client_step),
        finish: Some(_gsasl_scram_client_finish),
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha1_server_start),
        step: Some(_gsasl_scram_server_step),
        finish: Some(_gsasl_scram_server_finish),
        encode: None,
        decode: None,
    })),
};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SCRAM_SHA1_PLUS: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked(b"SCRAM-SHA-1-PLUS"),
    priority: 500,
    client: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha1_plus_client_start),
        step: Some(_gsasl_scram_client_step),
        finish: Some(_gsasl_scram_client_finish),
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha1_plus_server_start),
        step: Some(_gsasl_scram_server_step),
        finish: Some(_gsasl_scram_server_finish),
        encode: None,
        decode: None,
    })),
};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SCRAM_SHA256: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked(b"SCRAM-SHA-256"),
    priority: 600,
    client: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha256_client_start),
        step: Some(_gsasl_scram_client_step),
        finish: Some(_gsasl_scram_client_finish),
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha256_server_start),
        step: Some(_gsasl_scram_server_step),
        finish: Some(_gsasl_scram_server_finish),
        encode: None,
        decode: None,
    })),
};

#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS))]
pub static SCRAM_SHA256_PLUS: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked(b"SCRAM-SHA-256-PLUS"),
    priority: 700,
    client: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha256_plus_client_start),
        step: Some(_gsasl_scram_client_step),
        finish: Some(_gsasl_scram_client_finish),
        encode: None,
        decode: None,
    })),
    server: Some(|_sasl| CMechanismStateKeeper::build(MechanismVTable {
        init: None,
        done: None,
        start: Some(_gsasl_scram_sha256_plus_server_start),
        step: Some(_gsasl_scram_server_step),
        finish: Some(_gsasl_scram_server_finish),
        encode: None,
        decode: None,
    })),
};