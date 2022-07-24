#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]

pub mod consts;
pub mod gsasl;

pub mod gl {
    pub mod free;
    #[cfg(feature = "digest")]
    pub mod gc_gnulib;
    pub mod memxor;
}

#[cfg(feature = "base64")]
pub mod base64;
pub mod callback;

#[cfg(feature = "digest")]
pub mod crypto;

pub mod error;
pub mod free;
pub mod gc;
#[cfg(any(feature = "digest", feature = "openid20", feature = "saml20"))]
pub mod mechtools;
pub mod property;

#[cfg(feature = "saslprep")]
pub mod saslprep;
