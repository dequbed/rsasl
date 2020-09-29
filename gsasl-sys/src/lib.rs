#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(not(docsrs))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(docsrs)]
include!(concat!("stale_bindings.rs"));
