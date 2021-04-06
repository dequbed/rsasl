#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#![allow(improper_ctypes_definitions)]

#[cfg(feature = "build_bindgen")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(not(feature = "build_bindgen"))]
include!(concat!("stale_bindings.rs"));
