//! Utilities for using SASL in practical contexts (e.g. generating channel bindings)
//!
//! This module is only available if rsasl is compiled with the feature `rustls`. It only adds
//! utilities for rustls for now too.

#[cfg(feature = "rustls")]
mod rustls;