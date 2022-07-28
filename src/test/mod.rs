//! Test utilities for rsasl
//!
//! This module contains several utility functions and data types to test SASL handling in
//! protocol implementations and user code

mod mechanism;
mod config;
pub use config::EmptyCallback;