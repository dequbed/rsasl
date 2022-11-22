//! Test utilities for rsasl
//!
//! This module contains several utility functions and data types to test SASL handling in
//! protocol implementations and user code

mod config;
mod mechanism;

use crate::channel_bindings::NoChannelBindings;
use crate::config::SASLConfig;
use crate::registry::Mechanism;
use crate::sasl::Sasl;
use crate::session::{Session, Side};
use crate::typed::Tagged;
pub use config::{client_config, server_config, EmptyCallback};
use std::sync::Arc;

// TODO:
/// # Panics
#[must_use]
pub fn client_session(config: Arc<SASLConfig>, mechanism: &Mechanism) -> Session {
    let mech = mechanism.client().unwrap().unwrap();
    let sasl = Sasl {
        config,
        cb: NoChannelBindings,
        validation: Tagged(None),
    };
    Session::new(sasl, Side::Client, mech, *mechanism)
}

// TODO:
/// # Panics
#[must_use]
pub fn server_session(config: Arc<SASLConfig>, mechanism: &Mechanism) -> Session {
    let mech = mechanism.server(&config).unwrap().unwrap();
    let sasl = Sasl {
        config,
        cb: NoChannelBindings,
        validation: Tagged(None),
    };
    Session::new(sasl, Side::Server, mech, *mechanism)
}
