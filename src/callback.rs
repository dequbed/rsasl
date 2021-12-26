use std::fmt::Debug;
use crate::consts::Gsasl_property;
use crate::SASLError;
use crate::session::SessionData;

pub trait Callback: Debug {
    fn callback(&self, session: &mut SessionData, code: Gsasl_property) -> Result<(), SASLError>;
}