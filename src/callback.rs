use std::fmt::Debug;
use crate::SaslError;
use crate::consts::Gsasl_property;
use crate::session::Session;

pub trait Callback: Debug {
    fn callback(&self, session: &mut Session, code: Gsasl_property) -> Result<(), SaslError>;
}