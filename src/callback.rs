use std::fmt::Debug;
use crate::RsaslError;
use crate::session::Session;

pub trait Callback: Debug {
    fn callback(&self, session: &mut Session) -> Result<(), RsaslError>;
}