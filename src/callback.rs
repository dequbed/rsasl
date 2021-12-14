use std::fmt::Debug;
use crate::gsasl::consts::{GSASL_OK, Gsasl_property};
use crate::gsasl::gsasl::{};
use crate::{SASL, Property, RsaslError};
use crate::session::Session;

pub trait Callback: Debug {
    fn callback(&self, session: &mut Session) -> Result<(), RsaslError>;
}