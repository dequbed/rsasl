use std::fmt::Debug;
use std::io::Write;
use crate::{mechname, SASL, SASLError, SessionData};
use crate::SASLError::NoSecurityLayer;
use crate::session::StepResult;

pub trait MechanismBuilder: Sync + Send {
    fn init(&self) {}
    fn start(&self, sasl: &SASL) -> Result<MechanismInstance, SASLError>;
}

pub struct MechanismInstance {
    pub name: &'static mechname::Mechname,
    pub(crate) inner: Box<dyn Authentication>,
}

pub trait Authentication {
    fn step(&mut self,
            session: &mut SessionData,
            input: Option<&[u8]>,
            writer: &mut dyn Write
    ) -> StepResult;
}

impl Authentication for MechanismInstance {
    fn step(&mut self,
            session: &mut SessionData,
            input: Option<&[u8]>,
            writer: &mut dyn Write
        ) -> StepResult
    {
        self.inner.step(session, input, writer)
    }
}

trait SecurityLayer {
    fn encode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SASLError> {
        Err(NoSecurityLayer)
    }
    fn decode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SASLError> {
        Err(NoSecurityLayer)
    }
}