use std::io::Write;
use crate::{Mechname, SASL, SASLError};
use crate::SASLError::NoSecurityLayer;
use crate::session::{SessionData, StepResult};

pub trait MechanismBuilder: Sync + Send {
    fn init(&self) {}
    fn start(&self, sasl: &SASL) -> Result<MechanismInstance, SASLError>;
}

pub struct MechanismInstance {
    pub name: &'static Mechname,
    pub(crate) inner: Box<dyn Authentication>,
}

pub trait Authentication {
    fn step(&mut self,
            session: &mut SessionData,
            input: Option<&[u8]>,
            writer: &mut dyn Write
    ) -> StepResult;

    fn encode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SASLError> {
        Err(NoSecurityLayer)
    }
    fn decode(&mut self, input: &[u8]) -> Result<Box<[u8]>, SASLError> {
        Err(NoSecurityLayer)
    }
}