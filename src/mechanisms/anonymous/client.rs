
use crate::mechanism::Authentication;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::io::Write;

pub struct AnonymousToken(pub Option<String>);

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;
impl Authentication for Anonymous {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        let token = session.need::<AnonymousToken>(())?;
        let buf = token.as_bytes();
        writer.write_all(buf)?;
        Ok(Done(Some(buf.len())))
    }
}
