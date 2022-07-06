use crate::mechanism::Authentication;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::io::Write;
use crate::property::MaybeSizedProperty;

pub struct AnonymousToken;
impl MaybeSizedProperty for AnonymousToken {
    type Value = str;
}

#[derive(Copy, Clone, Debug)]
pub struct Anonymous;
impl Authentication for Anonymous {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        let mut write_out = Ok(());
        let mut len = None;
        session.need_with::<'_, AnonymousToken, _, _>(&(), &mut |token| {
            let buf = token.as_bytes();
            write_out = writer.write_all(buf);
            len = Some(buf.len());
        })?;
        write_out?;
        Ok(Done(len))
    }
}
