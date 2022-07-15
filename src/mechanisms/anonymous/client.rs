use crate::mechanism::Authentication;
use crate::property::MaybeSizedProperty;
use crate::session::{MechanismData, State, StepResult};
use std::io::Write;

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
        session.need_with::<AnonymousToken, _>(&(), &mut |token| {
            let buf = token.as_bytes();
            write_out = writer.write_all(buf);
            len = Some(buf.len());
        })?;
        write_out?;
        Ok((State::Finished, len))
    }
}
