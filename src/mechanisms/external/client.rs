use crate::mechanism::Authentication;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::io::Write;
use crate::property::MaybeSizedProperty;

pub struct AuthId;
impl MaybeSizedProperty for AuthId {
    type Value = str;
}

#[derive(Copy, Clone, Debug)]
pub struct External;

impl Authentication for External {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        let mut write_out = Ok(());
        let mut len = None;

        session.need_with::<'_, AuthId, _, _>(&(), &mut |authid| {
            let buf = authid.as_bytes();
            write_out = writer.write_all(buf);
            len = Some(buf.len());
        });

        write_out?;
        Ok(Done(len))
    }
}
