use crate::error::SessionError;
use crate::mechanism::Authentication;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::io::Write;
use crate::callback::{Answerable, Question};

pub struct AnonymousToken(pub Option<String>);
impl Question for AnonymousToken {
    type Params = ();

    fn build(_: Self::Params) -> Self {
        Self(None)
    }
}
impl Answerable for AnonymousToken {
    type Answer = String;

    fn respond(&mut self, resp: Self::Answer) {
        if resp.len() == 0 || resp.len() > 255 {
            return;
        }
        self.0 = Some(resp);
    }

    fn into_answer(self) -> Option<Self::Answer> {
        self.0
    }
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
        let token = session.need::<AnonymousToken>(())?;
        let buf = token.as_bytes();
        writer.write_all(buf)?;
        Ok(Done(Some(buf.len())))
    }
}
