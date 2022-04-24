use crate::mechanism::Authentication;
use crate::session::Step::Done;
use crate::session::{MechanismData, StepResult};
use std::io::Write;
use crate::callback::{Answerable, Question};

pub struct AuthId(pub Option<String>);
impl Question for AuthId {
    type Params = ();

    fn build(_: Self::Params) -> Self {
        Self(None)
    }
}
impl Answerable for AuthId {
    type Answer = String;

    fn respond(&mut self, resp: Self::Answer) {
        self.0 = Some(resp);
    }

    fn into_answer(self) -> Option<Self::Answer> {
        self.0
    }
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
        if let Ok(authid) = session.need::<AuthId>(()) {
            let buf = authid.as_bytes();
            writer.write_all(buf)?;
            Ok(Done(Some(buf.len())))
        } else {
            Ok(Done(None))
        }
    }
}
