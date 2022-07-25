use crate::mechanism::Authentication;
use crate::session::{MechanismData, State, StepResult};

use crate::callback::CallbackError;
use crate::context::EmptyProvider;
use crate::error::SessionError;
use std::io::Write;

use super::mechinfo::PlainError;
use crate::property::{AuthId, AuthzId, Password};

#[derive(Copy, Clone, Debug)]
pub struct Plain;

impl Authentication for Plain {
    fn step(
        &mut self,
        session: &mut MechanismData,
        _input: Option<&[u8]>,
        writer: &mut dyn Write,
    ) -> StepResult {
        let mut len = 0usize;
        let res = session.need_with::<AuthzId, _, _>(&EmptyProvider, &mut |authzid| {
            if authzid.contains('\0') {
                return Err(SessionError::MechanismError(Box::new(
                    PlainError::ContainsNull,
                )));
            }
            writer.write_all(authzid.as_bytes())?;
            len += authzid.len();
            Ok(())
        });
        match res {
            Ok(_) => {}
            Err(SessionError::CallbackError(CallbackError::NoCallback)) => {}
            Err(other) => return Err(other.into()),
        }
        len += writer.write(&[0])?;

        session.need_with::<AuthId, _, _>(&EmptyProvider, &mut |authid| {
            if authid.contains('\0') {
                return Err(SessionError::MechanismError(Box::new(
                    PlainError::ContainsNull,
                )));
            }
            writer.write_all(authid.as_bytes())?;
            len += authid.len();
            Ok(())
        })?;
        len += writer.write(&[0])?;

        session.need_with::<Password, _, _>(&EmptyProvider, &mut |password| {
            writer.write_all(password)?;
            len += password.len();
            Ok(())
        })?;

        Ok((State::Finished, Some(len)))
    }
}

#[cfg(testn)]
mod test {
    use super::*;
    use crate::mechanisms::plain::mechinfo::PLAIN;
    use crate::session::MechanismData;
    use crate::session::Step::NeedsMore;
    use crate::Side;
    use std::io::Cursor;
    use std::sync::Arc;

    #[test]
    fn split_writer() {
        let mut session = MechanismData::new(None, &PLAIN, Side::Client);

        let username = "testuser".to_string();
        assert_eq!(username.len(), 8);
        let password = "secret".to_string();
        assert_eq!(password.len(), 6);

        session.set_property::<AuthId>(Arc::new(username));
        session.set_property::<Password>(Arc::new(password));

        struct SplitWriter {
            data: Cursor<Vec<u8>>,
            cnt: usize,
        }
        impl Write for SplitWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let wrt = if self.cnt != 0 && self.cnt < buf.len() {
                    println!("Partial write: {:?}", &buf[0..self.cnt]);
                    self.data.write(&buf[0..self.cnt])?
                } else {
                    println!("Complete write: {:?}", &buf[..]);
                    self.data.write(buf)?
                };
                self.cnt = self.cnt.saturating_sub(wrt);
                Ok(wrt)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.data.flush()
            }
        }

        let mut out = SplitWriter {
            data: Cursor::new(Vec::with_capacity(16)),
            cnt: 5,
        };

        // Do an authentication step. In a PLAIN exchange there is only one step, with no data.
        let mut plain = Plain;
        let step_result = plain.step(&mut session, None, &mut out).unwrap();

        match step_result {
            Done(Some(len)) => {
                assert_eq!(len, 1 + 8 + 1 + 6);
                let buffer = &out.data.into_inner()[0..len];
                // (1) "\0" + (8) "testuser" + (1) "\0" + (6) "secret"
                let (name, pass) = buffer.split_at(9);
                assert_eq!(name[0], 0);
                assert_eq!(name, b"\0testuser");
                assert_eq!(pass[0], 0);
                assert_eq!(pass, b"\0secret");
                return;
            }
            Done(None) => panic!("PLAIN exchange produced no output"),
            NeedsMore(_) => panic!("PLAIN exchange took more than one step"),
        }
    }
}
