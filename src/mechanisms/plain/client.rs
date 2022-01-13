use std::io::{IoSlice, Write};
use crate::mechanism::Authentication;
use crate::property::{AuthId, AuthzId, Password};
use crate::registry::Mechanism;
use crate::session::Step::Done;
use crate::session::{SessionData, StepResult};
use crate::Mechname;

#[derive(Copy, Clone, Debug)]
pub struct Plain;

impl Authentication for Plain {
    fn step(&mut self, session: &mut SessionData, _input: Option<&[u8]>, writer: &mut dyn Write)
        -> StepResult
    {
        let authzid = session.get_property_or_callback::<AuthzId>().ok()
            .map(Clone::clone);

        let authid = session.get_property_or_callback::<AuthId>()
            .map(Clone::clone)?;
        let password = session.get_property_or_callback::<Password>()
            .map(Clone::clone)?;

        let authzidbuf = if let Some(authz) = &authzid {
            authz.as_bytes()
        } else {
            &[]
        };
        let data: &[&[u8]] = &[
            authzidbuf,
            &[0],
            authid.as_bytes(),
            &[0],
            password.as_bytes(),
        ];
        let mut bufs: [IoSlice; 5] = [
            IoSlice::new(data[0]),
            IoSlice::new(data[1]),
            IoSlice::new(data[2]),
            IoSlice::new(data[3]),
            IoSlice::new(data[4]),
        ];

        let mut skip = if authzid.is_none() { 1 } else { 0 };
        let mut written = 0;
        while {
            let len = writer.write_vectored(&bufs[skip..])?;
            written += len;

            // Number of buffers to remove.
            let mut remove = 0;
            // Total length of all the to be removed buffers.
            let mut accumulated_len = 0;
            for buf in bufs[skip..].iter() {
                if accumulated_len + buf.len() > len {
                    break;
                } else {
                    accumulated_len += buf.len();
                    remove += 1;
                }
            }
            skip += remove;
            if skip < 5 {
                let rem = len - accumulated_len;
                bufs[skip] = IoSlice::new(&data[skip][rem..]);
            }

            skip < 5
        } {}

        Ok(Done(Some(written)))
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Arc;
    use crate::session::SessionData;
    use crate::session::Step::NeedsMore;
    use super::*;

    #[test]
    fn simple() {
        let mut session = SessionData::new(None, Arc::new(HashMap::new()), Mechname::new_unchecked("X-TEST"));

        let username = "testuser".to_string();
        assert_eq!(username.len(), 8);
        let password = "secret".to_string();
        assert_eq!(password.len(), 6);

        session.set_property::<AuthId>(Box::new(username));
        session.set_property::<Password>(Box::new(password));

        let mut out = Cursor::new(Vec::new());

        // Do an authentication step. In a PLAIN exchange there is only one step, with no data.
        let mut plain = Plain;
        let step_result = plain.step(&mut session, None, &mut out).unwrap();

        match step_result {
            Done(Some(len)) => {
                assert_eq!(len, 1 + 8 + 1 + 6);
                let buffer = &out.into_inner()[0..len];
                // (1) "\0" + (8) "testuser" + (1) "\0" + (6) "secret"
                let (name, pass) = buffer.split_at(9);
                assert_eq!(name[0], 0);
                assert_eq!(name, b"\0testuser");
                assert_eq!(pass[0], 0);
                assert_eq!(pass, b"\0secret");
                return;
            },
            Done(None) => panic!("PLAIN exchange produced no output"),
            NeedsMore(_) => panic!("PLAIN exchange took more than one step"),
        }
    }

    #[test]
    fn split_writer() {
        let mut session = SessionData::new(None, Arc::new(HashMap::new()), Mechname::new_unchecked("X-TEST"));

        let username = "testuser".to_string();
        assert_eq!(username.len(), 8);
        let password = "secret".to_string();
        assert_eq!(password.len(), 6);

        session.set_property::<AuthId>(Box::new(username));
        session.set_property::<Password>(Box::new(password));

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
            },
            Done(None) => panic!("PLAIN exchange produced no output"),
            NeedsMore(_) => panic!("PLAIN exchange took more than one step"),
        }
    }
}

#[cfg(feature = "registry_static")]
use crate::registry::{distributed_slice, MECHANISMS_CLIENT};
#[cfg_attr(feature = "registry_static", distributed_slice(MECHANISMS_CLIENT))]
pub static PLAIN: Mechanism = Mechanism {
    mechanism: &Mechname::const_new_unchecked("PLAIN"),
    client: Some(|_sasl| Ok(Box::new(Plain))),
    server: None,
};