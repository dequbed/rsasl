use rsasl::callback::{CallbackError, Context, Request, SessionCallback, SessionData};
use rsasl::prelude::*;
use rsasl::property::{AuthId, AuthzId};
use rsasl::validate::{Validate, Validation, ValidationError};
use std::io;
use std::io::Cursor;
use std::sync::Arc;

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;
impl SessionCallback for OurCallback {
    fn callback(
        &self,
        _session_data: &SessionData,
        context: &Context,
        _request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
        let _authid = context
            .get_ref::<AuthId>()
            .ok_or(SessionError::CallbackError(CallbackError::NoCallback))?;

        Ok(())
    }
    fn validate(
        &self,
        _session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        let authid = context.get_ref::<AuthId>().unwrap();

        if let Some(authzid) = context.get_ref::<AuthzId>() {
            if authzid == authid {
                validate.finalize::<TestValidation>(User {
                    name: authzid.to_string(),
                });
                return Ok(());
            }
        } else {
            validate.finalize::<TestValidation>(User {
                name: authid.to_string(),
            });
            return Ok(());
        }

        Ok(())
    }
}

struct User {
    name: String,
}

struct TestValidation;
impl Validation for TestValidation {
    type Value = User;
}

pub fn main() {
    let config = SASLConfig::builder()
        .with_defaults()
        .with_callback(OurCallback)
        .unwrap();
    let sasl = SASLServer::<TestValidation>::new(config);

    let mut session = sasl
        .start_suggested(Mechname::new(b"SCRAM-SHA-1").unwrap())
        .unwrap();

    loop {
        // Read data from STDIN
        let mut in_data = String::new();
        if let Err(error) = io::stdin().read_line(&mut in_data) {
            println!("error: {}", error);
            return;
        }
        in_data.pop(); // Remove the newline char at the end of the string

        let mut out = Cursor::new(Vec::new());
        let (_state, _written) = session.step64(Some(in_data.as_ref()), &mut out).unwrap();
    }
}
