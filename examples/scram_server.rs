use rsasl::callback::{CallbackError, Request, SessionCallback};
use rsasl::callback::Context;
use rsasl::error::SessionError;
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, AuthzId};
use rsasl::session::SessionData;
use rsasl::validate::{NoValidation, Validate, Validation, ValidationError};
use rsasl::SASL;
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
    let sasl = SASL::new(Arc::new(OurCallback));

    let mut session = sasl
        .server_start(Mechname::new(b"SCRAM-SHA-1").unwrap())
        .unwrap()
        .without_channel_binding::<NoValidation>();

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
