use rsasl::callback::{Answerable, CallbackError, Query, SessionCallback, ValidationError};
use rsasl::error::SessionError;
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, Password};
use rsasl::session::Step::Done;
use rsasl::session::{MechanismData, SessionData, Step, StepResult};
use rsasl::validate::{validations, Validation, Validation};
use rsasl::SASL;
use std::io::Cursor;
use std::sync::Arc;
use rsasl::mechanisms::common::properties::SimpleCredentials;
use rsasl::mechanisms::plain::server::PlainValidation;

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl SessionCallback for OurCallback {
    fn validate(&self, _session_data: &SessionData, query: &dyn Query)
        -> Result<(), ValidationError>
    {
        if let Some(PlainValidation { authcid, authzid, password }) = PlainValidation::downcast(query) {
            if authzid.is_none() && authcid == "username" && password == "secret" {
                Ok(())
            } else {
                Err(ValidationError::BadAuthentication)
            }
        } else {
            Err(ValidationError::NoValidation)
        }
    }
}

pub fn main() {
    let mut sasl = SASL::new(Arc::new(OurCallback));

    // Authentication exchange 1
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with correct password:\n   ");
        let mut session = sasl
            .server_start(Mechname::new(b"PLAIN").unwrap())
            .unwrap()
            .without_channel_binding();
        let step_result = session.step(Some(b"\0username\0secret"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert_eq!(step_result.unwrap(), Done(None));
    }
    // Authentication exchange 2
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with wrong password:\n   ");
        let mut session = sasl.server_start(Mechname::new(b"PLAIN").unwrap()).unwrap()
            .without_channel_binding();
        let step_result = session.step(Some(b"\0username\0badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert_eq!(
            step_result.unwrap_err(),
            SessionError::AuthenticationFailure
        );
    }
    // Authentication exchange 2
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with malformed data:\n   ");
        let mut session = sasl.server_start(Mechname::new(b"PLAIN").unwrap()).unwrap()
            .without_channel_binding();
        let step_result = session.step(Some(b"\0username badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert!(step_result.unwrap_err().is_mechanism_error());
    }
}

fn print_outcome(step_result: &StepResult, buffer: Vec<u8>) {
    match step_result {
        Ok(Step::Done(Some(_))) => {
            println!(
                "Authentication successful, bytes to return to client: {:?}",
                buffer
            );
        }
        Ok(Step::Done(None)) => {
            println!("Authentication successful, no data to return");
        }
        Ok(Step::NeedsMore(_)) => assert!(false, "PLAIN exchange took more than one step"),
        Err(SessionError::AuthenticationFailure) => {
            println!("Authentication failed, bad username or password")
        }
        Err(e) => println!("Authentication errored: {}", e),
    }
}
