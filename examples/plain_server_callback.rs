use rsasl::callback::SessionCallback;
use rsasl::context::Context;
use rsasl::error::SessionError;
use rsasl::mechanisms::common::properties::ValidateSimple;
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, AuthzId, Password};
use rsasl::session::{SessionData, State, Step, StepResult};
use rsasl::validate::{Validate, ValidationError, ValidationOutcome};
use rsasl::SASL;
use std::io::Cursor;
use std::sync::Arc;
use thiserror::Error;

struct OurCallback;
#[derive(Debug, Error)]
enum OurCallbackError {}
impl OurCallback {
    fn validate_simple(&self, context: &Context) -> Result<ValidationOutcome, OurCallbackError> {
        let authzid = context.get_ref::<AuthzId>();
        let authid = context
            .get_ref::<AuthId>()
            .expect("SIMPLE validation requested but AuthId prop is missing!");
        let password = context
            .get_ref::<Password>()
            .expect("SIMPLE validation requested but Password prop is missing!");

        println!(
            "SIMPLE VALIDATION for (authzid: {:?}, authid: {}, password: {:?})",
            authzid,
            authid,
            std::str::from_utf8(password)
        );

        if !(authzid.is_none() || authzid == Some(authid)) {
            Ok(ValidationOutcome::AuthorizationFailed)
        } else if authid == "username" && password == b"secret" {
            Ok(ValidationOutcome::Successful)
        } else {
            Ok(ValidationOutcome::AuthenticationFailed)
        }
    }
}
impl SessionCallback for OurCallback {
    fn validate(
        &self,
        session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        validate.with::<ValidateSimple, _, _>(|| self.validate_simple(context))?;
        Err(ValidationError::NoValidation)
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
        assert_eq!(step_result.unwrap(), (State::Finished, None));
    }
    // Authentication exchange 2
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with wrong password:\n   ");
        let mut session = sasl
            .server_start(Mechname::new(b"PLAIN").unwrap())
            .unwrap()
            .without_channel_binding();
        let step_result = session.step(Some(b"\0username\0badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert!(step_result.unwrap_err().is_authentication_failure());
    }
    // Authentication exchange 2
    {
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with malformed data:\n   ");
        let mut session = sasl
            .server_start(Mechname::new(b"PLAIN").unwrap())
            .unwrap()
            .without_channel_binding();
        let step_result = session.step(Some(b"\0username badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert!(step_result.unwrap_err().is_mechanism_error());
    }
}

fn print_outcome(step_result: &StepResult, buffer: Vec<u8>) {
    match step_result {
        Ok((State::Finished, Some(_))) => {
            println!(
                "Authentication successful, bytes to return to client: {:?}",
                buffer
            );
        }
        Ok((State::Finished, None)) => {
            println!("Authentication successful, no data to return");
        }
        Ok((State::Running, _)) => assert!(false, "PLAIN exchange took more than one step"),
        Err(SessionError::AuthenticationFailure) => {
            println!("Authentication failed, bad username or password")
        }
        Err(e) => println!("Authentication errored: {}", e),
    }
}
