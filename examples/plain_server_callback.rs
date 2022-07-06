use std::io::Cursor;
use std::sync::Arc;
use rsasl::callback::{RequestResponse, SessionCallback};
use rsasl::context::Context;
use rsasl::error::SessionError;
use rsasl::mechanisms::common::properties::ValidateSimple;
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, AuthzId, Password};
use rsasl::SASL;
use rsasl::session::{SessionData, Step, StepResult};
use rsasl::validate::{Validate, ValidationError};

// Callback is an unit struct since no data can be accessed from it.
struct OurCallback;

impl SessionCallback for OurCallback {
    fn validate(&self, session_data: &SessionData, context: &Context, validate: &mut Validate<'_>)
        -> Result<(), ValidationError>
    {
        if validate.is::<ValidateSimple>() {
            let authzid = context.get_ref::<AuthzId>();
            let authid = context.get_ref::<AuthId>()
                .expect("SIMPLE validation requested but AuthId prop is missing!");
            let password = context.get_ref::<Password>()
                .expect("SIMPLE validation requested but Password prop is missing!");
            println!("authzid: {:?}, authid: {}, password: {:?}",
                     authzid, authid, std::str::from_utf8(password));
            let o = authzid.is_none() && authid == "username" && password == b"secret";
            validate.finalize::<ValidateSimple>(o);
            Ok(())
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
        assert_eq!(step_result.unwrap(), Step::Done(None));
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
