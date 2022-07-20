use rsasl::callback::{Context, SessionCallback};
use rsasl::prelude::{ServerConfig, SessionError};
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, AuthzId, Password};
use rsasl::prelude::{SessionData, State};
use rsasl::validate::{Validate, Validation, ValidationError};
use rsasl::prelude::SASLServer;
use std::io::Cursor;
use std::sync::Arc;
use thiserror::Error;

struct OurCallback;
#[derive(Debug, Error)]
enum OurCallbackError {}
impl OurCallback {
    fn test_validate(
        &self,
        _session_data: &SessionData,
        context: &Context,
    ) -> Result<Result<String, AuthError>, OurCallbackError> {
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

        use AuthError::*;
        if !(authzid.is_none() || authzid == Some(authid)) {
            Ok(Err(AuthzBad))
        } else if authid == "username" && password == b"secret" {
            Ok(Ok(String::from(authid)))
        } else if authid == "username" {
            Ok(Err(PasswdBad))
        } else {
            Ok(Err(NoSuchUser))
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
        validate.with::<TestValidation, _, _>(|| self.test_validate(session_data, context))?;
        Ok(())
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
enum AuthError {
    AuthzBad,
    PasswdBad,
    NoSuchUser,
}

struct TestValidation;
impl Validation for TestValidation {
    type Value = Result<String, AuthError>;
}

pub fn main() {
    let config = ServerConfig::builder().with_defaults().with_callback(Box::new(OurCallback), false).unwrap();
    let config = Arc::new(config);

    // Authentication exchange 1
    {
        let sasl = SASLServer::<TestValidation>::new(config.clone());
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with correct password:\n   ");
        let mut session = sasl
            .start_suggested(&[Mechname::new(b"PLAIN").unwrap()])
            .unwrap();
        let step_result = session.step(Some(b"\0username\0secret"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert_eq!(step_result.unwrap(), (State::Finished, None));
        assert_eq!(session.validation(), Some(Ok(String::from("username"))))
    }
    // Authentication exchange 2
    {
        let sasl = SASLServer::<TestValidation>::new(config.clone());
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with wrong password:\n   ");
        let mut session = sasl
            .start_suggested(&[Mechname::new(b"PLAIN").unwrap()])
            .unwrap();
        let step_result = session.step(Some(b"\0username\0badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert_eq!(step_result.unwrap(), (State::Finished, None));
        assert_eq!(session.validation(), Some(Err(AuthError::PasswdBad)));
    }

    {
        let sasl = SASLServer::<TestValidation>::new(config.clone());
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with unknown user:\n   ");
        let mut session = sasl
            .start_suggested(&[Mechname::new(b"PLAIN").unwrap()])
            .unwrap();
        let step_result = session.step(Some(b"\0somebody\0somepass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert_eq!(step_result.unwrap(), (State::Finished, None));
        assert_eq!(session.validation(), Some(Err(AuthError::NoSuchUser)));
    }

    {
        let sasl = SASLServer::<TestValidation>::new(config.clone());
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with bad authzid:\n   ");
        let mut session = sasl
            .start_suggested(&[Mechname::new(b"PLAIN").unwrap()])
            .unwrap();
        let step_result = session.step(Some(b"username\0somebody\0badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert_eq!(step_result.unwrap(), (State::Finished, None));
        assert_eq!(session.validation(), Some(Err(AuthError::AuthzBad)));
    }
    // Authentication exchange 2
    {
        let sasl = SASLServer::<TestValidation>::new(config.clone());
        let mut out = Cursor::new(Vec::new());
        print!("Authenticating to server with malformed data:\n   ");
        let mut session = sasl
            .start_suggested(&[Mechname::new(b"PLAIN").unwrap()])
            .unwrap();
        let step_result = session.step(Some(b"\0username badpass"), &mut out);
        print_outcome(&step_result, out.into_inner());
        assert!(step_result.unwrap_err().is_mechanism_error());
    }
}

fn print_outcome(step_result: &Result<(State, Option<usize>), SessionError>, buffer: Vec<u8>) {
    match step_result {
        Ok((State::Finished, Some(_))) => {
            println!(
                "Authentication finished, bytes to return to client: {:?}",
                buffer
            );
        }
        Ok((State::Finished, None)) => {
            println!("Authentication finished, no data to return");
        }
        Ok((State::Running, _)) => assert!(false, "PLAIN exchange took more than one step"),
        Err(e) => println!("Authentication errored: {}", e),
    }
}
