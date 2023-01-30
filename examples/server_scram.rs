use digest::generic_array::GenericArray;
use digest::{Digest, Output};
use rsasl::callback::{Context, Request, SessionCallback, SessionData};
use rsasl::mechanisms::scram;
use rsasl::mechanisms::scram::properties::ScramStoredPassword;
use rsasl::mechname::Mechname;
use rsasl::prelude::{SASLClient, SASLServer};
use rsasl::prelude::{SASLConfig, SessionError};
use rsasl::property::{AuthId, AuthzId};
use rsasl::validate::{Validate, Validation, ValidationError};
use sha2::Sha256;
use std::io::Cursor;
use thiserror::Error;

// The callback used by our server.
struct OurCallback {
    // This could also store shared data, e.g. a DB-handle to look up users.
    // It's passed as &self in callbacks.
    stored_key: Output<Sha256>,
    server_key: Output<Sha256>,
    salt: &'static [u8],
}

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
            .expect("SCRAM should always set AuthId");

        println!("Validation for (authzid: {authzid:?}, authid: {authid})");

        use AuthError::*;
        if !(authzid.is_none() || authzid == Some(authid)) {
            Ok(Err(AuthzBad))
        } else if authid == "username" {
            Ok(Ok(String::from(authid)))
        } else {
            Ok(Err(NoSuchUser))
        }
    }
}

// Our validation type later used to exfiltrate data from the callback
struct TestValidation;

impl Validation for TestValidation {
    type Value = Result<String, AuthError>;
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
enum AuthError {
    AuthzBad,
    NoSuchUser,
}

impl SessionCallback for OurCallback {
    fn callback(
        &self,
        _session_data: &SessionData,
        context: &Context,
        request: &mut Request,
    ) -> Result<(), SessionError> {
        if let Some("username") = context.get_ref::<AuthId>() {
            request.satisfy::<ScramStoredPassword>(&ScramStoredPassword::new(
                4096,
                self.salt,
                self.stored_key.as_slice(),
                self.server_key.as_slice(),
            ))?;
        }
        Ok(())
    }

    fn validate(
        &self,
        session_data: &SessionData,
        context: &Context,
        validate: &mut Validate<'_>,
    ) -> Result<(), ValidationError> {
        if session_data.mechanism().mechanism.starts_with("SCRAM-") {
            // We defined a type 'TestValidation' that we fulfill here. It expects us to return an
            // `Result<String, AuthError>`.
            validate.with::<TestValidation, _>(|| {
                self.test_validate(session_data, context)
                    .map_err(|e| ValidationError::Boxed(Box::new(e)))
            })?;
        }
        Ok(())
    }
}

pub fn main() {
    /*
     * As a showcase, we hash & salt the password on startup. You should of course do this at
     * registration time instead.
     */
    let plain_password = b"secret";
    let salt = b"bad salt";
    let mut salted_password = GenericArray::default();
    // Derive the PBKDF2 key from the password and salt. This is the expensive part
    scram::tools::hash_password::<Sha256>(plain_password, 4096, &salt[..], &mut salted_password);
    let (client_key, server_key) = scram::tools::derive_keys::<Sha256>(salted_password.as_slice());
    let stored_key = Sha256::digest(client_key);

    let config = SASLConfig::builder()
        .with_defaults()
        .with_callback(OurCallback {
            salt,
            server_key,
            stored_key,
        })
        .unwrap();
    let server = SASLServer::<TestValidation>::new(config);

    let mechname = Mechname::parse(b"SCRAM-SHA-256").unwrap();

    let mut server_session = server
        .start_suggested(mechname)
        .expect("Failed to start SASL server session");

    /* ==============================
     * Change the below authid/password to change the authentication outcome
     * ============================== */
    let client = SASLClient::new(
        SASLConfig::with_credentials(None, "username".to_string(), "secret".to_string()).unwrap(),
    );

    let mut client_session = client
        .start_suggested(&[mechname])
        .expect("Failed to start SASL client session");

    let mut client_out = Cursor::new(Vec::new());
    client_session
        .step(None, &mut client_out)
        .expect("SCRAM step failed");

    while {
        let mut server_out = Cursor::new(Vec::new());
        let state = server_session
            .step(Some(client_out.get_ref().as_slice()), &mut server_out)
            .expect("Unexpected error occurred during stepping the session");

        client_out = Cursor::new(Vec::new());
        client_session
            .step(Some(server_out.get_ref().as_slice()), &mut client_out)
            .expect("SCRAM step failed");

        state.is_running()
    } {}
    let v = server_session.validation();
    println!("Validation: {v:?}");
}
