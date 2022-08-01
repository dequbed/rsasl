//! Interop testing client
//!
//! This client allows testing interoperability between different SASL implementations.

use std::io;
use std::io::Cursor;
use miette::{IntoDiagnostic, WrapErr};
use rsasl::callback::{CallbackError, Context, Request, SessionCallback, SessionData};
use rsasl::prelude::*;
use rsasl::property::*;
use rsasl::validate::{Validate, ValidationError};

struct EnvCallback;
impl SessionCallback for EnvCallback {
    fn callback(&self, _session_data: &SessionData, _context: &Context, request: &mut Request<'_>)
        -> Result<(), SessionError>
    {
        fn var(key: &'static str) -> Result<String, SessionError> {
            std::env::var(key).map_err(|_| CallbackError::NoValue.into())
        }

        if request.is::<AuthId>() {
            let authid = var("RSASL_AUTHID")?;
            request.satisfy::<AuthId>(authid.as_ref())?;

        } else if request.is::<Password>() {
            let password = var("RSASL_PASSWORD")?;
            request.satisfy::<Password>(password.as_bytes())?;

        } else if request.is::<AuthzId>() {
            let authzid = var("RSASL_AUTHZID")?;
            request.satisfy::<AuthzId>(authzid.as_ref())?;

        } else if request.is::<OverrideCBType>() {
            let cbtype = var("RSASL_CBNAME")?;
            request.satisfy::<OverrideCBType>(cbtype.as_str())?;

        } else if request.is::<ChannelBindings>() {
            let cbdata = var("RSASL_CBDATA")?;
            request.satisfy::<ChannelBindings>(cbdata.as_bytes())?;
        }
        Ok(())
    }
}

pub fn main() -> miette::Result<()> {
    let mech = std::env::var("RSASL_MECH")
        .into_diagnostic()
        .wrap_err("The env variable 'RSASL_MECH' must be set to the mechanism to use")?;

    let mechname = Mechname::new(mech.as_bytes())
        .into_diagnostic()
        .wrap_err(format!("The provided RSASL_MECH={} is not a valid mechanism name", mech))?;

    let config = SASLConfig::builder()
        .with_default_mechanisms()
        .with_default_sorting()
        .with_callback(EnvCallback)
        .into_diagnostic()
        .wrap_err("Failed to generate SASL config")?;

    let mut session = SASLClient::new(config)
        .start_suggested(&[mechname])
        .into_diagnostic()
        .wrap_err("Failed to start client session")?;

    let chosen = session.get_mechname();
    // Print the selected mechanism as the first output
    println!("{}", chosen.as_str());

    let mut input = if session.are_we_first() {
        None
    } else {
        // If the server needs to go first, we print an empty line
        println!();
        // Then we wait on the first line sent by the server.
        let mut line = String::new();
        io::stdin().read_line(&mut line)
            .into_diagnostic()
            .wrap_err("failed to read line from stdin")?;
        Some(line)
    };

    while {
        let mut out = Cursor::new(Vec::new());
        let (state, _) = session.step64(input.as_deref().map(|s| s.trim().as_bytes()), &mut out)
               .into_diagnostic()
               .wrap_err("Unexpected error occurred during stepping the session")?;
        let mut output = out.into_inner();

        let output = String::from_utf8(output)
            .expect("base64 encoded output is somehow not valid UTF-8");
        println!("{}", output);

        state.is_running()
    } {
        let mut line = String::new();
        io::stdin().read_line(&mut line)
                   .into_diagnostic()
                   .wrap_err("failed to read line from stdin")?;
        input = Some(line);
    }

    Ok(())
}

