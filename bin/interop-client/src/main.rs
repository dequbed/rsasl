//! Interop testing client
//!
//! This client allows testing interoperability between different SASL implementations.

use clap::builder::TypedValueParser;
use clap::{Arg, Command, Error, ErrorKind};
use miette::{miette, IntoDiagnostic, WrapErr};
use rsasl::callback::{CallbackError, Context, Request, SessionCallback, SessionData};
use rsasl::mechanisms::gssapi::properties::GssService;
use rsasl::mechanisms::scram::properties::{Iterations, Salt, ScramCachedPassword};
use rsasl::prelude::*;
use rsasl::property::*;
use std::ffi::OsStr;
use std::io;
use std::io::{Cursor, Write};
use std::net::TcpStream;
use url::Host;

struct EnvCallback;
impl SessionCallback for EnvCallback {
    fn callback(
        &self,
        _session_data: &SessionData,
        context: &Context,
        request: &mut Request<'_>,
    ) -> Result<(), SessionError> {
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
        } else if request.is::<ScramCachedPassword>() {
            if let Some(ScramCachedPassword {
                client_key,
                server_key,
                ..
            }) = request.get_action::<ScramCachedPassword>()
            {
                let salt = context.get_ref::<Salt>().unwrap();
                let iterations = context.get_ref::<Iterations>().unwrap();
                println!("callback action to cache scram keys");
                println!(
                    "salt={} iterations={} client_key={} server_key={}",
                    hex::encode(salt),
                    iterations,
                    hex::encode(client_key),
                    hex::encode(server_key)
                );
            }
        } else if request.is::<GssService>() {
            let service = var("RSASL_SERVICE")?;
            request.satisfy::<GssService>(&service)?;
        } else if request.is::<Hostname>() {
            let hostname = var("RSASL_HOST")?;
            request.satisfy::<Hostname>(&hostname)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum Either<A, B> {
    Left(A),
    Right(B),
}

#[derive(Debug, Copy, Clone)]
pub struct UrlStdin;

#[derive(Debug, Clone, Eq, PartialEq)]
struct UrlParser;
impl TypedValueParser for UrlParser {
    type Value = Either<url::Url, UrlStdin>;
    fn parse_ref(
        &self,
        _cmd: &Command,
        _arg: Option<&Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, Error> {
        if let Some(value) = value.to_str() {
            if value == "-" {
                return Ok(Either::Right(UrlStdin));
            }
            let url = url::Url::parse(value)
                .map_err(|error| Error::raw(ErrorKind::InvalidValue, error))?;
            match url.scheme() {
                "tls" | "tcp" => Ok(Either::Left(url)),
                x => Err(Error::raw(
                    ErrorKind::InvalidValue,
                    format!(
                        "Listen URL scheme {} is unknown, only 'tls' and 'tcp' are possible.",
                        x,
                    ),
                )),
            }
        } else {
            Err(Error::raw(
                ErrorKind::InvalidUtf8,
                "URL arguments must be valid UTF-8",
            ))
        }
    }
}

fn connect<S: AsRef<str>>(
    host: url::Host<S>,
    port: u16,
) -> miette::Result<(Box<dyn io::BufRead>, Box<dyn io::Write>)> {
    let stream = match host {
        Host::Ipv4(ip) => TcpStream::connect((ip, port)),
        Host::Ipv6(ip) => TcpStream::connect((ip, port)),
        Host::Domain(ref domain) => TcpStream::connect((domain.as_ref(), port)),
    }
    .into_diagnostic()
    .wrap_err(format!("failed to connect to {}:{}", host, port))?;

    let write_end = stream
        .try_clone()
        .into_diagnostic()
        .wrap_err("Failed to clone stream")?;
    Ok((Box::new(io::BufReader::new(stream)), Box::new(write_end)))
}

pub fn main() -> miette::Result<()> {
    let matches = Command::new("interop-client")
        .arg(
            Arg::new("listen")
                .long("listen")
                .short('l')
                .takes_value(true)
                .value_parser(UrlParser)
                .help(
                    "address to listen to. Either '-' for STDIN or an url with scheme tcp or tls",
                ),
        )
        .get_matches();

    let mech = std::env::var("RSASL_MECH")
        .into_diagnostic()
        .wrap_err("The env variable 'RSASL_MECH' must be set to the mechanism to use")?;

    let mechname = Mechname::parse(mech.as_bytes())
        .into_diagnostic()
        .wrap_err(format!(
            "The provided RSASL_MECH={} is not a valid mechanism name",
            mech
        ))?;

    let config = SASLConfig::builder()
        .with_default_mechanisms()
        .with_callback(EnvCallback)
        .into_diagnostic()
        .wrap_err("Failed to generate SASL config")?;

    let mut session = SASLClient::new(config)
        .start_suggested(&[mechname])
        .into_diagnostic()
        .wrap_err("Failed to start client session")?;

    let (mut rx, mut tx): (Box<dyn io::BufRead>, Box<dyn io::Write>) =
        match matches.get_one::<Either<url::Url, UrlStdin>>("listen") {
            Some(Either::Left(url)) => {
                let host = url
                    .host()
                    .ok_or_else(|| miette!("URL must have a host part"))?;
                let port = url.port().unwrap_or(62185);

                connect(host, port)?
            }
            Some(Either::Right(UrlStdin)) => {
                let stdin = io::stdin().lock();
                let stdout = io::stdout().lock();
                (Box::new(stdin), Box::new(stdout))
            }
            None => connect(Host::Domain("127.0.0.1"), 62185)?,
        };

    let chosen = session.get_mechname();
    // Print the selected mechanism as the first output
    println!("{}", chosen.as_str());
    tx.write_all(chosen.as_bytes())
        .into_diagnostic()
        .wrap_err("failed to write to stream")?;
    tx.write_all(b"\n")
        .into_diagnostic()
        .wrap_err("failed to write to stream")?;

    let mut input = if session.are_we_first() {
        None
    } else {
        // If the server needs to go first, we print an empty line
        println!();
        // Then we wait on the first line sent by the server.
        let mut line = String::new();
        rx.read_line(&mut line)
            .into_diagnostic()
            .wrap_err("failed to read line from stdin")?;
        Some(line)
    };

    while {
        let mut out = Cursor::new(Vec::new());
        let state = session
            .step64(input.as_deref().map(|s| s.trim().as_bytes()), &mut out)
            .into_diagnostic()
            .wrap_err("Unexpected error occurred during stepping the session")?;
        let output = out.into_inner();

        let output =
            String::from_utf8(output).expect("base64 encoded output is somehow not valid UTF-8");
        println!("{}", output);

        state.is_running()
    } {
        let mut line = String::new();
        rx.read_line(&mut line)
            .into_diagnostic()
            .wrap_err("failed to read line from stdin")?;
        input = Some(line);
    }

    Ok(())
}
