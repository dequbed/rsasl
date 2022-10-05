//! A simple client using SASLConfig::with_credentials
//!
//! This can authenticate a client side with mechanisms that only require an authid, authzid and
//! password. Currently this means 'SCRAM-SHA-2', 'SCRAM-SHA-1', 'PLAIN', and 'LOGIN', preferred
//! in that order.

use rsasl::prelude::*;
use std::io;
use std::io::Cursor;

pub fn main() {
    let mut username = String::new();
    println!("Enter username:");
    if let Err(error) = io::stdin().read_line(&mut username) {
        println!("error: {}", error);
        return;
    }

    println!("\nEnter password:");
    let mut password = String::new();
    if let Err(error) = io::stdin().read_line(&mut password) {
        println!("error: {}", error);
        return;
    }
    println!();

    // Construct a a config from only the credentials.
    // This takes the authzid, authid/username and password that are to be used.
    let config = SASLConfig::with_credentials(None, username, password).unwrap();

    // The config can now be sent to a protocol handling crate and used there. Below we simulate
    // a PLAIN authentication happening with the config:

    let sasl = SASLClient::new(config);

    // There are often more than one Mechanisms offered by the server, `start_suggested` will
    // select the best ones from those available to both sides.
    let offered = [Mechname::parse(b"PLAIN").unwrap()];
    let mut session = sasl.start_suggested(&offered).unwrap();

    // Do the authentication steps.
    let mut out = Cursor::new(Vec::new());
    // PLAIN is client-first, and thus takes no input data on the first step.
    let input: Option<&[u8]> = None;
    // Actually generate the authentication data to send to a server
    let state = session.step(input, &mut out).unwrap();

    match state {
        State::Running => panic!("PLAIN exchange took more than one step"),
        State::Finished(MessageSent::Yes) => {
            let buffer = out.into_inner();
            println!("Encoded bytes: {:?}", buffer);
            println!("As string: {:?}", std::str::from_utf8(buffer.as_ref()));
        }
        State::Finished(MessageSent::No) => {
            panic!("PLAIN exchange produced no output")
        }
    }
}
