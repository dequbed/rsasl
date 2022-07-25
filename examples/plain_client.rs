use rsasl::prelude::*;

use std::io;
use std::io::Cursor;
use std::sync::Arc;

pub fn main() {
    // Read the "authcid" from stdin
    let mut username = String::new();
    println!("Enter username to encode for PLAIN auth:");
    if let Err(error) = io::stdin().read_line(&mut username) {
        println!("error: {}", error);
        return;
    }

    // Read the "password" from stdin
    println!("\nEnter password to encode for PLAIN auth:");
    let mut password = String::new();
    if let Err(error) = io::stdin().read_line(&mut password) {
        println!("error: {}", error);
        return;
    }
    print!("\n");
    let config = ClientConfig::with_credentials(None, username, password).unwrap();

    // Create an untyped SASL because we won't store/retrieve information in the context since
    // we don't use callbacks.
    let sasl = SASLClient::new(Arc::new(config));

    let offered = [Mechname::new(b"PLAIN").unwrap()];
    // Usually you would first agree on a mechanism with the server, for demostration purposes
    // we directly start a PLAIN "exchange"
    let mut session = sasl.start_suggested(&offered).unwrap();

    // Do an authentication step. In a PLAIN exchange there is only one step, with no data.
    let mut out = Cursor::new(Vec::new());
    let data: Option<&[u8]> = None;
    let (state, written) = session.step(data, &mut out).unwrap();

    match state {
        State::Running => panic!("PLAIN exchange took more than one step"),
        State::Finished => {
            if written.is_some() {
                let buffer = out.into_inner();
                println!("Encoded bytes: {:?}", buffer);
                println!("As string: {:?}", std::str::from_utf8(&buffer.as_ref()));
            } else {
                panic!("PLAIN exchange produced no output")
            }
        }
    }
}
