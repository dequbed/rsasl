use std::io;
use rsasl::consts::{GSASL_AUTHID, GSASL_PASSWORD};
use rsasl::{SASL, Step::{Done, NeedsMore}};


pub fn main() {
    // Create an untyped SASL because we won't store/retrieve information in the context since
    // we don't use callbacks.
    let mut sasl = SASL::new_untyped().unwrap();

    // Usually you would first agree on a mechanism with the server, for demostration purposes
    // we directly start a PLAIN "exchange"
    let mut session = sasl.client_start("PLAIN").unwrap();

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

    // Set the username that will be used in the PLAIN authentication
    session.set_property(GSASL_AUTHID, username.as_bytes());

    // Now set the password that will be used in the PLAIN authentication
    session.set_property(GSASL_PASSWORD, password.as_bytes());


    // Do an authentication step. In a PLAIN exchange there is only one step, with no data.
    let step_result = session.step(&[]).unwrap();

    match step_result {
        Done(buffer) => {
            println!("Encoded bytes: {:?}", buffer.as_ref());
            println!("As string: {:?}", unsafe { std::str::from_utf8_unchecked(buffer.as_ref()) });
        },
        NeedsMore(_) => assert!(false, "PLAIN exchange took more than one step"),
    }
}
