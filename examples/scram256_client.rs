use std::io;
use std::ffi::CString;

use rsasl::{SASL, Property, Step::{Done, NeedsMore}};


// A SCRAM-SHA-1 authentication exchange.
//
// Run both this and the `scram_server` example to pass data to and fro

pub fn main() {
    // Create an untyped SASL because we won't store/retrieve information in the context since
    // we don't use callbacks.
    let mut sasl = SASL::new_untyped().unwrap();

    // Usually you would first agree on a mechanism with the server, for demostration purposes
    // we directly start a SCRAM-SHA-1 "exchange"
    let mut session = sasl.client_start("SCRAM-SHA-256").unwrap();

    // Read the "authcid" from stdin
    let mut username = String::new();
    println!("Enter username to encode for SCRAM-SHA-1 auth:");
    if let Err(error) = io::stdin().read_line(&mut username) {
        println!("error: {}", error);
        return;
    }
    username.pop(); // Remove the newline char at the end of the string


    // Read the "password" from stdin
    println!("\nEnter password to encode for SCRAM-SHA-1 auth:");
    let mut password = String::new();
    if let Err(error) = io::stdin().read_line(&mut password) {
        println!("error: {}", error);
        return;
    }
    password.pop(); // Remove the newline char at the end of the string
    print!("\n");

    // Set the username that will be used in the SCRAM-SHA-1 authentication
    session.set_property(Property::GSASL_AUTHID, CString::new(username).unwrap().as_bytes_with_nul());

    // Now set the password that will be used in the SCRAM-SHA-1 authentication
    session.set_property(Property::GSASL_PASSWORD, CString::new(password).unwrap().as_bytes_with_nul());


    let mut data = CString::new("").unwrap();

    loop {
        // Do an authentication step. In a SCRAM-SHA-1 exchange there is only one step, with no data.
        let step_result = session.step64(&data);

        match step_result {
            Ok(Done(buffer)) => {
                println!("Done: {:?}", buffer.as_ref());
                break;
            },
            Ok(NeedsMore(buffer)) => {
                println!("Data to send: {:?}", buffer.as_ref());

                let mut in_data = String::new();
                if let Err(error) = io::stdin().read_line(&mut in_data) {
                    println!("error: {}", error);
                    return;
                }
                in_data.pop(); // Remove the newline char at the end of the string

                data = CString::new(in_data.as_bytes()).unwrap();

            }
            Err(e) => println!("{}", e),
        }
    }
}
