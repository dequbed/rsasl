use std::io;
use std::ffi::CString;
use std::io::Cursor;
use std::sync::Arc;
use rsasl::mechanisms::scram::client::ScramClient;
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, Password};
use rsasl::registry::Mechanism;
use rsasl::SASL;
use rsasl::session::Side;
use rsasl::session::Step::{Done, NeedsMore};

pub fn main() {
    let mut sasl = SASL::new();
    const M: Mechanism = Mechanism {
        mechanism: Mechname::const_new_unchecked(b"SCRAM"),
        priority: 0,
        client: Some(|_sasl| Ok(Box::new(ScramClient::<18>::new()))),
        server: None,
        first: Side::Client
    };
    sasl.register(&M);

    // Usually you would first agree on a mechanism with the server, for demostration purposes
    // we directly start a SCRAM-SHA-256 "exchange"
    let mut session = sasl.client_start(Mechname::new(b"SCRAM").unwrap()).unwrap();

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
    session.set_property::<AuthId>(Arc::new(username));

    // Now set the password that will be used in the SCRAM-SHA-1 authentication
    session.set_property::<Password>(Arc::new(password));


    let mut data: Option<Box<[u8]>> = None;

    loop {
        let mut out = Cursor::new(Vec::new());
        // Do an authentication step. In a SCRAM-SHA-1 exchange there is only one step, with no data.
        let step_result = session.step(data.as_ref(), &mut out);

        match step_result {
            Ok(Done(Some(_))) => {
                let buffer = out.into_inner();
                let output = std::str::from_utf8(buffer.as_ref()).unwrap();
                println!("Done: {:?}", output);
                break;
            },
            Ok(Done(None)) => {
                println!("Done, but the mechanism wants to send no further data to the other party");
                break;
            }
            Ok(NeedsMore(Some(_))) => {
                let buffer = out.into_inner();
                let output = std::str::from_utf8(buffer.as_ref()).unwrap();
                println!("Data to send: {:?}", output);

                let mut in_data = String::new();
                if let Err(error) = io::stdin().read_line(&mut in_data) {
                    println!("error: {}", error);
                    return;
                }
                in_data.pop(); // Remove the newline char at the end of the string

                data = Some(in_data.into_boxed_str().into_boxed_bytes());

            }
            Ok(NeedsMore(None)) => {
                println!("Need more data, the mechanism can not provide any data to the other party at the moment");
                break;
            }
            Err(e) => {
                println!("{}", e);
                break;
            },
        }
    }
}
