use std::ffi::CString;
use std::io::Cursor;
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, Password};
use rsasl::SASL;
use rsasl::session::{Step, StepResult};

#[test]
pub fn test_scram_sha() {
    let mut client_sasl = SASL::new();
    let mut server_sasl = SASL::new();

    for i in 0..2 {
        let mut client_starts = i == 0;
        let mut client_session = client_sasl.client_start(Mechname::try_parse(b"SCRAM-SHA-256").unwrap()).unwrap();
        let mut server_session = server_sasl.server_start(Mechname::try_parse(b"SCRAM-SHA-256").unwrap()).unwrap();

        let authid = Box::new("testuser".to_string());
        let password = Box::new("secret".to_string());

        client_session.set_property::<AuthId>(authid.clone());
        client_session.set_property::<Password>(password.clone());
        server_session.set_property::<AuthId>(authid);
        server_session.set_property::<Password>(password);


        if client_starts {
            println!("Running a round client-first");
        } else {
            println!("Running a round server-first");
        }

        let mut step = 0;
        let mut data = None;
        let mut server_done = false;
        let mut client_done = false;

        while !(server_done && client_done) {
            step += 1;

            if client_starts && !client_done {
                let mut out = Cursor::new(Vec::new());
                println!("[CLIENT] >>> Step {} (Has Data: {})", step, data.is_some());
                match client_session.step(data.take(), &mut out).expect("client side step failed") {
                    Step::Done(Some(len)) => {
                        let buffer = out.into_inner();
                        let str = std::str::from_utf8(&buffer).unwrap();
                        client_done = true;
                        // Server needs to receive our data
                        server_done = false;
                        data = Some(str.to_string().into_boxed_str().into_boxed_bytes());
                        println!("Done, send {} bytes back: {}", len, str);
                    }
                    Step::Done(None) => {
                        println!("Done, send nothing back");
                        client_done = true;
                    }
                    Step::NeedsMore(Some(len)) => {
                        let buffer = out.into_inner();
                        let str = std::str::from_utf8(&buffer).unwrap();
                        println!("Needs more data, send {} bytes back: {}", len, str);
                        data = Some(str.to_string().into_boxed_str().into_boxed_bytes());
                    }
                    Step::NeedsMore(None) => {
                        println!("Needs more data, send nothing back");
                    }
                }
            }
            client_starts = true;

            if !server_done {
                let mut out = Cursor::new(Vec::new());
                println!("[SERVER] <<< Step {} (Has Data: {})", step, data.is_some());
                match server_session.step(data.take(), &mut out).expect("server side step failed") {
                    Step::Done(Some(len)) => {
                        let buffer = out.into_inner();
                        let str = std::str::from_utf8(&buffer).unwrap();
                        println!("Done, send {} bytes back: {}", len, str);
                        data = Some(str.to_string().into_boxed_str().into_boxed_bytes());
                        server_done = true;
                        // Client needs to receive our data
                        client_done = false;
                    }
                    Step::Done(None) => {
                        println!("Done, send nothing back");
                        server_done = true;
                    }
                    Step::NeedsMore(Some(len)) => {
                        let buffer = out.into_inner();
                        let str = std::str::from_utf8(&buffer).unwrap();
                        println!("Needs more data, send {} bytes back: {}", len, str);
                        data = Some(str.to_string().into_boxed_str().into_boxed_bytes());
                    }
                    Step::NeedsMore(None) => {
                        println!("Needs more data, send nothing back");
                    }
                }
            }
        }
        println!("\n\n");
    }
}