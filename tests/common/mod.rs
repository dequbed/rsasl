use std::borrow::Cow;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;
use rsasl::prelude::{Mechname, SASLClient, SASLConfig, State};

pub fn test_client(mechanism: &Mechname, config: Arc<SASLConfig>) -> String {
    // Allow configuring a different test server address if required
    let addr = std::env::var("RSASL_TEST_REMOTE")
        .map(|string| Cow::Owned(string))
        .unwrap_or(Cow::Borrowed("localhost:62185"));

    let stream = TcpStream::connect(addr.as_ref())
        .expect(&format!("[addr={}] failed to connect to remote server", addr));
    let mut write_end = stream.try_clone().expect("failed to clone TcpStream");

    let mut lines = BufReader::new(stream).lines();

    // Server is expected to write first a list of mechanisms it supports, space-separated
    let mechs_line = lines.next()
                          .expect("server disconnected unexpectedly!")
                          .expect("Protocol error, server should send an UTF-8 list of mechs first");
    let mut mechs = mechs_line.split_whitespace();
    assert!(mechs.any(|m| m == mechanism), "Server does not support {} authentication!", mechanism);

    let client = SASLClient::new(config);
    let mut session = client.start_suggested(&[mechanism])
                            .expect("failed to start SASL session");

    // Send mechanism name with ASCII SPC appended so initial data will work, other end MUST
    // ignore all trailing whitespace.
    write_end.write_all(mechanism.as_bytes()).expect("failed to send mechanism name");

    let mut buffer = Vec::new();

    // Initialize with running state so we can write the while loop below.
    // Otherwise we have to special case one-step mechanisms such as PLAIN since we send initial
    // data
    let mut state = State::Running;

    // Send the initial request, with initial data if we are going first
    if session.are_we_first() {
        state = session.step64(None, &mut buffer)
                          .expect("failed to step mechanism");
        if state.has_sent_message() {
            let o = std::str::from_utf8(&buffer[..]).unwrap();
            println!("> {}", o);
            write_end.write_all(b" ").expect("failed to write initial line");
            write_end.write_all(&buffer[..]).expect("failed to write initial line");
        }
    }

    write_end.write_all(b"\n").expect("failed to  newline");

    while state.is_running() {
        let step_line = lines.next()
                             .expect("server disconnected unexpectedly")
                             .expect("protocol error, server should send valid UTF-8 lines");
        println!("< {}", &step_line);
        let input = step_line.as_bytes();

        buffer.clear();
        state = session.step64(Some(input), &mut buffer)
                          .expect("failed to step mechanism");

        let buf = if state.has_sent_message() {
            buffer.push(b'\n');
            &buffer[..]
        } else {
            b"-\n"
        };
        let o = std::str::from_utf8(buf).unwrap();
        println!("> {}", o);
        write_end.write_all(buf).expect("failed to write output");
    }

    lines.next()
         .expect("server didn't send outcome line")
         .expect("outcome line isn't valid UTF-8")
}