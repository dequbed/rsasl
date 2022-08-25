use std::borrow::Cow;
use std::io::{BufRead, BufReader, IoSlice, Write};
use std::net::TcpStream;
use rsasl::config::SASLConfig;
use rsasl::prelude::{Mechname, SASLClient, State};

#[test]
fn plain_client() {
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
    assert!(mechs.any(|m| m == "PLAIN"), "Server does not support PLAIN authentication!");

    let config = SASLConfig::with_credentials(None, "testuser".to_string(), "secret".to_string())
        .expect("failed to construct SASL config");
    let client = SASLClient::new(config);
    let mut session = client.start_suggested(&[Mechname::parse(b"PLAIN").unwrap()])
        .expect("failed to start SASL session");

    // Send mechanism name with ASCII SPC appended so initial data will work, other end MUST
    // ignore all trailing whitespace.
    write_end.write_all(b"PLAIN ").expect("failed to send mechanism name");

    let mut buffer = Vec::new();

    // Initialize with running state so we can write the while loop below.
    // Otherwise we have to special case one-step mechanisms such as PLAIN since we send initial
    // data
    let mut state = State::Running;
    let mut written = Some(b"PLAIN ".len());

    // Send the initial request, with initial data if we are going first
    if session.are_we_first() {
        let step = session.step64(None, &mut buffer)
            .expect("failed to step mechanism");
        state = step.0;
        written = step.1;
    }

    write_end.write_all(&buffer[..]).expect("failed to write initial line");
    write_end.write_all(b"\n").expect("failed to  newline");

    while state.is_running() {
        let step_line = lines.next()
            .expect("server disconnected unexpectedly")
            .expect("protocol error, server should send valid UTF-8 lines");
        let input = step_line.as_bytes();

        buffer.clear();
        let step = session.step64(Some(input), &mut buffer)
            .expect("failed to step mechanism");
        state = step.0;
        written = step.1;

        if let Some(len) = written {
            assert!(buffer.len() >= len, "mechanism returned too large `written`!");

            let buf = if len == 0 {
                b"-\n"
            } else {
                // Add an ASCII newline at the end to make this a line-delimited protocol
                buffer.truncate(len);
                buffer.push(b'\n');

                // Since we truncated the buffer, this will only output exactly the part indicated by
                // `written`
                &buffer[..]
            };

            // Write the mechanism output with appended newline to the other party
            write_end.write_all(buf).expect("failed to write output");
        } else {
            assert!(state.is_finished(), "state is running but a step did not send any output?");
        }
    }

    let outcome_line = lines.next()
        .expect("server didn't send outcome line")
        .expect("outcome line isn't valid UTF-8");
    println!("{}", outcome_line);
    assert!(outcome_line.starts_with("OK"));
}

#[test]
fn plain_server() {}

/*
#[test]
fn plain_client_edgecase_tests() {
    let sasl = SASL::new();
    fn l(
        sasl: &SASL,
        authid: Arc<String>,
        authzid: Option<Arc<String>>,
        passwd: Arc<String>,
        expected: &StepResult,
        expected_output: &[u8],
    ) {
        let mut client = sasl.client_start(Mechname::new(b"PLAIN").unwrap()).unwrap();
        client.set_property::<AuthId>(authid);
        if let Some(authzid) = authzid {
            client.set_property::<AuthzId>(authzid);
        }
        client.set_property::<Password>(passwd);
        let mut out = Cursor::new(Vec::new());
        let input: Option<&[u8]> = None;
        assert_eq!(client.step(input, &mut out), *expected);
        let buf = out.into_inner();
        assert_eq!(&buf[..], expected_output);
    }

    let data: &[(&str, Option<&str>, &str, StepResult, &[u8])] = &[
        ("", None, "", Ok(Done(Some(2))), b"\0\0"),
        ("\0", None, "\0\0", Ok(Done(Some(5))), b"\0\0\0\0\0"),
    ];

    for (authid, authzid, passwd, expected, output) in data.into_iter() {
        l(
            &sasl,
            Arc::new(authid.to_string()),
            authzid.map(|s: &str| Arc::new(s.to_string())),
            Arc::new(passwd.to_string()),
            expected,
            *output,
        );
    }
}
*/
