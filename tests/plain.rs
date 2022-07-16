#[test]
fn plain_client() {}

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
