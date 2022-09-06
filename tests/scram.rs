use rsasl::prelude::{Mechname, SASLConfig};

mod common;

#[test]
#[cfg_attr(miri, ignore)]
fn scram_client() {
    let config = SASLConfig::with_credentials(None, "username".to_string(), "secret".to_string())
        .expect("failed to construct SASL config");
    let outcome_line = common::test_client(Mechname::parse(b"SCRAM-SHA-256").unwrap(), config);
    println!("{}", outcome_line);
    assert!(outcome_line.starts_with("OK"));
}
