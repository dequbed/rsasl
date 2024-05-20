use rsasl::prelude::{Mechname, SASLConfig};

mod common;

#[test]
#[cfg_attr(miri, ignore)]
fn login_client() {
    let config = SASLConfig::with_credentials(None, "testuser".to_string(), "secret".to_string())
        .expect("failed to construct SASL config");
    let outcome_line = common::test_client(Mechname::parse(b"LOGIN").unwrap(), config);
    println!("{}", outcome_line);
    assert!(outcome_line.starts_with("OK"));
}
