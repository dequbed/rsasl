use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, Password};
use rsasl::SASL;

use std::io::Cursor;
use std::sync::Arc;
use rsasl::callback::EmptyCallback;

#[test]
pub fn test_scram_sha() {
}
