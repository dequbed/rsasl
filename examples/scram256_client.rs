use rsasl::mechanisms::scram::client::ScramClient;
use rsasl::mechname::Mechname;
use rsasl::property::{AuthId, Password};
use rsasl::registry::Mechanism;
use rsasl::session::Side;
use rsasl::SASL;

use std::io;
use std::io::Cursor;
use std::sync::Arc;
use rsasl::callback::EmptyCallback;
use rsasl::validate::NoValidation;

pub fn main() {

}
