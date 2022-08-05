use crate::prelude::Property;
use crate::property::SizedProperty;

#[derive(Debug)]
pub struct XOAuth2Error;
impl Property<'_> for XOAuth2Error {
    type Value = str;
}

#[derive(Debug)]
/// Accept an user and token or set an error response
///
/// If set to `Ok(())` a successful authentication will be indicated, if set to an error string
/// this string will be sent verbatim as error indication. This string is required to be a
/// plaintext json-encoded object, the fields of which are listed in the
/// [protocol description](https://developers.google.com/gmail/imap/xoauth2-protocol#error_response).
///
/// **The `base64` encoding will be handled by rsasl, the error str thus MUST NOT be encoded**
pub struct XOAuth2Validate;
impl<'a> SizedProperty<'a> for XOAuth2Validate {
    type Value = Result<(), &'a str>;
}