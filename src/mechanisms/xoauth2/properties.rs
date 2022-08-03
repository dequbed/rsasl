use crate::prelude::Property;

pub struct XOAuth2Error;
impl Property<'_> for XOAuth2Error {
    type Value = str;
}