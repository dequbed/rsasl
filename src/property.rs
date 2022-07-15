//! # Defining Properties
//!
//! If the existing properties in this module are not sufficient for your mechanism, you can
//! define additional properties to be queried.

pub trait Property: 'static {
    type Value: 'static;
}

pub trait MaybeSizedProperty: 'static {
    type Value: ?Sized + 'static;
}
impl<P: Property> MaybeSizedProperty for P {
    type Value = P::Value;
}

#[derive(Debug)]
pub struct AuthId;
impl MaybeSizedProperty for AuthId {
    type Value = str;
}

#[derive(Debug)]
pub struct AuthzId;
impl MaybeSizedProperty for AuthzId {
    type Value = str;
}

#[derive(Debug)]
pub struct OpenID20AuthenticateInBrowser;

#[derive(Debug)]
pub struct Saml20AuthenticateInBrowser;

#[derive(Debug)]
pub struct OpenID20OutcomeData;

#[derive(Debug)]
pub struct OpenID20RedirectUrl;

#[derive(Debug)]
pub struct SAML20RedirectUrl;

#[derive(Debug)]
pub struct SAML20IDPIdentifier;

#[derive(Debug)]
pub struct Qop;

#[derive(Debug)]
pub struct Qops;

#[derive(Debug)]
pub struct DigestMD5HashedPassword;

#[derive(Debug)]
pub struct Realm;
impl MaybeSizedProperty for Realm {
    type Value = str;
}

#[derive(Debug)]
pub struct Pin;

#[derive(Debug)]
pub struct SuggestedPin;

#[derive(Debug)]
pub struct Passcode;

#[derive(Debug)]
pub struct GssapiDisplayName;

#[derive(Debug)]
pub struct Hostname;
impl MaybeSizedProperty for Hostname {
    type Value = str;
}

#[derive(Debug)]
pub struct Service;
impl MaybeSizedProperty for Service {
    type Value = str;
}

#[derive(Debug)]
pub struct Password;
impl MaybeSizedProperty for Password {
    type Value = [u8];
}
