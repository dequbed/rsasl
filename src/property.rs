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
impl MaybeSizedProperty for OpenID20AuthenticateInBrowser {
    type Value = str;
}

#[derive(Debug)]
pub struct Saml20AuthenticateInBrowser;
impl MaybeSizedProperty for Saml20AuthenticateInBrowser {
    type Value = str;
}

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
/// A plain text password
///
/// Additional constraints may be put on this property by some mechanisms, refer to their
/// documentation for further details.
pub struct Password;
impl MaybeSizedProperty for Password {
    type Value = [u8];
}

#[derive(Debug)]
/// Provide channel binding data
///
/// Channel binding data can be used by some mechanisms to cryptographically bind the
/// authentication to the encrypted transport layer (e.g. TLS or IPsec), usually indicated by the
/// mechanism name ending in `-PLUS`. Since this channel binding data may be only be available to
/// the protocol crate it will be requested from both the protocol crate and the user callback.
pub struct ChannelBindings;
impl MaybeSizedProperty for ChannelBindings {
    type Value = [u8];
}

#[derive(Debug)]
/// Override the type of channel bindings to be used.
///
/// Some mechanisms such as the `SCRAM-` family define that specific channel binding types are to
/// be used (e.g. `tls-unique` for `SCRAM-SHA-1`). If it is known that a different channel
/// binding type is to be used (e.g. because TLS-1.3 is in use that does not allow for
/// `tls-unique`) a user callback should satisfy a request for this property with the name of
/// alternative channel binding. The actual channel binding data will be requested using the
/// [`ChannelBindings`] property from both the protocol crate and the user callback.
///
/// Refer to the documentation of the [`ChannelBindings`] property for further information.
pub struct OverrideCBType;
impl MaybeSizedProperty for OverrideCBType {
    type Value = str;
}
