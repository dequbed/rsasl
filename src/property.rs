//! # Type-safe queryable values
//!
//! Properties are used by mechanisms to retrieve data from user callbacks using
//! [`Request`](crate::callback::Request)s.
//!
//! A `Property` defines an associated data type [`Value`](Property::Value) that is requested by
//! or stored in a `Request` for the given `Property`.
//!
//! As an example, [`AuthId`] has `Value = str`. Thus a
//! [`Request::satisfy`](crate::callback::Request::satisfy) will require a `&str` to be sent as
//! `answer`. [`Password`] has `Value = [u8]`. Thus `satisfy` would in that case require a
//! `&[u8]` instead.

pub trait SizedProperty: 'static {
    type Value: 'static;
}

pub trait Property: 'static {
    type Value: ?Sized + 'static;
}

impl<P: SizedProperty> Property for P {
    type Value = P::Value;
}

#[derive(Debug)]
/// The username to authenticate with
///
/// SASL makes a distinction between this type and [`AuthzId`]. The `AuthId` generally represents
/// the name of the user to whom the password or other authentication data belongs to, while the
/// [`AuthzId`] is the user to authentication *as*.
///
/// E.g. in an authentication with `AuthId`="Bob", `AuthzId`="Alice", and `Password`="secret" a
/// server would first verify if "secret" is Bobs password. If so, it would then create a session
/// as if *Alice* has logged in with her password, letting Bob act on her behalf. (Given of
/// course that Bob has the required permission to do so)
pub struct AuthId;
impl Property for AuthId {
    type Value = str;
}

#[derive(Debug)]
/// The name of the entity to act as
///
/// SASL makes a distinction between [`AuthId`] and this type. The `AuthzId` generally represents
/// the name of the user that is used for auth**orization**. In other words, the user to act as.
///
/// E.g. in an authentication with `AuthId`="Bob", `AuthzId`="Alice", and `Password`="secret" a
/// server would first verify if "secret" is Bobs password. If so, it would then create a session
/// as if *Alice* has logged in with her password, letting Bob act on her behalf. (Given of
/// course that Bob has the required permission to do so)
pub struct AuthzId;
impl Property for AuthzId {
    type Value = str;
}

#[derive(Debug)]
pub struct OpenID20AuthenticateInBrowser;
impl Property for OpenID20AuthenticateInBrowser {
    type Value = str;
}

#[derive(Debug)]
pub struct Saml20AuthenticateInBrowser;
impl Property for Saml20AuthenticateInBrowser {
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
impl Property for Realm {
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
impl Property for Hostname {
    type Value = str;
}

#[derive(Debug)]
pub struct Service;
impl Property for Service {
    type Value = str;
}

#[derive(Debug)]
/// A plain text password
///
/// Additional constraints may be put on this property by some mechanisms, refer to their
/// documentation for further details.
pub struct Password;
impl Property for Password {
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
impl Property for ChannelBindings {
    type Value = [u8];
}

#[derive(Debug)]
/// Name of the channel bindings used
pub struct ChannelBindingName;
impl Property for ChannelBindingName {
    type Value = str;
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
impl Property for OverrideCBType {
    type Value = str;
}
