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

pub trait SizedProperty<'a>: 'static {
    /// The Value being transferred by this Property
    type Value: 'a;

    /// A description of this property, shown in several Display implementations
    const DESCRIPTION: &'static str = "";
}

pub trait Property<'a>: 'static {
    /// The Value being transferred by this Property
    type Value: ?Sized + 'a;

    /// A description of this property, shown in several Display implementations
    const DESCRIPTION: &'static str = "";
}

impl<'a, P: SizedProperty<'a>> Property<'a> for P {
    type Value = P::Value;
    const DESCRIPTION: &'static str = P::DESCRIPTION;
}

pub use properties::*;
mod properties {
    use super::Property;

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
    #[non_exhaustive]
    pub struct AuthId;
    impl Property<'_> for AuthId {
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
    #[non_exhaustive]
    pub struct AuthzId;
    impl Property<'_> for AuthzId {
        type Value = str;
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct OpenID20AuthenticateInBrowser;
    impl Property<'_> for OpenID20AuthenticateInBrowser {
        type Value = str;
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Saml20AuthenticateInBrowser;
    impl Property<'_> for Saml20AuthenticateInBrowser {
        type Value = str;
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct OpenID20OutcomeData;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct OpenID20RedirectUrl;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct SAML20RedirectUrl;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct SAML20IDPIdentifier;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Qop;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Qops;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct DigestMD5HashedPassword;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Realm;
    impl Property<'_> for Realm {
        type Value = str;
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Pin;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct SuggestedPin;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Passcode;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct GssapiDisplayName;

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Hostname;
    impl Property<'_> for Hostname {
        type Value = str;
    }

    #[derive(Debug)]
    #[non_exhaustive]
    pub struct Service;
    impl Property<'_> for Service {
        type Value = str;
    }

    #[derive(Debug)]
    /// A plain text password
    ///
    /// Additional constraints may be put on this property by some mechanisms, refer to their
    /// documentation for further details.
    #[non_exhaustive]
    pub struct Password;
    impl Property<'_> for Password {
        type Value = [u8];
    }

    #[derive(Debug)]
    /// An OAuth 2.0 Bearer token
    ///
    /// The token is required to be [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) format.
    #[non_exhaustive]
    pub struct OAuthBearerToken;
    impl Property<'_> for OAuthBearerToken {
        type Value = str;
    }

    #[derive(Debug)]
    /// Provide channel binding data
    ///
    /// Channel binding data can be used by some mechanisms to cryptographically bind the
    /// authentication to the encrypted transport layer (e.g. TLS or IPsec), usually indicated by the
    /// mechanism name ending in `-PLUS`. Since this channel binding data may be only be available to
    /// the protocol crate it will be requested from both the protocol crate and the user callback.
    #[non_exhaustive]
    pub struct ChannelBindings;
    impl Property<'_> for ChannelBindings {
        type Value = [u8];
    }

    #[derive(Debug)]
    /// Name of the channel bindings used
    #[non_exhaustive]
    pub struct ChannelBindingName;
    impl Property<'_> for ChannelBindingName {
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
    #[non_exhaustive]
    pub struct OverrideCBType;
    impl Property<'_> for OverrideCBType {
        type Value = str;
    }
}
