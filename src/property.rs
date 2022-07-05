//! # Defining Properties
//!
//! If the existing properties in this module are not sufficient for your mechanism, you can
//! define additional properties to be queried.
//! This consists of two parts:
//! 1. A type indicating your property
//! 2. A `const Property` that is used to query this property
//!
//! **Note: To enable custom mechanisms you have to enable the feature `unstable_custom_mechanism`**
//! ```ignore
//! #use std::marker::PhantomData;
//! use rsasl::property::{Property, PropertyQ, PropertyDefinition};
//! // All Property types must implement Debug.
//! #[derive(Debug)]
//! // The `PhantomData` in the constructor is only used so external crates can't construct this type.
//! pub struct MyCoolNewProperty(PhantomData<()>);
//! impl PropertyQ for MyCoolNewProperty {
//!     // This is the type stored for this property. This could also be the struct itself if you
//!     // so choose
//!     type Item = usize;
//!     // You need to return the constant you define below here for things to work properly
//!     fn property() -> Property {
//!         MYCOOLPROPERTY
//!     }
//! }
//! // This const is used by your mechanism to query and by your users to set your property. It
//! // thus needs to be exported from your crate
//! pub const MYCOOLPROPERTY: Property = Property::new(&PropertyDefinition::new(
//!     // Short name, used in `Debug` output
//!     "mycoolnewproperty",
//!     // A longer user-facing name used in `Display` output
//!     "a cool property you should definitely set!"
//! ));
//! ```
use std::any::{Any, TypeId};
use std::ffi::CString;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::marker::PhantomData;

mod construct {
    #[derive(Debug)]
    pub struct PropertyDefinition {
        pub name: &'static str,
        pub display: &'static str,
    }
    impl PropertyDefinition {
        pub const fn new(name: &'static str, display: &'static str) -> Self {
            Self { name, display }
        }
    }
}
#[cfg(feature = "unstable_custom_mechanism")]
pub use construct::*;
#[cfg(not(feature = "unstable_custom_mechanism"))]
use construct::*;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
/// Defined by mechanism crates as they see fit, need to provide a `const` one too
pub struct Property {
    name: &'static str,
    display: &'static str,
}
impl Debug for Property {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Property")
            .field("name", &self.name)
            .field("description", &self.display)
            .finish()
    }
}
impl Display for Property {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display)
    }
}
impl Property {
    pub const fn new(definition: &'static PropertyDefinition) -> Self {
        Self {
            name: definition.name,
            display: definition.display,
        }
    }
    pub const fn name(&self) -> &'static str {
        self.name
    }
}


/// Property Query marker
///
/// This trait is used to associate a type to this property so that [`get_property`] and
/// [`set_property`] can properly downcast to this type
pub trait PropertyQ: 'static + Debug {
    type Item: 'static + Send + Sync;
    fn property() -> Property;
    fn type_id() -> TypeId where Self: Any {
        TypeId::of::<Self>()
    }
}

/// (Trait) Object safe version of [`PropertyQ`]
pub trait CallbackQ {
    fn type_id(&self) -> TypeId;
    fn property(&self) -> Property;
    fn as_any(&self) -> &dyn Any;
}
impl<T: Any + PropertyQ> CallbackQ for T {
    fn type_id(&self) -> TypeId {
        <T as PropertyQ>::type_id()
    }
    fn property(&self) -> Property {
        <T as PropertyQ>::property()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub trait CallbackA: Any + Clone {
    fn as_any(&self) -> &dyn Any;
}
impl<T: Any + Clone> CallbackA for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct AnonymousToken;
impl<'a> tags::Type<'a> for AnonymousToken {
    type Reified = &'a str;
}


#[derive(Debug)]
pub struct AuthId(PhantomData<()>);
impl PropertyQ for AuthId {
    type Item = String;
    fn property() -> Property {
        AUTHID
    }
}

#[derive(Debug)]
pub struct AuthzId(PhantomData<()>);
impl PropertyQ for AuthzId {
    type Item = String;
    fn property() -> Property {
        AUTHZID
    }
}

#[derive(Debug)]
pub struct OpenID20AuthenticateInBrowser(PhantomData<()>);
impl PropertyQ for OpenID20AuthenticateInBrowser {
    type Item = ();
    fn property() -> Property {
        OPENID20_AUTHENTICATE_IN_BROWSER
    }
}

#[derive(Debug)]
pub struct Saml20AuthenticateInBrowser(PhantomData<()>);
impl PropertyQ for Saml20AuthenticateInBrowser {
    type Item = CString;
    fn property() -> Property {
        SAML20_AUTHENTICATE_IN_BROWSER
    }
}

#[derive(Debug)]
pub struct OpenID20OutcomeData(PhantomData<()>);
impl PropertyQ for OpenID20OutcomeData {
    type Item = CString;
    fn property() -> Property {
        OPENID20_OUTCOME_DATA
    }
}

#[derive(Debug)]
pub struct OpenID20RedirectUrl(PhantomData<()>);
impl PropertyQ for OpenID20RedirectUrl {
    type Item = CString;
    fn property() -> Property {
        OPENID20_REDIRECT_URL
    }
}

#[derive(Debug)]
pub struct SAML20RedirectUrl(PhantomData<()>);
impl PropertyQ for SAML20RedirectUrl {
    type Item = CString;
    fn property() -> Property {
        SAML20_REDIRECT_URL
    }
}

#[derive(Debug)]
pub struct SAML20IDPIdentifier(PhantomData<()>);
impl PropertyQ for SAML20IDPIdentifier {
    type Item = CString;
    fn property() -> Property {
        SAML20_IDP_IDENTIFIER
    }
}

#[derive(Debug)]
pub struct CBTlsUnique(PhantomData<()>);
impl PropertyQ for CBTlsUnique {
    type Item = CString;
    fn property() -> Property {
        CB_TLS_UNIQUE
    }
}

#[derive(Debug)]
pub struct Qop(PhantomData<()>);
impl PropertyQ for Qop {
    type Item = CString;
    fn property() -> Property {
        QOP
    }
}

#[derive(Debug)]
pub struct Qops(PhantomData<()>);
impl PropertyQ for Qops {
    type Item = CString;
    fn property() -> Property {
        QOPS
    }
}

#[derive(Debug)]
pub struct DigestMD5HashedPassword(PhantomData<()>);
impl PropertyQ for DigestMD5HashedPassword {
    type Item = CString;
    fn property() -> Property {
        DIGEST_MD5_HASHED_PASSWORD
    }
}

#[derive(Debug)]
pub struct Realm(PhantomData<()>);
impl PropertyQ for Realm {
    type Item = CString;
    fn property() -> Property {
        REALM
    }
}

#[derive(Debug)]
pub struct Pin(PhantomData<()>);
impl PropertyQ for Pin {
    type Item = CString;
    fn property() -> Property {
        PIN
    }
}

#[derive(Debug)]
pub struct SuggestedPin(PhantomData<()>);
impl PropertyQ for SuggestedPin {
    type Item = CString;
    fn property() -> Property {
        SUGGESTED_PIN
    }
}

#[derive(Debug)]
pub struct Passcode(PhantomData<()>);
impl PropertyQ for Passcode {
    type Item = CString;
    fn property() -> Property {
        PASSCODE
    }
}

#[derive(Debug)]
pub struct GssapiDisplayName(PhantomData<()>);
impl PropertyQ for GssapiDisplayName {
    type Item = CString;
    fn property() -> Property {
        GSSAPI_DISPLAY_NAME
    }
}

#[derive(Debug)]
pub struct Hostname(PhantomData<()>);
impl PropertyQ for Hostname {
    type Item = CString;
    fn property() -> Property {
        HOSTNAME
    }
}

#[derive(Debug)]
pub struct Service(PhantomData<()>);
impl PropertyQ for Service {
    type Item = CString;
    fn property() -> Property {
        SERVICE
    }
}

#[derive(Debug)]
pub struct Password(PhantomData<()>);
impl PropertyQ for Password {
    type Item = String;
    fn property() -> Property {
        PASSWORD
    }
}

pub mod properties {
    use super::*;

    pub const AUTHID: Property =
        Property::new(&PropertyDefinition::new("authid", "authentication id"));
    pub const AUTHZID: Property =
        Property::new(&PropertyDefinition::new("authzid", "authorization id"));
    pub const OPENID20_AUTHENTICATE_IN_BROWSER: Property = Property::new(&PropertyDefinition::new(
        "openid20_authenticate_in_browser",
        "query to authenticate to the user's OIDC IdP using the systems browser",
    ));
    pub const SAML20_AUTHENTICATE_IN_BROWSER: Property = Property::new(&PropertyDefinition::new(
        "saml20_authenticate_in_browser",
        "query to authenticate to the user's SAML IdP using the systems browser",
    ));
    pub const OPENID20_OUTCOME_DATA: Property = Property::new(&PropertyDefinition::new(
        "openid_outcome_data",
        "outcome of the OIDC authentication",
    ));
    pub const OPENID20_REDIRECT_URL: Property = Property::new(&PropertyDefinition::new(
        "openid_redirect_url",
        "OpenID Connect redirect url",
    ));
    pub const SAML20_REDIRECT_URL: Property = Property::new(&PropertyDefinition::new(
        "saml20_redirect_url",
        "SAML redirect url",
    ));
    pub const SAML20_IDP_IDENTIFIER: Property = Property::new(&PropertyDefinition::new(
        "saml20_idp_identifier",
        "SAML IdP Identifier",
    ));
    pub const CB_TLS_UNIQUE: Property = Property::new(&PropertyDefinition::new(
        "cb_tls_unique",
        "TLS Channel binding \"unique\"",
    ));
    pub const QOP: Property = Property::new(&PropertyDefinition::new("Qop", ""));
    pub const QOPS: Property = Property::new(&PropertyDefinition::new("Qops", ""));
    pub const DIGEST_MD5_HASHED_PASSWORD: Property =
        Property::new(&PropertyDefinition::new("DigestMD5HashedPassword", ""));
    pub const REALM: Property = Property::new(&PropertyDefinition::new("Realm", ""));
    pub const PIN: Property = Property::new(&PropertyDefinition::new("Pin", ""));
    pub const SUGGESTED_PIN: Property = Property::new(&PropertyDefinition::new("SuggestedPin", ""));
    pub const PASSCODE: Property = Property::new(&PropertyDefinition::new("Passcode", ""));
    pub const GSSAPI_DISPLAY_NAME: Property =
        Property::new(&PropertyDefinition::new("GssapiDisplayName", ""));
    pub const HOSTNAME: Property = Property::new(&PropertyDefinition::new("Hostname", ""));
    pub const SERVICE: Property = Property::new(&PropertyDefinition::new("Service", ""));
    pub const PASSWORD: Property = Property::new(&PropertyDefinition::new("password", ""));
}
use properties::*;
use crate::callback::tags;


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness() {
        println!("{:?}", AUTHID);
    }
}
