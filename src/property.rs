//! # Defining Properties
//!
//! If the existing properties in this module are not sufficient for your mechanism, you can
//! define additional properties to be queried.
//! This consists of two parts:
//! 1. A type indicating your property
//! 2. A `const Property` that is used to query this property
//!
//! ```rust
//! use std::marker::PhantomData;
//! use rsasl::{Property, PropertyQ, PropertyDefinition};
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
use std::ffi::CString;
use std::hash::Hash;
use std::marker::PhantomData;
use std::fmt::{Debug, Display, Formatter};

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
    type Item: 'static;
    fn property() -> Property;
}

#[derive(Debug)]
pub struct AuthId(PhantomData<()>);
impl PropertyQ for AuthId {
    type Item = String;
    fn property() -> Property {
        AUTHID
    }
}
pub const AUTHID: Property = Property::new(&PropertyDefinition::new(
    "authid", "authentication id"));

#[derive(Debug)]
pub struct AuthzId(PhantomData<()>);
impl PropertyQ for AuthzId {
    type Item = String;
    fn property() -> Property {
        AUTHZID
    }
}
pub const AUTHZID: Property = Property::new(&PropertyDefinition::new(
    "authzid", "authorization id"));


#[derive(Debug)]
pub struct OpenID20AuthenticateInBrowser(PhantomData<()>);
pub const OPENID20_AUTHENTICATE_IN_BROWSER: Property = Property::new(&PropertyDefinition::new(
    "openid20_authenticate_in_browser",
    "query to authenticate to the user's OIDC IdP using the systems browser"
));

#[derive(Debug)]
pub struct Saml20AuthenticateInBrowser(PhantomData<()>);
impl PropertyQ for Saml20AuthenticateInBrowser {
    type Item = CString;
    fn property() -> Property {
        SAML20_AUTHENTICATE_IN_BROWSER
    }
}
pub const SAML20_AUTHENTICATE_IN_BROWSER: Property = Property::new(&PropertyDefinition::new(
    "saml20_authenticate_in_browser",
    "query to authenticate to the user's SAML IdP using the systems browser"
));

#[derive(Debug)]
pub struct OpenID20OutcomeData(PhantomData<()>);
impl PropertyQ for OpenID20OutcomeData {
    type Item = CString;
    fn property() -> Property {
        OPENID20_OUTCOME_DATA
    }
}
pub const OPENID20_OUTCOME_DATA: Property = Property::new(&PropertyDefinition::new(
    "openid_outcome_data", "outcome of the OIDC authentication"));

#[derive(Debug)]
pub struct OpenID20RedirectUrl(PhantomData<()>);
impl PropertyQ for OpenID20RedirectUrl {
    type Item = CString;
    fn property() -> Property {
        OPENID20_REDIRECT_URL
    }
}
pub const OPENID20_REDIRECT_URL: Property = Property::new(&PropertyDefinition::new(
    "openid_redirect_url", "OpenID Connect redirect url"
));

#[derive(Debug)]
pub struct SAML20RedirectUrl(PhantomData<()>);
impl PropertyQ for SAML20RedirectUrl {
    type Item = CString;
    fn property() -> Property {
        SAML20_REDIRECT_URL
    }
}
pub const SAML20_REDIRECT_URL: Property = Property::new(&PropertyDefinition::new(
    "saml20_redirect_url", "SAML redirect url"
));


#[derive(Debug)]
pub struct SAML20IDPIdentifier(PhantomData<()>);
impl PropertyQ for SAML20IDPIdentifier {
    type Item = CString;
    fn property() -> Property {
        SAML20_IDP_IDENTIFIER
    }
}
pub const SAML20_IDP_IDENTIFIER: Property = Property::new(&PropertyDefinition::new(
    "saml20_idp_identifier", "SAML IdP Identifier"
));

#[derive(Debug)]
pub struct CBTlsUnique(PhantomData<()>);
impl PropertyQ for CBTlsUnique {
    type Item = CString;
    fn property() -> Property {
        CB_TLS_UNIQUE
    }
}
pub const CB_TLS_UNIQUE: Property = Property::new(&PropertyDefinition::new(
    "cb_tls_unique", "TLS Channel binding \"unique\""
));

#[derive(Debug)]
pub struct ScramStoredkey(PhantomData<()>);
impl PropertyQ for ScramStoredkey {
    type Item = CString;
    fn property() -> Property {
        SCRAM_STOREDKEY
    }
}
pub const SCRAM_STOREDKEY: Property = Property::new(&PropertyDefinition::new(
    "scram_storedkey", "SCRAM stored key"
));

#[derive(Debug)]
pub struct ScramServerkey(PhantomData<()>);
impl PropertyQ for ScramServerkey {
    type Item = CString;
    fn property() -> Property {
        SCRAM_SERVERKEY
    }
}
pub const SCRAM_SERVERKEY: Property = Property::new(&PropertyDefinition::new(
    "ScramServerkey", ""
));

#[derive(Debug)]
pub struct ScramSaltedPassword(PhantomData<()>);
impl PropertyQ for ScramSaltedPassword {
    type Item = CString;
    fn property() -> Property {
        SCRAM_SALTED_PASSWORD
    }
}
pub const SCRAM_SALTED_PASSWORD: Property = Property::new(&PropertyDefinition::new(
    "ScramSaltedPassword", ""
));

#[derive(Debug)]
pub struct ScramSalt(PhantomData<()>);
impl PropertyQ for ScramSalt {
    type Item = CString;
    fn property() -> Property {
        SCRAM_SALT
    }
}
pub const SCRAM_SALT: Property = Property::new(&PropertyDefinition::new(
    "ScramSalt", ""
));

#[derive(Debug)]
pub struct ScramIter(PhantomData<()>);
impl PropertyQ for ScramIter {
    type Item = CString;
    fn property() -> Property {
        SCRAM_ITER
    }
}
pub const SCRAM_ITER: Property = Property::new(&PropertyDefinition::new(
    "ScramIter", ""
));

#[derive(Debug)]
pub struct Qop(PhantomData<()>);
impl PropertyQ for Qop {
    type Item = CString;
    fn property() -> Property {
        QOP
    }
}
pub const QOP: Property = Property::new(&PropertyDefinition::new(
    "Qop", ""
));

#[derive(Debug)]
pub struct Qops(PhantomData<()>);
impl PropertyQ for Qops {
    type Item = CString;
    fn property() -> Property {
        QOPS
    }
}
pub const QOPS: Property = Property::new(&PropertyDefinition::new(
    "Qops", ""
));

#[derive(Debug)]
pub struct DigestMD5HashedPassword(PhantomData<()>);
impl PropertyQ for DigestMD5HashedPassword {
    type Item = CString;
    fn property() -> Property {
        DIGEST_MD5_HASHED_PASSWORD
    }
}
pub const DIGEST_MD5_HASHED_PASSWORD: Property = Property::new(&PropertyDefinition::new(
    "DigestMD5HashedPassword", ""
));

#[derive(Debug)]
pub struct Realm(PhantomData<()>);
impl PropertyQ for Realm {
    type Item = CString;
    fn property() -> Property {
        REALM
    }
}
pub const REALM: Property = Property::new(&PropertyDefinition::new(
    "Realm", ""
));

#[derive(Debug)]
pub struct Pin(PhantomData<()>);
impl PropertyQ for Pin {
    type Item = CString;
    fn property() -> Property {
        PIN
    }
}
pub const PIN: Property = Property::new(&PropertyDefinition::new(
    "Pin", ""
));

#[derive(Debug)]
pub struct SuggestedPin(PhantomData<()>);
impl PropertyQ for SuggestedPin {
    type Item = CString;
    fn property() -> Property {
        SUGGESTED_PIN
    }
}
pub const SUGGESTED_PIN: Property = Property::new(&PropertyDefinition::new(
    "SuggestedPin", ""
));

#[derive(Debug)]
pub struct Passcode(PhantomData<()>);
impl PropertyQ for Passcode {
    type Item = CString;
    fn property() -> Property {
        PASSCODE
    }
}
pub const PASSCODE: Property = Property::new(&PropertyDefinition::new(
    "Passcode", ""
));

#[derive(Debug)]
pub struct GssapiDisplayName(PhantomData<()>);
impl PropertyQ for GssapiDisplayName {
    type Item = CString;
    fn property() -> Property {
        GSSAPI_DISPLAY_NAME
    }
}
pub const GSSAPI_DISPLAY_NAME: Property = Property::new(&PropertyDefinition::new(
    "GssapiDisplayName", ""
));

#[derive(Debug)]
pub struct Hostname(PhantomData<()>);
impl PropertyQ for Hostname {
    type Item = CString;
    fn property() -> Property {
        HOSTNAME
    }
}
pub const HOSTNAME: Property = Property::new(&PropertyDefinition::new(
    "Hostname", ""
));

#[derive(Debug)]
pub struct Service(PhantomData<()>);
impl PropertyQ for Service {
    type Item = CString;
    fn property() -> Property {
        SERVICE
    }
}
pub const SERVICE: Property = Property::new(&PropertyDefinition::new(
    "Service", ""
));


#[derive(Debug)]
pub struct AnonymousToken(PhantomData<()>);
impl PropertyQ for AnonymousToken {
    type Item = String;
    fn property() -> Property {
        ANONYMOUS_TOKEN
    }
}
pub const ANONYMOUS_TOKEN: Property = Property::new(&PropertyDefinition::new(
    "AnonymousToken", ""
));


#[derive(Debug)]
pub struct Password(PhantomData<()>);
impl PropertyQ for Password {
    type Item = String;
    fn property() -> Property {
        PASSWORD
    }
}
pub const PASSWORD: Property = Property::new(&PropertyDefinition::new(
    "password", ""
));


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness() {
        println!("{:?}", AUTHID);
    }
}