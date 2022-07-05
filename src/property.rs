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


use std::marker::PhantomData;
use crate::callback::tags;

#[derive(Debug)]
pub struct AuthId(PhantomData<()>);
impl<'a> tags::MaybeSizedType<'a> for AuthId {
    type Reified = str;
}

#[derive(Debug)]
pub struct AuthzId(PhantomData<()>);
impl<'a> tags::MaybeSizedType<'a> for AuthzId {
    type Reified = str;
}

#[derive(Debug)]
pub struct OpenID20AuthenticateInBrowser(PhantomData<()>);

#[derive(Debug)]
pub struct Saml20AuthenticateInBrowser(PhantomData<()>);

#[derive(Debug)]
pub struct OpenID20OutcomeData(PhantomData<()>);

#[derive(Debug)]
pub struct OpenID20RedirectUrl(PhantomData<()>);

#[derive(Debug)]
pub struct SAML20RedirectUrl(PhantomData<()>);

#[derive(Debug)]
pub struct SAML20IDPIdentifier(PhantomData<()>);

#[derive(Debug)]
pub struct CBTlsUnique(PhantomData<()>);

#[derive(Debug)]
pub struct Qop(PhantomData<()>);

#[derive(Debug)]
pub struct Qops(PhantomData<()>);

#[derive(Debug)]
pub struct DigestMD5HashedPassword(PhantomData<()>);

#[derive(Debug)]
pub struct Realm(PhantomData<()>);

#[derive(Debug)]
pub struct Pin(PhantomData<()>);

#[derive(Debug)]
pub struct SuggestedPin(PhantomData<()>);

#[derive(Debug)]
pub struct Passcode(PhantomData<()>);

#[derive(Debug)]
pub struct GssapiDisplayName(PhantomData<()>);

#[derive(Debug)]
pub struct Hostname(PhantomData<()>);

#[derive(Debug)]
pub struct Service(PhantomData<()>);

#[derive(Debug)]
pub struct Password(PhantomData<()>);
impl<'a> tags::MaybeSizedType<'a> for Password {
    type Reified = [u8];
}