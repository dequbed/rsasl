use crate::error::{MechanismError, MechanismErrorKind};
use crate::property::SizedProperty;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to parse message")]
    Parse(
        #[source]
        #[from]
        super::parser::ParseError,
    ),
    #[error("failed to serialize error message")]
    Serde(
        #[source]
        #[from]
        serde_json::Error,
    ),
}

impl MechanismError for Error {
    fn kind(&self) -> MechanismErrorKind {
        MechanismErrorKind::Parse
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthBearerError<'a> {
    /// Authorization error code
    ///
    /// Valid error codes are defined in the
    /// [IANA OAuth Extensions Error Registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#extensions-error)
    /// as specified in the OAuth 2.0 core specification.
    pub status: &'a str,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// An OAuth scope that is valid to access the service.
    ///
    /// This may be omitted, which implies that unscoped tokens are required.  If a scope is
    /// specified, then a single scope is preferred.  At the time this document was written,
    /// there are several implementations that do not properly support space-separated lists of
    /// scopes, so the use of a space- separated list of scopes is NOT RECOMMENDED.
    pub scope: Option<&'a str>,

    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "openid-configuration"
    )]
    /// The URL for a document following the OpenID Provider Configuration Information schema as
    /// described in
    /// [OIDCD OpenID.Discovery, Section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
    /// that is appropriate for the user.
    ///
    /// As specified in OIDCD, this will have the "https" URL scheme.  This document MUST have
    /// all OAuth-related data elements populated.  The server MAY return different URLs for
    /// users in different domains, and the client SHOULD NOT cache a single returned value and
    /// assume it applies for all users/domains that the server supports.  The returned discovery
    /// document SHOULD have all data elements required by the OpenID Connect Discovery
    /// specification populated.  In addition, the discovery document SHOULD contain the
    /// 'registration_endpoint' element to identify the endpoint to be used with the Dynamic
    /// Client Registration protocol [RFC7591](https://www.rfc-editor.org/rfc/rfc7591) to obtain
    /// the minimum number of parameters necessary for the OAuth protocol exchange to function.
    /// Another comparable discovery or client registration mechanism MAY be used if available.
    /// The use of the 'offline_access' scope, as defined in
    /// [OpenID.Core](http://openid.net/specs/openid-connect-core-1_0.html), is RECOMMENDED to
    /// give clients the capability to explicitly request a refresh token.
    pub openid_config: Option<&'a str>,
}

#[non_exhaustive]
pub struct OAuthBearerValidate;
impl<'a> SizedProperty<'a> for OAuthBearerValidate {
    type Value = Result<(), OAuthBearerError<'a>>;
}

#[non_exhaustive]
pub struct OAuthBearerErrored;
impl<'a> SizedProperty<'a> for OAuthBearerErrored {
    type Value = OAuthBearerError<'a>;
}
