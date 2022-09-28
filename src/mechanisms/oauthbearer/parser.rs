use alloc::str::Utf8Error;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("input is missing a required part")]
    MissingPart,
    #[error("final terminator is missing. Incomplete input?")]
    MissingEnd,
    #[error("required 'auth' field is missing")]
    MissingToken,
    #[error("gs2-header is invalid")]
    InvalidGs2,
    #[error("OAUTHBEARER can't support channel bindings")]
    ChannelBindings,
    #[error("K/V pair is invalid")]
    InvalidKVPair,
    #[error("Invalid UTF-8")]
    InvalidUtf8(#[from] #[source] Utf8Error),
}

pub struct OAuthBearerMsg<'a> {
    pub authzid: Option<&'a str>,
    pub token: &'a str,
    pub fields: Vec<(&'a str, &'a str)>,
}

impl<'a> OAuthBearerMsg<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        // Make sure the token isn't trimmed but contains the end bytes
        if let Some(bytes) = bytes.strip_suffix(b"\x01\x01") {
            let mut it = bytes.split(|b| matches!(b, b'\x01'));
            let gs2 = it.next().ok_or(ParseError::MissingPart)?;
            let mut gs2iter = gs2.split(|b| matches!(b, b','));
            let gs2_first = gs2iter.next().ok_or(ParseError::InvalidGs2)?;
            if gs2_first != b"n" {
                return Err(ParseError::ChannelBindings);
            }
            let gs2_authzid = gs2iter.next().ok_or(ParseError::InvalidGs2)?;

            let authzid = if !gs2_authzid.is_empty() {
                if let Some(rem) = gs2_authzid.strip_prefix(b"a=") {
                    Some(core::str::from_utf8(rem)?)
                } else {
                    return Err(ParseError::InvalidGs2);
                }
            } else {
                None
            };

            let mut token = None;
            let mut fields = Vec::new();

            for kv in it {
                if let Some(t) = kv.strip_prefix(b"auth=") {
                    token = Some(core::str::from_utf8(t)?);
                } else {
                    let mut kviter = kv.split(|b| matches!(b, b'='));
                    let key = kviter.next().ok_or(ParseError::InvalidKVPair)?;
                    let val = kviter.next().ok_or(ParseError::InvalidKVPair)?;
                    if kviter.next().is_some() {
                        return Err(ParseError::InvalidKVPair);
                    }
                    let key = core::str::from_utf8(key)?;
                    let val = core::str::from_utf8(val)?;
                    fields.push((key, val));
                }
            }

            let token = token.ok_or(ParseError::MissingToken)?;
            Ok(Self {
                authzid,
                token,
                fields,
            })
        } else {
            Err(ParseError::MissingEnd)
        }
    }
}