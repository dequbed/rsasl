use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::Utf8Error;
use thiserror::Error;

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum SaslNameError {
    Empty,
    InvalidUtf8,
    InvalidChar(u8),
    InvalidEscape,
}

#[derive(Copy, Clone)]
enum SaslEscapeState {
    Done,
    Char(char),
    Comma,
    Comma1,
    Equals,
    Equals1,
}

impl SaslEscapeState {
    pub fn escape(c: char) -> Self {
        match c {
            ',' => Self::Comma,
            '=' => Self::Equals,
            _ => Self::Char(c),
        }
    }
}

impl Iterator for SaslEscapeState {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            Self::Done => None,
            Self::Char(c) => {
                *self = Self::Done;
                Some(c)
            }
            Self::Comma => {
                *self = Self::Comma1;
                Some('=')
            }
            Self::Comma1 => {
                *self = Self::Char('C');
                Some('2')
            }
            Self::Equals => {
                *self = Self::Equals1;
                Some('=')
            }
            Self::Equals1 => {
                *self = Self::Char('D');
                Some('3')
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for SaslEscapeState {
    fn len(&self) -> usize {
        match self {
            SaslEscapeState::Done => 0,
            SaslEscapeState::Char(_) => 1,
            SaslEscapeState::Comma => 3,
            SaslEscapeState::Comma1 => 2,
            SaslEscapeState::Equals => 3,
            SaslEscapeState::Equals1 => 2,
        }
    }
}

#[repr(transparent)]
/// Escaped saslname type
pub struct SaslName<'a>(Cow<'a, str>);
impl<'a> SaslName<'a> {
    /// Convert a Rust-side string into the representation required by SCRAM
    ///
    /// This will clone the given string if characters need escaping
    pub fn escape(input: &str) -> Result<Cow<'_, str>, SaslNameError> {
        if input.contains('\0') {
            return Err(SaslNameError::InvalidChar(0));
        }

        if input.contains(&[',', '=']) {
            let escaped: String = input.chars().flat_map(SaslEscapeState::escape).collect();
            Ok(Cow::Owned(escaped))
        } else {
            Ok(Cow::Borrowed(input))
        }
    }

    /// Convert a SCRAM-side string into the representation expected by Rust
    ///
    /// This will clone the given string if characters need unescaping
    pub fn unescape(input: &'a str) -> Result<Self, SaslNameError> {
        if input.is_empty() {
            return Err(SaslNameError::Empty);
        }

        if let Some(c) = input.find(&['\0', ',']) {
            return Err(SaslNameError::InvalidChar(c as u8));
        }

        if let Some(bad) = input.bytes().position(|b| matches!(b, b'=')) {
            let mut out = String::with_capacity(input.len());
            let good = std::str::from_utf8(&input.as_bytes()[..bad])
                .map_err(|_| SaslNameError::InvalidUtf8)?;
            out.push_str(good);
            let mut input = &input[bad..];

            while let Some(bad) = input.bytes().position(|b| matches!(b, b'=')) {
                let good = std::str::from_utf8(&input.as_bytes()[..bad])
                    .map_err(|_| SaslNameError::InvalidUtf8)?;
                out.push_str(good);
                let c = match &input.as_bytes()[bad + 1..bad + 3] {
                    b"2C" => ',',
                    b"3D" => '=',
                    _ => return Err(SaslNameError::InvalidEscape),
                };
                out.push(c);
                input = &input[bad..];
            }

            Ok(Self(out.into()))
        } else {
            Ok(Self(Cow::Borrowed(input)))
        }
    }

    pub fn as_str(&self) -> &str {
        self.0.deref()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Error)]
pub enum ParseError {
    #[error("bad channel flag")]
    BadCBFlag,
    #[error("channel binding name contains invalid byte {0:#x}")]
    BadCBName(u8),
    #[error("invalid gs2header")]
    BadGS2Header,
    #[error("attribute contains invalid byte {0:#x}")]
    InvalidAttribute(u8),
    #[error("required attribute is missing")]
    MissingAttributes,
    #[error("too many attributes were provided")]
    TooManyAttributes,
    #[error("an extension is unknown but marked mandatory")]
    UnknownMandatoryExtensions,
    #[error("invalid UTF-8: {0}")]
    BadUtf8(
        #[from]
        #[source]
        Utf8Error,
    ),
    #[error("nonce contains invalid character")]
    BadNonce,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum GS2CBindFlag<'scram> {
    SupportedNotUsed,
    NotSupported,
    Used(&'scram str),
}
impl<'scram> GS2CBindFlag<'scram> {
    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        match input {
            b"n" => Ok(Self::NotSupported),
            b"y" => Ok(Self::SupportedNotUsed),
            _x if input.len() > 2 && input[0] == b'p' && input[1] == b'=' => {
                let cbname = &input[2..];
                if let Some(bad) = cbname.into_iter().find(|b|
                          // According to [RFC5056 Section 7](https://www.rfc-editor.org/rfc/rfc5056#section-7)
                          // valid cb names are only composed of ASCII alphanumeric, '.' and '-'
                          !(matches!(b, b'.' | b'-' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z')))
                {
                    Err(ParseError::BadCBName(*bad))
                } else {
                    // SAFE because we just checked for a subset of ASCII which is always UTF-8
                    let name = unsafe { std::str::from_utf8_unchecked(cbname) };
                    Ok(Self::Used(name))
                }
            }
            _ => Err(ParseError::BadCBFlag),
        }
    }

    pub fn to_ioslices(&self) -> [&'scram [u8]; 2] {
        match self {
            Self::NotSupported => [b"n", &[]],
            Self::SupportedNotUsed => [b"y", &[]],
            Self::Used(name) => [b"p=", name.as_bytes()],
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct ClientFirstMessage<'scram> {
    pub cbflag: GS2CBindFlag<'scram>,
    pub authzid: Option<&'scram str>,
    pub username: &'scram str,
    pub nonce: &'scram [u8],
}
impl<'scram> ClientFirstMessage<'scram> {
    pub fn new(
        cbflag: GS2CBindFlag<'scram>,
        authzid: Option<&'scram String>,
        username: &'scram str,
        nonce: &'scram [u8],
    ) -> Self {
        Self {
            cbflag,
            authzid: authzid.map(|s| s.as_ref()),
            username,
            nonce,
        }
    }

    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        let mut partiter = input.split(|b| matches!(b, b','));

        let first = partiter.next().ok_or(ParseError::BadCBFlag)?;
        let cbflag = GS2CBindFlag::parse(first)?;

        let authzid = partiter.next().ok_or(ParseError::BadGS2Header)?;
        let authzid = if !authzid.is_empty() {
            Some(std::str::from_utf8(authzid).map_err(|e| ParseError::BadUtf8(e))?)
        } else {
            None
        };

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        if &next[0..2] == b"m=" {
            return Err(ParseError::UnknownMandatoryExtensions);
        }

        let username = if &next[0..2] == b"n=" {
            std::str::from_utf8(&next[2..]).map_err(|e| ParseError::BadUtf8(e))?
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let nonce = if &next[0..2] == b"r=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };
        if !nonce
            .into_iter()
            .all(|b| matches!(b, 0x21..=0x2B | 0x2D..=0x7E))
        {
            return Err(ParseError::BadNonce);
        }

        Ok(Self {
            cbflag,
            authzid,
            username,
            nonce,
        })
    }

    fn gs2_header_parts(&self) -> [&'scram [u8]; 4] {
        let [cba, cbb] = self.cbflag.to_ioslices();

        let (prefix, authzid): (&[u8], &[u8]) = if let Some(authzid) = self.authzid {
            (b",a=", authzid.as_bytes())
        } else {
            (b",", &[])
        };

        [cba, cbb, prefix, authzid]
    }

    pub fn to_ioslices(&self) -> [&'scram [u8]; 8] {
        let [cba, cbb, prefix, authzid] = self.gs2_header_parts();

        [
            cba,
            cbb,
            prefix,
            authzid,
            b",n=",
            self.username.as_bytes(),
            b",r=",
            self.nonce,
        ]
    }

    pub(super) fn build_gs2_header_vec(&self) -> Vec<u8> {
        let [cba, cbb, prefix, authzid] = self.gs2_header_parts();

        let gs2_header_len = cba.len() + cbb.len() + prefix.len() + authzid.len() + 1;
        let mut gs2_header = Vec::with_capacity(gs2_header_len);

        // y | n | p=
        gs2_header.extend_from_slice(cba);
        // &[] | cbname
        gs2_header.extend_from_slice(cbb);
        // b","
        gs2_header.extend_from_slice(prefix);
        // authzid
        gs2_header.extend_from_slice(authzid);
        // b","
        gs2_header.extend_from_slice(b",");

        gs2_header
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct ServerFirst<'scram> {
    /// Client or Client+Server Nonce
    ///
    /// If the field `server_nonce` is None this contains both client and server nonce
    /// concatenated, otherwise it contains only the client nonce.
    pub nonce: &'scram [u8],
    pub server_nonce: Option<&'scram [u8]>,
    pub salt: &'scram [u8],
    pub iteration_count: &'scram [u8],
}

impl<'scram> ServerFirst<'scram> {
    pub fn new(
        client_nonce: &'scram [u8],
        server_nonce: &'scram [u8],
        salt: &'scram [u8],
        iteration_count: &'scram [u8],
    ) -> Self {
        Self {
            nonce: client_nonce,
            server_nonce: Some(server_nonce),
            salt,
            iteration_count: iteration_count,
        }
    }

    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        let mut partiter = input.split(|b| matches!(b, b','));

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        if next.len() < 2 {
            println!("{:?}", input);
        }
        if &next[0..2] == b"m=" {
            return Err(ParseError::UnknownMandatoryExtensions);
        }

        let nonce = if &next[0..2] == b"r=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let salt = if &next[0..2] == b"s=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let iteration_count = if &next[0..2] == b"i=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };

        if let Some(next) = partiter.next() {
            return Err(ParseError::InvalidAttribute(next[0]));
        }

        Ok(Self {
            nonce,
            server_nonce: None,
            salt,
            iteration_count,
        })
    }

    pub fn to_ioslices(&self) -> [&'scram [u8]; 7] {
        [
            b"r=",
            self.nonce,
            self.server_nonce.unwrap_or(&[]),
            b",s=",
            self.salt,
            b",i=",
            self.iteration_count,
        ]
    }
}

pub struct ClientFinal<'scram> {
    pub channel_binding: &'scram [u8],
    pub nonce: &'scram [u8],
    pub proof: &'scram [u8],
}

impl<'scram> ClientFinal<'scram> {
    pub fn new(channel_binding: &'scram [u8], nonce: &'scram [u8], proof: &'scram [u8]) -> Self {
        Self {
            channel_binding,
            nonce,
            proof,
        }
    }

    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        let mut partiter = input.split(|b| matches!(b, b','));

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let channel_binding = if &next[0..2] == b"c=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0]));
        };
        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let nonce = if &next[0..2] == b"r=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0]));
        };
        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let proof = if &next[0..2] == b"p=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0]));
        };

        if let Some(next) = partiter.next() {
            return Err(ParseError::InvalidAttribute(next[0]));
        }

        Ok(Self {
            channel_binding,
            nonce,
            proof,
        })
    }

    pub fn to_ioslices(&self) -> [&'scram [u8]; 6] {
        [
            b"c=",
            self.channel_binding,
            b",r=",
            self.nonce,
            b",p=",
            self.proof,
        ]
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum ServerErrorValue {
    InvalidEncoding,
    ExtensionsNotSupported,
    InvalidProof,
    ChannelBindingsDontMatch,
    ServerDoesSupportChannelBinding,
    ChannelBindingNotSupported,
    UnsupportedChannelBindingType,
    UnknownUser,
    InvalidUsernameEncoding,
    NoResources,
    OtherError,
}
impl ServerErrorValue {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Self::InvalidEncoding => b"invalid-encoding",
            Self::ExtensionsNotSupported => b"extensions-not-supported",
            Self::InvalidProof => b"invalid-proof",
            Self::ChannelBindingsDontMatch => b"channel-bindings-dont-match",
            Self::ServerDoesSupportChannelBinding => b"server-does-support-channel-binding",
            Self::ChannelBindingNotSupported => b"channel-binding-not-supported",
            Self::UnsupportedChannelBindingType => b"unsupported-channel-binding-type",
            Self::UnknownUser => b"unknown-user",
            Self::InvalidUsernameEncoding => b"invalid-username-encoding",
            Self::NoResources => b"no-resources",
            Self::OtherError => b"other-error",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidEncoding => "invalid encoding",
            Self::ExtensionsNotSupported => "extensions not supported",
            Self::InvalidProof => "invalid proof",
            Self::ChannelBindingsDontMatch => "channel bindings dont match",
            Self::ServerDoesSupportChannelBinding => "server does support channel binding",
            Self::ChannelBindingNotSupported => "channel binding not supported",
            Self::UnsupportedChannelBindingType => "unsupported channel binding type",
            Self::UnknownUser => "unknown user",
            Self::InvalidUsernameEncoding => "invalid username encoding",
            Self::NoResources => "no resources",
            Self::OtherError => "other error",
        }
    }
}
impl Display for ServerErrorValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub enum ServerFinal<'scram> {
    Verifier(&'scram [u8]),
    Error(ServerErrorValue),
}

impl<'scram> ServerFinal<'scram> {
    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        if &input[0..2] == b"v=" {
            Ok(Self::Verifier(&input[2..]))
        } else if &input[0..2] == b"e=" {
            use ServerErrorValue::*;
            let e = match &input[2..] {
                b"invalid-encoding" => InvalidEncoding,
                b"extensions-not-supported" => ExtensionsNotSupported,
                b"invalid-proof" => InvalidProof,
                b"channel-bindings-dont-match" => ChannelBindingsDontMatch,
                b"server-does-support-channel-binding" => ServerDoesSupportChannelBinding,
                b"channel-binding-not-supported" => ChannelBindingNotSupported,
                b"unsupported-channel-binding-type" => UnsupportedChannelBindingType,
                b"unknown-user" => UnknownUser,
                b"invalid-username-encoding" => InvalidUsernameEncoding,
                b"no-resources" => NoResources,
                _ => OtherError,
            };
            Ok(Self::Error(e))
        } else {
            Err(ParseError::InvalidAttribute(input[0]))
        }
    }

    pub fn to_ioslices(&self) -> [&'scram [u8]; 2] {
        match self {
            Self::Verifier(v) => [b"v=", v],
            Self::Error(e) => [b"e=", e.as_bytes()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    

    #[test]
    fn test_parse_gs2_cbind_flag() {
        let valid: [(&[u8], GS2CBindFlag); 7] = [
            (b"n", GS2CBindFlag::NotSupported),
            (b"y", GS2CBindFlag::SupportedNotUsed),
            (b"p=tls-unique", GS2CBindFlag::Used("tls-unique")),
            (b"p=.", GS2CBindFlag::Used(".")),
            (b"p=-", GS2CBindFlag::Used("-")),
            (b"p=a", GS2CBindFlag::Used("a")),
            (
                b"p=a-very-long-cb-name.indeed",
                GS2CBindFlag::Used("a-very-long-cb-name.indeed"),
            ),
        ];

        for (input, output) in valid.iter() {
            assert_eq!(GS2CBindFlag::parse(input), Ok(*output))
        }
    }
}
