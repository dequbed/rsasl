use std::borrow::Cow;
use std::io::IoSlice;
use ::libc;
use libc::{malloc, memchr, memcpy, size_t, strnlen};
use crate::mechanisms::scram::client::{scram_client_final, scram_client_first, SCRAMError};
use crate::mechanisms::scram::parser::ParseError::InvalidAttribute;
use crate::mechanisms::scram::server::{scram_server_final, scram_server_first};
use crate::mechanisms::scram::validate::{scram_valid_client_final, scram_valid_client_first, scram_valid_server_final, scram_valid_server_first};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum SaslNameError {
    Empty,
    InvalidUtf8,
    InvalidChar(u8),
    InvalidEscape,
}

#[repr(transparent)]
/// Escaped saslname type
pub struct SaslName(str);
impl SaslName {
    /// Construct a new saslname from a given str
    ///
    /// This function will *fail* if the given name is not a valid saslname. To escape an
    /// arbitratry string into a valid saslname use [`SaslName::escape`].
    pub fn from_str(input: &str) -> Result<&Self, SaslNameError> {
        if let Some(b) = input.find(&['\0', ',', '=']) {
            Err(SaslNameError::InvalidChar(b as u8))
        } else {
            let this = unsafe { &*(input as *const str as *const SaslName) };
            Ok(this)
        }
    }

    pub fn from_boxed_str(mut input: Box<str>) -> Result<Box<Self>, SaslNameError> {
        if let Some(b) = input.find(&['\0', ',', '=']) {
            Err(SaslNameError::InvalidChar(b as u8))
        } else {
            let this = unsafe { Box::from_raw(Box::into_raw(input) as *mut SaslName) };
            Ok(this)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn escape(input: &str) -> Result<Cow<'_, str>, SaslNameError> {
        if input.contains('\0') {
            return Err(SaslNameError::InvalidChar(0));
        }

        if input.contains(&[',', '=']) {
            Ok(input.replace(',', "=2C").replace('=', "=3D").into())
        } else {
            Ok(input.into())
        }
    }

    pub fn unescape(&self) -> Result<Cow<'_, str>, SaslNameError> {
        let v = &self.0;
        if v.is_empty() {
            return Err(SaslNameError::Empty);
        }
        if let Some(c) = v.find(&['\0', ',']) {
            return Err(SaslNameError::InvalidChar(c as u8))
        }
        if let Some(bad) = v.bytes().position(|b| matches!(b, b'=')) {
            let mut out = String::with_capacity(v.len());
            let good = std::str::from_utf8(&v.as_bytes()[..bad]).map_err(|_| SaslNameError::InvalidUtf8)?;
            out.push_str(good);
            let mut v = &v[bad..];

            while let Some(bad) = v.bytes().position(|b| matches!(b, b'=')) {
                let good = std::str::from_utf8(&v.as_bytes()[..bad]).map_err(|_| SaslNameError::InvalidUtf8)?;
                out.push_str(good);
                let c = match &v.as_bytes()[bad+1..bad+3] {
                    b"2C" => ',',
                    b"3D" => '=',
                    _ => return Err(SaslNameError::InvalidEscape),
                };
                out.push(c);
                v = &v[bad..];
            }

            Ok(Cow::Owned(out))
        } else {
            Ok(Cow::Borrowed(&self.0))
        }
    }
}


#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum ParseError {
    BadCBFlag,
    BadCBName(u8),
    BadGS2Header,
    InvalidAttribute(u8),
    MissingAttributes,
    TooManyAttributes,
    UnknownMandatoryExtensions,
    BadUtf8,
    BadNonce,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum GS2CBindFlag<'scram> {
    SupportedNotUsed,
    NotSupported,
    Used(&'scram str)
}
impl<'scram> GS2CBindFlag<'scram> {
    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        match input {
            b"n" => Ok(Self::NotSupported),
            b"y" => Ok(Self::SupportedNotUsed),
            x if input.len() > 2 && input[0] == b'p' && input[1] == b'=' => {
                let cbname = &input[2..];
                if let Some(bad) = cbname.into_iter()
                      .find(|b|
                          // According to [RFC5056 Section 7](https://www.rfc-editor.org/rfc/rfc5056#section-7)
                          // valid cb names are only composed of ASCII alphanumeric, '.' and '-'
                          !(matches!(b, b'.' | b'-' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'))
                      ) {
                    Err(ParseError::BadCBName(*bad))
                } else {
                    // SAFE because we just checked for a subset of ASCII which is always UTF-8
                    let name = unsafe { std::str::from_utf8_unchecked(cbname) };
                    Ok(Self::Used(name))
                }
            },
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
        authzid: Option<&'scram str>,
        username: &'scram SaslName,
        nonce: &'scram [u8],
    )
        -> Self
    {
        Self { cbflag, authzid, username: username.as_str(), nonce }
    }

    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        let mut partiter = input.split(|b| matches!(b, b','));

        let first = partiter.next().ok_or(ParseError::BadCBFlag)?;
        let cbflag = GS2CBindFlag::parse(first)?;

        let authzid = partiter.next().ok_or(ParseError::BadGS2Header)?;
        let authzid = if !authzid.is_empty() {
            Some(std::str::from_utf8(authzid).map_err(|_| ParseError::BadUtf8)?)
        } else {
            None
        };

        let mut next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        if &next[0..2] == b"m=" {
            return Err(ParseError::UnknownMandatoryExtensions);
        }

        let username = if &next[0..2] == b"n=" {
            std::str::from_utf8(&next[2..]).map_err(|_| ParseError::BadUtf8)?
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };

        let next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let nonce = if &next[0..2] == b"r=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };
        if !nonce.into_iter().all(|b| matches!(b, 0x21..=0x2B | 0x2D..=0x7E)) {
            return Err(ParseError::BadNonce)
        }

        Ok(Self { cbflag, authzid, username, nonce })
    }

    pub fn to_ioslices(&self) -> [&'scram [u8]; 8] {
        let [cba, cbb] = self.cbflag.to_ioslices();

        let (prefix, authzid): (&[u8], &[u8]) = if let Some(authzid) = self.authzid {
            (b",a=", authzid.as_bytes())
        } else {
            (b",", &[])
        };

        [
            cba, cbb,
            prefix, authzid,
            b",n=", self.username.as_bytes(),
            b",r=", self.nonce
        ]
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub struct ServerFirst<'scram> {
    pub nonce: &'scram [u8],
    pub salt: &'scram [u8],
    pub iteration_count: &'scram [u8],
}

impl<'scram> ServerFirst<'scram> {
    pub fn parse(input: &'scram [u8]) -> Result<Self, ParseError> {
        let mut partiter = input.split(|b| matches!(b, b','));

        let mut next = partiter.next().ok_or(ParseError::MissingAttributes)?;
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

        let mut next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let salt = if &next[0..2] == b"s=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };

        let mut next = partiter.next().ok_or(ParseError::MissingAttributes)?;
        let iteration_count = if &next[0..2] == b"i=" {
            &next[2..]
        } else {
            return Err(ParseError::InvalidAttribute(next[0] as u8));
        };

        if let Some(next) = partiter.next() {
            return Err(ParseError::InvalidAttribute(next[0]));
        }

        Ok(Self { nonce, salt, iteration_count })
    }

    pub fn to_ioslices(&self) -> [&'scram [u8]; 6] {
        [
            b"r=", self.nonce,
            b",s=", self.salt,
            b",i=", self.iteration_count,
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
        Self { channel_binding, nonce, proof }
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

        Ok(Self { channel_binding, nonce, proof })
    }

    pub fn to_ioslices(&self) -> [&'scram [u8]; 6] {
        [
            b"c=", self.channel_binding,
            b",r=", self.nonce,
            b",p=", self.proof,
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
    OtherError
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
    use std::io::Cursor;
    use crate::vectored_io::VectoredWriter;
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
            (b"p=a-very-long-cb-name.indeed", GS2CBindFlag::Used("a-very-long-cb-name.indeed")),
        ];

        for (input, output) in valid.iter() {
            assert_eq!(GS2CBindFlag::parse(input), Ok(*output))
        }
    }

    #[test]
    fn write_client_first_message() {
        let username = "testuser";
        let nonce = b"testnonce";
        let cbname = "tls-unique";

        let msg = ClientFirstMessage {
            cbflag: GS2CBindFlag::Used(cbname),
            authzid: None,
            username,
            nonce,
        };

        let expected = "p=tls-unique,,n=testuser,r=testnonce";

        let mut out = Cursor::new(Vec::new());
        let mut vecw = VectoredWriter::new(msg.to_ioslices());
        let written = vecw.write_all_vectored(&mut out).unwrap();

        let v = out.into_inner();
        let f = std::str::from_utf8(&v[..]).unwrap();
        println!("Output: {:?}", f);
        assert_eq!(f, expected);

        let parsed = ClientFirstMessage::parse(expected.as_bytes()).unwrap();
        println!("Parsed: {:?}", parsed);
        assert_eq!(parsed.cbflag, GS2CBindFlag::Used("tls-unique"));
        assert_eq!(parsed.authzid, None);
        assert_eq!(parsed.username, username);
        assert_eq!(parsed.nonce, nonce);
    }
}

/* tokens.h --- Types for SCRAM tokens.
 * Copyright (C) 2009-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#[inline]
unsafe fn c_isalpha(mut c: libc::c_int) -> bool {
    match c {
        97 | 98 | 99 | 100 | 101 | 102 | 103 | 104 | 105 | 106 | 107 | 108 |
        109 | 110 | 111 | 112 | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120
        | 121 | 122 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 |
        76 | 77 | 78 | 79 | 80 | 81 | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 |
        90 => {
            return 1 as libc::c_int != 0
        }
        _ => { return 0 as libc::c_int != 0 }
    };
}
/* parser.c --- SCRAM parser.
 * Copyright (C) 2009-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
/* Get prototypes. */
/* Get malloc, free. */
/* Get memcpy, strlen. */
/* Get validator. */
/* Get c_isalpha. */
unsafe fn unescape(mut str: *const libc::c_char, mut len: size_t)
 -> *mut libc::c_char {
    let mut out: *mut libc::c_char = malloc(len.wrapping_add(1)) as *mut libc::c_char;
    let mut p: *mut libc::c_char = out;
    if out.is_null() { return 0 as *mut libc::c_char }
    while len > 0 && *str as libc::c_int != 0
          {
        if len >= 3 &&
               *str.offset(0 as libc::c_int as isize) as libc::c_int ==
                   '=' as i32 &&
               *str.offset(1 as libc::c_int as isize) as libc::c_int ==
                   '2' as i32 &&
               *str.offset(2 as libc::c_int as isize) as libc::c_int ==
                   'C' as i32 {
            let fresh0 = p;
            p = p.offset(1);
            *fresh0 = ',' as i32 as libc::c_char;
            str = str.offset(3 as libc::c_int as isize);
            len =
                (len as
                     libc::c_ulong).wrapping_sub(3 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t
        } else if len >= 3 &&
                      *str.offset(0 as libc::c_int as isize) as libc::c_int ==
                          '=' as i32 &&
                      *str.offset(1 as libc::c_int as isize) as libc::c_int ==
                          '3' as i32 &&
                      *str.offset(2 as libc::c_int as isize) as libc::c_int ==
                          'D' as i32 {
            let fresh1 = p;
            p = p.offset(1);
            *fresh1 = '=' as i32 as libc::c_char;
            str = str.offset(3 as libc::c_int as isize);
            len =
                (len as
                     libc::c_ulong).wrapping_sub(3 as libc::c_int as
                                                     libc::c_ulong) as size_t
                    as size_t
        } else {
            let fresh2 = p;
            p = p.offset(1);
            *fresh2 = *str;
            str = str.offset(1);
            len = len.wrapping_sub(1)
        }
    }
    *p = '\u{0}' as i32 as libc::c_char;
    return out;
}
pub unsafe fn scram_parse_client_first(
    mut str: *const libc::c_char,
    mut len: size_t,
    mut cf: *mut scram_client_first,
) -> libc::c_int {
    /* Minimum client first string is 'n,,n=a,r=b'. */
    if strnlen(str, len) < 10 {
        return -(1 as libc::c_int)
    }
    if len == 0 ||
           *str as libc::c_int != 'n' as i32 &&
               *str as libc::c_int != 'y' as i32 &&
               *str as libc::c_int != 'p' as i32 {
        return -(1 as libc::c_int)
    }
    (*cf).cbflag = *str;
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if (*cf).cbflag as libc::c_int == 'p' as i32 {
        let mut p: *const libc::c_char = 0 as *const libc::c_char;
        if len == 0 ||
               *str as libc::c_int != '=' as i32 {
            return -(1 as libc::c_int)
        }
        str = str.offset(1);
        len = len.wrapping_sub(1);
        p =
            memchr(str as *const libc::c_void, ',' as i32, len) as
                *const libc::c_char;
        if p.is_null() { return -(1 as libc::c_int) }
        (*cf).cbname = malloc((p.offset_from(str) + 1) as size_t) as *mut libc::c_char;
        if (*cf).cbname.is_null() { return -(1 as libc::c_int) }
        memcpy((*cf).cbname as *mut libc::c_void,
               str as *const libc::c_void,
               p.offset_from(str) as size_t);
        *(*cf).cbname.offset(p.offset_from(str) as libc::c_long as
                                 isize) = '\u{0}' as i32 as libc::c_char;
        len =
            (len as
                 libc::c_ulong).wrapping_sub(p.offset_from(str) as
                                                 libc::c_long as
                                                 libc::c_ulong) as size_t as
                size_t;
        str = str.offset(p.offset_from(str) as libc::c_long as isize)
    }
    if len == 0 ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 { return -(1 as libc::c_int) }
    if *str as libc::c_int == 'a' as i32 {
        let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
        let mut l: size_t = 0;
        str = str.offset(1);
        len = len.wrapping_sub(1);
        if len == 0 ||
               *str as libc::c_int != '=' as i32 {
            return -(1 as libc::c_int)
        }
        str = str.offset(1);
        len = len.wrapping_sub(1);
        p_0 =
            memchr(str as *const libc::c_void, ',' as i32, len) as
                *const libc::c_char;
        if p_0.is_null() { return -(1 as libc::c_int) }
        l = p_0.offset_from(str) as libc::c_long as size_t;
        if len < l { return -(1 as libc::c_int) }
        (*cf).authzid = unescape(str, l);
        if (*cf).authzid.is_null() { return -(1 as libc::c_int) }
        str = p_0;
        len = len.wrapping_sub(l) as size_t as size_t
    }
    if len == 0 ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != 'n' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p_1: *const libc::c_char = 0 as *const libc::c_char;
    let mut l_0: size_t = 0;
    p_1 =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p_1.is_null() { return -(1 as libc::c_int) }
    l_0 = p_1.offset_from(str) as libc::c_long as size_t;
    if len < l_0 { return -(1 as libc::c_int) }
    (*cf).username = unescape(str, l_0);
    if (*cf).username.is_null() { return -(1 as libc::c_int) }
    str = p_1;
    len = len.wrapping_sub(l_0) as size_t as size_t;
    if len == 0 ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != 'r' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p_2: *const libc::c_char = 0 as *const libc::c_char;
    let mut l_1: size_t = 0;
    p_2 = memchr(str as *const libc::c_void, ',' as i32, len) as *const libc::c_char;
    if p_2.is_null() { p_2 = str.offset(len as isize) }
    if p_2.is_null() { return -(1 as libc::c_int) }
    l_1 = p_2.offset_from(str) as libc::c_long as size_t;
    if len < l_1 { return -(1 as libc::c_int) }
    (*cf).client_nonce = malloc(l_1.wrapping_add(1)) as *mut libc::c_char;
    if (*cf).client_nonce.is_null() { return -(1 as libc::c_int) }
    memcpy((*cf).client_nonce as *mut libc::c_void,
           str as *const libc::c_void, l_1);
    *(*cf).client_nonce.offset(l_1 as isize) = '\u{0}' as i32 as libc::c_char;
    str = p_2;
    len = len.wrapping_sub(l_1);
    /* FIXME check that any extension fields follow valid syntax. */
    if !scram_valid_client_first(cf) { return -(1 as libc::c_int) }
    return 0 as libc::c_int;
}

pub unsafe fn scram_parse_server_first(
    mut str: *const libc::c_char,
    mut len: size_t,
    mut sf: *mut scram_server_first,
) -> libc::c_int {
    /* Minimum server first string is 'r=ab,s=biws,i=1'. */
    if strnlen(str, len) < 15 {
        return -(1 as libc::c_int)
    }
    if len == 0 ||
           *str as libc::c_int != 'r' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut l: size_t = 0;
    p =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p.is_null() { return -(1 as libc::c_int) }
    l = p.offset_from(str) as libc::c_long as size_t;
    if len < l { return -(1 as libc::c_int) }
    (*sf).nonce =
        malloc(l.wrapping_add(1)) as
            *mut libc::c_char;
    if (*sf).nonce.is_null() { return -(1 as libc::c_int) }
    memcpy((*sf).nonce as *mut libc::c_void, str as *const libc::c_void, l);
    *(*sf).nonce.offset(l as isize) = '\u{0}' as i32 as libc::c_char;
    str = p;
    len = len.wrapping_sub(l) as size_t as size_t;
    if len == 0 ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != 's' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
    let mut l_0: size_t = 0;
    p_0 =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p_0.is_null() { return -(1 as libc::c_int) }
    l_0 = p_0.offset_from(str) as libc::c_long as size_t;
    if len < l_0 { return -(1 as libc::c_int) }
    (*sf).salt =
        malloc(l_0.wrapping_add(1)) as
            *mut libc::c_char;
    if (*sf).salt.is_null() { return -(1 as libc::c_int) }
    memcpy((*sf).salt as *mut libc::c_void, str as *const libc::c_void, l_0);
    *(*sf).salt.offset(l_0 as isize) = '\u{0}' as i32 as libc::c_char;
    str = p_0;
    len = len.wrapping_sub(l_0);
    if len == 0 ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != 'i' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    (*sf).iter = 0 as libc::c_int as size_t;
    while len > 0 &&
              *str as libc::c_int >= '0' as i32 &&
              *str as libc::c_int <= '9' as i32 {
        let mut last_iter: size_t = (*sf).iter;
        (*sf).iter =
            (*sf).iter.wrapping_mul(10).wrapping_add((*str - '0' as libc::c_char) as usize);
        /* Protect against wrap arounds. */
        if (*sf).iter < last_iter { return -(1 as libc::c_int) }
        str = str.offset(1);
        len = len.wrapping_sub(1)
    }
    if len > 0 &&
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    /* FIXME check that any extension fields follow valid syntax. */
    if !scram_valid_server_first(sf) { return -(1 as libc::c_int) }
    return 0 as libc::c_int;
}
/* parser.h --- SCRAM parser.
 * Copyright (C) 2009-2021 Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */
/* Get token types. */
pub unsafe fn scram_parse_client_final(
    mut str: *const libc::c_char,
    mut len: size_t,
    mut cl: *mut scram_client_final,
) -> libc::c_int {
    /* Minimum client final string is 'c=biws,r=ab,p=ab=='. */
    if strnlen(str, len) < 18 {
        return -(1 as libc::c_int)
    }
    if len == 0 ||
           *str as libc::c_int != 'c' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p: *const libc::c_char = 0 as *const libc::c_char;
    let mut l: size_t = 0;
    p =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p.is_null() { return -(1 as libc::c_int) }
    l = p.offset_from(str) as libc::c_long as size_t;
    if len < l { return -(1 as libc::c_int) }
    (*cl).cbind =
        malloc(l.wrapping_add(1)) as
            *mut libc::c_char;
    if (*cl).cbind.is_null() { return -(1 as libc::c_int) }
    memcpy((*cl).cbind as *mut libc::c_void, str as *const libc::c_void, l);
    *(*cl).cbind.offset(l as isize) = '\u{0}' as i32 as libc::c_char;
    str = p;
    len = len.wrapping_sub(l);
    if len == 0 ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != 'r' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    let mut p_0: *const libc::c_char = 0 as *const libc::c_char;
    let mut l_0: size_t = 0;
    p_0 =
        memchr(str as *const libc::c_void, ',' as i32, len) as
            *const libc::c_char;
    if p_0.is_null() { return -(1 as libc::c_int) }
    l_0 = p_0.offset_from(str) as libc::c_long as size_t;
    if len < l_0 { return -(1 as libc::c_int) }
    (*cl).nonce =
        malloc(l_0.wrapping_add(1)) as
            *mut libc::c_char;
    if (*cl).nonce.is_null() { return -(1 as libc::c_int) }
    memcpy((*cl).nonce as *mut libc::c_void, str as *const libc::c_void, l_0);
    *(*cl).nonce.offset(l_0 as isize) = '\u{0}' as i32 as libc::c_char;
    str = p_0;
    len = len.wrapping_sub(l_0) as size_t as size_t;
    if len == 0 ||
           *str as libc::c_int != ',' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    /* Ignore extensions. */
    while len > 0 &&
              c_isalpha(*str as libc::c_int) as libc::c_int != 0 &&
              *str as libc::c_int != 'p' as i32 {
        let mut p_1: *const libc::c_char = 0 as *const libc::c_char;
        let mut l_1: size_t = 0;
        str = str.offset(1);
        len = len.wrapping_sub(1);
        if len == 0 ||
               *str as libc::c_int != '=' as i32 {
            return -(1 as libc::c_int)
        }
        str = str.offset(1);
        len = len.wrapping_sub(1);
        p_1 =
            memchr(str as *const libc::c_void, ',' as i32, len) as
                *const libc::c_char;
        if p_1.is_null() { return -(1 as libc::c_int) }
        p_1 = p_1.offset(1);
        l_1 = p_1.offset_from(str) as libc::c_long as size_t;
        if len < l_1 { return -(1 as libc::c_int) }
        str = p_1;
        len = len.wrapping_sub(l_1) as size_t as size_t
    }
    if len == 0 ||
           *str as libc::c_int != 'p' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    /* Sanity check proof. */
    if !memchr(str as *const libc::c_void, '\u{0}' as i32, len).is_null() {
        return -(1 as libc::c_int)
    }
    (*cl).proof =
        malloc(len.wrapping_add(1)) as
            *mut libc::c_char;
    if (*cl).proof.is_null() { return -(1 as libc::c_int) }
    memcpy((*cl).proof as *mut libc::c_void, str as *const libc::c_void, len);
    *(*cl).proof.offset(len as isize) = '\u{0}' as i32 as libc::c_char;
    if !scram_valid_client_final(cl) { return -(1 as libc::c_int) }
    return 0 as libc::c_int;
}
pub unsafe fn scram_parse_server_final(
    mut str: *const libc::c_char,
    mut len: size_t,
    mut sl: *mut scram_server_final,
) -> libc::c_int {
    /* Minimum client final string is 'v=ab=='. */
    if strnlen(str, len) < 6 {
        return -(1 as libc::c_int)
    }
    if len == 0 ||
           *str as libc::c_int != 'v' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    if len == 0 ||
           *str as libc::c_int != '=' as i32 {
        return -(1 as libc::c_int)
    }
    str = str.offset(1);
    len = len.wrapping_sub(1);
    /* Sanity check proof. */
    if !memchr(str as *const libc::c_void, '\u{0}' as i32, len).is_null() {
        return -(1 as libc::c_int)
    }
    (*sl).verifier =
        malloc(len.wrapping_add(1)) as
            *mut libc::c_char;
    if (*sl).verifier.is_null() { return -(1 as libc::c_int) }
    memcpy((*sl).verifier as *mut libc::c_void, str as *const libc::c_void,
           len);
    *(*sl).verifier.offset(len as isize) = '\u{0}' as i32 as libc::c_char;
    if !scram_valid_server_final(sl) { return -(1 as libc::c_int) }
    return 0 as libc::c_int;
}
