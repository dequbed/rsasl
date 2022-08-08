//! Utilities for handling and validating names of Mechanisms
//!
use core::convert::TryFrom;

use core::fmt;
use core::ops::Deref;
use thiserror::Error;

use crate::mechname::MechanismNameError::InvalidChar;

#[repr(transparent)]
#[derive(Eq, PartialEq)]
/// A validated Mechanism name (akin to [`str`])
///
/// This struct, like `str`, is only ever passed by reference since it's `!Sized`. The main
/// reason to have this struct is to ensure at type level and with no run-time overhead that a
/// passed mechanism name was verified.
///
/// The main way to construct a `Mechname` is by calling [`Mechname::parse`].
///
/// This type implements `Deref<Target=str>` so it can be used anywhere where `&str` is expected.
/// Alternatively the methods [`Mechname::as_str`] and [`Mechname::as_bytes`] can be used to
/// manually extract a `&str` and `&[u8]` respectively.
///
/// Note: While RFC 4422 Section 3.1 explicitly limits Mechanism name to 20 characters or less you
/// **SHOULD NOT** rely on this behaviour as there are mechanisms in use that break this
/// rule, e.g. `ECDSA-NIST256P-CHALLENGE` (25 chars) used by some IRCv3 implementations.
pub struct Mechname {
    inner: str,
}

impl Mechname {
    /// Convert a byte slice into a `&Mechname` after checking it for validity.
    ///
    ///
    pub fn parse(input: &[u8]) -> Result<&Mechname, MechanismNameError> {
        if input.is_empty() {
            Err(MechanismNameError::TooShort)
        } else {
            input.iter().enumerate().try_for_each(|(index, value)| {
                if is_invalid(*value) {
                    Err(InvalidChar {
                        index,
                        value: *value,
                    })
                } else {
                    Ok(())
                }
            })?;
            Ok(Self::const_new(input))
        }
    }

    #[must_use]
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    #[must_use]
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    pub(crate) const fn const_new(s: &[u8]) -> &Mechname {
        unsafe { core::mem::transmute(s) }
    }
}

#[cfg(feature = "unstable_custom_mechanism")]
/// These associated functions are only available with feature `unstable_custom_mechanism`. They
/// are *not guaranteed to be stable under semver*
impl Mechname {
    #[inline(always)]
    /// `const` capable conversion from `&'a [u8]` to `&'a Mechname` with no validity checking.
    ///
    /// While this is safe from a memory protection standpoint since `&Mechname` and `&[u8]` have
    /// the exact same representation it can be used to break the contract of `Mechname` only
    /// containing a subset of ASCII, which may result in undefined behaviour.
    ///
    /// Uses transmute due to [rustc issue #51911](https://github.com/rust-lang/rust/issues/51911)
    pub const fn const_new_unchecked(s: &[u8]) -> &Mechname {
        Self::const_new(s)
    }
}

impl fmt::Display for Mechname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Mechname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MECHANISM({})", self.as_str())
    }
}

impl PartialEq<[u8]> for Mechname {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_bytes() == other
    }
}
impl PartialEq<Mechname> for [u8] {
    fn eq(&self, other: &Mechname) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<str> for Mechname {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}
impl PartialEq<Mechname> for str {
    fn eq(&self, other: &Mechname) -> bool {
        self == other.as_str()
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a Mechname {
    type Error = MechanismNameError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Mechname::parse(value)
    }
}

impl<'a> TryFrom<&'a str> for &'a Mechname {
    type Error = MechanismNameError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Mechname::parse(value.as_bytes())
    }
}

impl Deref for Mechname {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[inline(always)]
const fn is_invalid(byte: u8) -> bool {
    !(is_valid(byte))
}

#[inline(always)]
const fn is_valid(byte: u8) -> bool {
    // RFC 4422 section 3.1 limits mechanism names to:
    //     sasl-mech    = 1*20mech-char
    //     mech-char    = UPPER-ALPHA / DIGIT / HYPHEN / UNDERSCORE
    //     ; mech-char is restricted to A-Z (uppercase only), 0-9, -, and _
    //     ; from ASCII character set.
    core::matches!(byte, b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_')
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Error)]
pub enum MechanismNameError {
    /// Mechanism name is shorter than 1 character
    #[error("a mechanism name can not be empty")]
    TooShort,

    /// Mechanism name contained a character outside of [A-Z0-9-_] at `index`
    ///
    ///
    #[error("contains invalid character at offset {index}: {value:#x}")]
    InvalidChar {
        /// Index of the invalid character byte
        index: usize,
        /// Value of the invalid character byte
        value: u8,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mechname() {
        let valids = [
            "PLAIN",
            "SCRAM-SHA256-PLUS",
            "GS2-KRB5-PLUS",
            "XOAUTHBEARER",
            "EXACTLY_20_CHAR_LONG",
            "X-THIS-MECHNAME-IS-TOO-LONG",
            "EXACTLY_21_CHARS_LONG",
        ];
        let invalidchars = [
            ("PLAIN GSSAPI LOGIN", 5, b' '),
            ("SCRAM-SHA256-PLUS GSSAPI X-OAUTH2", 17, b' '),
            ("X-CONTAINS-NULL\0", 15, b'\0'),
            ("PLAIN\0", 5, b'\0'),
            ("X-lowercase", 2, b'l'),
            ("X-LÄTIN1", 3, b'\xC3'),
        ];

        for m in valids {
            println!("Checking {}", m);
            let res = Mechname::parse(m.as_bytes()).map(|m| m.as_bytes());
            assert_eq!(res, Ok(m.as_bytes()));
        }
        for (m, index, value) in invalidchars {
            let e = Mechname::parse(m.as_bytes())
                .map(|m| m.as_bytes())
                .unwrap_err();
            println!("Checking {}: {}", m, e);
            assert_eq!(e, MechanismNameError::InvalidChar { index, value })
        }
    }
}
