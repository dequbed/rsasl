//! Utilities for handling and validating names of Mechanisms
//!
use std::convert::TryFrom;

use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;
use thiserror::Error;

use crate::mechname::MechanismNameError::InvalidChar;

#[repr(transparent)]
#[derive(Ord, PartialOrd, Eq, PartialEq)]
/// A validated Mechanism name (akin to [`str`])
///
/// This struct, like `str`, is only ever passed by reference since it's `!Sized`. The main
/// reason to have this struct is to ensure at type level and with no run-time overhead that a
/// passed mechanism name was verified.
///
/// The main way to construct a `Mechname` is by calling [`Mechname::new`].
///
/// This type implements `Deref<Target=[u8]>` so it can be used anywhere where `&[u8]` is expected.
/// Alternatively the methods [`Mechname::as_str`] and [`Mechname::as_bytes`] can be used to
/// manually extract a `&str` and `&[u8]` respectively.
///
/// Note: While RFC 4422 Section 3.1 explicitly limits Mechanism name to 20 characters or less you
/// **SHOULD NOT** rely on this behaviour as there are mechanisms in use that break this
/// rule, e.g. `ECDSA-NIST256P-CHALLENGE` (25 chars) used by some IRCv3 implementations.
pub struct Mechname {
    inner: [u8],
}

impl Mechname {
    /// Convert a byte slice into a `&Mechname` after checking it for validity.
    ///
    ///
    pub fn new(input: &[u8]) -> Result<&Mechname, MechanismNameError> {
        if input.len() < 1 {
            Err(MechanismNameError::TooShort)
        } else {
            let len = input.iter().try_fold(0usize, |index, value| {
                if is_invalid(*value) {
                    Err(InvalidChar {
                        index,
                        value: *value,
                    })
                } else {
                    Ok(index + 1)
                }
            })?;
            // The above fold should have run for *all* bytes in input and thus the index should
            // be equivalent to the length of the input
            debug_assert_eq!(len, input.len());

            Ok(Self::const_new(input))
        }
    }


    #[inline(always)]
    /// Convert a `&[u8]` into an `&Mechname` without checking validity.
    ///
    /// Like [`Mechname::const_new_unchecked`] this is not marked `unsafe` because it is save
    /// from a Memory protection POV, and does not validate the implicit UTF-8 assertion of
    /// Rust, it just potentially may result in (memory-safe!) bugs if the given slice contains
    /// invalid bytes.
    pub fn new_unchecked(input: &[u8]) -> &Mechname {
        Self::const_new(input)
    }

    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.inner) }
    }

    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub(crate) const fn const_new(s: &[u8]) -> &Mechname {
        unsafe { std::mem::transmute(s) }
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

impl Display for Mechname {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Debug for Mechname {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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

impl<'a> TryFrom<&'a [u8]> for &'a Mechname {
    type Error = MechanismNameError;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Mechname::new(value)
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
    // VALID characters are one of A-Z, 0-9 or - or _
    byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Error)]
pub enum MechanismNameError {
    /// Mechanism name shorter than 1 character
    #[error("can not be the empty string")]
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
            "SCRAM-SHA256-PLUS GSSAPI X-OAUTH2",
        ];
        let invalidchars = [
            ("PLAIN GSSAPI LOGIN", 6, b' '),
            ("X-CONTAINS-NULL\0", 16, b'\0'),
            ("PLAIN\0", 6, b'\0'),
            ("X-lowercase", 3, b'l'),
            ("X-LÄTIN1", 4, b'\xC3'),
        ];

        for m in valids {
            println!("Checking {}", m);
            let res = Mechname::new(m.as_bytes()).map(|m| m.as_bytes());
            assert_eq!(res, Ok(m.as_bytes()));
        }
        for (m, index, value) in invalidchars {
            let e = Mechname::new(m.as_bytes())
                .map(|m| m.as_bytes())
                .unwrap_err();
            println!("Checking {}: {}", m, e);
            assert_eq!(e, MechanismNameError::InvalidChar {
                index, value
            })
        }
    }
}
