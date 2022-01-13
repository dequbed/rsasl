use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;
use crate::error::MechanismNameError;
use crate::error::MechanismNameError::{InvalidChars, TooLong, TooShort};

#[repr(transparent)]
#[derive(Ord, PartialOrd, Eq, PartialEq)]
/// A validated Mechanism name (akin to [`str`])
///
/// This struct, like `str`, is only ever passed by reference since it's `!Sized`. The main
/// reason to have this struct is to ensure at type level and with no run-time overhead that a
/// passed mechanism name was verified.
///
/// The main way to construct a `&Mechanism` is by calling [`Mechanism::new`]. This type
/// implements `Deref<Target=str>` so it can be used anywhere where `&str` is expected.
pub struct Mechname {
    inner: str,
}

impl Mechname {
    /// `const` capable conversion from `&'a str` to `&'a Mechname`. This is safe from a memory
    /// protection standpoint since `&Mechname` and `&str` have the exact same representation but
    /// it can be used to break the contract of `Mechname` which may result in undefined behaviour.
    ///
    /// Uses transmute due to [rustc issue #51911](https://github.com/rust-lang/rust/issues/51911)
    pub const fn const_new_unchecked(s: &str) -> &Mechname {
        unsafe { std::mem::transmute(s) }
    }

    pub(crate) fn new_unchecked<S: AsRef<str> + ?Sized>(s: &S) -> &Mechname {
        unsafe { &*(s.as_ref() as *const str as *const Mechname) }
    }

    pub fn new(input: &[u8]) -> Result<&Mechname, MechanismNameError> {
        let input = input.as_ref();
        if input.len() < 1 {
            Err(TooShort)
        } else if input.len() > 20 {
            Err(TooLong)
        } else {
            if let Some(byte) = input.iter().find(|byte| is_invalid(*byte)) {
                Err(InvalidChars(*byte))
            } else {
                let s = unsafe {
                    // Safety: We just checked the entire string for a subset of ASCII so anything
                    // getting here is guaranteed valid ASCII and thus also guaranteed valid UTF-8
                    std::str::from_utf8_unchecked(input)
                };
                Ok(Mechname::new_unchecked(s))
            }
        }
    }

    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
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
        Mechname::new(value)
    }
}

impl Deref for Mechname {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

pub fn try_parse_mechanism_lenient(input: &[u8]) -> Result<&Mechname, MechanismNameError> {
    if input.len() < 1 {
        Err(TooShort)
    } else {
        if let Some(subslice) = input.split(is_invalid).next() {
            Mechname::new(subslice)
        } else {
            Err(InvalidChars(input[0]))
        }
    }
}

pub fn is_invalid(byte: &u8) -> bool {
    let byte = *byte;
    let isLet = byte.is_ascii_uppercase();
    let is_num = byte.is_ascii_digit();
    let is_sym = byte == b'-' || byte == b'_';

    !(isLet || is_num || is_sym)
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
        ];
        let toolong = [
            "X-THIS-MECHNAME-IS-TOO-LONG",
            "EXACTLY_21_CHARS_LONG",
            "SCRAM-SHA256-PLUS GSSAPI X-OAUTH2",
        ];
        let invalidchars = [
            ("PLAIN GSSAPI LOGIN", b' '),
            ("X-CONTAINS-NULL\0", b'\0'),
            ("PLAIN\0", b'\0'),
            ("X-lowercase", b'l'),
            ("X-LÄTIN1", b'\xC3'),
        ];

        for m in valids {
            println!("Checking {}", m);
            let res = Mechname::new(m.as_bytes())
                .map(|m| m.as_bytes());
            assert_eq!(res, Ok(m.as_bytes()));
        }
        for m in toolong {
            let e = Mechname::new(m.as_bytes())
                .map(|m| m.as_bytes())
                .unwrap_err();
            println!("Checking {}: {}", m, e);
            assert_eq!(e, TooLong);
        }
        for (m, bad) in invalidchars {
            let e = Mechname::new(m.as_bytes())
                .map(|m| m.as_bytes())
                .unwrap_err();
            println!("Checking {}: {}", m, e);
            assert_eq!(e, InvalidChars(bad))
        }
    }
}