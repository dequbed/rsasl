use crate::error::MechanismNameError;
use crate::error::MechanismNameError::{InvalidChars, TooLong, TooShort};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;

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
    inner: [u8],
}

impl Mechname {
    /// `const` capable conversion from `&'a str` to `&'a Mechname`. This is safe from a memory
    /// protection standpoint since `&Mechname` and `&str` have the exact same representation but
    /// it can be used to break the contract of `Mechname` which may result in undefined behaviour.
    /// This function uses const parameters to check the length of the passed Mechanism and will
    /// fail to compile (with a rather cryptic message) when passed a `const [u8]` that's shorter
    /// than 1 char or longer than 20.
    ///
    /// Uses transmute due to [rustc issue #51911](https://github.com/rust-lang/rust/issues/51911)
    pub const fn const_new_unchecked<const LEN: usize>(s: &'static [u8; LEN]) -> &Mechname
    where
        CheckLen<LEN>: IsOk,
    {
        let r: &'static [u8] = s;
        unsafe { std::mem::transmute(r) }
    }

    pub(crate) fn new_unchecked<S: AsRef<[u8]> + ?Sized>(s: &S) -> &Mechname {
        unsafe { &*(s.as_ref() as *const [u8] as *const Mechname) }
    }

    pub fn new(input: &[u8]) -> Result<&Mechname, MechanismNameError> {
        if input.len() < 1 {
            Err(TooShort)
        } else if input.len() > 20 {
            Err(TooLong)
        } else {
            if let Some(byte) = input.iter().find(|byte| is_invalid(*byte)) {
                Err(InvalidChars(*byte))
            } else {
                Ok(Mechname::new_unchecked(input))
            }
        }
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

pub trait IsOk {}
pub struct CheckLen<const N: usize>;
impl IsOk for CheckLen<1> {}
impl IsOk for CheckLen<2> {}
impl IsOk for CheckLen<3> {}
impl IsOk for CheckLen<4> {}
impl IsOk for CheckLen<5> {}
impl IsOk for CheckLen<6> {}
impl IsOk for CheckLen<7> {}
impl IsOk for CheckLen<8> {}
impl IsOk for CheckLen<9> {}
impl IsOk for CheckLen<10> {}
impl IsOk for CheckLen<11> {}
impl IsOk for CheckLen<12> {}
impl IsOk for CheckLen<13> {}
impl IsOk for CheckLen<14> {}
impl IsOk for CheckLen<15> {}
impl IsOk for CheckLen<16> {}
impl IsOk for CheckLen<17> {}
impl IsOk for CheckLen<18> {}
impl IsOk for CheckLen<19> {}
impl IsOk for CheckLen<20> {}

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
            let res = Mechname::new(m.as_bytes()).map(|m| m.as_bytes());
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
