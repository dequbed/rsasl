use std::iter::{FromIterator, IntoIterator};
use crate::buffer::SaslString;

/// A String representing a list of Mechanisms
///
/// Gsasl uses the concept of 'string of Mechanism, separated by invalid characters such as SPC' in
/// several locations. This struct allows to easier de-/construct of such values.
pub struct Mechanisms {
    inner: Alloc,
}

/// The allocation source.
///
/// If gsasl allocated the string it should be used to free it again, if Rust allocated it then
/// gsasl must not be used to free it.
enum Alloc {
    Rust(String),
    Gsasl(SaslString),
}

impl Mechanisms {
    pub fn from_sasl(inner: SaslString) -> Self {
        Self { inner: Alloc::Gsasl(inner) }
    }

    /// Iterate over the mechanism names
    pub fn iter(&self) -> impl Iterator<Item=&str> {
        let s = match self.inner {
            // If gsasl returns a mechanism that is not valid UTF-8 that is a rather grievous bug
            // we can't really handle.
            Alloc::Gsasl(ref s) => s.to_str().unwrap(),
            Alloc::Rust(ref s) => s,
        };

        s.split_ascii_whitespace()
    }

    pub fn as_slice(&self) -> &[u8] {
        match self.inner {
            Alloc::Gsasl(ref s) => s.to_bytes(),
            Alloc::Rust(ref s) => s.as_bytes(),
        }
    }

    /// Convert the Mechanism List into a C pointer
    pub fn as_raw_ptr(&self) -> *const libc::c_char {
        match self.inner {
            Alloc::Gsasl(ref s) => s.as_raw_ptr() as *const libc::c_char,
            Alloc::Rust(ref s) => s.as_ptr() as *const libc::c_char,
        }
    }
}

impl<B: AsRef<str>> FromIterator<B> for Mechanisms {
    fn from_iter<I: IntoIterator<Item=B>>(iter: I) -> Self {
        let mut buf = String::new();

        for m in iter {
            buf.push_str(m.as_ref());
            buf.push(' ');
        }
        // Remove the last space
        buf.pop();

        Self { inner: Alloc::Rust(buf) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_iter_test() {
        let mechs = ["PLAIN", "SCRAM-SHA1", "GSSAPI"];

        let m: Mechanisms = mechs.iter().collect();

        assert_eq!(m.as_slice(), b"PLAIN SCRAM-SHA1 GSSAPI");

    }
}
