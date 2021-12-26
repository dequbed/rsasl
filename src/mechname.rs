use crate::error::MechanismNameError;
use crate::error::MechanismNameError::{InvalidChars, TooLong, TooShort};

pub fn try_parse_mechanism(input: &[u8]) -> Result<&[u8], MechanismNameError> {
    let input = input.as_ref();
    if input.len() < 1 {
        Err(TooShort)
    } else if input.len() > 20 {
        Err(TooLong)
    } else {
        if let Some(byte) = input.iter().find(|byte| is_invalid(*byte)) {
            Err(InvalidChars(*byte))
        } else {
            Ok(input)
        }
    }
}

pub fn try_parse_mechanism_lenient(input: &[u8]) -> Result<&[u8], MechanismNameError> {
    if input.len() < 1 {
        Err(TooShort)
    } else {
        if let Some(subslice) = input.split(is_invalid).next() {
            try_parse_mechanism(subslice)
        } else {
            Err(InvalidChars(input[0]))
        }
    }
}

pub fn is_invalid(byte: &u8) -> bool {
    let byte = *byte;
    let isLet = byte.is_ascii_uppercase();
    let isNum = byte.is_ascii_digit();
    let isSym = byte == b'-' || byte == b'_';

    !(isLet || isNum || isSym)
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
            assert_eq!(try_parse_mechanism(m.as_bytes()), Ok(m.as_bytes()));
        }
        for m in toolong {
            let e = try_parse_mechanism(m.as_bytes()).unwrap_err();
            println!("Checking {}: {}", m, e);
            assert_eq!(e, TooLong);
        }
        for (m, bad) in invalidchars {
            let e = try_parse_mechanism(m.as_bytes()).unwrap_err();
            println!("Checking {}: {}", m, e);
            assert_eq!(e, InvalidChars(bad))
        }
    }

    #[test]
    fn test_mechname_lenient() {
        let ugly = [
            ("PLAIN\0", "PLAIN"),
            ("SCRAM-SHA256-PLUS GSSAPI X-OAUTH2", "SCRAM-SHA256-PLUS"),
            ("PLAIN GSSAPI LOGIN", "PLAIN"),
        ];
        for (m, out) in ugly {
            println!("Checking {}", m);
            assert_eq!(try_parse_mechanism_lenient(m.as_bytes()), Ok(out.as_bytes()));
        }
    }
}