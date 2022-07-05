//! A simplistic fake line-based protocol to showcase how to use rsasl in different contexts.
//!
//! This crate is the protocol implementation, providing higher level abstraction for a protocol
//! to make applications wanting to use that protocol easier to write.
//!
//! The Protocol is line based with ASCII-Space (0x20) used in a line as separator. It's a
//! syncronous client-first protocol meaning that for each line the client sends the server sends
//! one line in return.

use std::str::FromStr;

pub enum ProtocolVerb {
    Hello(String),
    Auth(AuthMessage),
    Echo(String),
    Error(ProtocolError),
}
impl FromStr for ProtocolVerb {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let i = s.find(' ').unwrap_or(s.len());
        let (verb, rest) = s.split_at(i);
        match verb {
            "HELLO" => Ok(Self::Hello(rest.to_string())),
            "AUTH" => Ok(Self::Auth(AuthMessage::from_str(rest)?)),
            "ECHO" => Ok(Self::Echo(rest.to_string())),
            "ERR" => Ok(Self::Error(ProtocolError::from_str(rest)?)),
            _ => Err(()),
        }
    }
}

pub enum ProtocolError {
    SyntaxError(String),
    AuthenticationError(String),
}
impl FromStr for ProtocolError {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let i = s.find(' ').unwrap_or(s.len());
        let (verb, rest) = s.split_at(i);
        match verb {
            "SYN" => Ok(Self::SyntaxError(rest.to_string())),
            "AUTH" => Ok(Self::AuthenticationError(rest.to_string())),
            _ => Err(()),
        }
    }
}

pub enum AuthMessage {
    Start(String, Option<String>),
    Continue(Option<String>),
    Done,
}
impl FromStr for AuthMessage {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut i = s.split(' ');
        let verb = i.next().ok_or(())?;
        let snd = i.next();
        let lst = i.next();
        match verb {
            "START" => {
                if let Some(mech) = snd {
                    Ok(Self::Start(mech.to_string(), lst.map(|s| s.to_string())))
                } else {
                    Err(())
                }
            }
            "CONT" => Ok(Self::Continue(snd.map(|s| s.to_string()))),
            "DONE" => Ok(Self::Done),
            _ => Err(()),
        }
    }
}
