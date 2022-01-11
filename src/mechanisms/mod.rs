#[cfg(feature = "anonymous")]
pub mod anonymous {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "cram-md5")]
pub mod cram_md5 {
    pub mod challenge;
    pub mod client;
    pub mod digest;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "digest-md5")]
pub mod digest_md5 {
    pub mod client;
    pub mod digesthmac;
    pub mod free;
    pub mod getsubopt;
    pub mod mechinfo;
    pub mod nonascii;
    pub mod parser;
    pub mod printer;
    pub mod qop;
    pub mod server;
    pub mod session;
    pub mod validate;
}

#[cfg(feature = "external")]
pub mod external {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "login")]
pub mod login {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "openid20")]
pub mod openid20 {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "plain")]
pub mod plain {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(feature = "saml20")]
pub mod saml20 {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

#[cfg(any(feature = "scram-sha-1", feature = "scram-sha-2"))]
pub mod scram {
    pub mod client;
    pub mod mechinfo;
    pub mod parser;
    pub mod printer;
    pub mod server;
    pub mod tokens;
    pub mod tools;
    pub mod validate;
}

#[cfg(feature = "securid")]
pub mod securid {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}