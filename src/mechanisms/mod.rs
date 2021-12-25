pub mod anonymous {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

// mod anonymous
pub mod cram_md5 {
    pub mod challenge;
    pub mod client;
    pub mod digest;
    pub mod mechinfo;
    pub mod server;
}

// mod cram_md5
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

// mod digest_md5
pub mod external {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

// mod gl
pub mod login {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

// mod login
pub mod openid20 {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

// mod openid20
pub mod plain {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}

// mod plain
pub mod saml20 {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
}// mod saml20

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

// mod scram
pub mod securid {
    pub mod client;
    pub mod mechinfo;
    pub mod server;
} // mod securid

