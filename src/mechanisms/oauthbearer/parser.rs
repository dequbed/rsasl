use acid_io::Write;

pub enum ParseError {
    MissingPart,
    MissingEnd,
    MissingToken,
    InvalidGs2,
    ChannelBindings,
    InvalidKVPair,
}

pub struct OAuthBearerMsg<'a> {
    authzid: Option<&'a [u8]>,
    token: &'a [u8],
    fields: Vec<(&'a [u8], &'a [u8])>,
}

impl<'a> OAuthBearerMsg<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        // Make sure the token isn't trimmed but contains the end bytes
        if let Some(bytes) = bytes.strip_suffix(b"\x01\x01") {
            let mut it = bytes.split(|b| matches!(b, b'\x01'));
            let gs2 = it.next().ok_or(ParseError::MissingPart)?;
            let mut gs2iter = gs2.split(|b| matches!(b, b','));
            let gs2_first = gs2iter.next().ok_or(ParseError::InvalidGs2)?;
            if gs2_first != b"n" {
                return Err(ParseError::ChannelBindings);
            }
            let gs2_authzid = gs2iter.next().ok_or(ParseError::InvalidGs2)?;

            let authzid = if !gs2_authzid.is_empty() {
                if let Some(rem) = gs2_authzid.strip_prefix(b"a=") {
                    Some(rem)
                } else {
                    return Err(ParseError::InvalidGs2);
                }
            } else {
                None
            };

            let mut token = None;
            let mut fields = Vec::new();

            for kv in it {
                if let Some(t) = kv.strip_prefix(b"auth=") {
                    token = Some(t);
                } else {
                    let mut kviter = kv.split(|b| matches!(b, b'='));
                    let key = kviter.next().ok_or(ParseError::InvalidKVPair)?;
                    let val = kviter.next().ok_or(ParseError::InvalidKVPair)?;
                    if kviter.next().is_some() {
                        return Err(ParseError::InvalidKVPair);
                    }
                    fields.push((key, val));
                }
            }

            let token = token.ok_or(ParseError::MissingToken)?;
            Ok(Self {
                authzid,
                token,
                fields,
            })
        } else {
            Err(ParseError::MissingEnd)
        }
    }

    pub fn write_into(&self, w: &mut impl Write) -> acid_io::Result<()> {
        w.write_all(b"n,")?;
        if let Some(authzid) = self.authzid {
            w.write_all(b"a=")?;
            w.write_all(authzid)?;
        }
        w.write_all(b",")?;

        for (k,v) in self.fields.iter() {
            w.write_all(b"\x01")?;
            w.write_all(k)?;
            w.write_all(b"=")?;
            w.write_all(v)?;
        }
        w.write_all(b"\x01auth=")?;
        w.write_all(self.token)?;

        w.write_all(b"\x01\x01")?;
        Ok(())
    }
}