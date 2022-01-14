use crate::SASL;

pub(crate) fn register_builtin(ctx: &mut SASL) {
    #[cfg(feature = "plain")] {
        let m = &crate::mechanisms::plain::mechinfo::PLAIN;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    #[cfg(feature = "login")] {
        let m = &crate::mechanisms::login::mechinfo::LOGIN;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    #[cfg(feature = "anonymous")] {
        let m = &crate::mechanisms::anonymous::mechinfo::ANONYMOUS;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    #[cfg(feature = "external")] {
        let m = &crate::mechanisms::external::mechinfo::EXTERNAL;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    #[cfg(feature = "saml20")] {
        let m = &crate::mechanisms::saml20::mechinfo::SAML20;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    #[cfg(feature = "securid")] {
        let m = &crate::mechanisms::securid::mechinfo::SECURID;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    /* USE_NTLM */

    #[cfg(feature = "digest-md5")] {
        let m = &crate::mechanisms::digest_md5::mechinfo::DIGEST_MD5;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    #[cfg(feature = "cram-md5")] {
        let m = &crate::mechanisms::cram_md5::mechinfo::CRAM_MD5;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    #[cfg(feature = "scram-sha-1")] {
        let m = &crate::mechanisms::scram::mechinfo::SCRAM_SHA1;
        let n = &crate::mechanisms::scram::mechinfo::SCRAM_SHA1_PLUS;
        #[cfg(feature = "registry_dynamic")] {
            ctx.register(m);
            ctx.register(n);
        }
    }

    #[cfg(feature = "scram-sha-2")] {
        let m = &crate::mechanisms::scram::mechinfo::SCRAM_SHA256;
        let n = &crate::mechanisms::scram::mechinfo::SCRAM_SHA256_PLUS;
        #[cfg(feature = "registry_dynamic")] {
            ctx.register(m);
            ctx.register(n);
        }
    }

    #[cfg(feature = "openid20")] {
        let m = &crate::mechanisms::openid20::mechinfo::OPENID20;
        #[cfg(feature = "registry_dynamic")]
            ctx.register(m);
    }

    /* USE_GSSAPI */
}
