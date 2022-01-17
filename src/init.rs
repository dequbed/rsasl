use crate::SASL;

pub(crate) fn register_builtin(_ctx: &mut SASL) {
    #[cfg(feature = "plain")] {
        let _m = &crate::mechanisms::plain::mechinfo::PLAIN;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    #[cfg(feature = "login")] {
        let _m = &crate::mechanisms::login::mechinfo::LOGIN;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    #[cfg(feature = "anonymous")] {
        let _m = &crate::mechanisms::anonymous::mechinfo::ANONYMOUS;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    #[cfg(feature = "external")] {
        let _m = &crate::mechanisms::external::mechinfo::EXTERNAL;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    #[cfg(feature = "saml20")] {
        let _m = &crate::mechanisms::saml20::mechinfo::SAML20;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    #[cfg(feature = "securid")] {
        let _m = &crate::mechanisms::securid::mechinfo::SECURID;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    /* USE_NTLM */

    #[cfg(feature = "digest-md5")] {
        let _m = &crate::mechanisms::digest_md5::mechinfo::DIGEST_MD5;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    #[cfg(feature = "cram-md5")] {
        let _m = &crate::mechanisms::cram_md5::mechinfo::CRAM_MD5;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    #[cfg(feature = "scram-sha-1")] {
        let _m = &crate::mechanisms::scram::mechinfo::SCRAM_SHA1;
        let _n = &crate::mechanisms::scram::mechinfo::SCRAM_SHA1_PLUS;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))] {
            _ctx.register(_m);
            _ctx.register(_n);
        }
    }

    #[cfg(feature = "scram-sha-2")] {
        let _m = &crate::mechanisms::scram::mechinfo::SCRAM_SHA256;
        let _n = &crate::mechanisms::scram::mechinfo::SCRAM_SHA256_PLUS;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))] {
            _ctx.register(_m);
            _ctx.register(_n);
        }
    }

    #[cfg(feature = "openid20")] {
        let _m = &crate::mechanisms::openid20::mechinfo::OPENID20;
        #[cfg(all(feature = "registry_dynamic", not(feature = "registry_static")))]
            _ctx.register(_m);
    }

    /* USE_GSSAPI */
}
