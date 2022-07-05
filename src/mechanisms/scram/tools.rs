use crate::mechanisms::scram::parser::ServerFirst;
use digest::crypto_common::BlockSizeUser;
use digest::generic_array::GenericArray;
use digest::{Digest, Mac, OutputSizeUser};
use hmac::SimpleHmac;
use rand::distributions::{Distribution, Slice};
use rand::Rng;

/// All the characters that are valid chars for a nonce
pub(super) const PRINTABLE: &'static [u8] =
    b"!\"#$%&'()*+-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy";

pub(super) fn generate_nonce<const N: usize>(rng: &mut impl Rng) -> [u8; N] {
    let distribution = Slice::new(PRINTABLE).unwrap();
    [0u8; N].map(|_| *distribution.sample(rng))
}

pub(super) type DOutput<D> = GenericArray<u8, <SimpleHmac<D> as OutputSizeUser>::OutputSize>;

pub fn hash_password<D>(password: &[u8], iterations: u32, salt: &[u8], out: &mut DOutput<D>)
where
    D: Digest + BlockSizeUser + Clone + Sync,
{
    pbkdf2::pbkdf2::<SimpleHmac<D>>(password, salt, iterations, out.as_mut_slice());
}

pub fn find_proofs<D>(
    username: &str,
    client_nonce: &[u8],
    server_first: ServerFirst<'_>,
    gs2headerb64: &str,
    salted_password_hash: &DOutput<D>,
) -> (DOutput<D>, DOutput<D>)
where
    D: Digest + BlockSizeUser,
{
    let mut salted_password_hmac = <SimpleHmac<D>>::new_from_slice(salted_password_hash)
        .expect("HMAC can work with any key size");
    salted_password_hmac.update(b"Client Key");
    let mut client_key = salted_password_hmac.finalize().into_bytes();

    let mut salted_password_hmac = <SimpleHmac<D>>::new_from_slice(salted_password_hash)
        .expect("HMAC can work with any key size");
    salted_password_hmac.update(b"Server Key");
    let server_key = salted_password_hmac.finalize().into_bytes();

    let stored_key = D::digest(client_key.as_ref());

    let ServerFirst {
        nonce,
        server_nonce,
        ..
    } = server_first;
    let server_first_parts = server_first.to_ioslices();
    let auth_message_parts: [&[u8]; 17] = [
        b"n=",
        username.as_bytes(),
        b",r=",
        client_nonce,
        b",",
        server_first_parts[0],
        server_first_parts[1],
        server_first_parts[2],
        server_first_parts[3],
        server_first_parts[4],
        server_first_parts[5],
        server_first_parts[6],
        b",c=",
        gs2headerb64.as_bytes(),
        b",r=",
        nonce,
        server_nonce.unwrap_or(&[]),
    ];

    let mut stored_key_hmac = <SimpleHmac<D>>::new_from_slice(stored_key.as_ref())
        .expect("HMAC can work with any key size");
    for part in auth_message_parts {
        stored_key_hmac.update(part);
    }
    let client_signature = stored_key_hmac.finalize().into_bytes();

    // Client Key => Client Proof
    {
        let client_key_mut = client_key.as_mut();
        client_key_mut
            .iter_mut()
            .zip(client_signature.iter())
            .for_each(|(a, b)| *a ^= b);
    }

    let mut server_key_hmac = <SimpleHmac<D>>::new_from_slice(server_key.as_ref())
        .expect("HMAC can work with any key size");
    for part in auth_message_parts {
        server_key_hmac.update(part);
    }
    let server_signature = server_key_hmac.finalize().into_bytes();

    (client_key, server_signature)
}
