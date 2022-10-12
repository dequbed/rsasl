use digest::crypto_common::BlockSizeUser;
use digest::generic_array::GenericArray;
use digest::{Digest, FixedOutput, FixedOutputReset, Mac, OutputSizeUser, Update};
use hmac::SimpleHmac;
use rand::distributions::{Distribution, Slice};
use rand::Rng;

/// All the characters that are valid chars for a nonce
pub(super) const PRINTABLE: &[u8] =
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

#[allow(clippy::too_many_arguments)]
pub fn compute_signatures<D: Digest + BlockSizeUser + FixedOutput>(
    stored_key: &GenericArray<u8, D::OutputSize>,
    server_key: &DOutput<D>,
    username: &str,
    client_nonce: &[u8],
    server_nonce: &[u8],
    salt: &[u8],
    iterations: &[u8],
    channel_binding: &[u8],
    client_signature: &mut DOutput<D>,
    server_signature: &mut DOutput<D>,
) {
    <SimpleHmac<D>>::new_from_slice(stored_key.as_slice())
        .expect("HMAC can work with any key size")
        .chain(b"n=")
        .chain(username.as_bytes())
        .chain(b",r=")
        .chain(client_nonce)
        .chain(b",r=")
        .chain(client_nonce)
        .chain(server_nonce)
        .chain(",s=")
        .chain(salt)
        .chain(",i=")
        .chain(iterations)
        .chain(b",c=")
        .chain(channel_binding)
        .chain(b",r=")
        .chain(client_nonce)
        .chain(server_nonce)
        .finalize_into(client_signature);

    <SimpleHmac<D>>::new_from_slice(server_key.as_slice())
        .expect("HMAC can work with any key size")
        .chain(b"n=")
        .chain(username.as_bytes())
        .chain(b",r=")
        .chain(client_nonce)
        .chain(b",r=")
        .chain(client_nonce)
        .chain(server_nonce)
        .chain(",s=")
        .chain(salt)
        .chain(",i=")
        .chain(iterations)
        .chain(b",c=")
        .chain(channel_binding)
        .chain(b",r=")
        .chain(client_nonce)
        .chain(server_nonce)
        .finalize_into(server_signature);
}

#[must_use]
pub fn derive_keys<D>(password: &[u8]) -> (DOutput<D>, DOutput<D>)
where
    D: Digest + BlockSizeUser + FixedOutputReset,
{
    // todo: I technically do know that password can only be valid if it's of the
    //       exact size. (i.e. use KeyInit's new() here)
    let mut key_hmac =
        <SimpleHmac<D>>::new_from_slice(password).expect("HMAC should work with every key length");

    Mac::update(&mut key_hmac, b"Client Key");
    let client_key = key_hmac.finalize_reset().into_bytes();

    Mac::update(&mut key_hmac, b"Server Key");
    let server_key = key_hmac.finalize().into_bytes();

    (client_key, server_key)
}
