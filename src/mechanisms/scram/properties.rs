use crate::property::{Property, SizedProperty};

pub struct Iterations;
impl SizedProperty<'_> for Iterations {
    type Value = u32;
}

pub struct Salt;
impl Property<'_> for Salt {
    type Value = [u8];
}

pub struct AlgorithmName;
impl Property<'_> for AlgorithmName {
    type Value = str;
}

pub struct ScramStoredPassword<'a> {
    pub iterations: u32,
    pub salt: &'a [u8],
    pub stored_key: &'a [u8],
    pub server_key: &'a [u8],
}
impl<'a> Property<'a> for ScramStoredPassword<'static> {
    type Value = ScramStoredPassword<'a>;
}

pub struct ScramCachedPassword<'a> {
    pub client_key: &'a [u8],
    pub server_key: &'a [u8],
}
impl<'a> Property<'a> for ScramCachedPassword<'static> {
    type Value = ScramCachedPassword<'a>;
}

pub struct SaltedPassword;
impl Property<'_> for SaltedPassword {
    type Value = [u8];
}