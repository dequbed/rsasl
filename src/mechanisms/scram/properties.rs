use crate::property::{Property, SizedProperty};

pub struct HashIterations;
impl SizedProperty for HashIterations {
    type Value = u32;
}

pub struct Salt;
impl Property for Salt {
    type Value = [u8];
}

pub struct PasswordHash;
impl Property for PasswordHash {
    type Value = [u8];
}
