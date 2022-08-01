use crate::property::{Property, SizedProperty};

pub struct HashIterations;
impl SizedProperty<'_> for HashIterations {
    type Value = u32;
}

pub struct Salt;
impl Property<'_> for Salt {
    type Value = [u8];
}

pub struct PasswordHash;
impl Property<'_> for PasswordHash {
    type Value = [u8];
}
