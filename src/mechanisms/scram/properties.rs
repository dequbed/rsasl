use crate::property::{MaybeSizedProperty, Property};

pub struct HashIterations;
impl Property for HashIterations {
    type Value = u32;
}

pub struct Salt;
impl MaybeSizedProperty for Salt {
    type Value = [u8];
}

pub struct PasswordHash;
impl MaybeSizedProperty for PasswordHash {
    type Value = [u8];
}
