use crate::crypto::generate_salt;
use serde::{Deserialize, Serialize};
use validation::Email;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: Email,
    pub salt: String,
    pub hash_password: String,
    pub two_f_a: bool,
    pub yubikey: Vec<u8>,
}

impl Default for User {
    fn default() -> Self {
        User {
            email: Email::default(),
            salt: generate_salt(),
            hash_password: "hash_password".to_string(),
            two_f_a: true,
            yubikey: vec![],
        }
    }
}
