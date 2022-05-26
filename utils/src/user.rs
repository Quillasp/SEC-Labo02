use serde::{Deserialize, Serialize};
use validation::{Email, Password};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: Email,
    pub salt: String,
    pub hash_password: String,
    pub two_f_a: bool,
    pub yubikey: Vec<u8>,
}
