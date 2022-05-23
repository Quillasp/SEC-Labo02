use serde::{Deserialize, Serialize};
use validation::{Email, Password};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: Email,
    pub password: Password,
    pub switch_2fa: bool,
    pub yk_info: Vec<u8>,
}
