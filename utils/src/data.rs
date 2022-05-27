use serde::{Deserialize, Serialize};
use validation::{Email, Password};

// Register
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterData {
    pub email: Email,
    pub password: Password,
    pub yubikey: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmailData {
    pub email: Email,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChallengeData {
    pub salt: String,
    pub challenge: [u8; 16],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HmacData {
    pub hmac: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerMessage {
    pub message: String,
    pub success: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerMessage2FA {
    pub message: String,
    pub success: bool,
    pub two_f_a: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Switch2FA {
    pub two_f_a: bool,
}
