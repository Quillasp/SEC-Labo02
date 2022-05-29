use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Error {
    AuthFailed,
    InvalidEmail,
    UserAlreadyExist,
    TwoFAFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> core::result::Result<(), fmt::Error> {
        match self {
            Self::AuthFailed => write!(f, "Authentication failed"),
            Self::InvalidEmail => write!(f, "Invalid email"),
            Self::UserAlreadyExist => write!(f, "User already exists"),
            Self::TwoFAFailed => write!(f, "2FA Failed"),
        }
    }
}

impl std::error::Error for Error {}
