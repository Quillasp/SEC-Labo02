use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Messages {
    UserRegistered,
    AuthTo2FA,
    AuthSuccess,
    YubiKeyPubInfo,
}

impl fmt::Display for Messages {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserRegistered => write!(f, "User registered"),
            Self::AuthTo2FA => write!(f, "Proceeding with the 2FA"),
            Self::AuthSuccess => write!(f, "Authentication success"),
            Self::YubiKeyPubInfo => write!(f, "Proceeding with the YubiKey"),
        }
    }
}
