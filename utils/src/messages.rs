use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Messages {
    AuthSuccess,
    AuthTo2FA,
    EmailMessage,
    EmailSent,
    EmailSubject,
    UserRegistered,
    UuidSuccess,
    YubiKeyPubInfo,
}

impl fmt::Display for Messages {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthSuccess => write!(f, "Authentication success"),
            Self::AuthTo2FA => write!(f, "Proceeding with the 2FA"),
            Self::EmailMessage => write!(f, "You can reset your password with the provided token"),
            Self::EmailSent => write!(f, "An email was sent to your address"),
            Self::EmailSubject => write!(f, "Reset your password"),
            Self::UserRegistered => write!(f, "User registered"),
            Self::UuidSuccess => write!(f, "Correct UUID"),
            Self::YubiKeyPubInfo => write!(f, "Proceeding with the YubiKey"),
        }
    }
}
