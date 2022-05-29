use std::str::FromStr;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
lazy_static! {
    static ref EMAIL_RULE: Regex = Regex::new(
        // r"^[a-zA-Z0-9_+&*-]+(\.[a-zA-Z0-9_+&*-]+)*@([a-zA-Z0-9_+&*-]+\.)+[a-zA-Z]{2,7}$"
        r#"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"#
    )
    .unwrap();
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Email(String);

#[derive(Debug)]
pub struct EmailError;

impl FromStr for Email {
    type Err = EmailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if EMAIL_RULE.is_match(s) {
            return Ok(Email(String::from(s)));
        } else {
            return Err(EmailError);
        }
    }
}

impl Default for Email {
    fn default() -> Self {
        Email("email@email.email".to_string())
    }
}
