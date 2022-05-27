use std::str::FromStr;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref EMAIL_RULE: Regex = Regex::new(
        r"^[a-zA-Z0-9_+&*-]+(\.[a-zA-Z0-9_+&*-]+)*@([a-zA-Z0-9_+&*-]+\.)+[a-zA-Z]{2,7}$"
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
