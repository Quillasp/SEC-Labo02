use std::str::FromStr;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref PASSWORD_RULE: Regex = Regex::new(r"").unwrap();
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Password(String);

#[derive(Debug)]
pub struct PasswordError;

impl FromStr for Password {
    type Err = PasswordError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if PASSWORD_RULE.is_match(s) {
            return Ok(Password(String::from(s)));
        } else {
            return Err(PasswordError);
        }
    }
}
