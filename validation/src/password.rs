use std::str::FromStr;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref PW_LENGTH_RULE: Regex = Regex::new(r"^.{8,64}$").unwrap();
    static ref PW_UPPER_RULE: Regex = Regex::new(r"[[:upper:]]").unwrap();
    static ref PW_LOWER_RULE: Regex = Regex::new(r"[[:lower:]]").unwrap();
    static ref PW_DIGIT_RULE: Regex = Regex::new(r"[[:digit:]]").unwrap();
    static ref PW_SPECIAL_RULE: Regex = Regex::new(r"[#?!@$ %&\*\^\-\+\./\\]").unwrap();
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Password(String);

impl std::ops::Deref for Password {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[derive(Debug)]
pub struct PasswordError;

impl FromStr for Password {
    type Err = PasswordError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if PW_LENGTH_RULE.is_match(s)
            && PW_UPPER_RULE.is_match(s)
            && PW_LOWER_RULE.is_match(s)
            && PW_DIGIT_RULE.is_match(s)
            && PW_SPECIAL_RULE.is_match(s)
        {
            return Ok(Password(String::from(s)));
        } else {
            return Err(PasswordError);
        }
    }
}

impl Default for Password {
    fn default() -> Self {
        Password("12*#abCD".to_string())
    }
}
