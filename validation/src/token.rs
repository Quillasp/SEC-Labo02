use std::str::FromStr;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref UUID_RULE: Regex =
        Regex::new(r"^[[:xdigit:]]{8}\-([[:xdigit:]]{4}\-){3}[[:xdigit:]]{12}$").unwrap();
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Token(String);

impl std::ops::Deref for Token {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct TokenError;

impl FromStr for Token {
    type Err = TokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if UUID_RULE.is_match(s) {
            return Ok(Token(String::from(s)));
        } else {
            return Err(TokenError);
        }
    }
}
