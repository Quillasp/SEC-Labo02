use std::str::FromStr;

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref PIN_RULE: Regex = Regex::new(r"^[[:alnum:]]{6,8}$").unwrap();
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct Pin(String);

impl std::ops::Deref for Pin {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct PinError;

impl FromStr for Pin {
    type Err = PinError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if PIN_RULE.is_match(s) {
            return Ok(Pin(String::from(s)));
        } else {
            return Err(PinError);
        }
    }
}
