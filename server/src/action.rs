use crate::connection::Connection;
use serde::{Deserialize, Serialize};
use std::error::Error;

use user::User;

/// `Action` enum is used to perform logged operations:
/// -   Enable/Disable 2fa authentication
#[derive(Serialize, Deserialize, Debug)]
pub enum Action {
    Switch2FA,
    Logout,
}

impl Action {
    pub fn perform(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        match connection.receive()? {
            Action::Switch2FA => Action::switch_2fa(),
            Action::Logout => Ok(false),
        }
    }

    fn switch_2fa() -> Result<bool, Box<dyn Error>> {
        Ok(true) // TODO
    }
}
