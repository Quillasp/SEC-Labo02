use crate::{connection::Connection, database::Database};
use serde::{Deserialize, Serialize};
use std::error::Error;

use utils::*;

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
            Action::Switch2FA => Action::switch_2fa(user, connection),
            Action::Logout => Ok(false),
        }
    }

    fn switch_2fa(user: &mut User, connection: &mut Connection) -> Result<bool, Box<dyn Error>> {
        log::info!("Changing 2FA account status");
        user.two_f_a = !user.two_f_a;

        Database::insert(&user)?;

        connection
            .send(&Switch2FA {
                two_f_a: user.two_f_a,
            })
            .map(|_| true)
    }
}
