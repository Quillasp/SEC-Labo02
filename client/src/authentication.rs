use crate::{connection::Connection, yubi::Yubi};
use serde::{Deserialize, Serialize};
use std::{error::Error, f32::consts::E};

use read_input::prelude::*;
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString};
use utils::{
    crypto::{hash_password, hmac_256},
    ChallengeData, EmailData, HmacData, RegisterData, ServerMessage, ServerMessage2FA,
};
use validation::{Email, Password};

/// `Authenticate` enum is used to perform:
/// -   User
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, Debug, EnumString, EnumIter)]
pub enum Authenticate {
    #[strum(serialize = "Authenticate", serialize = "1")]
    Authenticate,
    #[strum(serialize = "Register", serialize = "2")]
    Register,
    #[strum(serialize = "Reset password", serialize = "3")]
    Reset,
    #[strum(serialize = "Exit", serialize = "4")]
    Exit,
}

impl Authenticate {
    pub fn display() {
        let mut actions = Authenticate::iter();
        for i in 1..=actions.len() {
            println!("{}.\t{:?}", i, actions.next().unwrap());
        }
    }

    pub fn perform(&self, connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        connection.send(self)?;

        match self {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => {
                println!("Exiting...");
                std::process::exit(0);
            }
        }
    }

    fn register(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("\n\n<< Please register yourself >>\n");

        let email = input::<Email>().msg("- Email: ").get();
        let password = input::<Password>().msg("- Password: ").get();

        let yubikey = Yubi::generate()?;

        connection.send(&RegisterData {
            email,
            password,
            yubikey,
        })?;

        let server_message: ServerMessage = connection.receive()?;
        if !server_message.success {
            return Err(server_message.message.into());
        }

        Ok(())
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("<< Please authenticate yourself >>");

        let email = input::<Email>().msg("- Email: ").get();
        let password = input::<Password>().msg("- Password:").get();
        connection.send(&EmailData { email })?;

        let challenge_data: ChallengeData = connection.receive()?;

        let hash_password = hash_password(&password, &challenge_data.salt).unwrap();

        match hmac_256(&challenge_data.challenge, &hash_password) {
            Ok(hmac) => connection.send(&HmacData { hmac })?,
            Err(e) => return Err(e.into()),
        }

        let server_message: ServerMessage2FA = connection.receive()?;
        if !server_message.success {
            return Err(server_message.message.into());
        } else {
            println!("{}", server_message.message);
        }
        Ok(()) // TODO
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        Ok(()) // TODO
    }
}
