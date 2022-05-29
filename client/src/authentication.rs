use crate::{connection::Connection, yubi::Yubi};
use serde::{Deserialize, Serialize};
use std::error::Error;

use read_input::prelude::*;
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString};
use utils::{
    crypto::{hash_password, hash_sha256, hmac_sha256},
    ChallengeData, ClientMessage, EmailData, HmacData, RegisterData, ServerMessage,
    ServerMessage2FA, YubiKeyPubInfoData,
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

        connection.send(&RegisterData {
            email: input::<Email>().msg("- Email: ").get(),
            password: input::<Password>().msg("- Password: ").get(),
        })?;

        Authenticate::receive_server_message(connection)?;

        connection.send(&YubiKeyPubInfoData {
            yubikey: Yubi::generate()?,
        })?;

        Authenticate::receive_server_message(connection)?;

        Ok(())
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("\n\n<< Please authenticate yourself >>\n");

        connection.send(&EmailData {
            email: input::<Email>().msg("- Email: ").get(),
        })?;
        let password = input::<Password>().msg("- Password: ").get();

        let challenge_data: ChallengeData = connection.receive()?;
        let hash_password = hash_password(&password, &challenge_data.salt).unwrap();
        match hmac_sha256(&challenge_data.challenge, &hash_password) {
            Ok(hmac) => connection.send(&HmacData { hmac })?,
            Err(e) => return Err(e.into()),
        }

        let server_message: ServerMessage2FA = connection.receive()?;
        if !server_message.success {
            return Err(server_message.message.into());
        } else if !server_message.two_f_a {
            println!("{}", server_message.message);
            return Ok(());
        }
        println!("{}", server_message.message);

        connection.send(&ClientMessage {
            message: Yubi::sign(&hash_sha256(&challenge_data.challenge))?.to_vec(),
        })?;

        Authenticate::receive_server_message(connection)?;
        Ok(()) // TODO
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        println!("\n\n<< Reset password >>\n");

        connection.send(&EmailData {
            email: input::<Email>().msg("- Email: ").get(),
        })?;

        Authenticate::receive_server_message(connection)?;

        let challenge_data: ChallengeData = connection.receive()?;

        connection.send(&ClientMessage {
            message: Yubi::sign(&hash_sha256(&challenge_data.challenge))?.to_vec(),
        })?;

        Ok(()) // TODO
    }

    fn receive_server_message(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        let server_message: ServerMessage = connection.receive()?;
        if server_message.success {
            println!("Server message: {}", server_message.message);
        } else {
            return Err(server_message.message.into());
        }
        Ok(())
    }
}
