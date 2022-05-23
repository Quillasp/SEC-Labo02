use crate::{connection::Connection, yubi::Yubi};
use serde::{Deserialize, Serialize};
use std::error::Error;

use read_input::prelude::*;
use strum::IntoEnumIterator;
use strum_macros::{EnumIter, EnumString};
use user::User;
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
        let ykey = Yubi::info();

        let email = input::<Email>().msg("Enter your email: ").get();
        let password = input::<Password>().msg("Enter your password: ").get();

        println!(
            "YubiKey Serial : {:?}, version {:?}",
            ykey.serial(),
            ykey.version()
        );

        let yubikey_pub_info = match Yubi::generate() {
            Ok(y) => y,
            Err(e) => return Err(Box::new(e)),
        };

        println!("YubiKey Public Info : {:?}", yubikey_pub_info);

        connection.send(&User {
            email,
            password,
            switch_2fa: true,
            yk_info: Vec::new(),
        })
    }

    fn authenticate(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        Ok(()) // TODO
    }

    fn reset_password(connection: &mut Connection) -> Result<(), Box<dyn Error>> {
        Ok(()) // TODO
    }
}
