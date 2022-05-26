use crate::{connection::Connection, database::Database};
use serde::{Deserialize, Serialize};
use std::error::Error;
use utils::{RegisterData, ServerMessage, User};

/// `Authenticate` enum is used to perform:
/// -   Authentication
/// -   Registration
/// -   Password Reset
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Authenticate {
    Authenticate,
    Register,
    Reset,
    Exit,
}

impl Authenticate {
    pub fn perform(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        match connection.receive()? {
            Authenticate::Authenticate => Authenticate::authenticate(connection),
            Authenticate::Register => Authenticate::register(connection),
            Authenticate::Reset => Authenticate::reset_password(connection),
            Authenticate::Exit => Err("Client disconnected")?,
        }
    }

    fn register(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let register_data: RegisterData = connection.receive()?;
        println!("--- Registation process ---");

        if Database::get(&register_data.email)?.is_some() {
            println!("Error: User already exists");
            connection.send(&ServerMessage {
                message: String::from("User already exists"),
                success: false,
            })?;
            return Err("User already exists".into());
        }

        println!("Generating the salt");
        let salt = utils::crypto::generate_salt();
        println!("Hashing the password");
        let hash_password = utils::crypto::hash_password(&register_data.password, &salt).unwrap();

        println!("Entering user in the Database");
        let user = User {
            email: register_data.email,
            salt,
            hash_password,
            two_f_a: true,
            yubikey: register_data.yubikey,
        };

        connection.send(&ServerMessage {
            message: String::from("User registered"),
            success: true,
        })?;
        Database::insert(&user).map(|_| Some(user))
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        Ok(None) // TODO
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        Ok(None) // TODO
    }
}
