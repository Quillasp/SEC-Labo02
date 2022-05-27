use crate::{connection::Connection, database::Database};
use serde::{Deserialize, Serialize};
use std::error::Error;
use utils::{
    crypto::{generate_random_128_bits, hmac_256},
    ChallengeData, EmailData, HmacData, RegisterData, ServerMessage, ServerMessage2FA, User,
};

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

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        let email_data: EmailData = connection.receive()?;

        let mut user = User::default();
        let mut salt: String = user.salt;
        let mut valid: bool;

        match Database::get(&email_data.email)? {
            Some(u) => {
                salt = u.salt.clone();
                valid = true;
                user = u;
            }
            None => valid = false,
        }

        let challenge = generate_random_128_bits();

        connection.send(&ChallengeData { salt, challenge })?;

        let hmac = match hmac_256(&challenge, &user.hash_password) {
            Ok(hmac) => hmac,
            Err(e) => return Err(e.into()),
        };

        let hmac_data: HmacData = connection.receive()?;

        if hmac_data.hmac != hmac || !valid {
            connection.send(&ServerMessage2FA {
                message: "C'est faux!".to_string(),
                success: false,
                two_f_a: false,
            })?;
            return Ok(None);
        } else {
            connection.send(&ServerMessage2FA {
                message: "bien ouej".to_string(),
                success: true,
                two_f_a: true,
            })?;
        }

        Ok(None) // TODO
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        Ok(None) // TODO
    }
}
