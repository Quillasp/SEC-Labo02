use crate::{connection::Connection, database::Database};
use serde::{Deserialize, Serialize};
use std::error::Error;

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
        let user: User = connection.receive()?;
        Database::insert(&user).map(|_| Some(user))
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        Ok(None) // TODO
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        Ok(None) // TODO
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: String,
    pub password: String,
}
