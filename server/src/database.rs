use rustbreak::{deser::Ron, FileDatabase};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use user::User;
use validation::Email;

lazy_static! {
    static ref DB: FileDatabase<Database, Ron> =
        FileDatabase::load_from_path_or_default("db.ron").unwrap();
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Database {
    data: HashMap<Email, User>,
}

impl Database {
    pub fn insert(user: &User) -> Result<(), Box<dyn Error>> {
        DB.write(|db| db.data.insert(user.email.clone(), user.clone()))?;
        Ok(DB.save()?)
    }

    pub fn get(email: &Email) -> Result<Option<User>, Box<dyn Error>> {
        Ok(match DB.borrow_data()?.data.get(email) {
            Some(user) => Some(user.clone()),
            None => None,
        })
    }
}

impl Default for Database {
    fn default() -> Self {
        Database {
            data: HashMap::new(),
        }
    }
}
