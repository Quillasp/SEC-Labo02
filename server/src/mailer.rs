extern crate envfile;

use std::path::Path;
use std::{collections::BTreeMap, error::Error};

use envfile::EnvFile;
use lettre::{transport::smtp::authentication::Credentials, Message, SmtpTransport, Transport};

pub fn get_mailer_info() -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let envfile = EnvFile::new(&Path::new("./example.env"))?;

    Ok(envfile.store)
}

pub fn send_mail(to: &str, subject: &str, message: &str) -> Result<(), Box<dyn Error>> {
    let env = get_mailer_info()?;

    let email = Message::builder()
        .from(env.get("from").unwrap().parse()?)
        .reply_to(env.get("from").unwrap().parse()?)
        .to(to.parse()?)
        .subject(subject)
        .body(message.to_string())?;

    let creds = Credentials::new(
        env.get("username").unwrap().to_string(),
        env.get("password").unwrap().to_string(),
    );

    let mailer = SmtpTransport::relay(env.get("relay").unwrap())?
        .credentials(creds)
        .build();

    match mailer.send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
