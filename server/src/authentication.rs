use crate::{connection::Connection, database::Database, mailer::send_mail};
use ecdsa::signature::Verifier;
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use std::error::Error;
use utils::{
    crypto::{generate_random_128_bits, generate_salt, hash_password, hmac_sha256},
    ChallengeData, ClientStringMessage, ClientVecMessage, EmailData, Error as UtilsError, HmacData,
    Messages, RegisterData, ServerMessage, ServerMessage2FA, User, YubiKeyPubInfoData,
};
use uuid::Uuid;

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
                message: UtilsError::UserAlreadyExist.to_string(),
                success: false,
            })?;
            return Err(Box::new(UtilsError::UserAlreadyExist));
        } else {
            println!("{}", Messages::YubiKeyPubInfo);
            connection.send(&ServerMessage {
                message: Messages::YubiKeyPubInfo.to_string(),
                success: true,
            })?;
        }

        println!("Generating the salt");
        let salt = generate_salt();
        println!("Hashing the password");
        let hash_password = hash_password(&register_data.password, &salt).unwrap();

        println!("Getting YubiKey public info");
        let yubikey: YubiKeyPubInfoData = connection.receive()?;

        println!("Entering user in the Database");
        let user = User {
            email: register_data.email,
            salt,
            hash_password,
            two_f_a: true,
            yubikey: yubikey.yubikey,
        };

        connection.send(&ServerMessage {
            message: Messages::UserRegistered.to_string(),
            success: true,
        })?;
        Database::insert(&user).map(|_| Some(user))
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        println!("---Authentication process---\nGetting user email");
        let email_data: EmailData = connection.receive()?;

        let mut user = User::default();
        let mut salt: String = user.salt.clone();
        let valid: bool;

        println!("Looking for the input email inside the DB");
        match Database::get(&email_data.email)? {
            Some(db_user) => {
                salt = db_user.salt.clone();
                valid = true;
                user = db_user;
            }
            None => valid = false,
        }

        println!("Generating and sending challenge");
        let challenge = generate_random_128_bits();
        connection.send(&ChallengeData { salt, challenge })?;

        println!("Generating the HMAC");
        let hmac = match hmac_sha256(&challenge, &user.hash_password) {
            Ok(hmac) => hmac,
            Err(e) => return Err(e.into()),
        };
        println!("Getting user HMAC");
        let hmac_data: HmacData = connection.receive()?;
        if hmac_data.hmac != hmac || !valid {
            connection.send(&ServerMessage2FA {
                message: UtilsError::AuthFailed.to_string(),
                success: false,
                two_f_a: false,
            })?;
            return Err(UtilsError::AuthFailed.into());
        } else if user.two_f_a {
            connection.send(&ServerMessage2FA {
                message: Messages::AuthTo2FA.to_string(),
                success: true,
                two_f_a: true,
            })?;
        } else {
            connection.send(&ServerMessage2FA {
                message: Messages::AuthSuccess.to_string(),
                success: true,
                two_f_a: false,
            })?;
            return Ok(Some(user));
        }
        println!("Getting user yubikey public info");
        let client_message: ClientVecMessage = connection.receive()?;

        match Authenticate::verify_yubikey_challenge(
            &user.yubikey,
            &client_message.message,
            &challenge,
        ) {
            Ok(_) => {
                connection.send(&ServerMessage {
                    message: Messages::AuthSuccess.to_string(),
                    success: true,
                })?;
                Ok(Some(user))
            }
            Err(e) => {
                connection.send(&ServerMessage {
                    message: UtilsError::TwoFAFailed.to_string(),
                    success: false,
                })?;
                Err(e.into())
            }
        }
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        println!("---Reset password process---\nGetting user email");
        let email_data: EmailData = connection.receive()?;
        let user = Database::get(&email_data.email)?;
        let mut challenge: [u8; 16] = [0; 16];
        if user.is_none() {
            connection.send(&ServerMessage {
                message: UtilsError::InvalidEmail.to_string(),
                success: false,
            })?;
            return Err(Box::new(UtilsError::InvalidEmail));
        } else {
            challenge = generate_random_128_bits();
            connection.send(&ServerMessage {
                message: Messages::AuthTo2FA.to_string(),
                success: true,
            })?;

            connection.send(&ChallengeData {
                salt: String::new(),
                challenge,
            })?;
        }
        let user = user.unwrap();
        let client_message: ClientVecMessage = connection.receive()?;

        match Authenticate::verify_yubikey_challenge(
            &user.yubikey,
            &client_message.message,
            &challenge,
        ) {
            Ok(_) => {
                connection.send(&ServerMessage {
                    message: Messages::EmailSent.to_string(),
                    success: true,
                })?;
            }
            Err(e) => {
                connection.send(&ServerMessage {
                    message: UtilsError::TwoFAFailed.to_string(),
                    success: false,
                })?;
                return Err(e.into());
            }
        }
        println!("Sending email to requested username");
        let token = Authenticate::send_token(
            &user.email,
            Messages::EmailSubject.to_string().as_str(),
            Messages::EmailMessage.to_string().as_str(),
        )?;
        let token_user: ClientStringMessage = connection.receive()?;

        if token != token_user.message {
            connection.send(&ServerMessage {
                message: UtilsError::UuidFailed.to_string(),
                success: false,
            })?;
            return Err(UtilsError::UuidFailed.into());
        } else {
            connection.send(&ServerMessage {
                message: Messages::UuidSuccess.to_string(),
                success: true,
            })?;
        }

        let new_password: ClientStringMessage = connection.receive()?;

        println!("Generating the salt");
        let salt = generate_salt();
        println!("Hashing the password");
        let hash_password = hash_password(&new_password.message, &salt).unwrap();

        let user = User {
            email: user.email,
            salt,
            hash_password,
            two_f_a: user.two_f_a,
            yubikey: user.yubikey,
        };
        Database::insert(&user).map(|_| Some(user))
    }

    fn verify_yubikey_challenge(
        yubikey: &Vec<u8>,
        message: &Vec<u8>,
        challenge: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let encoded_point: EncodedPoint = match EncodedPoint::from_bytes(yubikey) {
            Ok(encoded_point) => encoded_point,
            Err(e) => return Err(e.into()),
        };
        let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;
        let signature = p256::ecdsa::Signature::from_der(message)?;

        println!("Verifying yubikey");
        match verifying_key.verify(&challenge, &signature) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn send_token(to: &str, subject: &str, message: &str) -> Result<String, Box<dyn Error>> {
        let id = Uuid::new_v4().as_hyphenated().to_string();
        let message = format!("{} {}", message, id);
        send_mail(to, subject, &message)?;
        Ok(id)
    }
}
