use crate::{connection::Connection, database::Database, mailer::send_mail};
use ecdsa::signature::Verifier;
use p256::EncodedPoint;
use serde::{Deserialize, Serialize};
use std::error::Error;
use utils::{
    crypto::{generate_random_128_bits, generate_salt, hash_password, hmac_sha256},
    ChallengeData, ClientMessage, EmailData, Error as UtilsError, HmacData, RegisterData,
    ServerMessage, ServerMessage2FA, Strings, User, YubiKeyData,
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
        log::info!("--- Registation process ---");

        if Database::get(&register_data.email)?.is_some() {
            log::error!("{}", UtilsError::UserAlreadyExist);
            connection.send(&ServerMessage {
                message: UtilsError::UserAlreadyExist.to_string(),
                success: false,
            })?;
            return Err(Box::new(UtilsError::UserAlreadyExist));
        } else {
            log::info!("{}", Strings::YubiKeyPubInfo);
            connection.send(&ServerMessage {
                message: Strings::YubiKeyPubInfo.to_string(),
                success: true,
            })?;
        }

        log::info!("Generating the salt");
        let salt = generate_salt();
        log::info!("Hashing the password");
        let hash_password = hash_password(&register_data.password, &salt).unwrap();

        log::info!("Getting YubiKey public info");
        let yubikey: YubiKeyData = connection.receive()?;

        log::info!("Creating the user");
        let user = User {
            email: register_data.email,
            salt,
            hash_password,
            two_f_a: true,
            yubikey: yubikey.yubikey,
        };

        connection.send(&ServerMessage {
            message: Strings::UserRegistered.to_string(),
            success: true,
        })?;
        log::info!("Inserting user in the database");
        Database::insert(&user).map(|_| Some(user))
    }

    fn authenticate(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        log::info!("---Authentication process---");
        log::info!("Getting user email");
        let email_data: EmailData = connection.receive()?;

        let mut user = User::default();
        let mut salt: String = user.salt.clone();
        let valid: bool;

        log::info!("Looking for the input email inside the DB");
        match Database::get(&email_data.email)? {
            Some(db_user) => {
                salt = db_user.salt.clone();
                valid = true;
                user = db_user;
            }
            None => valid = false,
        }

        log::info!("Generating and sending challenge");
        let challenge = generate_random_128_bits();
        connection.send(&ChallengeData { salt, challenge })?;

        log::info!("Generating the HMAC");
        let hmac = match hmac_sha256(&challenge, &user.hash_password) {
            Ok(hmac) => hmac,
            Err(e) => return Err(e.into()),
        };
        log::info!("Getting user HMAC");
        let hmac_data: HmacData = connection.receive()?;
        if hmac_data.hmac != hmac || !valid {
            log::error!("{}", UtilsError::AuthFailed);
            connection.send(&ServerMessage2FA {
                message: UtilsError::AuthFailed.to_string(),
                success: false,
                two_f_a: false,
            })?;
            return Err(UtilsError::AuthFailed.into());
        } else if user.two_f_a {
            log::info!("{}", Strings::AuthTo2FA);
            connection.send(&ServerMessage2FA {
                message: Strings::AuthTo2FA.to_string(),
                success: true,
                two_f_a: true,
            })?;
        } else {
            log::info!("{}", Strings::AuthSuccess);
            connection.send(&ServerMessage2FA {
                message: Strings::AuthSuccess.to_string(),
                success: true,
                two_f_a: false,
            })?;
            return Ok(Some(user));
        }
        log::info!("Getting user yubikey public info");
        let client_message: YubiKeyData = connection.receive()?;

        match Authenticate::verify_yubikey_challenge(
            &user.yubikey,
            &client_message.yubikey,
            &challenge,
        ) {
            Ok(_) => {
                log::info!("{}", Strings::AuthSuccess);
                connection.send(&ServerMessage {
                    message: Strings::AuthSuccess.to_string(),
                    success: true,
                })?;
                Ok(Some(user))
            }
            Err(e) => {
                log::error!("{}", UtilsError::TwoFAFailed);
                connection.send(&ServerMessage {
                    message: UtilsError::TwoFAFailed.to_string(),
                    success: false,
                })?;
                Err(e.into())
            }
        }
    }

    fn reset_password(connection: &mut Connection) -> Result<Option<User>, Box<dyn Error>> {
        log::info!("---Reset password process---");
        log::info!("Getting user email");

        let email_data: EmailData = connection.receive()?;
        let user = Database::get(&email_data.email)?;
        let mut challenge: [u8; 16] = [0; 16];

        log::info!("Retreiving user");
        if user.is_none() {
            log::error!("{}", UtilsError::InvalidEmail);
            connection.send(&ServerMessage {
                message: UtilsError::InvalidEmail.to_string(),
                success: false,
            })?;
            return Err(Box::new(UtilsError::InvalidEmail));
        } else {
            log::info!("{}", Strings::AuthTo2FA);
            challenge = generate_random_128_bits();
            connection.send(&ServerMessage {
                message: Strings::AuthTo2FA.to_string(),
                success: true,
            })?;

            log::info!("Sending challenge");
            connection.send(&ChallengeData {
                salt: String::new(),
                challenge,
            })?;
        }
        let user = user.unwrap();
        let client_message: YubiKeyData = connection.receive()?;

        match Authenticate::verify_yubikey_challenge(
            &user.yubikey,
            &client_message.yubikey,
            &challenge,
        ) {
            Ok(_) => {
                connection.send(&ServerMessage {
                    message: Strings::EmailSent.to_string(),
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

        let token = Authenticate::send_token(
            &user.email,
            Strings::EmailSubject.to_string().as_str(),
            Strings::EmailMessage.to_string().as_str(),
        )?;
        let token_user: ClientMessage = connection.receive()?;

        log::info!("Comparing tokens");
        if token != token_user.message {
            log::error!("{}", UtilsError::UuidFailed);
            connection.send(&ServerMessage {
                message: UtilsError::UuidFailed.to_string(),
                success: false,
            })?;
            return Err(UtilsError::UuidFailed.into());
        } else {
            log::info!("{}", Strings::UuidSuccess);
            connection.send(&ServerMessage {
                message: Strings::UuidSuccess.to_string(),
                success: true,
            })?;
        }

        log::info!("Getting new password");
        let new_password: ClientMessage = connection.receive()?;

        log::info!("Generating the salt");
        let salt = generate_salt();
        log::info!("Hashing the password");
        let hash_password = hash_password(&new_password.message, &salt).unwrap();

        log::info!("Updating user");
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

        log::info!("Verifying yubikey");
        match verifying_key.verify(&challenge, &signature) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn send_token(to: &str, subject: &str, message: &str) -> Result<String, Box<dyn Error>> {
        log::info!("Generating the token");
        let id = Uuid::new_v4().as_hyphenated().to_string();
        let message = format!("{} {}", message, id);
        log::info!("Sending token to the requested email");
        send_mail(to, subject, &message)?;
        Ok(id)
    }
}
