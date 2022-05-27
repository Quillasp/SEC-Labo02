use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub fn hash_password(s: &str, salt: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::new(salt)?;
    Ok(Argon2::default()
        .hash_password(s.as_bytes(), &salt)?
        .to_string())
}

pub fn generate_salt() -> String {
    SaltString::generate(&mut OsRng).to_string()
}

pub fn verifiy_password(s: &str, hash: &str) -> Result<(), argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(hash)?;
    Argon2::default().verify_password(s.as_bytes(), &parsed_hash)
}

pub fn generate_random_128_bits() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut dest: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut dest);
    dest
}

pub fn hmac_256(input: &[u8; 16], key: &str) -> Result<Vec<u8>, String> {
    let mut mac = match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(mac) => mac,
        Err(e) => return Err(e.to_string()),
    };
    mac.update(input);
    Ok(mac.finalize().into_bytes()[..].to_vec())
}
