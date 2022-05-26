use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

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
