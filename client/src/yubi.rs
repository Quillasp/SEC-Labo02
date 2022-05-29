use read_input::prelude::*;
use std::io;
use std::io::Read;
use x509::SubjectPublicKeyInfo;
use yubikey::*;

use validation::Pin;

pub struct Yubi;

impl Yubi {
    fn auto_yk() -> Result<YubiKey> {
        loop {
            for reader in Context::open()?.iter()? {
                if let Ok(yk) = reader.open() {
                    return Ok(yk);
                }
            }

            println!("No Yubikey detected: Please enter one and press [Enter] to continue...");
            let _ = io::stdin().read(&mut [0u8]).unwrap();
        }
    }

    pub fn generate() -> Result<Vec<u8>> {
        let mut yubikey = Yubi::auto_yk()?;
        yubikey.authenticate(MgmKey::default())?;
        Ok(piv::generate(
            &mut yubikey,
            piv::SlotId::Authentication,
            piv::AlgorithmId::EccP256,
            PinPolicy::Always,
            TouchPolicy::Never,
        )?
        .public_key())
    }

    pub fn sign(bytes: &[u8]) -> Result<Buffer> {
        let mut yubikey = Yubi::auto_yk()?;
        yubikey.verify_pin(input::<Pin>().msg("- PIN: ").get().as_bytes())?;
        Ok(piv::sign_data(
            &mut yubikey,
            bytes,
            piv::AlgorithmId::EccP256,
            piv::SlotId::Authentication,
        )?)
    }
}
