use std::io;
use std::io::Read;
use yubikey::certificate::PublicKeyInfo;
use yubikey::*;

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

    // TODO
    pub fn info() -> YubiKey {
        Yubi::auto_yk().unwrap()
    }

    pub fn generate() -> Result<PublicKeyInfo> {
        let mut yubikey = Yubi::auto_yk().unwrap();
        let slot_id = yubikey::piv::SlotId::Authentication;
        let algorithm_id = yubikey::piv::AlgorithmId::EccP256;
        let pin_policy = yubikey::PinPolicy::Once;
        let touch_policy = yubikey::TouchPolicy::Never;

        yubikey::piv::generate(
            &mut yubikey,
            slot_id,
            algorithm_id,
            pin_policy,
            touch_policy,
        )
    }
}
