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
    pub fn info() -> Serial {
        Yubi::auto_yk().unwrap().serial()
    }

    pub fn generate() -> Result<PublicKeyInfo> {
        let yubikey = Yubi::auto_yk().unwrap();
        // yubikey::piv::generate(&mut yubikey, slot, algorithm, pin_policy, touch_policy)
    }
}
