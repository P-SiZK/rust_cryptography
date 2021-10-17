use blockcipher::blockmode::{BlockMode, ECB};

use blockcipher::aes::AES128;
use blockcipher::BlockCipher;
use padding::NoPadding;

#[test]
fn ecb_aes128() {
    let aes_ecb = ECB::new(AES128, NoPadding);
    let plain = "hogefugapiyohogefugapiyohogefuga";
    let m = plain.as_bytes().to_vec();
    let key = AES128::key_gen();
    let c = aes_ecb.encrypt(&m, &key);
    let m_ = aes_ecb.decrypt(&c, &key);
    let plain_ = String::from_utf8(m_.clone()).unwrap();
    assert_eq!(m, m_);
    assert_eq!(plain, plain_);
}
