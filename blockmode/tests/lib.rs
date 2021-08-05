use blockmode::BlockMode;
use blockmode::ECB;

use blockcipher::BlockCipher;
use des::{DESKey, DES};

#[test]
fn ecb_des_decrypt() {
    let plain = "hogefugapiyohoge";
    let m = plain.as_bytes().to_vec();
    let key = DES::key_gen();
    let des_ecb = ECB::<DES, DESKey, 64>::new();
    let c = des_ecb.encrypt(&m, &key);
    let m_ = des_ecb.decrypt(&c, &key);
    let plain_ = String::from_utf8(m_.clone()).unwrap();
    assert_eq!(m, m_);
    assert_eq!(plain, plain_);
}
