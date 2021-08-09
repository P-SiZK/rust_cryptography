use blockmode::{BlockMode, ECB};

use blockcipher::BlockCipher;
use des::DES;
use padding::ZeroPadding;

#[test]
fn ecb_des_zeropad_decrypt() {
    let des_ecb = ECB::new(DES, ZeroPadding);
    let plain = "hogefugapiyofoobarbaz??";
    let m = plain.as_bytes().to_vec();
    let key = DES::key_gen();
    let c = des_ecb.encrypt(&m, &key);
    let m_ = des_ecb.decrypt(&c, &key);
    let plain_ = String::from_utf8(m_.clone()).unwrap();
    assert_eq!(m, m_);
    assert_eq!(plain, plain_);
    println!("{:?}", m_);
    println!("{}", plain_);
}
