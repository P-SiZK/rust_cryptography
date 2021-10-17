use blockcipher::des::DES;

use blockcipher::BlockCipher;

#[test]
fn des() {
    let plain = "hogefuga";
    let m = plain.as_bytes().to_vec();
    let key = DES::key_gen();
    let c = DES::encrypt(&m, &key);
    let m_ = DES::decrypt(&c, &key);
    let plain_ = String::from_utf8(m_.clone()).unwrap();
    assert_eq!(m, m_);
    assert_eq!(plain, plain_);
}
