use blockcipher::aes::AES128;

use blockcipher::BlockCipher;

#[test]
fn aes128() {
    let plain = "hogefugapiyohoge";
    let m = plain.as_bytes().to_vec();
    let key = AES128::key_gen();
    let c = AES128::encrypt(&m, &key);
    let m_ = AES128::decrypt(&c, &key);
    let plain_ = String::from_utf8(m_.clone()).unwrap();
    assert_eq!(m, m_);
    assert_eq!(plain, plain_);
}
