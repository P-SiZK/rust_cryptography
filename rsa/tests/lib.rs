use rsa;

use num_bigint::BigUint;

#[test]
fn decrypt() {
    let plain = "hogefugapiyo";
    let m = BigUint::from_bytes_be(plain.as_bytes());
    let key = rsa::key_gen(2048);
    let c = rsa::encrypt(&m, &key.public_key);
    let m_ = rsa::decrypt(&c, &key.private_key);
    let plain_ = String::from_utf8(m_.to_bytes_be()).unwrap();
    assert_eq!(m, m_);
    assert_eq!(plain, plain_);
}
