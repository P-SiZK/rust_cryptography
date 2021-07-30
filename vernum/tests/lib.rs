extern crate vernum;

use num_bigint::BigUint;

#[test]
fn decrypt() {
    let plain = "hogefugapiyo";
    let m = BigUint::from_bytes_be(plain.as_bytes());
    let key = vernum::key_gen(1024);
    let c = vernum::encrypt(&m, &key);
    let m_ = vernum::decrypt(&c, &key);
    let plain_ = String::from_utf8(m_.to_bytes_be()).unwrap();
    assert_eq!(m, m_);
    assert_eq!(plain, plain_);
}
