extern crate des;

use std::convert::TryInto;

#[test]
fn decrypt() {
    let plain = "hogefuga";
    let m = u64::from_be_bytes(plain.as_bytes().try_into().unwrap());
    let key = des::key_gen();
    let c = des::encrypt(m, &key);
    let m_ = des::decrypt(c, &key);
    let plain_ = String::from_utf8(m_.to_be_bytes().to_vec()).unwrap();
    assert_eq!(m, m_);
    assert_eq!(plain, plain_);
}
