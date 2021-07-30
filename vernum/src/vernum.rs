use num_bigint::{BigUint, RandBigInt};
use rand::{self, SeedableRng};

pub struct VernumKey {
    key: BigUint,
}

pub fn key_gen(bit_size: u64) -> VernumKey {
    let mut rng = rand::rngs::StdRng::from_entropy();
    VernumKey {
        key: rng.gen_biguint(bit_size),
    }
}

pub fn encrypt(m: &BigUint, key: &VernumKey) -> BigUint {
    m ^ key.key.clone()
}

pub fn decrypt(c: &BigUint, key: &VernumKey) -> BigUint {
    c ^ key.key.clone()
}
