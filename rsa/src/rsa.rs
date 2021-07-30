// reference: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1

use num_bigint::traits::ModInverse;
use num_bigint::{BigUint, RandPrime};
use num_traits::identities::One;
use rand::{self, SeedableRng};

pub struct RSAKeyPair {
    pub public_key: RSAPublicKey,
    pub private_key: RSAPrivateKey,
}

pub struct RSAPublicKey {
    modulus: BigUint,
    exponent: BigUint,
}

pub struct RSAPrivateKey {
    #[allow(dead_code)]
    modulus: BigUint,
    #[allow(dead_code)]
    public_exponent: BigUint,
    #[allow(dead_code)]
    private_exponent: BigUint,
    prime1: BigUint,
    prime2: BigUint,
    exponent1: BigUint,
    exponent2: BigUint,
    coefficient: BigUint,
}

pub fn key_gen(bit_size: usize) -> RSAKeyPair {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let p_bit_size = bit_size >> 1;
    let mut p: BigUint;
    let mut q: BigUint;
    loop {
        p = rng.gen_prime(p_bit_size);
        q = rng.gen_prime(p_bit_size);
        if p != q {
            break;
        }
    }
    let n = &p * &q;
    let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());
    let e = BigUint::from(65537u32);
    let d = e.clone().mod_inverse(phi_n).unwrap().to_biguint().unwrap();
    let dp = &d % (&p - BigUint::one());
    let dq = &d % (&q - BigUint::one());
    let qinv = q
        .clone()
        .mod_inverse(&p - BigUint::one())
        .unwrap()
        .to_biguint()
        .unwrap();

    RSAKeyPair {
        public_key: RSAPublicKey {
            modulus: n.clone(),
            exponent: e.clone(),
        },
        private_key: RSAPrivateKey {
            modulus: n,
            public_exponent: e,
            private_exponent: d,
            prime1: p,
            prime2: q,
            exponent1: dp,
            exponent2: dq,
            coefficient: qinv,
        },
    }
}

pub fn encrypt(m: &BigUint, key: &RSAPublicKey) -> BigUint {
    m.modpow(&key.exponent, &key.modulus)
}

pub fn decrypt(c: &BigUint, key: &RSAPrivateKey) -> BigUint {
    let m1 = c.modpow(&key.exponent1, &key.prime1);
    let m2 = c.modpow(&key.exponent2, &key.prime2);
    let h = (&m1 - &m2) * &key.coefficient % &key.prime1;
    &m2 + &key.prime2 * &h
}
