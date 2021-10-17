use crate::BlockCipher;
use rand::{self, Rng, SeedableRng};

use crate::aes::consts::*;

pub struct AESKey<const NK: usize> {
    key: [u32; NK],
}

macro_rules! define_aes {
    (
        $name:ident,
        $nk: expr,
        $nr: expr
    ) => {
        pub struct $name;

        impl BlockCipher<AESKey<$nk>, 128> for $name {
            fn key_gen() -> AESKey<$nk> {
                aes_key_gen::<$nk>()
            }

            fn encrypt(m: &Vec<u8>, key: &AESKey<$nk>) -> Vec<u8> {
                aes_encrypt::<$nk, $nr>(m, key)
            }

            fn decrypt(c: &Vec<u8>, key: &AESKey<$nk>) -> Vec<u8> {
                aes_decrypt::<$nk, $nr>(c, key)
            }
        }
    };
}

define_aes!(AES128, 4, 10);
define_aes!(AES192, 6, 12);
define_aes!(AES256, 8, 14);

fn aes_key_gen<const NK: usize>() -> AESKey<NK> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut key = [0u32; NK];
    rng.fill(&mut key[..]);
    AESKey { key: key }
}

fn aes_encrypt<const NK: usize, const NR: usize>(m: &Vec<u8>, key: &AESKey<NK>) -> Vec<u8> {
    let mut state = m.clone();
    let w = key_expansion::<NK, NR>(&key.key.to_vec());
    add_round_key(&mut state, &w[0..4]);
    for round in 1..NR {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &w[round * 4..(round + 1) * 4]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &w[NR * 4..(NR + 1) * 4]);

    state
}

fn aes_decrypt<const NK: usize, const NR: usize>(c: &Vec<u8>, key: &AESKey<NK>) -> Vec<u8> {
    let mut state = c.clone();
    let w = key_expansion::<NK, NR>(&key.key.to_vec());
    add_round_key(&mut state, &w[NR * 4..(NR + 1) * 4]);
    for round in (1..NR).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &w[round * 4..(round + 1) * 4]);
        inv_mix_columns(&mut state);
    }
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &w[0..4]);

    state
}

fn sub_bytes(state: &mut Vec<u8>) {
    for s in state {
        *s = SBOX[*s as usize];
    }
}

fn inv_sub_bytes(state: &mut Vec<u8>) {
    for s in state {
        *s = INV_SBOX[*s as usize];
    }
}

fn shift_rows(state: &mut Vec<u8>) {
    let mut tmp = state.clone();
    tmp[1] = state[5];
    tmp[5] = state[9];
    tmp[9] = state[13];
    tmp[13] = state[1];

    tmp[2] = state[10];
    tmp[6] = state[14];
    tmp[10] = state[2];
    tmp[14] = state[6];

    tmp[3] = state[15];
    tmp[7] = state[3];
    tmp[11] = state[7];
    tmp[15] = state[11];

    *state = tmp;
}

fn inv_shift_rows(state: &mut Vec<u8>) {
    let mut tmp = state.clone();
    tmp[1] = state[13];
    tmp[13] = state[9];
    tmp[9] = state[5];
    tmp[5] = state[1];

    tmp[2] = state[10];
    tmp[14] = state[6];
    tmp[10] = state[2];
    tmp[6] = state[14];

    tmp[3] = state[7];
    tmp[15] = state[3];
    tmp[11] = state[15];
    tmp[7] = state[11];

    *state = tmp;
}

fn mix_columns(state: &mut Vec<u8>) {
    let mut tmp = [0u8; 4];
    for c in 0..4 {
        tmp[0] = galois_mul(0x02, state[4 * c])
            ^ galois_mul(0x03, state[1 + 4 * c])
            ^ state[2 + 4 * c]
            ^ state[3 + 4 * c];

        tmp[1] = state[4 * c]
            ^ galois_mul(0x02, state[1 + 4 * c])
            ^ galois_mul(0x03, state[2 + 4 * c])
            ^ state[3 + 4 * c];

        tmp[2] = state[4 * c]
            ^ state[1 + 4 * c]
            ^ galois_mul(0x02, state[2 + 4 * c])
            ^ galois_mul(0x03, state[3 + 4 * c]);

        tmp[3] = galois_mul(0x03, state[4 * c])
            ^ state[1 + 4 * c]
            ^ state[2 + 4 * c]
            ^ galois_mul(0x02, state[3 + 4 * c]);

        state[4 * c] = tmp[0];
        state[1 + 4 * c] = tmp[1];
        state[2 + 4 * c] = tmp[2];
        state[3 + 4 * c] = tmp[3];
    }
}

fn inv_mix_columns(state: &mut Vec<u8>) {
    let mut tmp = [0u8; 4];
    for c in 0..4 {
        tmp[0] = galois_mul(0x0e, state[4 * c])
            ^ galois_mul(0x0b, state[1 + 4 * c])
            ^ galois_mul(0x0d, state[2 + 4 * c])
            ^ galois_mul(0x09, state[3 + 4 * c]);

        tmp[1] = galois_mul(0x09, state[4 * c])
            ^ galois_mul(0x0e, state[1 + 4 * c])
            ^ galois_mul(0x0b, state[2 + 4 * c])
            ^ galois_mul(0x0d, state[3 + 4 * c]);

        tmp[2] = galois_mul(0x0d, state[4 * c])
            ^ galois_mul(0x09, state[1 + 4 * c])
            ^ galois_mul(0x0e, state[2 + 4 * c])
            ^ galois_mul(0x0b, state[3 + 4 * c]);

        tmp[3] = galois_mul(0x0b, state[4 * c])
            ^ galois_mul(0x0d, state[1 + 4 * c])
            ^ galois_mul(0x09, state[2 + 4 * c])
            ^ galois_mul(0x0e, state[3 + 4 * c]);

        state[4 * c] = tmp[0];
        state[1 + 4 * c] = tmp[1];
        state[2 + 4 * c] = tmp[2];
        state[3 + 4 * c] = tmp[3];
    }
}

fn galois_mul(mut a: u8, mut b: u8) -> u8 {
    let mut res: u8 = 0;
    for _bit in 0..8 {
        if (b & 1) != 0 {
            res ^= a;
        }
        let overflow = (a & 0x80) != 0;
        if overflow {
            a ^= 0x80;
            a <<= 1;
            a ^= 0x1b; // 0x1b = (1 << 4) | (1 << 3) | (1 << 1) | 1
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    res
}

fn add_round_key(state: &mut Vec<u8>, w: &[u32]) {
    let w: Vec<[u8; 4]> = w.iter().map(|x| x.to_be_bytes()).collect();
    for c in 0..4 {
        for r in 0..4 {
            state[r + 4 * c] ^= w[c][r];
        }
    }
}

fn key_expansion<const NK: usize, const NR: usize>(key: &Vec<u32>) -> Vec<u32> {
    let mut w: Vec<u32> = Vec::with_capacity(4 * (NR + 1));
    w.append(&mut key.clone());
    for i in NK..4 * (NR + 1) {
        let mut temp = w[i - 1];
        if i % NK == 0 {
            temp = sub_word(rot_word(temp)) ^ RCON[i / NK];
        } else if (NK > 6) && (i % NK == 4) {
            temp = sub_word(temp);
        }
        w.push(w[i - NK] ^ temp);
    }
    w
}

fn sub_word(word: u32) -> u32 {
    let mut bytes = word.to_be_bytes();
    bytes[0] = SBOX[bytes[0] as usize];
    bytes[1] = SBOX[bytes[1] as usize];
    bytes[2] = SBOX[bytes[2] as usize];
    bytes[3] = SBOX[bytes[3] as usize];
    u32::from_be_bytes(bytes)
}

fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

#[test]
/// reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
/// Appendic C.1
fn test_aes128() {
    let plain: u128 = 0x00112233445566778899aabbccddeeff;
    let key = AESKey {
        key: [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f],
    };
    let m = plain.to_be_bytes().to_vec();
    let c = AES128::encrypt(&m, &key);
    assert_eq!(
        0x69c4e0d86a7b0430d8cdb78070b4c55au128
            .to_be_bytes()
            .to_vec(),
        c
    );
    let m_ = AES128::decrypt(&c, &key);
    assert_eq!(m, m_);
}

#[test]
/// reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
/// Appendic C.2
fn test_aes192() {
    let plain: u128 = 0x00112233445566778899aabbccddeeff;
    let key = AESKey {
        key: [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617,
        ],
    };
    let m = plain.to_be_bytes().to_vec();
    let c = AES192::encrypt(&m, &key);
    assert_eq!(
        0xdda97ca4864cdfe06eaf70a0ec0d7191u128
            .to_be_bytes()
            .to_vec(),
        c
    );
    let m_ = AES192::decrypt(&c, &key);
    assert_eq!(m, m_);
}

#[test]
/// reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
/// Appendic C.3
fn test_aes256() {
    let plain: u128 = 0x00112233445566778899aabbccddeeff;
    let key = AESKey {
        key: [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
            0x1c1d1e1f,
        ],
    };
    let m = plain.to_be_bytes().to_vec();
    let c = AES256::encrypt(&m, &key);
    assert_eq!(
        0x8ea2b7ca516745bfeafc49904b496089u128
            .to_be_bytes()
            .to_vec(),
        c
    );
    let m_ = AES256::decrypt(&c, &key);
    assert_eq!(m, m_);
}
