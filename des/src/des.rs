// reference: https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf

use rand::{self, Rng, SeedableRng};

use crate::consts::*;

pub struct DESKey {
    key: u64,
}

pub fn key_gen() -> DESKey {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut key: u64 = rng.gen();
    key &= 0xfefe_fefe_fefe_fefe;

    // calculation odd parity
    let mut parity = key;
    parity ^= parity >> 4;
    parity ^= parity >> 2;
    parity ^= parity >> 1;
    parity &= 0x0101_0101_0101_0101;
    parity ^= 0x0101_0101_0101_0101;
    key |= parity;

    DESKey { key: key }
}

pub fn encrypt(m: u64, key: &DESKey) -> u64 {
    let subkeys = subkey_gen(key);

    cipher_algorithm(m, &subkeys)
}

pub fn decrypt(c: u64, key: &DESKey) -> u64 {
    let mut subkeys = subkey_gen(key);
    subkeys.reverse();

    cipher_algorithm(c, &subkeys)
}

fn cipher_algorithm(val: u64, subkeys: &[u64]) -> u64 {
    let lr = bit_replacement(val, &IP, 64);
    let mut l = lr >> 32;
    let mut r = lr & 0xffff_ffff;
    for subkey in subkeys {
        l ^= f(r, *subkey);
        std::mem::swap(&mut l, &mut r);
    }
    let lr = (r << 32) | l;

    bit_replacement(lr, &IP_INV, 64)
}

fn subkey_gen(key: &DESKey) -> [u64; 16] {
    let mut subkeys = [0u64; 16];
    let c0_d0 = bit_replacement(key.key, &PC1, 64);
    let mut c = c0_d0 >> 28;
    let mut d = c0_d0 & 0x0fff_ffff;
    for i in 0..16 {
        let rot_num = if i == 0 || i == 1 || i == 8 || i == 15 {
            1
        } else {
            2
        };
        c = rotate_left(c, rot_num);
        d = rotate_left(d, rot_num);
        let cn_dn = (c << 28) | d;
        subkeys[i] = bit_replacement(cn_dn, &PC2, 56);
    }

    subkeys
}

fn rotate_left(bits: u64, n: u8) -> u64 {
    ((bits << n) & 0x0fff_ffff) | (bits >> n)
}

fn bit_replacement(bits: u64, map: &[u8], bit_size: u8) -> u64 {
    let mut res = 0u64;
    for (i, val) in map.iter().enumerate() {
        res |= ((bits >> (bit_size - val)) & 0b1) << i;
    }

    res
}

fn f(bits: u64, subkey: u64) -> u64 {
    let mut res = 0u64;
    let mut val = bit_replacement(bits, &E, 32);
    val ^= subkey;
    for (i, sbox) in SBOX.iter().rev().enumerate() {
        let b = ((val >> (6 * i)) & 0b111111) as usize;
        let row = ((b >> 4) & 0b10) | (b & 0b1);
        let col = (b >> 1) & 0b1111;
        res |= sbox[row][col] << (4 * i);
    }

    bit_replacement(res, &P, 32)
}
