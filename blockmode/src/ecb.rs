use crate::traits::BlockMode;

use blockcipher::BlockCipher;
use padding::Padding;
use std::marker::PhantomData;

pub struct ECB<C, K, P, const BLOCK_SIZE: usize>
where
    C: BlockCipher<K, BLOCK_SIZE>,
    P: Padding<BLOCK_SIZE>,
{
    _c: PhantomData<fn() -> C>,
    _k: PhantomData<fn() -> K>,
    _p: PhantomData<fn() -> P>,
}

impl<C, K, P, const BLOCK_SIZE: usize> BlockMode<C, K, P, BLOCK_SIZE> for ECB<C, K, P, BLOCK_SIZE>
where
    C: BlockCipher<K, BLOCK_SIZE>,
    P: Padding<BLOCK_SIZE>,
{
    fn new(_cipher: C, _padding: P) -> Self {
        Self {
            _c: PhantomData,
            _k: PhantomData,
            _p: PhantomData,
        }
    }

    fn encrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8> {
        let mut c: Vec<u8> = Vec::with_capacity((BLOCK_SIZE / 8) * blocks.len());
        for block in &blocks {
            let mut cblock = C::encrypt(block, key);
            c.append(&mut cblock);
        }
        c
    }

    fn decrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8> {
        let mut m: Vec<u8> = Vec::with_capacity((BLOCK_SIZE / 8) * blocks.len());
        for block in &blocks {
            let mut mblock = C::decrypt(block, key);
            m.append(&mut mblock);
        }
        m
    }
}
