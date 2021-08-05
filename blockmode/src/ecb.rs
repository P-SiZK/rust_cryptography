use crate::traits::BlockMode;

use blockcipher::BlockCipher;
use std::marker::PhantomData;

pub struct ECB<C, K, const BLOCK_SIZE: usize>
where
    C: BlockCipher<K, BLOCK_SIZE>,
{
    _c: PhantomData<fn() -> C>,
    _k: PhantomData<fn() -> K>,
}

impl<C, K, const BLOCK_SIZE: usize> BlockMode<C, K, BLOCK_SIZE> for ECB<C, K, BLOCK_SIZE>
where
    C: BlockCipher<K, BLOCK_SIZE>,
{
    fn new() -> Self {
        Self {
            _c: PhantomData,
            _k: PhantomData,
        }
    }

    fn encrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8> {
        let mut c: Vec<u8> = Vec::with_capacity(BLOCK_SIZE * blocks.len());
        for block in &blocks {
            let mut cblock = C::encrypt(block, key);
            c.append(&mut cblock);
        }
        c
    }

    fn decrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8> {
        let mut m: Vec<u8> = Vec::with_capacity(BLOCK_SIZE * blocks.len());
        for block in &blocks {
            let mut mblock = C::decrypt(block, key);
            m.append(&mut mblock);
        }
        m
    }
}
