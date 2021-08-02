use crate::traits::BlockMode;

use blockcipher::BlockCipher;
use core::marker::PhantomData;

pub struct ECB<C, K, const BLOCK_SIZE: usize>
where
    C: BlockCipher<K, BLOCK_SIZE>,
{
    block_cipher: C,
    _k: PhantomData<K>,
}

impl<C, K, const BLOCK_SIZE: usize> BlockMode<K, BLOCK_SIZE> for ECB<C, K, BLOCK_SIZE>
where
    C: BlockCipher<K, BLOCK_SIZE>,
{
    fn encrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8> {
        let mut c: Vec<u8> = Vec::with_capacity(BLOCK_SIZE * blocks.len());
        for block in blocks {
            let mut cblock = self.block_cipher.encrypt(block, key);
            c.append(&mut cblock);
        }
        c
    }

    fn decrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8> {
        let mut m: Vec<u8> = Vec::with_capacity(BLOCK_SIZE * blocks.len());
        for block in blocks {
            let mut mblock = self.block_cipher.decrypt(block, key);
            m.append(&mut mblock);
        }
        m
    }
}
