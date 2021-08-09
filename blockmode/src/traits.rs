use blockcipher::BlockCipher;
use padding::Padding;

/// C is block cipher algorithm
/// K is block cipher key
/// BLOCK_SIZE is bit length of a block
pub trait BlockMode<C, K, P, const BLOCK_SIZE: usize>
where
    C: BlockCipher<K, BLOCK_SIZE>,
    P: Padding<BLOCK_SIZE>,
{
    fn new(cipher: C, padding: P) -> Self;

    fn encrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8>;

    fn decrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8>;

    fn encrypt(&self, m: &Vec<u8>, key: &K) -> Vec<u8> {
        let m_pad = &P::pad(m);
        self.encrypt_block(block_from::<BLOCK_SIZE>(m_pad), key)
    }

    fn decrypt(&self, c: &Vec<u8>, key: &K) -> Vec<u8> {
        let m_pad = &self.decrypt_block(block_from::<BLOCK_SIZE>(c), key);
        P::unpad(m_pad)
    }
}

fn block_from<const BLOCK_SIZE: usize>(bytes: &Vec<u8>) -> Vec<Vec<u8>> {
    use std::convert::TryInto;
    bytes
        .chunks_exact(BLOCK_SIZE / 8)
        .map(|x| x.try_into().unwrap())
        .collect()
}
