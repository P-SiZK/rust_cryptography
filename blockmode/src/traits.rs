/// C is block cipher algorithm
/// K is block cipher key
/// BLOCK_SIZE is bit length of a block
pub trait BlockMode<C, K, const BLOCK_SIZE: usize> {
    fn new() -> Self;

    fn encrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8>;

    fn decrypt_block(&self, blocks: Vec<Vec<u8>>, key: &K) -> Vec<u8>;

    fn encrypt(&self, m: &Vec<u8>, key: &K) -> Vec<u8> {
        self.encrypt_block(block_from::<BLOCK_SIZE>(m), key)
    }

    fn decrypt(&self, m: &Vec<u8>, key: &K) -> Vec<u8> {
        self.decrypt_block(block_from::<BLOCK_SIZE>(m), key)
    }
}

fn block_from<const BLOCK_SIZE: usize>(bytes: &Vec<u8>) -> Vec<Vec<u8>> {
    use std::convert::TryInto;
    bytes
        .chunks_exact(BLOCK_SIZE / 8)
        .map(|x| x.try_into().unwrap())
        .collect()
}
