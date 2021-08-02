pub trait BlockCipher<K, const BLOCK_SIZE: usize> {
    fn key_gen(&self) -> K;

    fn encrypt(&self, m: Vec<u8>, key: &K) -> Vec<u8>;

    fn decrypt(&self, m: Vec<u8>, key: &K) -> Vec<u8>;
}
