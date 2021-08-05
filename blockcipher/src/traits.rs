pub trait BlockCipher<K, const BLOCK_SIZE: usize> {
    fn key_gen() -> K;

    fn encrypt(m: &Vec<u8>, key: &K) -> Vec<u8>;

    fn decrypt(m: &Vec<u8>, key: &K) -> Vec<u8>;
}
