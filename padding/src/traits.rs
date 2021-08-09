pub trait Padding<const BLOCK_SIZE: usize> {
    fn pad(m: &Vec<u8>) -> Vec<u8>;

    fn unpad(m: &Vec<u8>) -> Vec<u8>;
}
