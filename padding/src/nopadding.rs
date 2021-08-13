use crate::traits::Padding;

pub struct NoPadding<const BLOCK_SIZE: usize>;

impl<const BLOCK_SIZE: usize> Padding<BLOCK_SIZE> for NoPadding<BLOCK_SIZE> {
    fn pad(m: &Vec<u8>) -> Vec<u8> {
        m.clone()
    }

    fn unpad(m: &Vec<u8>) -> Vec<u8> {
        m.clone()
    }
}
