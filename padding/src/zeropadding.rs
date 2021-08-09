use crate::traits::Padding;

pub struct ZeroPadding<const BLOCK_SIZE: usize>;

impl<const BLOCK_SIZE: usize> Padding<BLOCK_SIZE> for ZeroPadding<BLOCK_SIZE> {
    fn pad(m: &Vec<u8>) -> Vec<u8> {
        let byte_size = BLOCK_SIZE / 8;
        let mut m_pad = m.clone();
        m_pad.resize((m.len() + byte_size - 1) / byte_size * byte_size, 0);
        m_pad
    }

    fn unpad(m: &Vec<u8>) -> Vec<u8> {
        for (i, val) in m.iter().enumerate().rev() {
            if *val != 0 {
                return m[..=i].to_vec();
            }
        }
        m.clone()
    }
}
