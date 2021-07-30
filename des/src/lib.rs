mod consts;
mod des;

pub use crate::des::DESKey;
pub use crate::des::{decrypt, encrypt, key_gen};
