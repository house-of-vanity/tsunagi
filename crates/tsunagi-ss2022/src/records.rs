//! The SIP022 record construction used by Shoes (MIT).
use super::{TAG, invalid};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::{Zeroize, Zeroizing};

pub(super) struct Records {
    key: LessSafeKey,
    counter: u128,
}
impl Records {
    pub(super) fn new(key: &[u8], salt: &[u8]) -> io::Result<Self> {
        let algorithm = match (key.len(), salt.len()) {
            (16, 16) => &aead::AES_128_GCM,
            (32, 32) => &aead::AES_256_GCM,
            _ => return Err(invalid()),
        };
        let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
        hasher.update(key).update(salt);
        let mut subkey = Zeroizing::new([0; 32]);
        hasher.finalize_xof().fill(&mut subkey[..key.len()]);
        hasher.zeroize();
        let key = UnboundKey::new(algorithm, &subkey[..key.len()]).map_err(|_| invalid())?;
        Ok(Self {
            key: LessSafeKey::new(key),
            counter: 0,
        })
    }
    fn nonce(&mut self) -> io::Result<Nonce> {
        if self.counter >= 1 << 96 {
            return Err(invalid());
        }
        let mut nonce = [0; 12];
        nonce.copy_from_slice(&self.counter.to_le_bytes()[..12]);
        self.counter += 1;
        Ok(Nonce::assume_unique_for_key(nonce))
    }
    pub(super) fn seal(&mut self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = self.nonce()?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
            .map_err(|_| invalid())?;
        Ok(buf)
    }
    pub(super) fn open(&mut self, mut buf: Vec<u8>) -> io::Result<Vec<u8>> {
        let nonce = self.nonce()?;
        let size = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut buf)
            .map_err(|_| invalid())?
            .len();
        buf.truncate(size);
        Ok(buf)
    }
    pub(super) async fn read(
        &mut self,
        r: &mut (impl AsyncRead + Unpin),
        len: usize,
    ) -> io::Result<Vec<u8>> {
        let mut buf = vec![0; len + TAG];
        r.read_exact(&mut buf).await?;
        self.open(buf)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn both_methods_authenticate_each_record_and_enforce_nonce_order() {
        for n in [16, 32] {
            let key = &[0x33; 32][..n];
            let salt = &[0x44; 32][..n];
            let mut tx = Records::new(key, salt).unwrap();
            let mut rx = Records::new(key, salt).unwrap();
            let a = tx.seal(b"ab").unwrap();
            let b = tx.seal(b"ab").unwrap();
            assert_ne!(a, b);
            assert_eq!(rx.open(a.clone()).unwrap(), b"ab");
            assert_eq!(rx.open(b).unwrap(), b"ab");
            assert!(rx.open(a.clone()).is_err());
            let mut corrupt = a;
            corrupt[1] ^= 0x40;
            assert!(Records::new(key, salt).unwrap().open(corrupt).is_err());
        }
    }
}
