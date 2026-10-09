use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SHARED_SECRET_LEN: usize = 32;

pub struct KeyPair {
    secret: StaticSecret,
}

impl KeyPair {
    pub fn generate() -> Self {
        Self {
            secret: StaticSecret::random_from_rng(OsRng),
        }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        PublicKey::from(&self.secret).to_bytes()
    }

    pub fn diffie_hellman(&self, peer_public: &[u8; PUBLIC_KEY_LEN]) -> [u8; SHARED_SECRET_LEN] {
        let peer = PublicKey::from(*peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_matches() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn different_peers_produce_different_secrets() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();
        let eve = KeyPair::generate();

        assert_ne!(
            alice.diffie_hellman(&bob.public_key()),
            alice.diffie_hellman(&eve.public_key())
        );
    }
}
