use crate::aead::{random_nonce, AeadKey, NONCE_LEN};
use crate::error::{CryptoError, Result};
use crate::kdf::derive_key;

/// How far the receiver may skip ahead of the next expected sequence. Covers
/// lost or rejected requests while staying small enough to bound abuse.
pub const MAX_SEQUENCE_GAP: u64 = 4096;

/// One sealed frame: monotonic sequence, random nonce, AEAD ciphertext.
#[derive(Debug, Clone)]
pub struct SealedFrame {
    pub sequence: u64,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Directional AEAD channel bound to a session id.
///
/// Both peers derive it from an X25519 shared secret. The initiator (agent)
/// sends with `a2c` and receives with `c2a`; the responder (server) uses the
/// opposite mapping. Sequence numbers are strict and monotonic in each
/// direction, which makes replay/truncation detectable at the channel layer.
pub struct SessionKeys {
    session_id: String,
    send_key: AeadKey,
    recv_key: AeadKey,
    send_seq: u64,
    recv_seq: u64,
}

impl SessionKeys {
    pub fn derive(session_id: &str, shared_secret: &[u8; 32], initiator: bool) -> Result<Self> {
        let salt = session_id.as_bytes();
        let c2a = derive_key(shared_secret, salt, b"shikra/v1/c2a")?;
        let a2c = derive_key(shared_secret, salt, b"shikra/v1/a2c")?;

        let (send_key, recv_key) = if initiator {
            (AeadKey::from_bytes(a2c), AeadKey::from_bytes(c2a))
        } else {
            (AeadKey::from_bytes(c2a), AeadKey::from_bytes(a2c))
        };

        Ok(Self {
            session_id: session_id.to_string(),
            send_key,
            recv_key,
            send_seq: 0,
            recv_seq: 0,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    fn aad(&self, sequence: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.session_id.len() + 8);
        aad.extend_from_slice(self.session_id.as_bytes());
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<SealedFrame> {
        let sequence = self.send_seq;
        let nonce = random_nonce();
        let ciphertext = self.send_key.seal(&nonce, &self.aad(sequence), plaintext)?;
        self.send_seq = self
            .send_seq
            .checked_add(1)
            .ok_or_else(|| CryptoError::Encrypt("sequence exhausted".into()))?;
        Ok(SealedFrame {
            sequence,
            nonce,
            ciphertext,
        })
    }

    pub fn open(
        &mut self,
        sequence: u64,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // Strict anti-replay: any sequence above the next expected one is
        // only tolerated inside a bounded window, so a dropped request (a
        // lost poll, an oversized body rejected by the server) heals on the
        // following message instead of bricking the session.
        if sequence < self.recv_seq || sequence - self.recv_seq > MAX_SEQUENCE_GAP {
            return Err(CryptoError::Replay);
        }
        let plaintext = self.recv_key.open(nonce, &self.aad(sequence), ciphertext)?;
        self.recv_seq = sequence
            .checked_add(1)
            .ok_or_else(|| CryptoError::Encrypt("sequence exhausted".into()))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kex::KeyPair;

    fn channel_pair(session_id: &str) -> (SessionKeys, SessionKeys) {
        let agent = KeyPair::generate();
        let server = KeyPair::generate();
        let agent_shared = agent.diffie_hellman(&server.public_key());
        let server_shared = server.diffie_hellman(&agent.public_key());
        assert_eq!(agent_shared, server_shared);
        (
            SessionKeys::derive(session_id, &agent_shared, true).expect("agent keys"),
            SessionKeys::derive(session_id, &server_shared, false).expect("server keys"),
        )
    }

    #[test]
    fn bidirectional_roundtrip() {
        let (mut agent, mut server) = channel_pair("session-1");

        let frame = agent.seal(b"hello from agent").expect("seal");
        let plaintext = server
            .open(frame.sequence, &frame.nonce, &frame.ciphertext)
            .expect("open");
        assert_eq!(plaintext, b"hello from agent");

        let reply = server.seal(b"hello from server").expect("seal");
        let plaintext = agent
            .open(reply.sequence, &reply.nonce, &reply.ciphertext)
            .expect("open");
        assert_eq!(plaintext, b"hello from server");
    }

    #[test]
    fn replay_is_rejected() {
        let (mut agent, mut server) = channel_pair("session-2");
        let frame = agent.seal(b"one").expect("seal");

        server
            .open(frame.sequence, &frame.nonce, &frame.ciphertext)
            .expect("first open");
        assert!(matches!(
            server.open(frame.sequence, &frame.nonce, &frame.ciphertext),
            Err(CryptoError::Replay)
        ));
    }

    #[test]
    fn dropped_frame_heals_within_window() {
        let (mut agent, mut server) = channel_pair("session-3");
        let first = agent.seal(b"one").expect("seal");
        let second = agent.seal(b"two").expect("seal");

        // The first request was lost (e.g. rejected upstream); the next one
        // must still be accepted and advance the receive sequence.
        let plaintext = server
            .open(second.sequence, &second.nonce, &second.ciphertext)
            .expect("gap open");
        assert_eq!(plaintext, b"two");

        // The skipped frame is now a replay.
        assert!(matches!(
            server.open(first.sequence, &first.nonce, &first.ciphertext),
            Err(CryptoError::Replay)
        ));

        // The following frame opens normally.
        let third = agent.seal(b"three").expect("seal");
        server
            .open(third.sequence, &third.nonce, &third.ciphertext)
            .expect("in-order open");
    }

    #[test]
    fn gap_beyond_window_is_rejected() {
        let (mut agent, mut server) = channel_pair("session-4");
        let mut last = None;
        for _ in 0..(MAX_SEQUENCE_GAP + 2) {
            last = Some(agent.seal(b"x").expect("seal"));
        }
        let frame = last.expect("frame");
        assert!(matches!(
            server.open(frame.sequence, &frame.nonce, &frame.ciphertext),
            Err(CryptoError::Replay)
        ));
    }

    #[test]
    fn cross_session_frame_is_rejected() {
        let (_agent, mut server) = channel_pair("session-4");
        let (mut other_agent, _) = channel_pair("session-5");
        let frame = other_agent.seal(b"foreign").expect("seal");
        assert!(server
            .open(frame.sequence, &frame.nonce, &frame.ciphertext)
            .is_err());
    }
}
