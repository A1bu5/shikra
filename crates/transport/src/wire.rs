use prost::Message;
use shikra_crypto::channel::{SealedFrame, SessionKeys};
use shikra_proto::v1::{AgentMessage, Envelope};
use thiserror::Error;

pub const ENVELOPE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum WireError {
    #[error("crypto error: {0}")]
    Crypto(#[from] shikra_crypto::CryptoError),
    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("unsupported envelope version {0}")]
    Version(u32),
    #[error("invalid nonce length {0}")]
    Nonce(usize),
    #[error("session id mismatch")]
    SessionMismatch,
    #[error("malformed wire data: {0}")]
    Malformed(&'static str),
}

pub fn seal_message(keys: &mut SessionKeys, message: &AgentMessage) -> Result<Envelope, WireError> {
    let plaintext = message.encode_to_vec();
    let frame = keys.seal(&plaintext)?;
    Ok(envelope_from_frame(keys.session_id(), frame))
}

pub fn open_message(
    keys: &mut SessionKeys,
    envelope: &Envelope,
) -> Result<AgentMessage, WireError> {
    if envelope.version != ENVELOPE_VERSION {
        return Err(WireError::Version(envelope.version));
    }
    if envelope.session_id != keys.session_id() {
        return Err(WireError::SessionMismatch);
    }
    let nonce: [u8; 12] = envelope
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| WireError::Nonce(envelope.nonce.len()))?;
    let plaintext = keys.open(envelope.sequence, &nonce, &envelope.ciphertext)?;
    Ok(AgentMessage::decode(plaintext.as_slice())?)
}

pub fn envelope_from_frame(session_id: &str, frame: SealedFrame) -> Envelope {
    Envelope {
        version: ENVELOPE_VERSION,
        session_id: session_id.to_string(),
        sequence: frame.sequence,
        nonce: frame.nonce.to_vec(),
        ciphertext: frame.ciphertext,
    }
}

pub fn encode_envelope(envelope: &Envelope) -> Result<Vec<u8>, WireError> {
    Ok(envelope.encode_to_vec())
}

pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, WireError> {
    Ok(Envelope::decode(bytes)?)
}

/// Message the agent signs to prove identity possession during enrollment.
pub fn enroll_message(kex_public: &[u8; 32]) -> Vec<u8> {
    let mut message = b"shikra-enroll-v1".to_vec();
    message.extend_from_slice(kex_public);
    message
}

/// Transcript the server signs to prove its identity and bind both kex keys.
pub fn checkin_response_message(
    session_id: &str,
    agent_kex_public: &[u8; 32],
    server_kex_public: &[u8; 32],
) -> Vec<u8> {
    let mut message = b"shikra-checkin-v1".to_vec();
    message.extend_from_slice(session_id.as_bytes());
    message.extend_from_slice(agent_kex_public);
    message.extend_from_slice(server_kex_public);
    message
}

pub fn to_timestamp(value: time::OffsetDateTime) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.unix_timestamp(),
        nanos: value.nanosecond() as i32,
    }
}

pub fn from_timestamp(value: &prost_types::Timestamp) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(value.seconds)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        + time::Duration::nanoseconds(value.nanos as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shikra_crypto::kex::KeyPair;
    use shikra_proto::v1::{agent_message, AgentHeartbeat};

    fn keys_pair() -> (SessionKeys, SessionKeys) {
        let agent = KeyPair::generate();
        let server = KeyPair::generate();
        let shared = agent.diffie_hellman(&server.public_key());
        (
            SessionKeys::derive("s-1", &shared, true).expect("agent"),
            SessionKeys::derive("s-1", &shared, false).expect("server"),
        )
    }

    #[test]
    fn message_roundtrip() {
        let (mut agent, mut server) = keys_pair();
        let message = AgentMessage {
            body: Some(agent_message::Body::Heartbeat(AgentHeartbeat {
                unix_ms: 42,
            })),
        };

        let envelope = seal_message(&mut agent, &message).expect("seal");
        let opened = open_message(&mut server, &envelope).expect("open");
        assert!(matches!(
            opened.body,
            Some(agent_message::Body::Heartbeat(AgentHeartbeat {
                unix_ms: 42
            }))
        ));
    }

    #[test]
    fn wrong_session_is_rejected() {
        let (mut agent, mut server) = keys_pair();
        let message = AgentMessage {
            body: Some(agent_message::Body::Heartbeat(AgentHeartbeat {
                unix_ms: 1,
            })),
        };
        let mut envelope = seal_message(&mut agent, &message).expect("seal");
        envelope.session_id = "other".into();
        assert!(matches!(
            open_message(&mut server, &envelope),
            Err(WireError::SessionMismatch)
        ));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut agent, mut server) = keys_pair();
        let message = AgentMessage {
            body: Some(agent_message::Body::Heartbeat(AgentHeartbeat {
                unix_ms: 1,
            })),
        };
        let mut envelope = seal_message(&mut agent, &message).expect("seal");
        if let Some(last) = envelope.ciphertext.last_mut() {
            *last ^= 0xff;
        }
        assert!(open_message(&mut server, &envelope).is_err());
    }
}
