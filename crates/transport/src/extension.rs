//! Extension package format.
//!
//! Packages carry a manifest, the payload bytes and an Ed25519 signature made
//! by the team's armory key. The signature covers a canonical byte string
//! derived from the manifest fields and the payload hash so that neither can be
//! altered independently.

use crate::wire::WireError;
use base64::Engine;
use sha2::{Digest, Sha256};
use shikra_crypto::signing::{verify, Identity};

const SIGNING_CONTEXT: &[u8] = b"shikra-extension-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionKind {
    Wasm,
    Native,
}

impl ExtensionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wasm => "wasm",
            Self::Native => "native",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "wasm" => Some(Self::Wasm),
            "native" | "dylib" | "so" | "dll" => Some(Self::Native),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionPlatform {
    Any,
    Macos,
    Linux,
    Windows,
}

impl ExtensionPlatform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "any" => Some(Self::Any),
            "macos" | "darwin" => Some(Self::Macos),
            "linux" => Some(Self::Linux),
            "windows" => Some(Self::Windows),
            _ => None,
        }
    }

    /// Matches the current host.
    pub fn matches_host(&self) -> bool {
        match self {
            Self::Any => true,
            Self::Macos => cfg!(target_os = "macos"),
            Self::Linux => cfg!(target_os = "linux"),
            Self::Windows => cfg!(target_os = "windows"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtensionManifest {
    pub name: String,
    pub version: String,
    pub kind: ExtensionKind,
    pub platform: ExtensionPlatform,
    #[serde(default = "default_arch")]
    pub architecture: String,
    #[serde(default)]
    pub description: String,
    /// Hex SHA-256 of the payload.
    pub sha256: String,
    pub size: u64,
}

fn default_arch() -> String {
    "any".into()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtensionPackage {
    pub manifest: ExtensionManifest,
    /// Base64 (standard) encoded payload.
    pub payload_b64: String,
    /// Hex Ed25519 public key of the signer.
    pub signer: String,
    /// Hex Ed25519 signature over the canonical signing message.
    pub signature: String,
}

impl ExtensionPackage {
    /// Builds and signs a package with `identity`.
    pub fn build(
        mut manifest: ExtensionManifest,
        payload: &[u8],
        identity: &Identity,
    ) -> Result<Self, WireError> {
        if manifest.name.trim().is_empty() {
            return Err(WireError::Malformed("extension name is required"));
        }
        if manifest.version.trim().is_empty() {
            return Err(WireError::Malformed("extension version is required"));
        }
        manifest.sha256 = hex_encode(&Sha256::digest(payload));
        manifest.size = payload.len() as u64;
        let signer = hex_encode(&identity.public_key_bytes());
        let message = signing_message(&manifest)?;
        let signature = hex_encode(&identity.sign(&message).to_bytes());
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        Ok(Self {
            manifest,
            payload_b64,
            signer,
            signature,
        })
    }

    /// Verifies the signature against `expected_signer` and returns the
    /// payload after checking its hash and size.
    pub fn verify(&self, expected_signer: &[u8; 32]) -> Result<Vec<u8>, WireError> {
        let signer = hex_decode(&self.signer)?;
        if signer.as_slice() != expected_signer {
            return Err(WireError::Malformed("extension signed by untrusted key"));
        }
        let signature = hex_decode(&self.signature)?;
        let message = signing_message(&self.manifest)?;
        verify(expected_signer, &message, &signature)
            .map_err(|_| WireError::Malformed("extension signature is invalid"))?;

        let payload = base64::engine::general_purpose::STANDARD
            .decode(self.payload_b64.as_bytes())
            .map_err(|_| WireError::Malformed("extension payload is not valid base64"))?;
        let digest = hex_encode(&Sha256::digest(&payload));
        if digest != self.manifest.sha256 {
            return Err(WireError::Malformed("extension payload hash mismatch"));
        }
        if payload.len() as u64 != self.manifest.size {
            return Err(WireError::Malformed("extension payload size mismatch"));
        }
        Ok(payload)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, WireError> {
        serde_json::to_vec_pretty(self).map_err(|_| WireError::Malformed("encode package"))
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, WireError> {
        serde_json::from_slice(bytes).map_err(|_| WireError::Malformed("decode package"))
    }
}

/// Canonical bytes covered by the signature.
fn signing_message(manifest: &ExtensionManifest) -> Result<Vec<u8>, WireError> {
    let mut message = Vec::with_capacity(256);
    message.extend_from_slice(SIGNING_CONTEXT);
    for field in [
        manifest.name.as_str(),
        manifest.version.as_str(),
        manifest.kind.as_str(),
        manifest.platform.as_str(),
        manifest.architecture.as_str(),
        manifest.description.as_str(),
        manifest.sha256.as_str(),
    ] {
        message.push(0);
        message.extend_from_slice(field.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&manifest.size.to_le_bytes());
    Ok(message)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(raw: &str) -> Result<Vec<u8>, WireError> {
    if raw.len() % 2 != 0 {
        return Err(WireError::Malformed("odd hex length"));
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    let bytes = raw.as_bytes();
    for pair in bytes.chunks(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, WireError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(WireError::Malformed("invalid hex digit")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> ExtensionManifest {
        ExtensionManifest {
            name: "hello".into(),
            version: "1.0.0".into(),
            kind: ExtensionKind::Native,
            platform: ExtensionPlatform::Any,
            architecture: "any".into(),
            description: "example".into(),
            sha256: String::new(),
            size: 0,
        }
    }

    #[test]
    fn package_roundtrip_and_verify() {
        let identity = Identity::generate();
        let payload = b"extension-payload-bytes";
        let package = ExtensionPackage::build(manifest(), payload, &identity).expect("build");
        let json = package.to_json().expect("json");
        let parsed = ExtensionPackage::from_json(&json).expect("parse");
        let verified = parsed.verify(&identity.public_key_bytes()).expect("verify");
        assert_eq!(verified, payload);
    }

    #[test]
    fn rejects_untrusted_signer() {
        let identity = Identity::generate();
        let other = Identity::generate();
        let package = ExtensionPackage::build(manifest(), b"payload", &identity).expect("build");
        assert!(package.verify(&other.public_key_bytes()).is_err());
    }

    #[test]
    fn rejects_tampered_payload() {
        let identity = Identity::generate();
        let mut package =
            ExtensionPackage::build(manifest(), b"payload", &identity).expect("build");
        let mut decoded = base64::engine::general_purpose::STANDARD
            .decode(package.payload_b64.as_bytes())
            .expect("decode");
        decoded[0] ^= 0x42;
        package.payload_b64 = base64::engine::general_purpose::STANDARD.encode(&decoded);
        assert!(package.verify(&identity.public_key_bytes()).is_err());
    }

    #[test]
    fn rejects_tampered_manifest() {
        let identity = Identity::generate();
        let mut package =
            ExtensionPackage::build(manifest(), b"payload", &identity).expect("build");
        package.manifest.version = "9.9.9".into();
        assert!(package.verify(&identity.public_key_bytes()).is_err());
    }

    #[test]
    fn rejects_empty_name() {
        let identity = Identity::generate();
        let mut manifest = manifest();
        manifest.name = "  ".into();
        assert!(ExtensionPackage::build(manifest, b"x", &identity).is_err());
    }

    #[test]
    fn platform_matching() {
        assert!(ExtensionPlatform::Any.matches_host());
        assert_eq!(
            ExtensionPlatform::parse("darwin"),
            Some(ExtensionPlatform::Macos)
        );
        assert_eq!(ExtensionKind::parse("dll"), Some(ExtensionKind::Native));
    }
}
