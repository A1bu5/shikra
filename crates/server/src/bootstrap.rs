use anyhow::{Context, Result};
use shikra_crypto::signing::Identity;
use shikra_transport::tls::{random_token, write_secret_file, TlsMaterial};
use std::path::Path;

pub struct Bootstrap {
    pub tls: TlsMaterial,
    pub server_identity: Identity,
    /// Public key extensions must be signed with.
    pub armory_public: [u8; 32],
    pub enroll_token: String,
    pub operator_token: String,
    /// Bearer token external agents present when registering.
    pub relay_token: String,
}

/// Generates a fresh random bearer token (hex).
pub fn new_token() -> String {
    shikra_transport::tls::random_token()
}

pub fn bootstrap(state_dir: &Path) -> Result<Bootstrap> {
    let tls = shikra_transport::tls::ensure_tls_material(state_dir)?;
    let server_identity = load_or_create_identity(state_dir)?;
    let armory_identity = load_or_create_identity_file(state_dir, "armory.key", "armory.pub")?;
    let armory_public = armory_identity.public_key_bytes();
    let enroll_token = load_or_create_token(state_dir, "enroll.token")?;
    let operator_token = load_or_create_token(state_dir, "operator.token")?;
    let relay_token = load_or_create_token(state_dir, "relay.token")?;
    shikra_transport::profile::ProfileSet::write_default_if_missing(state_dir)?;

    let public_hex = shikra_transport::tls::hex_encode(&server_identity.public_key_bytes());
    std::fs::write(state_dir.join("server-identity.pub"), public_hex.as_bytes())?;

    Ok(Bootstrap {
        tls,
        server_identity,
        armory_public,
        enroll_token,
        operator_token,
        relay_token,
    })
}

impl Bootstrap {
    pub fn server_identity_hex(&self) -> String {
        shikra_transport::tls::hex_encode(&self.server_identity.public_key_bytes())
    }
}

fn load_or_create_identity(state_dir: &Path) -> Result<Identity> {
    load_or_create_identity_file(state_dir, "server-identity.key", "server-identity.pub")
}

/// Loads or creates an Ed25519 identity persisted in `key_file`, writing the
/// public key hex to `public_file`.
pub fn load_or_create_identity_file(
    state_dir: &Path,
    key_file: &str,
    public_file: &str,
) -> Result<Identity> {
    let identity_path = state_dir.join(key_file);
    let identity = if identity_path.exists() {
        let hex_seed = shikra_transport::tls::read_text_file(&identity_path)?;
        let bytes = shikra_transport::tls::hex_decode(&hex_seed)?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .with_context(|| format!("{key_file} seed must be 32 bytes"))?;
        Identity::from_seed(&seed)
    } else {
        let identity = Identity::generate();
        write_secret_file(
            &identity_path,
            shikra_transport::tls::hex_encode(&identity.secret_key_bytes()).as_bytes(),
        )?;
        identity
    };
    std::fs::write(
        state_dir.join(public_file),
        shikra_transport::tls::hex_encode(&identity.public_key_bytes()).as_bytes(),
    )?;
    Ok(identity)
}

fn load_or_create_token(state_dir: &Path, file: &str) -> Result<String> {
    let path = state_dir.join(file);
    if path.exists() {
        return Ok(shikra_transport::tls::read_text_file(&path)?
            .trim()
            .to_string());
    }
    let token = random_token();
    write_secret_file(&path, token.as_bytes())?;
    Ok(token)
}

pub fn load_pinned_identity(state_dir: &Path) -> Result<String> {
    Ok(
        shikra_transport::tls::read_text_file(&state_dir.join("server-identity.pub"))?
            .trim()
            .to_string(),
    )
}
