use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct TlsMaterial {
    pub ca_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

pub fn ensure_tls_material(state_dir: &Path) -> Result<TlsMaterial> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("failed to create state dir {}", state_dir.display()))?;

    let ca_cert_path = state_dir.join("ca.pem");
    let ca_key_path = state_dir.join("ca-key.pem");
    let server_cert_path = state_dir.join("server.pem");
    let server_key_path = state_dir.join("server-key.pem");

    if ca_cert_path.exists()
        && ca_key_path.exists()
        && server_cert_path.exists()
        && server_key_path.exists()
    {
        return load_tls_material(state_dir);
    }

    let ca_key = KeyPair::generate().context("failed to generate CA key")?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .context("failed to build CA certificate params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Shikra Local CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("failed to self-sign CA certificate")?;

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()])
        .context("failed to build server certificate params")?;
    server_params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
    server_params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv6Addr::LOCALHOST.into()));
    server_params
        .distinguished_name
        .push(DnType::CommonName, "shikra-server");
    server_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    let server_key = KeyPair::generate().context("failed to generate server key")?;
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .context("failed to sign server certificate")?;

    write_secret(&ca_key_path, ca_key.serialize_pem().as_bytes())?;
    write_secret(&server_key_path, server_key.serialize_pem().as_bytes())?;
    write_public(&ca_cert_path, ca_cert.pem().as_bytes())?;
    write_public(&server_cert_path, server_cert.pem().as_bytes())?;

    load_tls_material(state_dir)
}

pub fn load_tls_material(state_dir: &Path) -> Result<TlsMaterial> {
    Ok(TlsMaterial {
        ca_pem: read_pem(&state_dir.join("ca.pem"))?,
        server_cert_pem: read_pem(&state_dir.join("server.pem"))?,
        server_key_pem: read_pem(&state_dir.join("server-key.pem"))?,
    })
}

pub fn load_ca_pem(state_dir: &Path) -> Result<String> {
    read_pem(&state_dir.join("ca.pem"))
}

pub fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    write_secret(path, contents)
}

pub fn read_text_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_decode(raw: &str) -> Result<Vec<u8>> {
    hex::decode(raw.trim()).context("invalid hex input")
}

pub fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    restrict_permissions(path)?;
    Ok(())
}

fn write_public(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("failed to chmod 600 {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn read_pem(path: &PathBuf) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_reloads_material() {
        let dir = std::env::temp_dir().join(format!("shikra-tls-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let material = ensure_tls_material(&dir).expect("generate");
        assert!(material.ca_pem.contains("BEGIN CERTIFICATE"));
        assert!(material.server_key_pem.contains("BEGIN PRIVATE KEY"));

        let reloaded = ensure_tls_material(&dir).expect("reload");
        assert_eq!(material.ca_pem, reloaded.ca_pem);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tokens_are_unique() {
        assert_ne!(random_token(), random_token());
    }
}
