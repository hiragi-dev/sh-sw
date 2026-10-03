//! MITM 用ルート CA の読み込み。CA は API が SHSW_CERT_DIR に書き出す。

use rama::error::BoxError;
use rama::tls::boring::core::{
    pkey::{PKey, Private},
    x509::X509,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub struct CaFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl CaFiles {
    pub fn from_dir(dir: &Path) -> Self {
        Self {
            cert: dir.join("ca.pem"),
            key: dir.join("ca-key.pem"),
        }
    }
}

pub struct LoadedCa {
    pub cert: X509,
    pub key: PKey<Private>,
    /// 証明書 DER の SHA-256 (hex)。API の ca_fingerprint と同じ形式
    pub fingerprint: String,
}

pub fn load(files: &CaFiles) -> Result<LoadedCa, BoxError> {
    let cert_pem = std::fs::read(&files.cert)?;
    let key_pem = std::fs::read(&files.key)?;
    let cert = X509::from_pem(&cert_pem)?;
    let key = PKey::private_key_from_pem(&key_pem)?;
    let fingerprint = hex::encode(Sha256::digest(cert.to_der()?));
    Ok(LoadedCa { cert, key, fingerprint })
}
