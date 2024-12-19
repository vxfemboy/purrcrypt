// src/keystore.rs
use crate::debug;
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Home directory not found")]
    NoHomeDir,
    #[error("Invalid key permissions: {0}")]
    InvalidPermissions(String),
    #[error("Key not found: {0}")]
    KeyNotFound(String),
}

pub struct Keystore {
    pub home_dir: PathBuf,
    pub keys_dir: PathBuf,
}

impl Keystore {
    pub fn new() -> Result<Self, KeystoreError> {
        let home = dirs::home_dir().ok_or(KeystoreError::NoHomeDir)?;
        let purr_dir = home.join(".purr");
        let keys_dir = purr_dir.join("keys");

        // Create required directories
        fs::create_dir_all(&keys_dir)?;
        fs::create_dir_all(keys_dir.join("public"))?;
        fs::create_dir_all(keys_dir.join("private"))?;

        #[cfg(unix)]
        {
            // ~/.purr and keys directories should be private (700)
            fs::set_permissions(&purr_dir, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&keys_dir, fs::Permissions::from_mode(0o700))?;

            // private key directory should be private (700)
            fs::set_permissions(&keys_dir.join("private"), fs::Permissions::from_mode(0o700))?;

            // public key directory can be readable (755)
            fs::set_permissions(&keys_dir.join("public"), fs::Permissions::from_mode(0o755))?;
        }

        Ok(Self {
            home_dir: purr_dir,
            keys_dir,
        })
    }

    pub fn get_key_paths(&self, name: &str) -> (PathBuf, PathBuf) {
        // Strip any existing extensions
        let stem = Path::new(name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(name);

        let pub_path = self.keys_dir.join("public").join(format!("{}.pub", stem));
        let priv_path = self.keys_dir.join("private").join(format!("{}.key", stem));

        debug!("Looking for public key at: {}", pub_path.display());
        debug!("Looking for private key at: {}", priv_path.display());

        (pub_path, priv_path)
    }

    pub fn import_key(&self, key_path: &Path, is_public: bool) -> Result<PathBuf, KeystoreError> {
        let stem = key_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                KeystoreError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid key filename",
                ))
            })?;

        let target_dir = if is_public {
            self.keys_dir.join("public")
        } else {
            self.keys_dir.join("private")
        };

        let ext = if is_public { "pub" } else { "key" };
        let target_path = target_dir.join(format!("{}.{}", stem, ext));

        fs::copy(key_path, &target_path)?;

        if !is_public {
            let perms = fs::Permissions::from_mode(0o600);
            fs::set_permissions(&target_path, perms)?;
        }

        Ok(target_path)
    }

    pub fn find_key(&self, name: &str, is_public: bool) -> Result<PathBuf, KeystoreError> {
        let (pub_path, priv_path) = self.get_key_paths(name);
        let path = if is_public { pub_path } else { priv_path };

        if path.exists() {
            Ok(path)
        } else {
            // Try as direct path if not found in keystore
            let direct_path = Path::new(name);
            if direct_path.exists() {
                Ok(direct_path.to_path_buf())
            } else {
                Err(KeystoreError::KeyNotFound(format!(
                    "Key not found at {} or {}",
                    path.display(),
                    direct_path.display()
                )))
            }
        }
    }

    pub fn list_keys(&self) -> Result<(Vec<PathBuf>, Vec<PathBuf>), KeystoreError> {
        let mut public_keys = Vec::new();
        let mut private_keys = Vec::new();

        for entry in fs::read_dir(self.keys_dir.join("public"))? {
            let entry = entry?;
            public_keys.push(entry.path());
        }

        for entry in fs::read_dir(self.keys_dir.join("private"))? {
            let entry = entry?;
            private_keys.push(entry.path());
        }

        Ok((public_keys, private_keys))
    }

    pub fn verify_permissions(&self) -> Result<(), KeystoreError> {
        for entry in fs::read_dir(self.keys_dir.join("private"))? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            let mode = metadata.permissions().mode();

            if mode & 0o077 != 0 {
                return Err(KeystoreError::InvalidPermissions(format!(
                    "Private key {} has unsafe permissions: {:o}",
                    entry.path().display(),
                    mode
                )));
            }
        }
        Ok(())
    }
}
