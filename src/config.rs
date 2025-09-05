// src/config.rs
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::{fs};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML error: {0}")]
    Toml(#[from] toml::ser::Error),
    #[error("TOML de error: {0}")]
    TomlDe(#[from] toml::de::Error),
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum PreferredDialect {
    #[serde(rename = "cat")]
    Cat,
    #[serde(rename = "dog")]
    Dog,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub dialect: PreferredDialect,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dialect: PreferredDialect::Cat,
        }
    }
}

impl Config {
    pub fn load(config_path: &Path) -> Result<Self, ConfigError> {
        if config_path.exists() {
            let contents = fs::read_to_string(config_path)?;
            Ok(toml::from_str(&contents)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_path: &Path) -> Result<(), ConfigError> {
        let contents = toml::to_string_pretty(self)?;
        fs::write(config_path, contents)?;
        Ok(())
    }
}

pub struct ConfigManager {
    config: Config,
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new(config_dir: &Path) -> Result<Self, ConfigError> {
        let config_path = config_dir.join("config.toml");
        let config = Config::load(&config_path)?;

        if !config_path.exists() {
            fs::create_dir_all(config_dir)?;
            config.save(&config_path)?;
        }

        Ok(Self {
            config,
            config_path,
        })
    }

    pub fn get_dialect(&self) -> PreferredDialect {
        self.config.dialect
    }

    pub fn set_dialect(&mut self, dialect: PreferredDialect) -> Result<(), ConfigError> {
        self.config.dialect = dialect;
        self.config.save(&self.config_path)?;
        Ok(())
    }
}
