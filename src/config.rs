// src/config.rs
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::path::PathBuf;
use std::{fs, path::Path};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("TOML error: {0}")]
    Toml(#[from] toml::ser::Error),
    #[error("TOML de error: {0}")]
    TomlDe(#[from] toml::de::Error),
}

#[derive(Debug, Serialize, Deserialize)]
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

    pub fn initialize(config_dir: &Path) -> Result<Self, ConfigError> {
        let config_path = config_dir.join("config.toml");

        if config_path.exists() {
            return Self::load(&config_path);
        }

        // Create config directory if it doesn't exist
        fs::create_dir_all(config_dir)?;

        print!("🐱 Welcome to purrcrypt! Do you prefer cat or dog mode? [cat/dog]: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let config = Config {
            dialect: match input.trim().to_lowercase().as_str() {
                "dog" => PreferredDialect::Dog,
                _ => PreferredDialect::Cat,
            },
        };

        config.save(&config_path)?;

        match config.dialect {
            PreferredDialect::Cat => println!("😺 Meow! Cat mode activated!"),
            PreferredDialect::Dog => println!("🐕 Woof! Dog mode activated!"),
        }

        Ok(config)
    }
}

pub struct ConfigManager {
    config: Config,
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new(config_dir: &Path) -> Result<Self, ConfigError> {
        let config_path = config_dir.join("config.toml");
        let config = if config_path.exists() {
            Config::load(&config_path)?
        } else {
            Config::initialize(config_dir)?
        };

        Ok(Self {
            config,
            config_path,
        })
    }

    pub fn get_dialect(&self) -> &PreferredDialect {
        &self.config.dialect
    }

    pub fn set_dialect(&mut self, dialect: PreferredDialect) -> Result<(), ConfigError> {
        self.config.dialect = dialect;
        self.config.save(&self.config_path)?;
        Ok(())
    }
}
