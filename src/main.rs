// src/main.rs
use purrcrypt::{
    cipher::CipherDialect,
    config::{ConfigManager, PreferredDialect},
    crypto, debug,
    keys::KeyPair,
    keystore::Keystore,
};
use std::{env, path::Path, process};

#[derive(Debug)]
enum Command {
    GenerateKey {
        name: Option<String>,
    },
    Encrypt {
        recipient_key: String,
        input_file: String,
        output_file: Option<String>,
        dialect: Option<String>,
    },
    Decrypt {
        private_key: String,
        input_file: String,
        output_file: Option<String>,
    },
    ImportKey {
        key_path: String,
        is_public: bool,
    },
    SetDialect {
        dialect: String,
    },
    ListKeys,
    Help,
}

fn print_usage(program: &str) {
    eprintln!(
        "purr - A cat/dog-themed encryption tool

Usage:
    {} [COMMAND] [OPTIONS]

Commands:
    genkey [name]                   Generate a new keypair
    import-key [--public] <keyfile> Import a key
    encrypt, -e                     Encrypt a message
    decrypt, -d                     Decrypt a message
    list-keys, -k                   List known keys
    set-dialect <cat|dog>          Set preferred dialect
    verbose, -v                     Enable verbose debug output

Options for encrypt:
    -r, --recipient <key>          Recipient's public key or name
    -o, --output <file>            Output file (default: adds .purr)
    -i, --input <file>             Input file
    --dialect <cat|dog>            Override dialect for this encryption

Options for decrypt:
    -k, --key <key>               Your private key or name
    -o, --output <file>           Output file
    -i, --input <file>            Input file

Examples:
    {} genkey                     # Generate keys as user.pub and user.key
    {} genkey alice               # Generate keys as alice.pub and alice.key
    {} import-key bob.pub         # Import Bob's public key
    {} -e -r bob message.txt      # Encrypt for Bob using preferred dialect
    {} -e -r bob -i message.txt   # Encrypt for Bob using --input flag
    {} -e -r bob --dialect dog    # Encrypt for Bob using dog dialect
    {} -d -k alice message.purr   # Decrypt using Alice's key
    {} -d -k alice -i message.purr # Decrypt using --input flag
    {} set-dialect dog            # Switch to dog mode
    {} -v -e -r bob msg.txt       # Encrypt with verbose output",
        program, program, program, program, program, program, program, program, program, program, program
    );
}

fn parse_args() -> Result<Command, String> {
    let args: Vec<String> = env::args().collect();
    parse_args_from_vec(args)
}

fn parse_args_from_vec(args: Vec<String>) -> Result<Command, String> {
    if args.len() < 2 {
        return Ok(Command::Help);
    }

    let verbose = args.iter().any(|arg| arg == "-v" || arg == "--verbose");
    debug::set_verbose(verbose);

    let filtered_args: Vec<String> = args
        .iter()
        .filter(|arg| *arg != "-v" && *arg != "--verbose")
        .cloned()
        .collect();

    if filtered_args.len() < 2 {
        return Ok(Command::Help);
    }

    match filtered_args[1].as_str() {
        "set-dialect" => {
            let dialect = filtered_args.get(2).ok_or("Missing dialect (cat/dog)")?;
            Ok(Command::SetDialect {
                dialect: dialect.clone(),
            })
        }
        "genkey" => Ok(Command::GenerateKey {
            name: filtered_args.get(2).cloned(),
        }),
        "import-key" => {
            if filtered_args.len() < 3 {
                return Err("Missing key file to import".to_string());
            }
            let is_public = filtered_args.get(2).map_or(false, |arg| arg == "--public");
            let key_path = if is_public {
                filtered_args.get(3).ok_or("Missing key file")?
            } else {
                &filtered_args[2]
            };
            Ok(Command::ImportKey {
                key_path: key_path.clone(),
                is_public,
            })
        }
        "list-keys" | "listkeys" | "-k" => Ok(Command::ListKeys),
        "encrypt" | "-e" => {
            let mut i = 2;
            let mut recipient = None;
            let mut input = None;
            let mut output = None;
            let mut dialect = None;

            while i < filtered_args.len() {
                match filtered_args[i].as_str() {
                    "-r" | "--recipient" => {
                        recipient = Some(filtered_args.get(i + 1).ok_or("Missing recipient")?);
                        i += 2;
                    }
                    "-o" | "--output" => {
                        output = Some(
                            filtered_args
                                .get(i + 1)
                                .ok_or("Missing output file")?
                                .clone(),
                        );
                        i += 2;
                    }
                    "-i" | "--input" => {
                        input = Some(filtered_args.get(i + 1).ok_or("Missing input file")?.clone());
                        i += 2;
                    }
                    "--dialect" => {
                        dialect = Some(filtered_args.get(i + 1).ok_or("Missing dialect")?.clone());
                        i += 2;
                    }
                    _ => {
                        if input.is_none() {
                            input = Some(filtered_args[i].clone());
                        }
                        i += 1;
                    }
                }
            }

            Ok(Command::Encrypt {
                recipient_key: recipient.ok_or("Missing recipient (-r)")?.clone(),
                input_file: input.ok_or("Missing input file")?.clone(),
                output_file: output,
                dialect,
            })
        }

        "decrypt" | "-d" => {
            let mut i = 2;
            let mut key = None;
            let mut input = None;
            let mut output = None;

            while i < filtered_args.len() {
                match filtered_args[i].as_str() {
                    "-k" | "--key" => {
                        key = Some(filtered_args.get(i + 1).ok_or("Missing key")?);
                        i += 2;
                    }
                    "-o" | "--output" => {
                        output = Some(
                            filtered_args
                                .get(i + 1)
                                .ok_or("Missing output file")?
                                .clone(),
                        );
                        i += 2;
                    }
                    "-i" | "--input" => {
                        input = Some(filtered_args.get(i + 1).ok_or("Missing input file")?.clone());
                        i += 2;
                    }
                    _ => {
                        if input.is_none() {
                            input = Some(filtered_args[i].clone());
                        }
                        i += 1;
                    }
                }
            }

            Ok(Command::Decrypt {
                private_key: key.ok_or("Missing private key (-k)")?.clone(),
                input_file: input.ok_or("Missing input file")?.clone(),
                output_file: output,
            })
        }
        _ => Ok(Command::Help),
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let keystore = Keystore::new()?;
    let mut config_manager = ConfigManager::new(&keystore.home_dir)?;

    if let Err(e) = keystore.verify_permissions() {
        eprintln!("⚠️  Warning: {}", e);
    }

    let command = parse_args().unwrap_or_else(|e| {
        eprintln!("Error: {}", e);
        eprintln!();
        print_usage(&env::args().next().unwrap_or_else(|| "purr".to_string()));
        process::exit(1);
    });

    match command {
        Command::GenerateKey { name } => {
            println!("🐱 Generating new keypair...");
            let name = name.unwrap_or_else(|| "default".to_string());
            let pub_path = keystore
                .keys_dir
                .join("public")
                .join(format!("{}.pub", name));
            let priv_path = keystore
                .keys_dir
                .join("private")
                .join(format!("{}.key", name));

            crypto::generate_keypair(&pub_path, &priv_path)?;
            println!("✨ Generated keys:");
            println!("  Public key:  {}", pub_path.display());
            println!("  Private key: {}", priv_path.display());
        }
        Command::SetDialect { dialect } => {
            let new_dialect = match dialect.to_lowercase().as_str() {
                "cat" => {
                    println!("😺 Switching to cat mode!");
                    PreferredDialect::Cat
                }
                "dog" => {
                    println!("🐕 Switching to dog mode!");
                    PreferredDialect::Dog
                }
                _ => return Err("Invalid dialect. Use 'cat' or 'dog'".into()),
            };
            config_manager.set_dialect(new_dialect)?;
        }
        Command::Encrypt {
            recipient_key,
            input_file,
            output_file,
            dialect,
        } => {
            let output = output_file.unwrap_or_else(|| format!("{}.purr", input_file));

            // Use command-line dialect if specified, otherwise use config
            let dialect = match dialect {
                Some(d) => match d.to_lowercase().as_str() {
                    "cat" => CipherDialect::Cat,
                    "dog" => CipherDialect::Dog,
                    _ => return Err("Invalid dialect. Use 'cat' or 'dog'".into()),
                },
                None => match config_manager.get_dialect() {
                    PreferredDialect::Cat => CipherDialect::Cat,
                    PreferredDialect::Dog => CipherDialect::Dog,
                },
            };

            let mode_emoji = match dialect {
                CipherDialect::Cat => "🐱",
                CipherDialect::Dog => "🐕",
            };

            println!(
                "{} Encrypting {} for {}",
                mode_emoji, input_file, recipient_key
            );

            let key_path = keystore
                .find_key(&recipient_key, true)
                .unwrap_or_else(|_| Path::new(&recipient_key).to_path_buf());

            let recipient_public_key = KeyPair::load_public_key(&key_path)?;
            crypto::encrypt_file(&input_file, &output, &recipient_public_key, dialect)?;
            println!("✨ Encrypted message saved to {}", output);
        }

        Command::Decrypt {
            private_key,
            input_file,
            output_file,
        } => {
            let output = output_file.unwrap_or_else(|| {
                input_file
                    .strip_suffix(".purr")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("{}.decrypted", input_file))
            });

            // Get both key paths based on the private key name
            let (pub_path, priv_path) = keystore.get_key_paths(&private_key);

            if !pub_path.exists() {
                eprintln!("Error: Public key not found at {}", pub_path.display());
                process::exit(1);
            }
            if !priv_path.exists() {
                eprintln!("Error: Private key not found at {}", priv_path.display());
                process::exit(1);
            }

            println!("🔓 Decrypting {} using:", input_file);
            println!("   Private key: {}", priv_path.display());
            println!("   Public key:  {}", pub_path.display());

            let keypair = KeyPair::load_keypair(&pub_path, &priv_path)?;
            crypto::decrypt_file(&input_file, &output, &keypair)?;
            println!("✨ Decrypted message saved to {}", output);
        }

        Command::ImportKey {
            key_path,
            is_public,
        } => {
            let path = keystore.import_key(Path::new(&key_path), is_public)?;
            println!("✨ Imported key to {}", path.display());
        }
        Command::ListKeys => {
            let (public_keys, private_keys) = keystore.list_keys()?;

            println!("🔑 Public keys in ~/.purr/keys/public/:");
            for key in public_keys {
                println!("  {}", key.file_name().unwrap().to_string_lossy());
            }

            println!("\n🔐 Private keys in ~/.purr/keys/private/:");
            for key in private_keys {
                println!("  {}", key.file_name().unwrap().to_string_lossy());
            }
        }
        Command::Help => {
            print_usage(&env::args().next().unwrap_or_else(|| "purr".to_string()));
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to convert string args to Vec<String>
    fn make_args(args: &[&str]) -> Vec<String> {
        let mut result = vec!["purr".to_string()]; // Program name
        result.extend(args.iter().map(|s| s.to_string()));
        result
    }

    #[test]
    fn test_help_command() {
        // Empty args or just the binary name
        let args = make_args(&[]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Help)));
    }

    #[test]
    fn test_genkey_command() {
        // Test genkey with no name
        let args = make_args(&["genkey"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::GenerateKey { name: None })));

        // Test genkey with name
        let args = make_args(&["genkey", "alice"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::GenerateKey { name: Some(name) }) if name == "alice"));
    }

    #[test]
    fn test_encrypt_command_positional_args() {
        // Test encrypt with positional input file
        let args = make_args(&["encrypt", "-r", "bob", "message.txt"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Encrypt { 
            recipient_key, 
            input_file, 
            output_file: None,
            dialect: None
        }) if recipient_key == "bob" && input_file == "message.txt"));
    }

    #[test]
    fn test_encrypt_command_with_input_flag() {
        // Test encrypt with --input flag
        let args = make_args(&["encrypt", "-r", "bob", "--input", "message.txt"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Encrypt { 
            recipient_key, 
            input_file, 
            output_file: None,
            dialect: None
        }) if recipient_key == "bob" && input_file == "message.txt"));

        // Test encrypt with -i flag
        let args = make_args(&["encrypt", "-r", "bob", "-i", "message.txt"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Encrypt { 
            recipient_key, 
            input_file, 
            output_file: None,
            dialect: None
        }) if recipient_key == "bob" && input_file == "message.txt"));
    }

    #[test]
    fn test_encrypt_command_with_all_options() {
        // Test encrypt with all options
        let args = make_args(&[
            "encrypt", 
            "-r", "bob", 
            "-i", "message.txt", 
            "-o", "output.purr", 
            "--dialect", "cat"
        ]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Encrypt { 
            recipient_key, 
            input_file, 
            output_file: Some(output),
            dialect: Some(d)
        }) if recipient_key == "bob" && input_file == "message.txt" && output == "output.purr" && d == "cat"));
    }

    #[test]
    fn test_decrypt_command_positional_args() {
        // Test decrypt with positional input file
        let args = make_args(&["decrypt", "-k", "alice", "message.purr"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Decrypt { 
            private_key, 
            input_file, 
            output_file: None
        }) if private_key == "alice" && input_file == "message.purr"));
    }

    #[test]
    fn test_decrypt_command_with_input_flag() {
        // Test decrypt with --input flag
        let args = make_args(&["decrypt", "-k", "alice", "--input", "message.purr"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Decrypt { 
            private_key, 
            input_file, 
            output_file: None
        }) if private_key == "alice" && input_file == "message.purr"));

        // Test decrypt with -i flag
        let args = make_args(&["decrypt", "-k", "alice", "-i", "message.purr"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Decrypt { 
            private_key, 
            input_file, 
            output_file: None
        }) if private_key == "alice" && input_file == "message.purr"));
    }

    #[test]
    fn test_decrypt_command_with_all_options() {
        // Test decrypt with all options
        let args = make_args(&[
            "decrypt", 
            "-k", "alice", 
            "-i", "message.purr", 
            "-o", "output.txt"
        ]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Decrypt { 
            private_key, 
            input_file, 
            output_file: Some(output)
        }) if private_key == "alice" && input_file == "message.purr" && output == "output.txt"));
    }

    #[test]
    fn test_import_key_command() {
        // Test import_key
        let args = make_args(&["import-key", "bob.pub"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::ImportKey { 
            key_path, 
            is_public: false
        }) if key_path == "bob.pub"));

        // Test import_key with --public flag
        let args = make_args(&["import-key", "--public", "bob.pub"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::ImportKey { 
            key_path, 
            is_public: true
        }) if key_path == "bob.pub"));
    }

    #[test]
    fn test_set_dialect_command() {
        // Test set_dialect
        let args = make_args(&["set-dialect", "cat"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::SetDialect { 
            dialect
        }) if dialect == "cat"));

        let args = make_args(&["set-dialect", "dog"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::SetDialect { 
            dialect
        }) if dialect == "dog"));
    }

    #[test]
    fn test_list_keys_command() {
        // Test list_keys
        let args = make_args(&["list-keys"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::ListKeys)));

        // Test with shorthand -k
        let args = make_args(&["-k"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::ListKeys)));
    }

    #[test]
    fn test_verbose_flag() {
        // Test verbose flag is filtered correctly
        let args = make_args(&["-v", "encrypt", "-r", "bob", "message.txt"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Encrypt { 
            recipient_key, 
            input_file, 
            output_file: None,
            dialect: None
        }) if recipient_key == "bob" && input_file == "message.txt"));

        // Test verbose flag in different position
        let args = make_args(&["encrypt", "-r", "bob", "message.txt", "-v"]);
        let result = parse_args_from_vec(args);
        assert!(matches!(result, Ok(Command::Encrypt { 
            recipient_key, 
            input_file, 
            output_file: None,
            dialect: None
        }) if recipient_key == "bob" && input_file == "message.txt"));
    }
}
