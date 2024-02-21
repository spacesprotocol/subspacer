use std::{fs, io};
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use atty::Stream;
use clap::{Parser, Subcommand};
use k256::ecdsa::SigningKey;
use rand_core::OsRng;
use program::builder::{Transaction, OwnerPublicKey, TransactionBuilder};

#[derive(Parser)]
#[command(bin_name = "subs")]
enum Cli {
    /// Key utilities
    #[command(name = "key", subcommand)]
    Key(KeyCommands),

    /// Create new subspaces
    #[command(name = "create")]
    Create(CreateArgs),

    /// Transfers
    #[command(name = "transfer")]
    TransferSubspace(TransferSubspaceArgs),

    /// Renewals
    #[command(name = "renew")]
    RenewSubspace(TransferSubspaceArgs),
}

#[derive(Subcommand)]
#[command(author, version, about, long_about = None)]
enum KeyCommands {
    /// Generates a new private key
    #[command(name = "gen")]
    GenKey {
        #[arg(short = 'C')]
        c: Option<String>,
    },

    /// Prints the public key of a private key
    #[command(name = "inspect")]
    InspectKey { path: String },
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
struct CreateArgs {
    subspaces: Option<Vec<String>>,

    #[arg(short='k', long)]
    private_key: Option<String>,

    #[arg(short = 'C')]
    c: Option<String>,
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
struct TransferSubspaceArgs {
    subspaces: Option<Vec<String>>,

    #[arg(short, long)]
    address: String,

    #[arg(short='k', long)]
    private_key: Option<String>,

    #[arg(short, long)]
    output: Option<String>,

    #[arg(short = 'C')]
    c: Option<String>,
}

fn new_subspace(mut args : CreateArgs) -> Result<(), io::Error> {
    let subspaces = read_subspaces_input(args.subspaces.take())?;

    let mut json : HashMap<String, TransactionBuilder> = HashMap::new();
    for (subspace, space) in subspaces {
        let wd = get_working_dir(&args.c)?;
        let mut c = true;
        let private_key_path = if args.private_key.is_some() {
            c = false;
            PathBuf::from(args.private_key.as_ref().unwrap())
        } else {
            wd.join(format!("{}@{}.priv", subspace, space))
        };

        let signing_key = load_signing_key(private_key_path.to_str().unwrap(), c);
        let builder = json.entry(space.clone()).or_insert_with(|| {
            TransactionBuilder::new()
        });

        let entry = Transaction::new(subspace.as_str(), signing_key.owner_public_key());
        builder.add(entry, None).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e.clone())
        })?;
    }

    let str = serde_json::to_string_pretty(&json).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e)
    })?;

    println!("{}", str);
    Ok(())
}

fn transfer_subspace(mut args : TransferSubspaceArgs) -> Result<(), io::Error> {
    let subspaces = read_subspaces_input(args.subspaces.take())?;
    let mut json : HashMap<String, TransactionBuilder> = HashMap::new();

    for (subspace, space) in subspaces {
        let wd = get_working_dir(&args.c)?;
        let private_key_path = if args.private_key.is_some() {
            PathBuf::from(args.private_key.as_ref().unwrap())
        } else {
            wd.join(format!("{}@{}.priv", subspace, space))
        };
        let signing_key = load_signing_key(private_key_path.to_str().unwrap(), false);

        let builder = json.entry(space.clone()).or_insert_with(|| {
            TransactionBuilder::new()
        });

        let transfer_addr = hex::decode(args.address.as_str()).map_err(|_e| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid address")
        })?;

        let entry = Transaction::new(subspace.as_str(), transfer_addr.as_slice().try_into()
            .map_err(|_e| io::Error::new(io::ErrorKind::InvalidInput, "invalid address"))?);

        builder.add(entry, Some((space.as_str(), signing_key))).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e.clone())
        })?;
    }

    let str = serde_json::to_string_pretty(&json).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e)
    })?;

    println!("{}", str);
    Ok(())
}

fn read_subspaces_input(mut subspaces: Option<Vec<String>>) -> Result<Vec<(String, String)>, io::Error> {
    if subspaces.is_none() {
        if !atty::is(Stream::Stdin) {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input).map_err(|_e| {
                io::Error::new(io::ErrorKind::InvalidData, "subspaces not provided")
            })?;
            subspaces = Some(input.lines().map(String::from).collect());
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "subspaces not provided"));
        }
    }
    let subspaces = subspaces.unwrap();
    let mut resolved = Vec::new();
    for sub in subspaces {
        let (subspace, space) = verify_name(&sub)?;
        resolved.push((subspace, space));
    }
    Ok(resolved)
}

fn get_working_dir(c : &Option<String>) -> Result<PathBuf, io::Error> {
    let mut path_prefix = PathBuf::new();
    if let Some(output) = c {
        path_prefix.push(output);
        if !path_prefix.exists() {
            fs::create_dir_all(&path_prefix)?;
        }

        let metadata = fs::metadata(&path_prefix)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(io::ErrorKind::Other, "Path is not a directory"));
        }
    } else {
        path_prefix.push(".");
    }
    Ok(path_prefix)
}

fn run() -> Result<(), io::Error> {
    let cmd = Cli::parse();
    match cmd {
        Cli::Create(args) => {
            new_subspace(args)
        },
        Cli::TransferSubspace(args) => {
            transfer_subspace(args)
        },
        Cli::RenewSubspace(args) => {
            transfer_subspace(args)
        },
        Cli::Key(args) => {
           match args {
               KeyCommands::GenKey{c} => {
                gen_key(c)
               },
               KeyCommands::InspectKey { path } => {
                inspect_key(path)
               }
           }
        }
    }

}

fn inspect_key(path: String) -> Result<(), io::Error> {
    let key = fs::read(path).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e)
    })?;

    let key = SigningKey::from_slice(key.as_slice()).map_err(|_e| {
        io::Error::new(io::ErrorKind::InvalidData, "Invalid private key")
    })?;

    let pub_key = key.owner_public_key();
    let pub_key_hex = hex::encode(&pub_key);
    println!("Public key: {}", pub_key_hex);
    Ok(())
}

fn gen_key(c: Option<String>) -> Result<(), io::Error> {
    let key = SigningKey::random(&mut OsRng);
    let pub_key = key.owner_public_key();
    let pub_key_hex = hex::encode(&pub_key);
    let path = get_working_dir(&c)?.join(format!("k-{}.priv", &pub_key_hex[0..8]));
    fs::write(path.to_str().unwrap(), key.to_bytes()).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e)
    })?;

    println!("Generated {}", path.to_str().unwrap());
    println!("Public key: {}", pub_key_hex);
    Ok(())
}

fn main() {
    run().unwrap_or_else(|e| {
        eprintln!("{}", e);
        std::process::exit(1);
    });
}

fn load_signing_key(path: &str, create: bool) -> SigningKey {
    if let Ok(key) = std::fs::read(path) {
        return SigningKey::from_slice(key.as_slice()).unwrap_or_else(|e| {
            eprintln!("Invalid private key: {}", e);
            std::process::exit(1);
        })
    }

    if !create {
        eprintln!("Private key not found at: {}", path);
        std::process::exit(1);
    }

   let key = SigningKey::random(&mut OsRng);
   fs::write(path, key.to_bytes()).unwrap_or_else(|e| {
            eprintln!("Failed to write private key: {}", e);
            std::process::exit(1);
   });
   key
}

fn verify_name(subspace: &str) -> Result<(String, String), io::Error> {
    let (subspace, space) = parse_name(subspace).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "Invalid subspace name")
    })?;

    if !is_valid_label(space.as_str()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            format!("Invalid space name @{}", space)));
    }
    if !is_valid_label(subspace.as_str()) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
            format!("Invalid subspace {}", subspace)));
    }

    Ok((subspace, space))
}

fn is_valid_label(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphabetic() && c.is_lowercase())
}

fn parse_name(subspace: &str) -> Option<(String, String)> {
    let mut parts = subspace.split('@');
    if let (Some(label), Some(space)) = (parts.next(), parts.next()) {
        if parts.next().is_some() {
            return None;
        }
        return Some((label.to_string(), space.to_string()))
    }

    None
}
