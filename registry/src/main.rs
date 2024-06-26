use std::collections::HashMap;
use std::{fs, io};
use std::io::Read;
use std::path::PathBuf;
use atty::Stream;
use clap::Parser;
use spacedb::Error;
// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use methods::{
    SUBSPACER_ELF, SUBSPACER_ID
};
use risc0_zkvm::{default_prover, ExecutorEnv};
use spacedb::{Hash};
use spacedb::db::Database;
use spacedb::tx::ProofType;
use program::builder::TransactionBuilder;
use program::guest::Commitment;
use program::TransactionReader;

const STAGING_FILE: &str = "uncommitted.json";

/// The CLI for the registry
///
/// Example usage:
/// $ registry status
/// $ registry add some_tx.json
/// $ registry commit
///
/// Dry run
/// $ registry commit --dry-run

#[derive(Parser)]
#[command(bin_name = "registry")]
pub enum Cli {
    #[command(name = "status")]
    Status(StatusArgs),

    /// Add transactions to the next batch
    #[command(name = "add")]
    Add(AddArgs),

    /// Prove and commit changes
    #[command(name = "commit")]
    Commit(CommitArgs),

    /// Issue a certificate for a subspace
    #[command(name = "issue")]
    Issue(IssueArgs),
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct StatusArgs {
    // Show status for an individual space
    pub(crate) space: Option<String>,

    #[arg(short = 'C')]
    c: Option<String>,
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct AddArgs {
    pub(crate) files: Vec<String>,

    #[arg(short = 'C')]
    c: Option<String>,
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct CommitArgs {
    #[arg(short = 'C')]
    c: Option<String>,

    #[arg(long, short)]
    dry_run: bool,
}

#[derive(clap::Args)]
#[command(author, version, about, long_about = None)]
pub struct IssueArgs {
    #[arg(short, long)]
    space: String,
}

fn load_builders(working_dir: &Option<String>) -> Result<HashMap<String, TransactionBuilder>, Error> {
    let input = get_working_dir(working_dir)?.join(STAGING_FILE);
    if !std::path::Path::new(input.to_str().unwrap()).exists() {
        return Ok(HashMap::new());
    }
    let raw = fs::read(input)?;
    let result = serde_json::from_slice(raw.as_slice()).map_err(|_e| {
        io::Error::new(io::ErrorKind::InvalidData, "could not parse uncommitted.json")
    })?;
    Ok(result)
}

fn save_builders(builders: &HashMap<String, TransactionBuilder>, working_dir: &Option<String>)
    -> Result<(), Error> {
    let str = serde_json::to_string_pretty(builders).map_err(|_e| {
        io::Error::new(io::ErrorKind::InvalidData, "unable to serialize builders")
    })?;
    let input = get_working_dir(working_dir)?.join(STAGING_FILE);
    fs::write(input, str)?;
    Ok(())
}

fn status(args : StatusArgs) -> Result<(), Error> {
    let builders = load_builders(&args.c)?;
    if args.space.is_some() {
        let space = args.space.unwrap();
        println!("On Space: {}", space.as_str());

        if !builders.contains_key(space.as_str()) {
            println!("No changes to prove and commit (use \"registry add\" to add changes)");
            return Ok(());
        }
        let (r, u) = builder_stats(builders.get(space.as_str()).unwrap());
        println!("Changes to prove and commit:");
        println!("Registrations: {}, Updates: {}", r, u);
        println!("  (use \"registry commit\" to prove and commit changes)");
        return Ok(());
    }

    let num_spaces = builders.len();
    if num_spaces == 0 {
        println!("No changes to prove and commit (use \"registry add\" to add changes)");
        return Ok(());
    }
    let mut registrations = 0;
    let mut updates = 0;

    for (_, builder) in builders {
        let (r, u) = builder_stats(&builder);
        registrations += r;
        updates += u;
    }

    println!("Changes to prove and commit:");
    println!("Total spaces: {}, Total Registrations: {}, Total Updates: {}",
             num_spaces, registrations, updates);
    println!("  (use \"registry commit\" to prove and commit changes)");

    Ok(())
}

fn builder_stats(builder: &TransactionBuilder) -> (usize, usize) {
    let mut registrations = 0;
    let mut updates = 0;
    for entry in &builder.transactions {
        if entry.witness.is_empty() {
            registrations += 1;
        } else {
            updates += 1;
        }
    }
    (registrations, updates)
}

fn add(args: AddArgs) -> Result<(), Error> {
    let mut builders = load_builders(&args.c)?;

    for file in args.files {
        let raw = fs::read(file)?;
        add_builder(&mut builders, raw)?;
    }
    if builders.len() == 0 && !atty::is(Stream::Stdin) {
        let mut raw = Vec::new();
        io::stdin().read_to_end(&mut raw).map_err(|_e| {
            io::Error::new(io::ErrorKind::InvalidData, "Nothing to add")
        })?;
        add_builder(&mut builders, raw)?;
    }

    save_builders(&builders, &args.c)
}

fn add_builder(builders: &mut HashMap<String, TransactionBuilder>, raw: Vec<u8>) -> Result<(), Error> {
    let user_builder : HashMap<String, TransactionBuilder> = serde_json::from_slice(raw.as_slice()).map_err(|_e| {
        io::Error::new(io::ErrorKind::InvalidData, "could not parse user tx")
    })?;

    for (space, user_builder) in user_builder {
        let builder = builders.entry(space.clone()).or_insert_with(|| {
            TransactionBuilder::new()
        });
        builder.merge(user_builder).map_err(|_e| {
            io::Error::new(io::ErrorKind::InvalidData, "unable to merge user tx")
        })?;
    }
    Ok(())
}

type ZKPayload = Vec<Vec<u8>>;
type TXSet = Vec<u8>;

fn prepare_zk_input(working_dir: &Option<String>) -> Result<(ZKPayload, HashMap<String, TXSet>), Error> {
    let builders = load_builders(working_dir)?;
    let mut payload : ZKPayload = Vec::with_capacity(builders.len());
    let mut tx_set : HashMap<String, TXSet> = HashMap::with_capacity(builders.len());

    for (space, builder) in builders {
        let raw = builder.build(space.as_str()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("could not build tx set: {}", e))
        })?;
        let db_filename = format!("{}.sdb", space);
        let raw = tx_set.entry(space.clone()).or_insert_with(|| {
            raw
        });

        let path = get_working_dir(working_dir)?.join(db_filename);

        if !std::path::Path::new(path.to_str().unwrap()).exists() {
            // we don't need to prove initial state
            continue;
        }

        // create subtree
        let reader = TransactionReader(raw.as_slice());

        let keys = reader.iter().map(|t| t.subspace_hash.try_into().map_err(
            |_| io::Error::new(io::ErrorKind::InvalidData, "invalid subspace hash")
        )).collect::<Result<Vec<Hash>, io::Error>>()?;

        let db = Database::open(path.to_str().unwrap())?;

        let mut snapshot = db.begin_read()?;
        let subtree = snapshot.prove(&keys, ProofType::Standard).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData,
                                format!("could not generate subtree: {}", e))
        })?;

        let mut subtree_raw = bincode::encode_to_vec(&subtree, bincode::config::standard())
            .map_err(|e| { io::Error::new(io::ErrorKind::InvalidData,
                                format!("could not encode subtree: {}", e))
        })?;

        subtree_raw.extend_from_slice(raw.as_slice());
        payload.push(subtree_raw);
    }

    Ok((payload, tx_set))
}

fn prove(working_dir : &Option<String>) -> Result<(Vec<Commitment>, HashMap<String, TXSet>), Error> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    env_logger::init();
    let (zk_input, tx_set) = prepare_zk_input(working_dir)?;
    if zk_input.is_empty() {
        return Ok((Vec::new(), tx_set));
    }

    let env = ExecutorEnv::builder().write(&zk_input).unwrap().build().unwrap();
    let prover = default_prover();

    println!("Proving Started ...");
    println!("-------------------------------------");
    println!("- Using Prover: {}", prover.get_name());

    // Produce a receipt by proving the specified ELF binary.
    let start = std::time::Instant::now();
    let receipt = prover.prove(env, SUBSPACER_ELF).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData,
                            format!("could not prove elf: {}", e))
    })?;
    println!("- Took: {:?}", start.elapsed());

    receipt.verify(SUBSPACER_ID).map_err(|e| {
        io::Error::new(std::io::ErrorKind::InvalidData,
                            format!("could not verify receipt: {}", e))
    })?;

    println!("- Receipt Verified\n");

    let output : Vec<Commitment> = receipt.journal.decode().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData,
                            format!("could not decode receipt: {}", e))
    })?;

    // save receipt to output arg
    let raw_receipt = bincode::serde::encode_to_vec(&receipt, bincode::config::standard())
        .map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData,
                            format!("could not serialize receipt: {}", e))
    })?;

    let path = get_working_dir(working_dir)?.join("receipt.bin");

    fs::write(path.to_str().unwrap(), raw_receipt)?;

    Ok((output, tx_set))
}


fn commit(args : CommitArgs) -> Result<(), Error> {
    let uncommitted_path = get_working_dir(&args.c)?.join(STAGING_FILE);
    if !std::path::Path::new(uncommitted_path.to_str().unwrap()).exists() {
        return Err(Error::from(io::Error::new(io::ErrorKind::InvalidData, "No changes to prove and commit")));
    }

    let (output, tx_set) = prove(&args.c)?;

    println!("Journal Output");
    println!("-------------------------------------");
    println!("Total Spaces: {}\n", output.len());
    for commitment in output.iter() {
        println!("\tID: {}", hex::encode(commitment.space));
        println!("\tMerkle Root Changes: ");
        println!("\t- Initial: {}", hex::encode(commitment.initial_root));
        println!("\t- Final: {}", hex::encode(commitment.final_root));
        println!("\n\n")
    }

    println!("Committing changes ...");

    let path = get_working_dir(&args.c)?;
    for (space, raw) in tx_set {
        let filename = format!("{}.sdb", space);
        let path = path.join(filename);
        let db = Database::open(path.to_str().unwrap())?;
        let mut tx = db.begin_write().unwrap();
        let reader = TransactionReader(raw.as_slice());

        for t in reader.iter() {
            let key = t.subspace_hash.try_into().unwrap();
            tx.insert(key, t.owner.to_vec()).unwrap();
        }
        tx.commit()?;
    }

    // remove uncommitted.json
    let input = path.join(STAGING_FILE);
    if std::path::Path::new(input.to_str().unwrap()).exists() {
        fs::remove_file(input)?;
    }

    println!("Done!");
    Ok(())
}

fn main() -> Result<(), Error> {
    let args = Cli::parse();
    match args {
        Cli::Status(args) => {
            status(args)?;
        }
        Cli::Add(args) => {
            add(args)?;
        }
        Cli::Commit(args) => {
            commit(args)?;
        }
        Cli::Issue(_) => {}
    }

    Ok(())
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
