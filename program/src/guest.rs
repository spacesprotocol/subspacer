use alloc::vec::Vec;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};
use spacedb::{Hash, Sha256Hasher, subtree::{SubTree, ValueOrHash}};
use spacedb::subtree::VerifyError;
use crate::{Entry, TransactionReader};

#[derive(Serialize, Deserialize)]
pub struct Commitment {
    pub space: Hash,
    pub initial_root: Hash,
    pub final_root: Hash,
}

#[derive(Debug)]
pub enum GuestError {
    ExpectedPublicKey,
    UnalignedSubTree,
    InvalidSignature,
    UnsupportedWitness,
    WitnessRequired,
    KeyExists,
    IncompleteSubTree,
}

const PUBLIC_KEY_SIZE : usize = 32;
const SEC1_COMPRESSED_TAG : u8 = 0x02;
const SEC1_PUBLIC_KEY_SIZE : usize = PUBLIC_KEY_SIZE + 1;
const WITNESS_TYPE_SIGNATURE : u8 = 0x00;

pub type Result<T> = core::result::Result<T, GuestError>;

pub fn run(mut input : Vec<Vec<u8>>) -> Result<Vec<Commitment>>  {
    let mut commitments = Vec::with_capacity(input.len());
    for tx_set in input.drain(..) {
        commitments.push(handle_tx_set(tx_set)?);
    }

    Ok(commitments)
}

pub fn handle_tx_set(mut input: Vec<u8>) -> Result<Commitment> {
    // Decode subtree
    let (mut subtree, subtree_size): (SubTree<Sha256Hasher>, usize) =
        bincode::decode_from_slice(input.as_slice(), bincode::config::standard()).unwrap();
    let input = &mut input.as_mut_slice()[subtree_size..];

    let initial_root = subtree.root().unwrap();

    let reader = TransactionReader(input);
    let space = reader.space_hash();

    let mut buffer = [0u8; 64];
    let mut transactions = reader.iter();

    // All leave values included in the subtree are processed
    // since the transactions are sorted, we can iterate through the subtree
    // and consume them as we go
    for ((key, value), tx) in subtree.iter_mut().zip(transactions.by_ref()) {
        handle_transition(&mut buffer, key, value, &tx)?;
    }

    // All remaining transactions are registrations
    for registration in transactions {
        subtree.insert(
            registration.subspace_hash.try_into().unwrap(),
            ValueOrHash::Hash(registration.owner.try_into().unwrap())
        )
            .map_err(|e| match e {
                VerifyError::KeyExists => GuestError::KeyExists,
                VerifyError::IncompleteProof => GuestError::IncompleteSubTree,
            })?;
    }

    // Calculate updated subtree root
    let final_root = subtree.root().unwrap();

    Ok(Commitment {
        space: space.try_into().unwrap(),
        initial_root,
        final_root,
    })
}

fn handle_transition(
    buffer: &mut [u8; 64],
    key: &[u8; 32],
    value: &mut Vec<u8>,
    tx: &Entry,
) -> Result<()> {
    if key != tx.subspace_hash {
        return Err(GuestError::UnalignedSubTree);
    }
    if value.len() != PUBLIC_KEY_SIZE {
        return Err(GuestError::ExpectedPublicKey);
    }

    buffer[0] = SEC1_COMPRESSED_TAG;
    buffer[1..SEC1_PUBLIC_KEY_SIZE].copy_from_slice(value.as_slice());

    let verifying_key =
        VerifyingKey::from_sec1_bytes(&buffer[..SEC1_PUBLIC_KEY_SIZE])
            .map_err(|_| GuestError::ExpectedPublicKey)?;

    buffer[..32].copy_from_slice(key);
    buffer[32..].copy_from_slice(tx.owner);

    if tx.witness.is_empty() {
        return Err(GuestError::WitnessRequired);
    }
    if tx.witness[0] != WITNESS_TYPE_SIGNATURE {
        return Err(GuestError::UnsupportedWitness);
    }

    let signature = Signature::from_slice(&tx.witness[1..])
        .map_err(|_| GuestError::InvalidSignature)?;

    verifying_key.verify(buffer, &signature).map_err(|_| GuestError::InvalidSignature)?;

    // Set the new owner
    value.copy_from_slice(tx.owner);
    Ok(())
}

impl core::fmt::Display for GuestError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            GuestError::ExpectedPublicKey => write!(f, "Parse error: expected a public key"),
            GuestError::UnalignedSubTree => write!(f, "Updates to subtree must be sorted"),
            GuestError::InvalidSignature => write!(f, "Invalid signature"),
            GuestError::UnsupportedWitness => write!(f, "Unsupported witness"),
            GuestError::WitnessRequired => write!(f, "Changes to an existing name require a witness"),
            GuestError::KeyExists => write!(f, "Cannot register a name that already exists"),
            GuestError::IncompleteSubTree => write!(f, "SubTree is incomplete"),
        }
    }
}