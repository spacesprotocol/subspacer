// Not part of the guest program

use core::fmt;
use std::collections::HashSet;

use k256::ecdsa::signature::Signer;
use k256::ecdsa::SigningKey;
use serde::{Serialize, Deserialize};
use serde::de::{Error};

use serde_with::{serde_as};
use serde_with::base64::{Base64};
use serde_with::hex::Hex;
use sha2::{Sha256, Digest};
use crate::{HEADER_SIZE};

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
#[derive(PartialEq)]
pub struct TransactionBuilder {
    version: u8,
    pub transactions: Vec<Transaction>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
#[derive(PartialEq)]
pub struct Transaction {
    pub name: String,

    #[serde_as(as = "Hex")]
    pub owner: [u8; 32],

    #[serde_as(as = "Base64")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<u8>,

    #[serde(skip)]
    key: [u8; 32],
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            version: 0,
            transactions: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: Self) -> Result<(), BuilderError> {
        if self.version != other.version {
            return Err(BuilderError(format!("versions do not match: {} != {}", self.version, other.version)));
        }
        for entry in other.transactions {
            self.add(entry, None)?;
        }
        Ok(())
    }

    fn make_header(&mut self, space: &str) -> [u8; HEADER_SIZE] {
        let mut raw_header = [0u8; HEADER_SIZE];
        raw_header[0] = self.version;
        let space_hash = hash(space.as_bytes());
        raw_header[1..].copy_from_slice(&space_hash);
        return raw_header;
    }

    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(json_str: &[u8]) -> serde_json::Result<Self> {
        let s : Self = serde_json::from_slice(json_str)?;
        let mut names = HashSet::new();
        // TODO: move this into verify
        for entry in &s.transactions {
            if !names.insert(&entry.name) {
                return Err(serde_json::Error::custom(
                    format!("Duplicate name found: {}", entry.name))
                );
            }
        }
        Ok(s)
    }

    pub fn add(&mut self, mut entry: Transaction, key: Option<(&str, SigningKey)>) -> Result<(), BuilderError> {
        if self.transactions.iter().any(|e| e.name == entry.name) {
            return Err(BuilderError(format!("duplicate name: {}", entry.name)));
        }

        if key.is_some() {
            let (space, key) = key.unwrap();
            let header = self.make_header(space);

            let mut msg = [0u8; HEADER_SIZE + 64];
            msg[..HEADER_SIZE].copy_from_slice(&header);
            let h = hash(entry.name.as_bytes());
            msg[HEADER_SIZE..HEADER_SIZE + 32].copy_from_slice(&h);
            msg[HEADER_SIZE + 32..HEADER_SIZE + 64].copy_from_slice(&entry.owner);

            let (sig, _) = key.sign(&msg);
            entry.witness.push(0x00);
            entry.witness.extend_from_slice(sig.to_bytes().as_slice());
        }

        self.transactions.push(entry);
        Ok(())
    }

    fn sort(&mut self) {
        for entry in self.transactions.iter_mut() {
            entry.key = hash(entry.name.as_bytes());
        }
        self.transactions.sort_by(|a, b| {
            // sort all non-empty witnesses to the front then sort by hash
            match (a.witness.is_empty(), b.witness.is_empty()) {
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                _ => a.key.cmp(&b.key)
            }
        });
    }

    /// Builds a transaction with a given space and a list of updates.
    /// The transaction format is structured as follows:
    ///
    /// Header:
    /// +------------------+---------------------+
    /// | 1-byte version |   32-byte space hash  |
    /// +------------------+---------------------+
    ///
    /// List of updates:
    /// +--------------+--------+----------+
    /// | <Update 1, 2, 3 ...>             |
    /// +-------------+-------+-----------+
    ///
    /// Each Update includes:
    /// +-----------------------+-------------------+------------------------+-----------+
    /// | 2-byte length         | 32-byte subspace hash |   32-byte owner    |  Witness  |
    /// +-----------------------+-------------------+------------------------+-----------+
    ///
    /// This function compiles the transaction bytes by following this structure.
    pub fn build(mut self, space: &str) -> Result<Vec<u8>, BuilderError> {
        let mut buffer = Vec::new();
        buffer.push(self.version); // 1-byte version
        let space_hash = hash(space.as_bytes()); // 32-byte space hash
        buffer.extend_from_slice(&space_hash);
        self.sort();

        for tx in &self.transactions {
            self.write_tx(&mut buffer, tx);
        }

        Ok(buffer)
    }

    fn write_tx(&self, buffer: &mut Vec<u8>, tx: &Transaction) {
        // 2 bytes length + 32 bytes subspace hash + 32 bytes owner + witness length
        let len = 32 + 32 + tx.witness.len();
        let length_bytes = (len as u16).to_le_bytes();
        buffer.extend_from_slice(&length_bytes);

        // Write the subspace hash (32 bytes)
        let subspace = hash(tx.name.as_bytes());
        buffer.extend_from_slice(&subspace);

        // Write the owner (32 bytes)
        buffer.extend_from_slice(&tx.owner);

        // Write the witness data
        buffer.extend_from_slice(&tx.witness);
    }
}

impl Transaction {
    pub fn new(name: &str, owner: [u8; 32]) -> Self {
        Self {
            name: String::from(name),
            owner,
            witness: Vec::with_capacity(65),
            key: hash(name.as_bytes()),
        }
    }
}

pub trait OwnerPublicKey {
    fn owner_public_key(&self) -> [u8; 32];
}

impl OwnerPublicKey for SigningKey {
    fn owner_public_key(&self) -> [u8; 32] {
        let ep = self.verifying_key().to_encoded_point(true);
        let k = ep.as_bytes();
        k[1..].try_into().unwrap()
    }
}

#[derive(Debug)]
pub struct SigningError;

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error signing transaction")
    }
}

impl std::error::Error for SigningError {}


#[derive(Debug, Clone)]
pub struct BuilderError(String);


impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Builder error: {}", self.0)
    }
}

impl std::error::Error for BuilderError {}

fn hash(slice: &[u8]) -> [u8;32] {
    let mut hasher = Sha256::new();
    hasher.update(slice);
    hasher.finalize().try_into().unwrap()
}
