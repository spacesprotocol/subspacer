#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
extern crate core;

#[cfg(feature = "std")]
pub mod builder;
pub mod guest;

pub struct TransactionReader<'a>(pub &'a [u8]);

pub const HEADER_SIZE: usize = 1 /* version */ + 32 /* space hash */;

impl<'a> TransactionReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        TransactionReader(data)
    }

    pub fn header(&self) -> &'a [u8] {
        &self.0[..HEADER_SIZE]
    }

    pub fn version(&self) -> u8 {
        self.0[0]
    }

    pub fn space_hash(&self) -> &'a [u8] {
        &self.0[1..33] // Skip 1 byte for version
    }

    pub fn iter(&self) -> BodyIterator<'a> {
        BodyIterator {
            data: &self.0[HEADER_SIZE..],
        }
    }

}

pub struct BodyIterator<'a> {
    data: &'a [u8],
}

impl<'a> Iterator for BodyIterator<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if 2 > self.data.len() {
            return None; // No more data to read
        }
        // Parse the 2-byte length of the tx
        let len = u16::from_le_bytes(
            self.data[.. 2].try_into().unwrap()
        ) as usize;

        self.data = &self.data[2..];
        if len > self.data.len() || len < 64 {
            return None;
        }
        self.data = &self.data[..len];

        // Extract subspace hash, owner, and witness from the update data
        let subspace_hash = &self.data[..32];
        let owner = &self.data[32..64];
        let witness = &self.data[64..];

        assert_eq!(witness.len(), len - 64, "witness length mismatch");

        self.data = &self.data[len..];

        Some(Entry {
            subspace_hash,
            owner,
            witness,
        })
    }
}

pub struct Entry<'a> {
    pub subspace_hash: &'a [u8],
    pub owner: &'a [u8],
    pub witness: &'a [u8],
}
