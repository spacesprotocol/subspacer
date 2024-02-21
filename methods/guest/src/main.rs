#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;
use alloc::vec::Vec;
use program::guest::{run};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let payload: Vec<Vec<u8>> = env::read();
    let out = match run(payload) {
        Ok(out) => out,
        Err(e) => panic!("{}", e),
    };
    // write public output to the journal
    env::commit(&out);
}
