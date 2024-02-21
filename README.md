# Subspacer

Note: this does not fully implement the functionality described in the [Spaces protocol](https://spacesprotocol.org) yet and should be considered a proof of concept.

Scalable layer-2 registry and prover for subspaces.

## How it works

<img src="https://spacesprotocol.org/images/subspacer.png" />

The registry uses a zero-knowledge virtual machine ([zkVM](https://dev.risczero.com/terminology#zero-knowledge-virtual-machine-zkvm)) to prove the correct execution of transactions associated with subspaces. It produces a `receipt` which contains a verifiable proof for the execution of the Spaces [program](https://github.com/spacesprotocol/subspacer/tree/main/program) and some public outputs.

## Installation

Clone the repo and build binaries with `cargo`:

```bash
cargo build --release
```

To build the `registry` binary with GPU acceleration, use `metal` or `cuda` features depending on your machine.
```rust
cargo build --release --package registry --features "metal"
```

## Quick Start

The `subs` command line utility can be used to generate keys and interact with the registry to create new subspaces, transfer ownership and renew names.

First, let's create a public/private key pair to use:

```bash
$ subs key gen
Generated k-db732761.priv
Public key: db732761ee9d82ba26aedc593d5c263bacd91f4b75a71712215ea94c5ece9ffe
```

Create a transaction to register `bob@example`:



```bash
$ subs create bob@example --private-key k-49f8d3a9.priv
{
  "example": {
    "version": 0,
    "transactions": [
      {
        "name": "bob",
        "owner": "db732761ee9d82ba26aedc593d5c263bacd91f4b75a71712215ea94c5ece9ffe"
      }
    ]
  }
}
```

We'll assume that we're operating `@example` and responsible for including this transaction.

```bash
$ registry add bob.json
```

Check the status of our changes

```bash
$ registry status
Changes to prove and commit:
Total spaces: 1, Total Registrations: 1, Total Updates: 0
  (use "registry commit" to prove and commit changes)
```

Prove and commit the changes:

```bash
$ registry commit
```

Initial commit does not requiring proving as the tree is empty but adding more names will run the prover and should produce something like this:

```
-------------------------------------
- Using Prover: local
- Took: 2.34743775s
- Receipt Verified

Journal Output
-------------------------------------
Total Spaces: 1

        ID: 50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c
        Merkle Root Changes: 
        - Initial: a08d760a9cd74c8bb4b9a0acba82ee31473faa5d654d2f25caf716033c67d0be
        - Final: 8fe93aad37f12e1d11126f2fd3d77fb08eff4f59222cc64e4eacbc64413bd9ad
```


### Using Bonsai

If you have a bonsai API key, you can run the prover remotely.

```bash
BONSAI_API_KEY="YOUR_API_KEY" BONSAI_API_URL="BONSAI_URL" registry commit
```


## License

This project is licensed under the [Apache 2.0](LICENSE).