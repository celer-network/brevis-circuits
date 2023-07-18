# Circuits of Brevis: An Omnichain ZK Data Attestation Platform

Refer to [brevis offcial document](https://docs.brevis.network/) for more details.

## fabric

The top level circuits of Brevis zkFabric.

* `sync-committee`, circuit to calculate the ssz commitment for the beacon sync committee and map the ssz representation to a poseidon hash
* `bls-sig`, circuit to verify the aggregated bls12-381 signature over BN254 scalar field. The set of signers are represented in poseidon hash format, so that on-chain contract can verify that the signers are correct against the result of `sync-committee` circuit
* `ed25519`, a demo circuit to verify a batch of 8 ed25519 signatures over BN254 scalar field
* `headers`, circuit to track of all historical blocks
* `storage-proof`, circuit to enable efficient verification of any EVM storage slot value from a connected remote chain
* `receipt-proof`, circuit to enable efficient verification of any transactions' receipt (included in the synced blocks) that happened on a connected remote chain
* `transaction-proof`, circuit to enable efficient verification of any transactions (included in the synced blocks) that happened on a connected remote chain

### Tests
* `circuit_test.go`, quickly test the correctness of a cuicuit.
* `main.go`, completely go through the whole process of compile, setup, prove and verify steps. It can also be used to generate the benchmark of a circuit. 

## gadgets

In addition to the standard gadgets provided by `gnark`, a powerful zk-SNARK development framework, we implement more in our case. They are:
* `pairing-bls12381` over any finite field
* `ed25519` over any finite field
* `sha256`
* `sha512`
* `keccak`
* `merkle`
* `mpt`
* `rlp`

