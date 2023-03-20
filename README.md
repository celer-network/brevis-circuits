# Circuits of Brevis: An Omnichain ZK Data Attestation Platform

## fabric

The top level circuits of Brevis zkFabric.

1. ETH 2.0
* `sync-committee`, circuit to map the ssz representation of the beacon sync committee to a poseidon hash
* `bls-sig`, circuit to verify the aggregated bls12-381 signature. The set of signers are represented in poseidon hash format, so that on-chain contract can verify that the signers are correct against the result of `sync-committee` circuit

2. COSMOS Chain
* `ed25519`, a demo circuit to verify 8 ed25519 signatures

### Tests
* `circuit_test.go`, quickly test the correctness of a cuicuit.
* `main.go`, completely go through the whole process of compile, setup, prove and verify steps. It can also be used to generate the benchmark of a circuit. 

## gadgets

In addition to the standard gadgets provided by `gnark`, a powerful zk-SNARK development framework, we implement more in our case. They are:
* `pairing-bls12381`
* `ed25519`
* `sha256`
* `sha512`
