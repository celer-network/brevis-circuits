package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"time"

	"fabric/common"
	"fabric/sync-committee/core"

	"gadgets/pairing_bls12381"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// generate CompiledConstraintSystem
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.SyncCommitteeUpdateCircuit{})
	if err != nil {
		log.Fatal("frontend.Compile")
	}

	// groth16 zkSNARK: Setup
	setupStart := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal("groth16.Setup")
	}
	setUpDuration := time.Since(setupStart)
	fmt.Printf("setup duration:%d\n", setUpDuration)

	_, g1s, _, _ := common.RandomG1G2Affines()

	var vgs [common.LenOfValidators]pairing_bls12381.G1Affine
	for i := range g1s {
		vgs[i] = pairing_bls12381.NewG1Affine(g1s[i])
	}

	var aggPubKey bls12381.G1Affine // default not set as infinitiy
	for i := 0; i < common.LenOfValidators; i++ {
		aggPubKey.Add(&aggPubKey, &g1s[i])
	}

	var pubkeys [common.LenOfValidators][common.LenOfPubkey]frontend.Variable
	for i := 0; i < common.LenOfValidators; i++ {
		pubkey := g1s[i].Bytes()
		var pubkeyInput [common.LenOfPubkey]frontend.Variable
		for i := range pubkey {
			pubkeyInput[i] = pubkey[i]
		}
		pubkeys[i] = pubkeyInput
	}

	aggregatePubkey := aggPubKey.Bytes()
	var aggPubkeyInput [common.LenOfPubkey]frontend.Variable
	for i := range aggregatePubkey {
		aggPubkeyInput[i] = aggregatePubkey[i]
	}

	expectSSZBytes := common.GetSSZRoot(pubkeys, aggregatePubkey)
	var expectSSZ [32]frontend.Variable
	for i := range expectSSZ {
		expectSSZ[i] = expectSSZBytes[i]
	}

	assignment := core.SyncCommitteeUpdateCircuit{
		Pubkeys:               pubkeys,
		AggregatePubkey:       aggPubkeyInput,
		SyncCommitteeSSZ:      expectSSZ,
		SyncCommitteePoseidon: common.GenPoseidonRoot(vgs),
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		debug.PrintStack()
		log.Fatal("prove computation failed...", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("groth16 verify failed...")
	}

	f, err := os.Create("SyncCommitteeVerifier.sol")
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	err = vk.ExportSolidity(f)
}
