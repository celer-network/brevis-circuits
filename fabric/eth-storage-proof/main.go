package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/celer-network/brevis-circuits/fabric/eth-storage-proof/core"

	"github.com/celer-network/brevis-circuits/common"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	assignment := core.GetEthAddressProofTestWitness()

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.EthAddressStorageProof{})
	if err != nil {
		log.Error(err)
	}

	pk, vk, err := groth16.Setup(ccs)

	if err != nil {
		log.Fatal("groth16.Setup")
	}

	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		debug.PrintStack()
		log.Fatal("prove computation failed...", err)
	}

	a, b, c, commitment := common.ExportProof(proof)
	fmt.Printf("\n,storage proof: a: %+v, b: %+v, c: %+v\n, commit: %+v\n", a, b, c, commitment)

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("groth16 verify failed...")
	}

	f, err := os.Create("EthStorageVerifier.sol")
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	err = vk.ExportSolidity(f)

	if err != nil {
		log.Fatal("export solidity failed...")
	}

}
