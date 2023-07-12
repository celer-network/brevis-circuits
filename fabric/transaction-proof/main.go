package main

import (
	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/core"
	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/mock"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	assigment := mock.GetTransactionProofWitness()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.TxHashCheckCircuit{})
	if err != nil {
		log.Fatal(err)
	}

	witness, err := frontend.NewWitness(&assigment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	pubW, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}

	err = groth16.Verify(proof, vk, pubW)
	if err != nil {
		log.Fatal(err)
	}

}
