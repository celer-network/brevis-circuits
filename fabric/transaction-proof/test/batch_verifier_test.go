package test

import (
	"fmt"
	"testing"

	"github.com/celer-network/brevis-circuits/common"
	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/core"
	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/mock"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

const batchSize = 2

type BatchVerifierCircuit struct {
	InnerProofs [batchSize]core.Proof
	InnerVk     core.VerifyingKey               // all the Vks are same
	TxHash      [batchSize][2]frontend.Variable `gnark:",public"`
	BlockHash   [batchSize][2]frontend.Variable `gnark:",public"`
	BlockNumber [batchSize]frontend.Variable    `gnark:",public"`
	BlockTime   [batchSize]frontend.Variable    `gnark:",public"`
}

func (circuit *BatchVerifierCircuit) Define(api frontend.API) error {

	for i := 0; i < batchSize; i++ {
		proof := circuit.InnerProofs[i]
		txHash := circuit.TxHash[i]
		blockHash := circuit.BlockHash[i]
		blockNum := circuit.BlockNumber[i]
		blockTime := circuit.BlockTime[i]

		var publicInputs []frontend.Variable
		publicInputs = append(publicInputs, txHash[:]...)
		publicInputs = append(publicInputs, blockHash[:]...)
		publicInputs = append(publicInputs, blockNum)
		publicInputs = append(publicInputs, blockTime)
		core.Verify(api, circuit.InnerVk, proof, publicInputs)
	}
	return nil
}

func TestTransactionBatchVerifier(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &core.TxHashCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}

	assignments := mock.GetTransactionProofWitness()
	preWitness, err := frontend.NewWitness(&assignments, ecc.BLS12_377.ScalarField())

	if err != nil {
		t.Fatal(err)
	}

	innerPk, innerVk, err := groth16.Setup(ccs)

	common.WriteVerifyingKey(innerVk, "transactionVk")
	common.WriteProvingKey(innerPk, "transactionPk")

	//var innerVk = groth16.NewVerifyingKey(ecc.BLS12_377)
	//var innerPk = groth16.NewProvingKey(ecc.BLS12_377)
	//err = util.ReadVerifyingKey("transactionVk", innerVk)
	//err = util.ReadProvingKey("transactionPk", innerPk)
	proof, err := groth16.Prove(ccs, innerPk, preWitness)

	publicWitness, err := preWitness.Public()
	if err != nil {
		t.Fatal(err)
	}

	// Check that proof verifies before continuing
	if err := groth16.Verify(proof, innerVk, publicWitness); err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)

	var circuit BatchVerifierCircuit
	circuit.InnerVk.Allocate(innerVk)

	var witness BatchVerifierCircuit

	// construct batch witness
	witness.InnerVk.Assign(innerVk)
	witness.InnerProofs[0].Assign(proof)
	//witness.TxHash[0] = assignments.TxHash
	witness.BlockNumber[0] = assignments.BlockNumber
	witness.BlockHash[0] = assignments.BlockHash
	witness.BlockTime[0] = assignments.BlockTime

	witness.InnerProofs[1].Assign(proof)
	//witness.TxHash[1] = assignments.TxHash
	witness.BlockNumber[1] = assignments.BlockNumber
	witness.BlockHash[1] = assignments.BlockHash
	witness.BlockTime[1] = assignments.BlockTime

	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761), test.WithBackends(backend.GROTH16))

}

func TestGenVkPk(t *testing.T) {
	ccs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, &core.TxHashCheckCircuit{})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(ccs.GetNbConstraints())
	//innerPk, innerVk, err := groth16.Setup(ccs)
	//
	//util.WriteVerifyingKey(innerVk, "transactionVk")
	//util.WriteProvingKey(innerPk, "transactionPk")
}
