package test

import (
	"testing"

	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/core"
	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/mock"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestTransactionRoot2(t *testing.T) {
	assert := test.NewAssert(t)

	witness := mock.GetTransactionMptProofWitness()
	err := test.IsSolved(&core.TransactionMptCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
