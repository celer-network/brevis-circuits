package test

import (
	"testing"

	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/core"
	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/mock"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func Test_TRANSACTIONS_MPT_LEAF_CHECK(t *testing.T) {
	assert := test.NewAssert(t)
	witness := mock.GetTransactionProofWitness()
	err := test.IsSolved(&core.TxHashCheckCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
