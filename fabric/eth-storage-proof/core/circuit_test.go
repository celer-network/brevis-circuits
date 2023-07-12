package core

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func TestEthAddressStorage(t *testing.T) {

	witness := GetEthAddressProofTestWitness()
	err := test.IsSolved(&EthAddressStorageProof{}, witness, ecc.BN254.ScalarField())

	if err != nil {
		fmt.Println(err)
	}

	assert := test.NewAssert(t)
	assert.NoError(err)

}
