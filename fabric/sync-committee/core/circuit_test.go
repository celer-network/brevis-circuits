package core

import (
	"fabric/common"
	"testing"

	"gadgets/pairing_bls12381"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestCircuitTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
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

	witness := SyncCommitteeUpdateCircuit{
		Pubkeys:               pubkeys,
		AggregatePubkey:       aggPubkeyInput,
		SyncCommitteeSSZ:      expectSSZ,
		SyncCommitteePoseidon: common.GenPoseidonRoot(vgs),
	}
	err := test.IsSolved(&SyncCommitteeUpdateCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
