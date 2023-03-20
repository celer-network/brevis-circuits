package core

import (
	"fabric/common"
	"testing"

	"gadgets/pairing_bls12381"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
)

var _ = sha3.NewCShake128(nil, nil)

func TestCircuitTestSolve(t *testing.T) {
	assert := test.NewAssert(t)

	var aggBits [common.LenOfValidators]frontend.Variable
	for i := 0; i < common.LenOfValidators; i++ {
		aggBits[i] = i % 2 // 1, 3... to sign
	}

	g1secrets, g1s, _, _ := common.RandomG1G2Affines()

	var vgs [common.LenOfValidators]pairing_bls12381.G1Affine
	for i := range g1s {
		vgs[i] = pairing_bls12381.NewG1Affine(g1s[i])
	}

	signingRoot := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	signingRootG2, err := bls12381.HashToG2(signingRoot, []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"))
	assert.NoError(err)
	var signingRootVar [32]frontend.Variable
	for i := 0; i < 32; i++ {
		signingRootVar[i] = signingRoot[i]
	}

	var aggSign bls12381.G2Affine // default not set as infinitiy
	participantNum := 0
	for i := 0; i < common.LenOfValidators; i++ {
		if aggBits[i] == 1 {
			var sign bls12381.G2Affine
			sign.ScalarMultiplication(&signingRootG2, g1secrets[i])
			aggSign.Add(&aggSign, &sign)
			participantNum++
		}
	}

	witness := BlsSignatureVerifyCircuit{
		Pubkeys:               vgs,
		AggBits:               aggBits,
		AggSig:                pairing_bls12381.NewG2Affine(aggSign),
		SigningRoot:           signingRootVar,
		ParticipantNum:        participantNum,
		SyncCommitteePoseidon: common.GenPoseidonRoot(vgs),
	}
	err = test.IsSolved(&BlsSignatureVerifyCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
