package common

import (
	"crypto/rand"
	gosha256 "crypto/sha256"
	"math/big"

	"gadgets/pairing_bls12381"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

func RandomG1G2Affines() (g1secrets [LenOfValidators]*big.Int, g1s [LenOfValidators]bls12381.G1Affine, g2secret *big.Int, g2 bls12381.G2Affine) {
	_, _, G1AffGen, G2AffGen := bls12381.Generators()
	mod := bls12381.ID.ScalarField()
	for i := 0; i < LenOfValidators; i++ {
		g1secret, _ := rand.Int(rand.Reader, mod)
		g1secrets[i] = g1secret
		g1s[i].ScalarMultiplication(&G1AffGen, g1secret)
	}
	g2secret, _ = rand.Int(rand.Reader, mod)
	g2.ScalarMultiplication(&G2AffGen, g2secret)

	return
}

func GenPoseidonRoot(validators [LenOfValidators]pairing_bls12381.G1Affine) *big.Int {
	var pubkeysLimbs [LenOfTotalPoseidonNums]*big.Int
	for i := 0; i < LenOfValidators; i++ {
		for j := 0; j < LimbsPerValidator; j++ {
			pubkeysLimbs[i*LimbsPerValidator+j] = validators[i].X.Limbs[j].(*big.Int)
		}
	}

	totalPoseidons := LenOfTotalPoseidonNums/15 + 1
	var lastPoseidonHash *big.Int
	var currentPoseidonHash *big.Int
	for i := 0; i < totalPoseidons; i++ {
		if i == 0 {
			currentPoseidonHash, _ = poseidon.Hash(pubkeysLimbs[i*15 : i*15+15])
		} else if i == totalPoseidons-1 {
			currentPoseidonHash, _ = poseidon.Hash(append(pubkeysLimbs[i*15:], lastPoseidonHash))
		} else {
			currentPoseidonHash, _ = poseidon.Hash(append(pubkeysLimbs[i*15:i*15+15], lastPoseidonHash))
		}
		lastPoseidonHash = currentPoseidonHash
	}

	return currentPoseidonHash
}

func GetSSZRoot(pubkeys [LenOfValidators][LenOfPubkey]frontend.Variable, aggPubkey [LenOfPubkey]byte) []byte {
	var totalValidatorsSSZBytes [LenOfTotalValidatorsSSZBytes]byte
	for i := 0; i < LenOfValidators; i++ {
		for j := 0; j < LenOfOnePubkeySSZBytes; j++ {
			if j < LenOfPubkey {
				totalValidatorsSSZBytes[i*LenOfOnePubkeySSZBytes+j] = pubkeys[i][j].(byte)
			} else {
				totalValidatorsSSZBytes[i*LenOfOnePubkeySSZBytes+j] = uint8(0)
			}
		}
	}

	var aggregateSSZBytes [LenOfOnePubkeySSZBytes]byte
	for i := 0; i < LenOfOnePubkeySSZBytes; i++ {
		if i < LenOfPubkey {
			aggregateSSZBytes[i] = aggPubkey[i]
		} else {
			aggregateSSZBytes[i] = uint8(0)
		}
	}

	validatorsSSZRoot := sszRoot(totalValidatorsSSZBytes[:])
	aggregateSSZRoot := sszRoot(aggregateSSZBytes[:])

	goSha256 := gosha256.New()
	goSha256.Write(validatorsSSZRoot)
	goSha256.Write(aggregateSSZRoot)

	return goSha256.Sum(nil)
}

func sszRoot(input []byte) (output []byte) {
	lenOfInput := len(input)
	output = make([]byte, lenOfInput/2)
	numParis := lenOfInput / 64
	goSha256 := gosha256.New()
	for i := 0; i < numParis; i++ {
		goSha256.Reset()
		goSha256.Write(input[i*64 : (i+1)*64])
		copy(output[i*32:(i+1)*32], goSha256.Sum(nil))
	}

	if numParis == 1 {
		return output
	} else {
		return sszRoot(output)
	}
}
