package main

import (
	"circuits/ed25519/core"
	goEd25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"math/big"

	"gadgets/ed25519"
	ed25519test "gadgets/ed25519/test"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/rs/zerolog/log"
)

func main() {

	var assignment = &core.Ed25519Circuit{}
	var sigs [8]ed25519.Signature
	var pks [8][2]frontend.Variable
	var pkPoints [8]ed25519.PublicKey
	var msgs [8][5]frontend.Variable

	for i := 0; i < 8; i++ {
		pub, priv, err := goEd25519.GenerateKey(nil)
		if err != nil {
			log.Err(err)
		}

		A, err := (&ed25519test.Point{}).SetBytes(pub)
		if err != nil {
			log.Err(err)
		}
		_A := (&ed25519test.Point{}).Negate(A)

		msg := getInputData(122)
		goSig := goEd25519.Sign(priv, msg)

		goSha512 := sha512.New()
		goSha512.Write(goSig[:32])
		goSha512.Write(pub)
		goSha512.Write(msg)
		hramDigest := goSha512.Sum(nil)

		//split 64 byte signature into two 32byte halves, first halve as point R, second half as S(integer)
		k, _ := ed25519test.NewScalar().SetUniformBytes(hramDigest)
		S, _ := ed25519test.NewScalar().SetCanonicalBytes(goSig[32:])
		R := (&ed25519test.Point{}).VarTimeDoubleScalarBaseMult(k, _A, S)

		eSig := &ed25519.Signature{
			R: *ed25519.NewEmulatedPoint(R),
			S: new(big.Int).SetBytes(ed25519.PutBigEndian(S.Bytes())),
		}
		ePublicKey := &ed25519.PublicKey{
			A: *ed25519.NewEmulatedPoint(A),
		}

		// compress 32byte public key to 2 frontend variable for bn254 field
		var pubBytes [32]byte
		for i := 0; i < 32; i++ {
			pubBytes[i] = pub[i]
		}
		pks[i][0] = pubBytes[:16]
		pks[i][1] = pubBytes[16:]

		pkPoints[i] = *ePublicKey

		sigs[i] = *eSig

		var msgFv [5]frontend.Variable
		// compress message to 5 frontend variable for bn254 field
		for i := 0; i < 5; i++ {
			if i == 4 {
				msgFv[i] = msg[i*25:]
			} else {
				msgFv[i] = msg[i*25 : (i+1)*25]
			}
		}
		msgs[i] = msgFv

	}

	assignment.Signatures = sigs
	assignment.PublicKeys = pks
	assignment.Messages = msgs
	assignment.PbPoints = pkPoints

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.Ed25519Circuit{})

	pk, vk, _ := groth16.Setup(ccs)

	witness, _ := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, err := groth16.Prove(ccs, pk, witness)

	err = groth16.Verify(proof, vk, publicWitness)

	log.Err(err)

}

func getInputData(N int) []byte {
	var base = "00"

	var inputStr = ""
	for i := 0; i < N; i++ {
		inputStr = inputStr + base
	}
	input, _ := hex.DecodeString(inputStr)

	return input
}
