package pairing_bls12381

import (
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type Bls12381Encode2CurveCircuit struct {
	InG2 G2Affine
	Msg  [32]frontend.Variable `gnark:"data,public"` // 32 bytes, 512 bits
}

func (circuit *Bls12381Encode2CurveCircuit) Define(api frontend.API) error {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)

	g2Affine := EncodeToG2(api, circuit.Msg)
	et2.AssertIsEqual(&circuit.InG2.X, &g2Affine.X)
	et2.AssertIsEqual(&circuit.InG2.Y, &g2Affine.Y)

	return nil
}

func Test_Bls12381EncodeToG2(t *testing.T) {
	for n := 0; n < 10; n++ {
		var signingRoot = [32]byte{
			244, byte(n), 2, 3, 4, 10, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
			21, 254, 23, 24, 25, 26, 88, 28, 29, 30,
			31,
		}

		expectedG2, err := bls12381.EncodeToG2(signingRoot[:], DST)
		if err != nil {
			log.Fatal(err)
		}

		assert := test.NewAssert(t)
		var c Bls12381Encode2CurveCircuit
		var msg [32]frontend.Variable
		for i, v := range signingRoot {
			msg[i] = v
		}
		c = Bls12381Encode2CurveCircuit{
			InG2: G2Affine{
				X: E2{
					A0: emulated.ValueOf[BLS12381Fp](expectedG2.X.A0),
					A1: emulated.ValueOf[BLS12381Fp](expectedG2.X.A1),
				},
				Y: E2{
					A0: emulated.ValueOf[BLS12381Fp](expectedG2.Y.A0),
					A1: emulated.ValueOf[BLS12381Fp](expectedG2.Y.A1),
				},
			},
			Msg: msg,
		}
		err = test.IsSolved(&Bls12381Encode2CurveCircuit{}, &c, ecc.BLS12_381.ScalarField())
		assert.NoError(err)
	}
}

type Bls12381Hash2CurveCircuit struct {
	InG2 G2Affine
	Msg  [32]frontend.Variable `gnark:"data,public"` // 32 bytes, 512 bits
}

func (circuit *Bls12381Hash2CurveCircuit) Define(api frontend.API) error {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)

	g2Affine := HashToG2(api, circuit.Msg)
	et2.AssertIsEqual(&circuit.InG2.X, &g2Affine.X)
	et2.AssertIsEqual(&circuit.InG2.Y, &g2Affine.Y)
	return nil
}

func Test_Bls12381HashToG2(t *testing.T) {
	for n := 0; n < 3; n++ {
		var signingRoot = [32]byte{
			244, byte(n), 2, 5, 4, 10, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
			21, 254, 23, 24, 25, 26, 88, 28, 29, 30,
			31,
		}

		expectedG2, err := bls12381.HashToG2(signingRoot[:], DST)
		if err != nil {
			log.Fatal(err)
		}

		assert := test.NewAssert(t)
		var c Bls12381Hash2CurveCircuit
		var msg [32]frontend.Variable
		for i, v := range signingRoot {
			msg[i] = v
		}
		c = Bls12381Hash2CurveCircuit{
			InG2: G2Affine{
				X: E2{
					A0: emulated.ValueOf[BLS12381Fp](expectedG2.X.A0),
					A1: emulated.ValueOf[BLS12381Fp](expectedG2.X.A1),
				},
				Y: E2{
					A0: emulated.ValueOf[BLS12381Fp](expectedG2.Y.A0),
					A1: emulated.ValueOf[BLS12381Fp](expectedG2.Y.A1),
				},
			},
			Msg: msg,
		}
		err = test.IsSolved(&Bls12381Hash2CurveCircuit{}, &c, ecc.BLS12_381.ScalarField())
		assert.NoError(err)

		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Bls12381Hash2CurveCircuit{})
		assert.NoError(err)
		fmt.Println(ccs.GetNbConstraints())
	}
}

func Test_Bls12381G2Config(t *testing.T) {
	var k [2]*big.Int
	k[0], _ = new(big.Int).SetString("15132376222941642752", 10)
	k[1] = new(big.Int)
	nbits := k[0].BitLen()
	if k[1].BitLen() > nbits {
		nbits = k[1].BitLen()
	}

	log.Printf("%v", k[0].Sign() == -1)
	log.Printf("%v", k[1].Sign() == -1)

	log.Printf("%v", k[0].Bit(0))
	log.Printf("%v", k[1].Bit(0))

	log.Printf("%d", nbits)

}
