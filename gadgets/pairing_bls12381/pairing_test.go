package pairing_bls12381

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/weierstrass"
	"github.com/consensys/gnark/test"
)

func randomG1G2Affines(assert *test.Assert) (bls12381.G1Affine, bls12381.G2Affine) {
	_, _, G1AffGen, G2AffGen := bls12381.Generators()
	mod := bls12381.ID.ScalarField()
	s1, err := rand.Int(rand.Reader, mod)
	assert.NoError(err)
	s2, err := rand.Int(rand.Reader, mod)
	assert.NoError(err)
	var p bls12381.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bls12381.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

type MillerLoopCircuit struct {
	InG1 weierstrass.AffinePoint[BLS12381Fp]
	InG2 G2Affine
	Res  GTEl
}

func (c *MillerLoopCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.MillerLoop([]*G1Affine{&c.InG1}, []*G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.ext12.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMillerLoopTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines(assert)
	res, err := bls12381.MillerLoop([]bls12381.G1Affine{p}, []bls12381.G2Affine{q})
	assert.NoError(err)
	witness := MillerLoopCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
		Res:  NewGTEl(res),
	}
	err = test.IsSolved(&MillerLoopCircuit{}, &witness, ecc.BLS12_381.ScalarField())
	assert.NoError(err)
}

type FinalExponentiationCircuit struct {
	InGt GTEl
	Res  GTEl
}

func (c *FinalExponentiationCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res := pairing.FinalExponentiation(&c.InGt)
	pairing.ext12.AssertIsEqual(res, &c.Res)
	return nil
}

func TestFinalExponentiationTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	var gt bls12381.GT
	gt.SetRandom()
	res := bls12381.FinalExponentiation(&gt)
	witness := FinalExponentiationCircuit{
		InGt: NewGTEl(gt),
		Res:  NewGTEl(res),
	}
	err := test.IsSolved(&FinalExponentiationCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type PairCircuit struct {
	InG1 G1Affine
	InG2 G2Affine
	Res  GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.Pair([]*G1Affine{&c.InG1}, []*G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.ext12.AssertIsEqual(res, &c.Res)
	return nil
}

func TestPairTestSolve(t *testing.T) {
	assert := test.NewAssert(t)
	p, q := randomG1G2Affines(assert)
	res, err := bls12381.Pair([]bls12381.G1Affine{p}, []bls12381.G2Affine{q})
	assert.NoError(err)
	witness := PairCircuit{
		InG1: NewG1Affine(p),
		InG2: NewG2Affine(q),
		Res:  NewGTEl(res),
	}
	err = test.IsSolved(&PairCircuit{}, &witness, ecc.BLS12_381.ScalarField())
	assert.NoError(err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PairCircuit{})
	assert.NoError(err)
	fmt.Println(ccs.GetNbConstraints())
}
