package pairing_bls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/algebra/native/weierstrass"
	"github.com/consensys/gnark/std/math/emulated"
)

type G1Affine = weierstrass.AffinePoint[BLS12381Fp]

func NewG1Affine(v bls12381.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[BLS12381Fp](v.X),
		Y: emulated.ValueOf[BLS12381Fp](v.Y),
	}
}
