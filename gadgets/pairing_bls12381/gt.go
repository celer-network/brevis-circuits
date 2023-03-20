package pairing_bls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/math/emulated"
)

type GTEl = E12

func NewGTEl(v bls12381.GT) GTEl {
	return GTEl{
		C0: E6{
			B0: E2{
				A0: emulated.ValueOf[BLS12381Fp](v.C0.B0.A0),
				A1: emulated.ValueOf[BLS12381Fp](v.C0.B0.A1),
			},
			B1: E2{
				A0: emulated.ValueOf[BLS12381Fp](v.C0.B1.A0),
				A1: emulated.ValueOf[BLS12381Fp](v.C0.B1.A1),
			},
			B2: E2{
				A0: emulated.ValueOf[BLS12381Fp](v.C0.B2.A0),
				A1: emulated.ValueOf[BLS12381Fp](v.C0.B2.A1),
			},
		},
		C1: E6{
			B0: E2{
				A0: emulated.ValueOf[BLS12381Fp](v.C1.B0.A0),
				A1: emulated.ValueOf[BLS12381Fp](v.C1.B0.A1),
			},
			B1: E2{
				A0: emulated.ValueOf[BLS12381Fp](v.C1.B1.A0),
				A1: emulated.ValueOf[BLS12381Fp](v.C1.B1.A1),
			},
			B2: E2{
				A0: emulated.ValueOf[BLS12381Fp](v.C1.B2.A0),
				A1: emulated.ValueOf[BLS12381Fp](v.C1.B2.A1),
			},
		},
	}
}
