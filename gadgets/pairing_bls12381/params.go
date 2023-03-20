package pairing_bls12381

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
)

// BLS12381Fp provide type parametrization for emulated field on 6 limb of width
// 64bits for modulus
// 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab.
// This is the base field of the BLS12-388 curve.
type BLS12381Fp struct{}

func (fp BLS12381Fp) NbLimbs() uint     { return 6 }
func (fp BLS12381Fp) BitsPerLimb() uint { return 64 }
func (fp BLS12381Fp) IsPrime() bool     { return true }
func (fp BLS12381Fp) Modulus() *big.Int { return ecc.BLS12_381.BaseField() }

type BLS12381Fr struct{}

func (fp BLS12381Fr) NbLimbs() uint     { return 4 }
func (fp BLS12381Fr) BitsPerLimb() uint { return 64 }
func (fp BLS12381Fr) IsPrime() bool     { return true }
func (fp BLS12381Fr) Modulus() *big.Int { return ecc.BLS12_381.ScalarField() }
