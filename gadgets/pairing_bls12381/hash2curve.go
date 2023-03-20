package pairing_bls12381

import (
	"log"
	"math/big"

	"gadgets/sha256"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

var (
	SswuIsoCurveCoeffA = E2{
		A0: emulated.ValueOf[BLS12381Fp](fp.Element{0}),
		A1: emulated.ValueOf[BLS12381Fp](fp.Element{16517514583386313282, 74322656156451461, 16683759486841714365, 815493829203396097, 204518332920448171, 1306242806803223655}),
	}

	SswuIsoCurveCoeffB = E2{
		A0: emulated.ValueOf[BLS12381Fp](fp.Element{2515823342057463218, 7982686274772798116, 7934098172177393262, 8484566552980779962, 4455086327883106868, 1323173589274087377}),
		A1: emulated.ValueOf[BLS12381Fp](fp.Element{2515823342057463218, 7982686274772798116, 7934098172177393262, 8484566552980779962, 4455086327883106868, 1323173589274087377}),
	}

	Tv4Z = E2{
		A0: emulated.ValueOf[BLS12381Fp](fp.Element{9794203289623549276, 7309342082925068282, 1139538881605221074, 15659550692327388916, 16008355200866287827, 582484205531694093}),
		A1: emulated.ValueOf[BLS12381Fp](fp.Element{4897101644811774638, 3654671041462534141, 569769440802610537, 17053147383018470266, 17227549637287919721, 291242102765847046}),
	}

	DST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
)

const Bytes = 1 + (fp.Bits-1)/8
const L = 16 + Bytes       // 52
const Sha256BlockSize = 64 // 512 bits, 64 bytes
const SizeDomain = 43
const Sha256Size = 32
const SignRootSize = 32

func ExpandMsgXmd(api frontend.API, msg [32]frontend.Variable, count int) []frontend.Variable {
	lenInBytes := count * L
	ell := (lenInBytes + Sha256Size - 1) / Sha256Size

	var b0Preimage [143]frontend.Variable

	for i := 0; i < Sha256BlockSize; i++ {
		b0Preimage[i] = uint8(0)
	}
	for i := 0; i < SignRootSize; i++ {
		b0Preimage[i+Sha256BlockSize] = msg[i]
	}

	b0Preimage[96] = uint8(lenInBytes >> 8)
	b0Preimage[97] = uint8(lenInBytes)
	b0Preimage[98] = uint8(0)

	for i := 0; i < 43; i++ {
		b0Preimage[i+99] = DST[i]
	}

	b0Preimage[142] = byte(SizeDomain)

	digest0 := sha256.New(api)
	digest0.Write(b0Preimage[:])
	b0 := digest0.Sum() // sha256, 32 bytes

	// b₁ = H(b₀ ∥ I2OSP(1, 1) ∥ DST_prime)
	var b1Preimage [77]frontend.Variable
	for i := 0; i < Sha256Size; i++ {
		b1Preimage[i] = b0[i]
	}
	b1Preimage[32] = uint8(1)
	for i := 0; i < 43; i++ {
		b1Preimage[i+33] = DST[i]
	}
	b1Preimage[76] = uint8(SizeDomain)

	digest1 := sha256.New(api)
	digest1.Write(b1Preimage[:])
	b1 := digest1.Sum() // sha256, 32 bytes

	pseudoRandomBytes := make([]frontend.Variable, lenInBytes)
	for i := 0; i < Sha256Size; i++ {
		pseudoRandomBytes[i] = b1[i]
	}
	for i := Sha256Size; i < lenInBytes; i++ {
		pseudoRandomBytes[i] = uint8(0)
	}

	uint8API := sha256.NewUint8API(api)

	for i := 2; i <= ell; i++ {
		for j := 0; j < Sha256Size; j++ {
			bb0 := uint8API.AsUint8(b0[j])
			bb1 := uint8API.AsUint8(b1[j])
			b1Preimage[j] = uint8API.FromUint8(uint8API.Xor(bb0, bb1))
		}

		b1Preimage[32] = uint8(i)
		for j := 0; j < 43; j++ {
			b1Preimage[j+33] = DST[j]
		}
		b1Preimage[76] = uint8(SizeDomain)

		digest1 = sha256.New(api)
		digest1.Write(b1Preimage[:])
		b1 = digest1.Sum() // sha256, 32 bytes

		copy(pseudoRandomBytes[Sha256Size*(i-1):min(Sha256Size*i, lenInBytes)], b1)
	}

	return pseudoRandomBytes
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// input is 8 bytes, 64 bits
// equal to bigint set bytes, big-endian bytes
func GetUint64From8Bytes(api frontend.API, v [8]frontend.Variable) frontend.Variable {
	uint64API := sha256.NewUint64API(api)

	var uint64var [64]frontend.Variable // use 64 bits as uint64
	for j := 0; j < 8; j++ {
		b := bits.ToBinary(api, v[j], bits.WithNbDigits(8))
		copy(uint64var[64-(j+1)*8:64-j*8], b)
	}

	return uint64API.FromUint64(uint64var)
}

// input is 8 bytes, 64 bits
// equal to bigint set bytes, big-endian bytes
func Get64BitsFrom8Bytes(api frontend.API, v [8]frontend.Variable) []frontend.Variable {
	var uint64var [64]frontend.Variable // use 64 bits as uint64
	for j := 0; j < 8; j++ {
		b := bits.ToBinary(api, v[j], bits.WithNbDigits(8))
		copy(uint64var[64-(j+1)*8:64-j*8], b)
	}

	return uint64var[:]
}

// 8 limbs, 8 bytes(uint64) per limb
// raw means this method will not do toMont on element.
func GetRawLimbsBy8Uint64(api frontend.API, v [8]frontend.Variable) *emulated.Element[BLS12381Fp] {
	f, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	return f.ReduceWithoutConstantCheck(f.NewInternalElement(v[:], 1))
}

func MapElementToCurve2(api frontend.API, e2 E2) (x, y *E2) {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}

	et2 := NewExt2(ba)

	tv1 := et2.Square(&e2)    // 1.  tv1 = u²
	tv1 = et2.Mul(tv1, &Tv4Z) // 2.  tv1 = Z * tv1
	tv2 := et2.Square(tv1)    // 3.  tv2 = tv1²
	tv2 = et2.Add(tv2, tv1)   // 4.  tv2 = tv2 + tv1

	tv3 := et2.Add(tv2, et2.One())          // 5.  tv3 = tv2 + 1
	tv3 = et2.Mul(tv3, &SswuIsoCurveCoeffB) // 6.  tv3 = B * tv3

	tv2 = et2.Neg(tv2)
	tv4 := et2.Mul(tv2, &SswuIsoCurveCoeffA)

	tv2 = et2.Square(tv3) // 9.  tv2 = tv3²

	tv6 := et2.Square(tv4)                   // 10. tv6 = tv4²
	tv5 := et2.Mul(tv6, &SswuIsoCurveCoeffA) // 11. tv5 = A * tv6
	tv2 = et2.Add(tv2, tv5)                  // 12. tv2 = tv2 + tv5
	tv2 = et2.Mul(tv2, tv3)                  // 13. tv2 = tv2 * tv3
	tv6 = et2.Mul(tv6, tv4)                  // 14. tv6 = tv6 * tv4

	tv5 = et2.Mul(tv6, &SswuIsoCurveCoeffB) // 15. tv5 = B * tv6
	tv2 = et2.Add(tv2, tv5)                 // 16. tv2 = tv2 + tv5

	x = et2.Mul(tv1, tv3) // 17.   x = tv1 * tv3

	y1, gx1NSquare := g2SqrtRatio(api, tv2, tv6) // 18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

	y = et2.Mul(tv1, &e2)              // 19.   y = tv1 * u
	y = et2.Mul(y, y1)                 // 20.   y = y * y1
	x = et2.Select(gx1NSquare, x, tv3) // 21.   x = CMOV(x, tv3, is_gx1_square)
	y = et2.Select(gx1NSquare, y, y1)  // 22.   y = CMOV(y, y1, is_gx1_square)

	y1 = et2.Neg(y)
	g2Sgn0U := g2Sgn0(api, &e2)
	g2Sgn0Y := g2Sgn0(api, y)
	useY1 := api.Xor(g2Sgn0U, g2Sgn0Y)
	y = et2.Select(useY1, y1, y)

	x = et2.Div(x, tv4)
	return x, y
}

func g2Sgn0(api frontend.API, u *E2) frontend.Variable {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}

	uu := E2{
		A0: *ba.Reduce(&u.A0),
		A1: *ba.Reduce(&u.A1),
	}
	var A0Bits [6][]frontend.Variable
	A0Bits[0] = bits.ToBinary(api, uu.A0.Limbs[0], bits.WithNbDigits(64))
	A0Bits[1] = bits.ToBinary(api, uu.A0.Limbs[1], bits.WithNbDigits(64))
	A0Bits[2] = bits.ToBinary(api, uu.A0.Limbs[2], bits.WithNbDigits(64))
	A0Bits[3] = bits.ToBinary(api, uu.A0.Limbs[3], bits.WithNbDigits(64))
	A0Bits[4] = bits.ToBinary(api, uu.A0.Limbs[4], bits.WithNbDigits(64))
	A0Bits[5] = bits.ToBinary(api, uu.A0.Limbs[5], bits.WithNbDigits(64))

	var sign, zero, signI, zeroI frontend.Variable
	sign = 0
	zero = 1
	signI = A0Bits[0][0]

	zeroI = 0
	for _, subBits := range A0Bits {
		for _, b := range subBits {
			zeroI = api.Or(signI, b)
		}
	}

	sign = api.Or(sign, api.And(zero, signI))
	zero = api.And(zero, zeroI)
	signI = bits.ToBinary(api, uu.A1.Limbs[0], bits.WithNbDigits(64))[0]
	sign = api.Or(sign, api.And(zero, signI))
	return sign
}

func g2SqrtRatio(api frontend.API, u *E2, v *E2) (z *E2, isQNr frontend.Variable) {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}

	et2 := NewExt2(ba)
	// https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-sqrt_ratio-for-any-field

	tv1 := E2{
		A0: emulated.ValueOf[BLS12381Fp](fp.Element{8921533702591418330, 15859389534032789116, 3389114680249073393, 15116930867080254631, 3288288975085550621, 1021049300055853010}),
		A1: emulated.ValueOf[BLS12381Fp](fp.Element{8921533702591418330, 15859389534032789116, 3389114680249073393, 15116930867080254631, 3288288975085550621, 1021049300055853010}),
	}

	var tv2, tv3, tv4, tv5 *E2
	var exp big.Int
	// c4 = 7 = 2³ - 1
	// q is odd so c1 is at least 1.
	exp.SetBytes([]byte{7})
	tv2 = E2Exp(api, *v, &exp) // 2. tv2 = vᶜ⁴

	tv3 = et2.Square(tv2) // 3. tv3 = tv2²
	tv3 = et2.Mul(tv3, v) // 4. tv3 = tv3 * v
	tv5 = et2.Mul(u, tv3) // 5. tv5 = u * tv3

	// c3 = 1001205140483106588246484290269935788605945006208159541241399033561623546780709821462541004956387089373434649096260670658193992783731681621012512651314777238193313314641988297376025498093520728838658813979860931248214124593092835
	exp.SetBytes([]byte{42, 67, 122, 75, 140, 53, 252, 116, 189, 39, 142, 170, 34, 242, 94, 158, 45, 201, 14, 80, 231, 4, 107, 70, 110, 89, 228, 147, 73, 232, 189, 5, 10, 98, 207, 209, 109, 220, 166, 239, 83, 20, 147, 48, 151, 142, 240, 17, 214, 134, 25, 200, 97, 133, 199, 178, 146, 232, 90, 135, 9, 26, 4, 150, 107, 249, 30, 211, 231, 27, 116, 49, 98, 195, 56, 54, 33, 19, 207, 215, 206, 214, 177, 215, 99, 130, 234, 178, 106, 160, 0, 1, 199, 24, 227})

	tv5 = E2Exp(api, *tv5, &exp) // 6. tv5 = tv5ᶜ³
	tv5 = et2.Mul(tv5, tv2)      // 7. tv5 = tv5 * tv2
	tv2 = et2.Mul(tv5, v)        // 8. tv2 = tv5 * v
	tv3 = et2.Mul(tv5, u)        // 9. tv3 = tv5 * u
	tv4 = et2.Mul(tv3, tv2)      // 10. tv4 = tv3 * tv2

	exp.SetBytes([]byte{4})
	tv5 = E2Exp(api, *tv4, &exp) // 11. tv5 = tv4ᶜ⁵

	isQNr = E2NotOne(api, *tv5)

	c7 := E2{
		A0: emulated.ValueOf[BLS12381Fp](fp.Element{1921729236329761493, 9193968980645934504, 9862280504246317678, 6861748847800817560, 10375788487011937166, 4460107375738415}),
		A1: emulated.ValueOf[BLS12381Fp](fp.Element{16821121318233475459, 10183025025229892778, 1779012082459463630, 3442292649700377418, 1061500799026501234, 1352426537312017168}),
	}

	tv2 = et2.Mul(tv3, &c7)           // 13. tv2 = tv3 * c7
	tv5 = et2.Mul(tv4, &tv1)          // 14. tv5 = tv4 * tv1
	tv3 = et2.Select(isQNr, tv2, tv3) // tv3.Select(int(isQNr), &tv3, &tv2) // 15. tv3 = CMOV(tv2, tv3, isQR)
	tv4 = et2.Select(isQNr, tv5, tv4) // tv4.Select(int(isQNr), &tv4, &tv5) // 16. tv4 = CMOV(tv5, tv4, isQR)

	exp.Lsh(big.NewInt(1), 3-2) // 18, 19: tv5 = 2ⁱ⁻² for i = c1

	for i := 3; i >= 2; i-- { // 17. for i in (c1, c1 - 1, ..., 2):
		tv5 = E2Exp(api, *tv4, &exp)
		nE1 := E2NotOne(api, *tv5)
		tv2 = et2.Mul(tv3, &tv1)
		tv1 = *et2.Mul(&tv1, &tv1)
		tv5 = et2.Mul(tv4, &tv1)
		tv3 = et2.Select(nE1, tv2, tv3)
		tv4 = et2.Select(nE1, tv5, tv4)
		if i > 2 {
			exp.Rsh(&exp, 1) // 18, 19. tv5 = 2ⁱ⁻²
		}
	}

	z = tv3

	return z, isQNr
}

func E2Exp(api frontend.API, x E2, k *big.Int) *E2 {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)
	res := et2.One()

	if k.IsUint64() && k.Uint64() == 0 {
		return res
	}

	e := k
	if k.Sign() == -1 {
		// negative k, we invert
		// if k < 0: xᵏ (mod q²) == (x⁻¹)ᵏ (mod q²)
		x = *et2.Inverse(&x)

		// we negate k in a temp big.Int since
		// Int.Bit(_) of k and -k is different
		e.Neg(k)
	}

	b := e.Bytes()
	for i := 0; i < len(b); i++ {
		w := b[i]
		for j := 0; j < 8; j++ {
			res = et2.Square(res)
			if (w & (0b10000000 >> j)) != 0 {
				res = et2.Mul(res, &x)
			}
		}
	}
	return res
}

func G2Isogeny(api frontend.API, p *G2Affine) *G2Affine {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)

	den := make([]*E2, 2)

	den[1] = g2IsogenyYDenominator(api, &p.X)
	den[0] = g2IsogenyXDenominator(api, &p.X)

	newPy := g2IsogenyYNumerator(api, &p.X, &p.Y)
	newPx := g2IsogenyXNumerator(api, &p.X)

	den[1] = et2.Inverse(den[1])
	den[0] = et2.Inverse(den[0])

	newPoint := &G2Affine{
		X: *et2.Mul(newPx, den[0]),
		Y: *et2.Mul(newPy, den[1]),
	}

	return newPoint
}

func g2IsogenyXDenominator(api frontend.API, x *E2) *E2 {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)

	coefficients := [2]*E2{
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{0}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{2250392438786206615, 17463829474098544446, 14571211649711714824, 4495761442775821336, 258811604141191305, 357646605018048850}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{4933130441833534766, 15904462746612662304, 8034115857496836953, 12755092135412849606, 7007796720291435703, 252692002104915169}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{8469300574244328829, 4752422838614097887, 17848302789776796362, 12930989898711414520, 16851051131888818207, 1621106615542624696}),
		},
	}

	dst := coefficients[1]
	dst = et2.Add(dst, x)

	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[0])

	return dst
}

func g2IsogenyXNumerator(api frontend.API, x *E2) *E2 {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)
	coefficients := [4]*E2{
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{5185457120960601698, 494647221959407934, 8971396042087821730, 324544954362548322, 14214792730224113654, 1405280679127738945}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{5185457120960601698, 494647221959407934, 8971396042087821730, 324544954362548322, 14214792730224113654, 1405280679127738945}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{0}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{6910023028261548496, 9745789443900091043, 7668299866710145304, 2432656849393633605, 2897729527445498821, 776645607375592125}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{724047465092313539, 15783990863276714670, 12824896677063784855, 15246381572572671516, 13186611051602728692, 1485475813959743803}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{12678383550985550056, 4872894721950045521, 13057521970209848460, 10439700461551592610, 10672236800577525218, 388322803687796062}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{4659755689450087917, 1804066951354704782, 15570919779568036803, 15592734958806855601, 7597208057374167129, 1841438384006890194}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{0}),
		},
	}

	dst := coefficients[3]

	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[2])

	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[1])

	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[0])

	return dst
}

func g2IsogenyYDenominator(api frontend.API, x *E2) *E2 {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)

	coefficients := [3]*E2{
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{99923616639376095, 10339114964526300021, 6204619029868000785, 1288486622530663893, 14587509920085997152, 272081012460753233}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{99923616639376095, 10339114964526300021, 6204619029868000785, 1288486622530663893, 14587509920085997152, 272081012460753233}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{0}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{6751177316358619845, 15498000274876530106, 6820146801716041242, 13487284328327464010, 776434812423573915, 1072939815054146550}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{7399695662750302149, 14633322083064217648, 12051173786245255430, 9909266166264498601, 1288323043582377747, 379038003157372754}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{6002735353327561446, 6023563502162542543, 13831244861028377885, 15776815867859765525, 4123780734888324547, 1494760614490167112}),
		},
	}

	dst := coefficients[2]

	dst = et2.Add(dst, x)
	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[1])

	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[0])

	return dst
}

func g2IsogenyYNumerator(api frontend.API, x, y *E2) *E2 {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)
	coefficients := [4]*E2{
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{10869708750642247614, 13056187057366814946, 1750362034917495549, 6326189602300757217, 1140223926335695785, 632761649765668291}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{10869708750642247614, 13056187057366814946, 1750362034917495549, 6326189602300757217, 1140223926335695785, 632761649765668291}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{0}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{13765940311003083782, 5579209876153186557, 11349908400803699438, 11707848830955952341, 199199289641242246, 899896674917908607}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{15562563812347550836, 2436447360975022760, 6528760985104924230, 5219850230775796305, 5336118400288762609, 194161401843898031}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{16286611277439864375, 18220438224251737430, 906913588459157469, 2019487729638916206, 75985378181939686, 1679637215803641835}),
		},
		{
			A0: emulated.ValueOf[BLS12381Fp](fp.Element{11849179119594500956, 13906615243538674725, 14543197362847770509, 2041759640812427310, 2879701092679313252, 1259985822978576468}),
			A1: emulated.ValueOf[BLS12381Fp](fp.Element{0}),
		},
	}

	dst := coefficients[3]

	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[2])

	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[1])

	dst = et2.Mul(dst, x)
	dst = et2.Add(dst, coefficients[0])

	dst = et2.Mul(dst, y)
	return dst
}

func E2NotZero(api frontend.API, x E2) frontend.Variable {
	a0NotZero := G1NotZero(api, x.A0)
	a1NotZero := G1NotZero(api, x.A1)
	return api.Or(a0NotZero, a1NotZero)
}

func G1NotZero(api frontend.API, x baseEl) frontend.Variable {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	x = *ba.Reduce(&x)
	bs := ba.ToBits(&x)
	var isNotZero frontend.Variable
	isNotZero = 0
	for _, b := range bs {
		isNotZero = api.Or(isNotZero, b)
	}
	return isNotZero
}

func G1NotEqualOne(api frontend.API, x baseEl) frontend.Variable {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	return G1NotEqual(api, x, *ba.One())
}

func G1NotEqual(api frontend.API, x, y baseEl) frontend.Variable {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	x = *ba.Reduce(&x)
	y = *ba.Reduce(&y)
	xBits := ba.ToBits(&x)
	yBits := ba.ToBits(&y)

	var notEqual frontend.Variable
	notEqual = 0
	for i, b := range xBits {
		notEqual = api.Or(notEqual, api.Xor(b, yBits[i]))
	}

	return notEqual
}

func E2NotEqual(api frontend.API, x, y E2) frontend.Variable {
	var a0NotEqual, a1NotEqual frontend.Variable
	a0NotEqual = G1NotEqual(api, x.A0, y.A0)
	a1NotEqual = G1NotEqual(api, x.A1, y.A1)
	return api.Or(a0NotEqual, a1NotEqual)
}

func E2NotOne(api frontend.API, x E2) frontend.Variable {
	var a0NotOne, a1NotZero frontend.Variable
	a0NotOne = G1NotEqualOne(api, x.A0)
	a1NotZero = G1NotZero(api, x.A1)
	return api.Or(a0NotOne, a1NotZero)
}

func GetG2JacFromG2Affine(api frontend.API, Q *G2Affine) *G2Jacobian {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)
	g2NotInfinity := G2AffineNotInfinity(api, Q)

	z := *et2.Select(g2NotInfinity, et2.One(), et2.Zero())
	x := *et2.Select(g2NotInfinity, &Q.X, et2.One())
	y := *et2.Select(g2NotInfinity, &Q.Y, et2.One())

	return &G2Jacobian{
		X: x,
		Y: y,
		Z: z,
	}
}

func GetG2AffineFromG2Jac(api frontend.API, Q *G2Jacobian) *G2Affine {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)

	res1 := &G2Affine{
		X: *et2.Zero(),
		Y: *et2.Zero(),
	}
	a := et2.Inverse(&Q.Z)
	b := et2.Square(a)
	res2 := &G2Affine{}
	res2.X = *et2.Mul(&Q.X, b)
	res2.Y = *et2.Mul(&Q.Y, b)
	res2.Y = *et2.Mul(&res2.Y, a)
	jacZNotZero := E2NotZero(api, Q.Z)

	final := &G2Affine{}
	final.X = *et2.Select(jacZNotZero, &res2.X, &res1.X)
	final.Y = *et2.Select(jacZNotZero, &res2.Y, &res1.Y)
	return final
}

// ClearCofactor maps a point in curve to r-torsion
func ClearCofactor(api frontend.API, a G2Jacobian) *G2Jacobian {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		log.Fatal(err)
	}
	et2 := NewExt2(ba)
	// https://eprint.iacr.org/2017/419.pdf, 4.1
	var res G2Jacobian

	xg := G2JacobianConstScalarMul(api, a)
	xg = G2JacobianNeg(api, xg)

	xxg := G2JacobianConstScalarMul(api, xg)
	xxg = G2JacobianNeg(api, xxg)

	res = G2JacobianSubAssign(api, xxg, xg)
	res = G2JacobianSubAssign(api, res, a)

	t := G2JacobianSubAssign(api, xg, a)
	t = G2JacobianPsi(api, t)

	res = G2JacobianAddAssign(api, res, t)

	t = G2JacobianDouble(api, a)

	var thirdRootOneG1 fp.Element
	thirdRootOneG1.SetString("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	trog1 := emulated.ValueOf[BLS12381Fp](thirdRootOneG1)

	t.X = *et2.MulByElement(&t.X, &trog1)

	res = G2JacobianSubAssign(api, res, t)

	return &res

}

func G2AffineNotInfinity(api frontend.API, a *G2Affine) frontend.Variable {
	xNotZero := E2NotZero(api, a.X)
	yNotZero := E2NotZero(api, a.Y)
	return api.Or(xNotZero, yNotZero)
}

func HashToField(api frontend.API, msg [32]frontend.Variable, count int) []E2 {
	emx := ExpandMsgXmd(api, msg, count)
	u := make([]*emulated.Element[BLS12381Fp], count)
	for i := 0; i < count; i++ {
		var overflowLimbs [8]frontend.Variable // 8bytes
		var val8Bytes [8]frontend.Variable
		for j := 0; j < 8; j++ {
			copy(val8Bytes[:], emx[64*(i+1)-8*(j+1):64*(i+1)-8*j])
			overflowLimbs[j] = GetUint64From8Bytes(api, val8Bytes)
		}
		u[i] = GetRawLimbsBy8Uint64(api, overflowLimbs)
	}

	var res []E2

	// TODO
	for n := 0; n < count/2; n++ {
		res = append(res, E2{
			A0: *u[n*2],
			A1: *u[n*2+1],
		})
	}

	return res
}

func EncodeToG2OnJac(api frontend.API, msg [32]frontend.Variable) *G2Affine {
	e2 := HashToField(api, msg, 2)

	x, y := MapElementToCurve2(api, e2[0])
	g2Affine := G2Isogeny(api, &G2Affine{
		*x, *y,
	})
	g2Jac := GetG2JacFromG2Affine(api, g2Affine)
	g2Jac = ClearCofactor(api, *g2Jac)
	g2Affine = GetG2AffineFromG2Jac(api, g2Jac)

	return g2Affine
}

func EncodeToG2(api frontend.API, msg [32]frontend.Variable) *G2Affine {
	e2 := HashToField(api, msg, 2)
	x, y := MapElementToCurve2(api, e2[0])
	g2Affine := G2Isogeny(api, &G2Affine{
		*x, *y,
	})
	return G2ClearCofactor(api, *g2Affine)
}

func HashToG2OnJac(api frontend.API, msg [32]frontend.Variable) *G2Affine {
	e2 := HashToField(api, msg, 4)

	Q0X, Q0Y := MapElementToCurve2(api, e2[0])
	Q1X, Q1Y := MapElementToCurve2(api, e2[1])

	Q0 := G2Isogeny(api, &G2Affine{
		X: *Q0X,
		Y: *Q0Y,
	})
	Q1 := G2Isogeny(api, &G2Affine{
		X: *Q1X,
		Y: *Q1Y,
	})

	_Q0 := GetG2JacFromG2Affine(api, Q0)
	_Q1 := GetG2JacFromG2Affine(api, Q1)

	sum := G2JacobianAddAssign(api, *_Q0, *_Q1)

	sum = *ClearCofactor(api, sum)

	finalQ1 := GetG2AffineFromG2Jac(api, &sum)

	return finalQ1
}

func HashToG2(api frontend.API, msg [32]frontend.Variable) *G2Affine {
	e2 := HashToField(api, msg, 4)

	Q0X, Q0Y := MapElementToCurve2(api, e2[0])
	Q1X, Q1Y := MapElementToCurve2(api, e2[1])

	Q0 := G2Isogeny(api, &G2Affine{
		X: *Q0X,
		Y: *Q0Y,
	})
	Q1 := G2Isogeny(api, &G2Affine{
		X: *Q1X,
		Y: *Q1Y,
	})

	sum := G2AddAssign(api, *Q0, *Q1)
	sum = G2ClearCofactor(api, *sum)
	return sum
}
