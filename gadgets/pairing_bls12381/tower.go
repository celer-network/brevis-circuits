package pairing_bls12381

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type curveF = emulated.Field[BLS12381Fp]
type baseEl = emulated.Element[BLS12381Fp]

type E2 struct {
	A0, A1 baseEl
}

type E6 struct {
	B0, B1, B2 E2
}

type E12 struct {
	C0, C1 E6
}

type ext2 struct {
	fp          *curveF
	nonResidues map[int]map[int]*E2
}

func NewExt2(baseField *curveF) *ext2 {
	pwrs := map[int]map[int]struct {
		A0 string
		A1 string
	}{
		0: {
			-1: {"2001204777610833696708894912867952078278441409969503942666029068062015825245418932221343814564507832018947136279894", "0"},
			1:  {"1", "1"},
		},
		1: {
			1: {"3850754370037169011952147076051364057158807420970682438676050522613628423219637725072182697113062777891589506424760", "151655185184498381465642749684540099398075398968325446656007613510403227271200139370504932015952886146304766135027"},
			2: {"0", "4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436"},
			3: {"1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257", "1028732146235106349975324479215795277384839936929757896155643118032610843298655225875571310552543014690878354869257"},
			4: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437", "0"},
			5: {"877076961050607968509681729531255177986764537961432449499635504522207616027455086505066378536590128544573588734230", "3125332594171059424908108096204648978570118281977575435832422631601824034463382777937621250592425535493320683825557"},
		},
		2: {
			1: {"793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620351", "0"},
			2: {"793479390729215512621379701633421447060886740281060493010456487427281649075476305620758731620350", "0"},
			3: {"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559786", "0"},
			4: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436", "0"},
			5: {"4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939437", "0"},
		},
	}
	nonResidues := make(map[int]map[int]*E2)
	for pwr, v := range pwrs {
		for coeff, v := range v {
			el := E2{emulated.ValueOf[BLS12381Fp](v.A0), emulated.ValueOf[BLS12381Fp](v.A1)}
			if nonResidues[pwr] == nil {
				nonResidues[pwr] = make(map[int]*E2)
			}
			nonResidues[pwr][coeff] = &el
		}
	}
	return &ext2{fp: baseField, nonResidues: nonResidues}
}

type ext6 struct {
	*ext2
}

func NewExt6(baseField *curveF) *ext6 {
	return &ext6{ext2: NewExt2(baseField)}
}

type ext12 struct {
	*ext6
}

func NewExt12(baseField *curveF) *ext12 {
	return &ext12{ext6: NewExt6(baseField)}
}

// TODO: check where to use Mod and where ModMul.
func (e ext2) MulByElement(x *E2, y *baseEl) *E2 {
	// var yCopy fp.Element
	// yCopy.Set(y)
	z0 := e.fp.MulMod(&x.A0, y) // z.A0.Mul(&x.A0, &yCopy)
	z1 := e.fp.MulMod(&x.A1, y) // z.A1.Mul(&x.A1, &yCopy)
	return &E2{                 // return z
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) Conjugate(x *E2) *E2 {
	z0 := x.A0            // z.A0 = x.A0
	z1 := e.fp.Neg(&x.A1) // z.A1.Neg(&x.A1)
	return &E2{           // return z
		A0: z0,
		A1: *z1,
	}
}

func (e ext2) mulByNonResidue(x *E2, power, coef int) *E2 {
	y := e.nonResidues[power][coef]
	z := e.Mul(x, y)
	return z
}

// MulByNonResidue multiplies a E2 by (1,1)
func (e ext2) MulByNonResidue(x *E2) *E2 {

	// below is the direct transliteration of the gnark-crypto code. Now only,
	// for simplicity and debugging purposes, we do the non residue operations
	// without optimisations.

	/*
		//var a fp.Element
		a := e.fp.Sub(&x.A0, &x.A1)  //a.Sub(&x.A0, &x.A1)
		z1 := e.fp.Add(&x.A0, &x.A1) //z.A1.Add(&x.A0, &x.A1)
		z0 := a                      //z.A0.Set(&a)
		return &E2{
			A0: *z0,
			A1: *z1,
		} // return z
	*/
	// TODO: inline non-residue multiplication
	return e.mulByNonResidue(x, 0, 1)
}

func (e ext2) MulByNonResidueInv(x *E2) *E2 {
	z0 := e.fp.Add(&x.A0, &x.A1)
	z1 := e.fp.Sub(&x.A1, &x.A0)
	return e.mulByNonResidue(&E2{
		A0: *z0,
		A1: *z1,
	}, 0, -1)
}

func (e ext2) MulByNonResidue1Power1(x *E2) *E2 {
	return e.mulByNonResidue(x, 1, 1)
}

func (e ext2) MulByNonResidue1Power2(x *E2) *E2 {
	return e.mulByNonResidue(x, 1, 2)
}

func (e ext2) MulByNonResidue1Power3(x *E2) *E2 {
	return e.mulByNonResidue(x, 1, 3)
}

func (e ext2) MulByNonResidue1Power4(x *E2) *E2 {
	return e.mulByNonResidue(x, 1, 4)
}

func (e ext2) MulByNonResidue1Power5(x *E2) *E2 {
	return e.mulByNonResidue(x, 1, 5)
}

func (e ext2) MulByNonResidue2Power1(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidue(x, 2, 1)
}
func (e ext2) MulByNonResidue2Power2(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidue(x, 2, 2)
}

func (e ext2) MulByNonResidue2Power3(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidue(x, 2, 3)
}

func (e ext2) MulByNonResidue2Power4(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidue(x, 2, 4)
}

func (e ext2) MulByNonResidue2Power5(x *E2) *E2 {
	// TODO: A1 is 0, we can optimize for it
	return e.mulByNonResidue(x, 2, 5)
}

func (e ext2) Mul(x, y *E2) *E2 {
	// var a, b, c fp.Element
	a := e.fp.Add(&x.A0, &x.A1)    // a.Add(&x.A0, &x.A1)
	b := e.fp.Add(&y.A0, &y.A1)    // b.Add(&y.A0, &y.A1)
	a = e.fp.MulMod(a, b)          // a.Mul(&a, &b)
	b = e.fp.MulMod(&x.A0, &y.A0)  // b.Mul(&x.A0, &y.A0)
	c := e.fp.MulMod(&x.A1, &y.A1) // c.Mul(&x.A1, &y.A1)
	z1 := e.fp.Sub(a, b)           // z.A1.Sub(&a, &b).
	z1 = e.fp.Sub(z1, c)           //   Sub(&z.A1, &c)
	z0 := e.fp.Sub(b, c)           // z.A0.Sub(&b, &c)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) Add(x, y *E2) *E2 {
	z0 := e.fp.Add(&x.A0, &y.A0) // z.A0.Add(&x.A0, &y.A0)
	z1 := e.fp.Add(&x.A1, &y.A1) // z.A1.Add(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) Select(selector frontend.Variable, x, y *E2) *E2 {
	z0 := e.fp.Select(selector, &x.A0, &y.A0) // z.A0.Add(&x.A0, &y.A0)
	z1 := e.fp.Select(selector, &x.A1, &y.A1) // z.A1.Add(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) Sub(x, y *E2) *E2 {
	z0 := e.fp.Sub(&x.A0, &y.A0) // z.A0.Sub(&x.A0, &y.A0)
	z1 := e.fp.Sub(&x.A1, &y.A1) // z.A1.Sub(&x.A1, &y.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) Neg(x *E2) *E2 {
	z0 := e.fp.Neg(&x.A0) // z.A0.Neg(&x.A0)
	z1 := e.fp.Neg(&x.A1) // z.A1.Neg(&x.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) One() *E2 {
	z0 := e.fp.One()  // z.A0.SetOne()
	z1 := e.fp.Zero() // z.A1.SetZero()
	return &E2{       // return z
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) Zero() *E2 {
	z0 := e.fp.Zero()
	z1 := e.fp.Zero()
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) Square(x *E2) *E2 {
	// var a, b fp.Element
	a := e.fp.Add(&x.A0, &x.A1)         // a.Add(&x.A0, &x.A1)
	b := e.fp.Sub(&x.A0, &x.A1)         // b.Sub(&x.A0, &x.A1)
	a = e.fp.MulMod(a, b)               // a.Mul(&a, &b)
	b = e.fp.MulMod(&x.A0, &x.A1)       // b.Mul(&x.A0, &x.A1).
	b = e.fp.MulConst(b, big.NewInt(2)) //   Double(&b)

	return &E2{
		A0: *a,
		A1: *b,
	}
	//z.A0.Set(&a)
	//z.A1.Set(&b)
}

func (e ext2) Div(x *E2, y *E2) *E2 {
	//var r E2
	r := e.Inverse(y) //r.Inverse(y)
	r = e.Mul(x, r)   //.Mul(x, &r)

	return r
}

func (e ext2) Double(x *E2) *E2 {
	two := big.NewInt(2)
	z0 := e.fp.MulConst(&x.A0, two) // z.A0.Double(&x.A0)
	z1 := e.fp.MulConst(&x.A1, two) // z.A1.Double(&x.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) Halve(x *E2) *E2 {
	// I'm trying to avoid hard-coding modulus here in case want to make generic
	// for different curves.
	// TODO: if implemented Half in field emulation, then replace with it.
	one := e.fp.One()
	two := e.fp.MulConst(one, big.NewInt(2))
	z0 := e.fp.Div(&x.A0, two)
	z1 := e.fp.Div(&x.A1, two)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) MulBybTwistCurveCoeff(x *E2) *E2 {

	//var res E2
	a0 := e.fp.Sub(&x.A0, &x.A1) //	res.A0.Sub(&x.A0, &x.A1)
	a1 := e.fp.Add(&x.A0, &x.A1) //	res.A1.Add(&x.A0, &x.A1)

	res := &E2{
		A0: *a0,
		A1: *a1,
	}
	z := e.Double(res) //	z.Double(&res).
	z = e.Double(z)    //		Double(z)
	return z
}

func (e ext2) Inverse(x *E2) *E2 {
	// var t0, t1 fp.Element
	t0 := e.fp.MulMod(&x.A0, &x.A0) // t0.Square(&x.A0)
	t1 := e.fp.MulMod(&x.A1, &x.A1) // t1.Square(&x.A1)
	t0 = e.fp.Add(t0, t1)           // t0.Add(&t0, &t1)
	t1 = e.fp.Inverse(t0)           // t1.Inverse(&t0)
	z0 := e.fp.MulMod(&x.A0, t1)    // z.A0.Mul(&x.A0, &t1)
	z1 := e.fp.MulMod(&x.A1, t1)    // z.A1.Mul(&x.A1, &t1).
	z1 = e.fp.Neg(z1)               //   Neg(&z.A1)
	return &E2{
		A0: *z0,
		A1: *z1,
	}
}

func (e ext2) AssertIsEqual(x, y *E2) {
	e.fp.AssertIsEqual(&x.A0, &y.A0)
	e.fp.AssertIsEqual(&x.A1, &y.A1)
}

func (e ext6) Add(x, y *E6) *E6 {
	z0 := e.ext2.Add(&x.B0, &y.B0) // z.B0.Add(&x.B0, &y.B0)
	z1 := e.ext2.Add(&x.B1, &y.B1) // z.B1.Add(&x.B1, &y.B1)
	z2 := e.ext2.Add(&x.B2, &y.B2) // z.B2.Add(&x.B2, &y.B2)
	return &E6{                    // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) Neg(x *E6) *E6 {
	z0 := e.ext2.Neg(&x.B0) // z.B0.Neg(&x.B0)
	z1 := e.ext2.Neg(&x.B1) // z.B1.Neg(&x.B1)
	z2 := e.ext2.Neg(&x.B2) // z.B2.Neg(&x.B2)
	return &E6{             // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) Sub(x, y *E6) *E6 {
	z0 := e.ext2.Sub(&x.B0, &y.B0) // z.B0.Sub(&x.B0, &y.B0)
	z1 := e.ext2.Sub(&x.B1, &y.B1) // z.B1.Sub(&x.B1, &y.B1)
	z2 := e.ext2.Sub(&x.B2, &y.B2) // z.B2.Sub(&x.B2, &y.B2)
	return &E6{                    // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) Mul(x, y *E6) *E6 {
	// var t0, t1, t2, c0, c1, c2, tmp E2
	t0 := e.ext2.Mul(&x.B0, &y.B0)   // t0.Mul(&x.B0, &y.B0)
	t1 := e.ext2.Mul(&x.B1, &y.B1)   // t1.Mul(&x.B1, &y.B1)
	t2 := e.ext2.Mul(&x.B2, &y.B2)   // t2.Mul(&x.B2, &y.B2)
	c0 := e.ext2.Add(&x.B1, &x.B2)   // c0.Add(&x.B1, &x.B2)
	tmp := e.ext2.Add(&y.B1, &y.B2)  // tmp.Add(&y.B1, &y.B2)
	c0 = e.ext2.Mul(c0, tmp)         // c0.Mul(&c0, &tmp).
	c0 = e.ext2.Sub(c0, t1)          // 	Sub(&c0, &t1).
	c0 = e.ext2.Sub(c0, t2)          // 	Sub(&c0, &t2).
	c0 = e.ext2.MulByNonResidue(c0)  // 	MulByNonResidue(&c0).
	c0 = e.ext2.Add(c0, t0)          // 	Add(&c0, &t0)
	c1 := e.ext2.Add(&x.B0, &x.B1)   // c1.Add(&x.B0, &x.B1)
	tmp = e.ext2.Add(&y.B0, &y.B1)   // tmp.Add(&y.B0, &y.B1)
	c1 = e.ext2.Mul(c1, tmp)         // c1.Mul(&c1, &tmp).
	c1 = e.ext2.Sub(c1, t0)          // 	Sub(&c1, &t0).
	c1 = e.ext2.Sub(c1, t1)          // 	Sub(&c1, &t1)
	tmp = e.ext2.MulByNonResidue(t2) // tmp.MulByNonResidue(&t2)
	c1 = e.ext2.Add(c1, tmp)         // c1.Add(&c1, &tmp)
	tmp = e.ext2.Add(&x.B0, &x.B2)   // tmp.Add(&x.B0, &x.B2)
	c2 := e.ext2.Add(&y.B0, &y.B2)   // c2.Add(&y.B0, &y.B2).
	c2 = e.ext2.Mul(c2, tmp)         // 	Mul(&c2, &tmp).
	c2 = e.ext2.Sub(c2, t0)          // 	Sub(&c2, &t0).
	c2 = e.ext2.Sub(c2, t2)          // 	Sub(&c2, &t2).
	c2 = e.ext2.Add(c2, t1)          // 	Add(&c2, &t1)
	return &E6{
		B0: *c0, // z.B0.Set(&c0)
		B1: *c1, // z.B1.Set(&c1)
		B2: *c2, // z.B2.Set(&c2)
	} // return z
}

func (e ext6) Double(x *E6) *E6 {
	z0 := e.ext2.Double(&x.B0) // z.B0.Double(&x.B0)
	z1 := e.ext2.Double(&x.B1) // z.B1.Double(&x.B1)
	z2 := e.ext2.Double(&x.B2) // z.B2.Double(&x.B2)
	return &E6{                // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) Square(x *E6) *E6 {
	// var c4, c5, c1, c2, c3, c0 E2
	c4 := e.ext2.Mul(&x.B0, &x.B1)   // c4.Mul(&x.B0, &x.B1).
	c4 = e.ext2.Double(c4)           // 	Double(&c4)
	c5 := e.ext2.Square(&x.B2)       // c5.Square(&x.B2)
	c1 := e.ext2.MulByNonResidue(c5) // c1.MulByNonResidue(&c5).
	c1 = e.ext2.Add(c1, c4)          // 	Add(&c1, &c4)
	c2 := e.ext2.Sub(c4, c5)         // c2.Sub(&c4, &c5)
	c3 := e.ext2.Square(&x.B0)       // c3.Square(&x.B0)
	c4 = e.ext2.Sub(&x.B0, &x.B1)    // c4.Sub(&x.B0, &x.B1).
	c4 = e.ext2.Add(c4, &x.B2)       // 	Add(&c4, &x.B2)
	c5 = e.ext2.Mul(&x.B1, &x.B2)    // c5.Mul(&x.B1, &x.B2).
	c5 = e.ext2.Double(c5)           // 	Double(&c5)
	c4 = e.ext2.Square(c4)           // c4.Square(&c4)
	c0 := e.ext2.MulByNonResidue(c5) // c0.MulByNonResidue(&c5).
	c0 = e.ext2.Add(c0, c3)          // 	Add(&c0, &c3)
	z2 := e.ext2.Add(c2, c4)         // z.B2.Add(&c2, &c4).
	z2 = e.ext2.Add(z2, c5)          // 	Add(&z.B2, &c5).
	z2 = e.ext2.Sub(z2, c3)          // 	Sub(&z.B2, &c3)
	z0 := c0                         // z.B0.Set(&c0)
	z1 := c1                         // z.B1.Set(&c1)
	return &E6{                      // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) Inverse(x *E6) *E6 {
	// var t0, t1, t2, t3, t4, t5, t6, c0, c1, c2, d1, d2 E2
	t0 := e.ext2.Square(&x.B0)       // t0.Square(&x.B0)
	t1 := e.ext2.Square(&x.B1)       // t1.Square(&x.B1)
	t2 := e.ext2.Square(&x.B2)       // t2.Square(&x.B2)
	t3 := e.ext2.Mul(&x.B0, &x.B1)   // t3.Mul(&x.B0, &x.B1)
	t4 := e.ext2.Mul(&x.B0, &x.B2)   // t4.Mul(&x.B0, &x.B2)
	t5 := e.ext2.Mul(&x.B1, &x.B2)   // t5.Mul(&x.B1, &x.B2)
	c0 := e.ext2.MulByNonResidue(t5) // c0.MulByNonResidue(&t5).
	c0 = e.ext2.Neg(c0)              //    Neg(&c0).
	c0 = e.ext2.Add(c0, t0)          //    Add(&c0, &t0)
	c1 := e.ext2.MulByNonResidue(t2) // c1.MulByNonResidue(&t2).
	c1 = e.ext2.Sub(c1, t3)          //    Sub(&c1, &t3)
	c2 := e.ext2.Sub(t1, t4)         // c2.Sub(&t1, &t4)
	t6 := e.ext2.Mul(&x.B0, c0)      // t6.Mul(&x.B0, &c0)
	d1 := e.ext2.Mul(&x.B2, c1)      // d1.Mul(&x.B2, &c1)
	d2 := e.ext2.Mul(&x.B1, c2)      // d2.Mul(&x.B1, &c2)
	d1 = e.ext2.Add(d1, d2)          // d1.Add(&d1, &d2).
	d1 = e.ext2.MulByNonResidue(d1)  //    MulByNonResidue(&d1)
	t6 = e.ext2.Add(t6, d1)          // t6.Add(&t6, &d1)
	t6 = e.ext2.Inverse(t6)          // t6.Inverse(&t6)
	z0 := e.ext2.Mul(c0, t6)         // z.B0.Mul(&c0, &t6)
	z1 := e.ext2.Mul(c1, t6)         // z.B1.Mul(&c1, &t6)
	z2 := e.ext2.Mul(c2, t6)         // z.B2.Mul(&c2, &t6)
	return &E6{                      // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}
func (e ext6) MulByE2(x *E6, y *E2) *E6 {
	// var yCopy E2
	// yCopy.Set(y)
	z0 := e.ext2.Mul(&x.B0, y) // z.B0.Mul(&x.B0, &yCopy)
	z1 := e.ext2.Mul(&x.B1, y) // z.B1.Mul(&x.B1, &yCopy)
	z2 := e.ext2.Mul(&x.B2, y) // z.B2.Mul(&x.B2, &yCopy)
	return &E6{                // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) MulBy1(z *E6, c1 *E2) *E6 {
	//var b, tmp, t0, t1 E2
	b := e.ext2.Mul(&z.B1, c1) //b.Mul(&z.B1, c1)

	tmp := e.ext2.Add(&z.B1, &z.B2) //tmp.Add(&z.B1, &z.B2)
	t0 := e.ext2.Mul(c1, tmp)       //t0.Mul(c1, &tmp)
	t0 = e.ext2.Sub(t0, b)          //t0.Sub(&t0, &b)
	t0 = e.ext2.MulByNonResidue(t0) //t0.MulByNonResidue(&t0)

	tmp = e.ext2.Add(&z.B0, &z.B1) //tmp.Add(&z.B0, &z.B1)
	t1 := e.ext2.Mul(c1, tmp)      //t1.Mul(c1, &tmp)
	t1 = e.ext2.Sub(t1, b)         //t1.Sub(&t1, &b)

	z0 := t0
	z1 := t1
	z2 := b

	return &E6{
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) MulBy01(z *E6, c0, c1 *E2) *E6 {
	// var a, b, tmp, t0, t1, t2 E2
	a := e.ext2.Mul(&z.B0, c0)      // a.Mul(&z.B0, c0)
	b := e.ext2.Mul(&z.B1, c1)      // b.Mul(&z.B1, c1)
	tmp := e.ext2.Add(&z.B1, &z.B2) // tmp.Add(&z.B1, &z.B2)
	t0 := e.ext2.Mul(c1, tmp)       // t0.Mul(c1, &tmp)
	t0 = e.ext2.Sub(t0, b)          // t0.Sub(&t0, &b)
	t0 = e.ext2.MulByNonResidue(t0) // t0.MulByNonResidue(&t0)
	t0 = e.ext2.Add(t0, a)          // t0.Add(&t0, &a)
	tmp = e.ext2.Add(&z.B0, &z.B2)  // tmp.Add(&z.B0, &z.B2)
	t2 := e.ext2.Mul(c0, tmp)       // t2.Mul(c0, &tmp)
	t2 = e.ext2.Sub(t2, a)          // t2.Sub(&t2, &a)
	t2 = e.ext2.Add(t2, b)          // t2.Add(&t2, &b)
	t1 := e.ext2.Add(c0, c1)        // t1.Add(c0, c1)
	tmp = e.ext2.Add(&z.B0, &z.B1)  // tmp.Add(&z.B0, &z.B1)
	t1 = e.ext2.Mul(t1, tmp)        // t1.Mul(&t1, &tmp)
	t1 = e.ext2.Sub(t1, a)          // t1.Sub(&t1, &a)
	t1 = e.ext2.Sub(t1, b)          // t1.Sub(&t1, &b)
	return &E6{
		B0: *t0, // z.B0.Set(&t0)
		B1: *t1, // z.B1.Set(&t1)
		B2: *t2, // z.B2.Set(&t2)
	} // return z
}

func (e ext6) MulByNonResidue(x *E6) *E6 {
	z2, z1, z0 := &x.B1, &x.B0, &x.B2 // z.B2, z.B1, z.B0 = x.B1, x.B0, x.B2
	z0 = e.ext2.MulByNonResidue(z0)   // z.B0.MulByNonResidue(&z.B0)
	return &E6{                       // return z
		B0: *z0,
		B1: *z1,
		B2: *z2,
	}
}

func (e ext6) AssertIsEqual(x, y *E6) {
	e.ext2.AssertIsEqual(&x.B0, &y.B0)
	e.ext2.AssertIsEqual(&x.B1, &y.B1)
	e.ext2.AssertIsEqual(&x.B2, &y.B2)
}

func (e ext12) Conjugate(x *E12) *E12 {
	z1 := e.ext6.Neg(&x.C1) // z.C1.Neg(&z.C1)
	return &E12{            // return z
		C0: x.C0,
		C1: *z1,
	}
}

func (e ext12) Inverse(x *E12) *E12 {
	// var t0, t1, tmp E6
	t0 := e.ext6.Square(&x.C0)        // t0.Square(&x.C0)
	t1 := e.ext6.Square(&x.C1)        // t1.Square(&x.C1)
	tmp := e.ext6.MulByNonResidue(t1) // tmp.MulByNonResidue(&t1)
	t0 = e.ext6.Sub(t0, tmp)          // t0.Sub(&t0, &tmp)
	t1 = e.ext6.Inverse(t0)           // t1.Inverse(&t0)
	z0 := e.ext6.Mul(&x.C0, t1)       // z.C0.Mul(&x.C0, &t1)
	z1 := e.ext6.Mul(&x.C1, t1)       // z.C1.Mul(&x.C1, &t1).
	z1 = e.ext6.Neg(z1)               //      Neg(&z.C1)
	return &E12{                      // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e ext12) Mul(x, y *E12) *E12 {
	// var a, b, c E6
	a := e.ext6.Add(&x.C0, &x.C1)   // a.Add(&x.C0, &x.C1)
	b := e.ext6.Add(&y.C0, &y.C1)   // b.Add(&y.C0, &y.C1)
	a = e.ext6.Mul(a, b)            // a.Mul(&a, &b)
	b = e.ext6.Mul(&x.C0, &y.C0)    // b.Mul(&x.C0, &y.C0)
	c := e.ext6.Mul(&x.C1, &y.C1)   // c.Mul(&x.C1, &y.C1)
	z1 := e.ext6.Sub(a, b)          // z.C1.Sub(&a, &b).
	z1 = e.ext6.Sub(z1, c)          //      Sub(&z.C1, &c)
	z0 := e.ext6.MulByNonResidue(c) // z.C0.MulByNonResidue(&c).
	z0 = e.ext6.Add(z0, b)          //      Add(&z.C0, &b)
	return &E12{                    // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e ext12) CyclotomicSquare(x *E12) *E12 {
	// var t [9]E2
	t0 := e.ext2.Square(&x.C1.B1)        // t[0].Square(&x.C1.B1)
	t1 := e.ext2.Square(&x.C0.B0)        // t[1].Square(&x.C0.B0)
	t6 := e.ext2.Add(&x.C1.B1, &x.C0.B0) // t[6].Add(&x.C1.B1, &x.C0.B0).
	t6 = e.ext2.Square(t6)               // 	Square(&t[6]).
	t6 = e.ext2.Sub(t6, t0)              // 	Sub(&t[6], &t[0]).
	t6 = e.ext2.Sub(t6, t1)              // 	Sub(&t[6], &t[1])
	t2 := e.ext2.Square(&x.C0.B2)        // t[2].Square(&x.C0.B2)
	t3 := e.ext2.Square(&x.C1.B0)        // t[3].Square(&x.C1.B0)
	t7 := e.ext2.Add(&x.C0.B2, &x.C1.B0) // t[7].Add(&x.C0.B2, &x.C1.B0).
	t7 = e.ext2.Square(t7)               // 	Square(&t[7]).
	t7 = e.ext2.Sub(t7, t2)              // 	Sub(&t[7], &t[2]).
	t7 = e.ext2.Sub(t7, t3)              // 	Sub(&t[7], &t[3])
	t4 := e.ext2.Square(&x.C1.B2)        // t[4].Square(&x.C1.B2)
	t5 := e.ext2.Square(&x.C0.B1)        // t[5].Square(&x.C0.B1)
	t8 := e.ext2.Add(&x.C1.B2, &x.C0.B1) // t[8].Add(&x.C1.B2, &x.C0.B1).
	t8 = e.ext2.Square(t8)               // 	Square(&t[8]).
	t8 = e.ext2.Sub(t8, t4)              // 	Sub(&t[8], &t[4]).
	t8 = e.ext2.Sub(t8, t5)              // 	Sub(&t[8], &t[5]).
	t8 = e.ext2.MulByNonResidue(t8)      // 	MulByNonResidue(&t[8])
	t0 = e.ext2.MulByNonResidue(t0)      // t[0].MulByNonResidue(&t[0]).
	t0 = e.ext2.Add(t0, t1)              // 	Add(&t[0], &t[1])
	t2 = e.ext2.MulByNonResidue(t2)      // t[2].MulByNonResidue(&t[2]).
	t2 = e.ext2.Add(t2, t3)              // 	Add(&t[2], &t[3])
	t4 = e.ext2.MulByNonResidue(t4)      // t[4].MulByNonResidue(&t[4]).
	t4 = e.ext2.Add(t4, t5)              // 	Add(&t[4], &t[5])
	z00 := e.ext2.Sub(t0, &x.C0.B0)      // z.C0.B0.Sub(&t[0], &x.C0.B0).
	z00 = e.ext2.Double(z00)             // 	Double(&z.C0.B0).
	z00 = e.ext2.Add(z00, t0)            // 	Add(&z.C0.B0, &t[0])
	z01 := e.ext2.Sub(t2, &x.C0.B1)      // z.C0.B1.Sub(&t[2], &x.C0.B1).
	z01 = e.ext2.Double(z01)             // 	Double(&z.C0.B1).
	z01 = e.ext2.Add(z01, t2)            // 	Add(&z.C0.B1, &t[2])
	z02 := e.ext2.Sub(t4, &x.C0.B2)      // z.C0.B2.Sub(&t[4], &x.C0.B2).
	z02 = e.ext2.Double(z02)             // 	Double(&z.C0.B2).
	z02 = e.ext2.Add(z02, t4)            // 	Add(&z.C0.B2, &t[4])
	z10 := e.ext2.Add(t8, &x.C1.B0)      // z.C1.B0.Add(&t[8], &x.C1.B0).
	z10 = e.ext2.Double(z10)             // 	Double(&z.C1.B0).
	z10 = e.ext2.Add(z10, t8)            // 	Add(&z.C1.B0, &t[8])
	z11 := e.ext2.Add(t6, &x.C1.B1)      // z.C1.B1.Add(&t[6], &x.C1.B1).
	z11 = e.ext2.Double(z11)             // 	Double(&z.C1.B1).
	z11 = e.ext2.Add(z11, t6)            // 	Add(&z.C1.B1, &t[6])
	z12 := e.ext2.Add(t7, &x.C1.B2)      // z.C1.B2.Add(&t[7], &x.C1.B2).
	z12 = e.ext2.Double(z12)             // 	Double(&z.C1.B2).
	z12 = e.ext2.Add(z12, t7)            // 	Add(&z.C1.B2, &t[7])
	return &E12{                         // return z
		C0: E6{
			B0: *z00,
			B1: *z01,
			B2: *z02,
		},
		C1: E6{
			B0: *z10,
			B1: *z11,
			B2: *z12,
		},
	}
}

func (e ext12) Frobenius(x *E12) *E12 {
	// var t [6]E2
	t0 := e.ext2.Conjugate(&x.C0.B0)       // t[0].Conjugate(&x.C0.B0)
	t1 := e.ext2.Conjugate(&x.C0.B1)       // t[1].Conjugate(&x.C0.B1)
	t2 := e.ext2.Conjugate(&x.C0.B2)       // t[2].Conjugate(&x.C0.B2)
	t3 := e.ext2.Conjugate(&x.C1.B0)       // t[3].Conjugate(&x.C1.B0)
	t4 := e.ext2.Conjugate(&x.C1.B1)       // t[4].Conjugate(&x.C1.B1)
	t5 := e.ext2.Conjugate(&x.C1.B2)       // t[5].Conjugate(&x.C1.B2)
	t1 = e.ext2.MulByNonResidue1Power2(t1) // t[1].MulByNonResidue1Power2(&t[1])
	t2 = e.ext2.MulByNonResidue1Power4(t2) // t[2].MulByNonResidue1Power4(&t[2])
	t3 = e.ext2.MulByNonResidue1Power1(t3) // t[3].MulByNonResidue1Power1(&t[3])
	t4 = e.ext2.MulByNonResidue1Power3(t4) // t[4].MulByNonResidue1Power3(&t[4])
	t5 = e.ext2.MulByNonResidue1Power5(t5) // t[5].MulByNonResidue1Power5(&t[5])
	return &E12{                           // return z
		C0: E6{
			B0: *t0, // z.C0.B0 = t[0]
			B1: *t1, // z.C0.B1 = t[1]
			B2: *t2, // z.C0.B2 = t[2]
		},
		C1: E6{
			B0: *t3, // z.C1.B0 = t[3]
			B1: *t4, // z.C1.B1 = t[4]
			B2: *t5, // z.C1.B2 = t[5]
		},
	}
}

func (e ext12) FrobeniusSquare(x *E12) *E12 {
	z00 := &x.C0.B0                                // z.C0.B0 = x.C0.B0
	z01 := e.ext2.MulByNonResidue2Power2(&x.C0.B1) // z.C0.B1.MulByNonResidue2Power2(&x.C0.B1)
	z02 := e.ext2.MulByNonResidue2Power4(&x.C0.B2) // z.C0.B2.MulByNonResidue2Power4(&x.C0.B2)
	z10 := e.ext2.MulByNonResidue2Power1(&x.C1.B0) // z.C1.B0.MulByNonResidue2Power1(&x.C1.B0)
	z11 := e.ext2.MulByNonResidue2Power3(&x.C1.B1) // z.C1.B1.MulByNonResidue2Power3(&x.C1.B1)
	z12 := e.ext2.MulByNonResidue2Power5(&x.C1.B2) // z.C1.B2.MulByNonResidue2Power5(&x.C1.B2)
	return &E12{                                   // return z
		C0: E6{B0: *z00, B1: *z01, B2: *z02},
		C1: E6{B0: *z10, B1: *z11, B2: *z12},
	}
}

func (e ext12) FrobeniusCube(x *E12) *E12 {
	// var t [6]E2
	t0 := e.ext2.Conjugate(&x.C0.B0)       // t[0].Conjugate(&x.C0.B0)
	t1 := e.ext2.Conjugate(&x.C0.B1)       // t[1].Conjugate(&x.C0.B1)
	t2 := e.ext2.Conjugate(&x.C0.B2)       // t[2].Conjugate(&x.C0.B2)
	t3 := e.ext2.Conjugate(&x.C1.B0)       // t[3].Conjugate(&x.C1.B0)
	t4 := e.ext2.Conjugate(&x.C1.B1)       // t[4].Conjugate(&x.C1.B1)
	t5 := e.ext2.Conjugate(&x.C1.B2)       // t[5].Conjugate(&x.C1.B2)
	t1 = e.ext2.MulByNonResidue1Power2(t1) // t[1].MulByNonResidue3Power2(&t[1])
	t2 = e.ext2.MulByNonResidue1Power4(t2) // t[2].MulByNonResidue3Power4(&t[2])
	t3 = e.ext2.MulByNonResidue1Power1(t3) // t[3].MulByNonResidue3Power1(&t[3])
	t4 = e.ext2.MulByNonResidue1Power3(t4) // t[4].MulByNonResidue3Power3(&t[4])
	t5 = e.ext2.MulByNonResidue1Power5(t5) // t[5].MulByNonResidue3Power5(&t[5])
	return &E12{                           // return z
		C0: E6{
			B0: *t0, // z.C0.B0 = t[0]
			B1: *t1, // z.C0.B1 = t[1]
			B2: *t2, // z.C0.B2 = t[2]
		},
		C1: E6{
			B0: *t3, // z.C1.B0 = t[3]
			B1: *t4, // z.C1.B1 = t[4]
			B2: *t5, // z.C1.B2 = t[5]
		},
	}
}

func (e ext12) DecompressKarabina(x E12) *E12 {

	one := e.ext2.One()

	// TODO: add iszero handle

	t0 := e.ext2.Square(&x.C0.B1) //t0[i].Square(&x[i].C0.B1)
	// t1 = 3 * g1^2 - 2 * g2
	t1 := e.ext2.Sub(t0, &x.C0.B2) //			t1[i].Sub(&t0[i], &x[i].C0.B2).
	t1 = e.ext2.Double(t1)         //				Double(&t1[i]).
	t1 = e.ext2.Add(t1, t0)        //				Add(&t1[i], &t0[i])
	//			// t0 = E * g5^2 + t1
	t2 := e.ext2.Square(&x.C1.B2)   //			t2[i].Square(&x[i].C1.B2)
	t0 = e.ext2.MulByNonResidue(t2) //			t0[i].MulByNonResidue(&t2[i]).
	t0 = e.ext2.Add(t0, t1)         //				Add(&t0[i], &t1[i])
	//			// t1 = 4 * g3
	t1 = e.ext2.Double(&x.C1.B0) //			t1[i].Double(&x[i].C1.B0).
	t1 = e.ext2.Double(t1)       //				Double(&t1[i])

	// z4 = g4
	zc11 := e.ext2.Div(t0, t1) //	z.C1.B1.Div(&t[0], &t[1]) // costly

	//	// t1 = g2 * g1
	t1 = e.ext2.Mul(&x.C0.B2, &x.C0.B1) //	t[1].Mul(&x.C0.B2, &x.C0.B1)
	// t2 = 2 * g4^2 - 3 * g2 * g1
	t2 = e.ext2.Square(zc11) //	t[2].Square(&z.C1.B1).
	t2 = e.ext2.Sub(t2, t1)  //		Sub(&t[2], &t[1]).
	t2 = e.ext2.Double(t2)   //		Double(&t[2]).
	t2 = e.ext2.Sub(t2, t1)  //		Sub(&t[2], &t[1])
	// t1 = g3 * g5 (g3 can be 0)
	t1 = e.ext2.Mul(&x.C1.B0, &x.C1.B2) //t[1].Mul(&x.C1.B0, &x.C1.B2)
	// c_0 = E * (2 * g4^2 + g3 * g5 - 3 * g2 * g1) + 1
	t2 = e.ext2.Add(t2, t1)           //	t[2].Add(&t[2], &t[1])
	z00 := e.ext2.MulByNonResidue(t2) //	z.C0.B0.MulByNonResidue(&t[2]).
	z00 = e.ext2.Add(z00, one)        //		Add(&z.C0.B0, &one)

	return &E12{
		E6{
			B0: *z00,
			B1: x.C0.B1,
			B2: x.C0.B2,
		},
		E6{
			B0: x.C1.B0,
			B1: *zc11,
			B2: x.C1.B2,
		},
	}
}

func (e ext12) ExptHalf(x *E12) *E12 {
	//	var result E12
	//	var t [2]E12
	result := &E12{
		C0: x.C0,
		C1: x.C1,
	} //	result.Set(x)

	result = e.nSquareCompressed(result, 15) //	result.nSquareCompressed(15)
	t0 := &E12{
		C0: result.C0,
		C1: result.C1,
	} //	t[0].Set(&result)
	result = e.nSquareCompressedWithoutAssert(result, 32) //	result.nSquareCompressed(32)
	t1 := &E12{
		C0: result.C0,
		C1: result.C1,
	} //	t[1].Set(&result)

	b0 := e.DecompressKarabina(*t0) //	batch := BatchDecompressKarabina([]E12{t[0], t[1]})
	b1 := e.DecompressKarabina(*t1)

	result = e.Mul(b0, b1)      //	result.Mul(&batch[0], &batch[1])
	b1 = e.nSquare(b1, 9)       //	batch[1].nSquare(9)
	result = e.Mul(result, b1)  //	result.Mul(&result, &batch[1])
	b1 = e.nSquare(b1, 3)       //	batch[1].nSquare(3)
	result = e.Mul(result, b1)  //	result.Mul(&result, &batch[1])
	b1 = e.nSquare(b1, 2)       //	batch[1].nSquare(2)
	result = e.Mul(result, b1)  //	result.Mul(&result, &batch[1])
	b1 = e.CyclotomicSquare(b1) //	batch[1].CyclotomicSquare(&batch[1])
	result = e.Mul(result, b1)  //	result.Mul(&result, &batch[1])

	return e.Conjugate(result) // 	return z.Conjugate(&result) // because tAbs
}

func (e ext12) Expt(x *E12) *E12 {
	result := e.ExptHalf(x)
	return e.CyclotomicSquare(result) // return z
}

func (e *ext12) nSquareCompressed(z *E12, n int) *E12 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareCompressed(z, z)
	}
	return z
}

func (e *ext12) nSquareCompressedWithoutAssert(z *E12, n int) *E12 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareCompressed(z, z)
	}
	return z
}

func (e *ext12) CyclotomicSquareCompressed(z, x *E12) *E12 {
	//	var t [7]E2
	t0 := e.ext2.Square(&x.C0.B1)        // t[0].Square(&x.C0.B1)
	t1 := e.ext2.Square(&x.C1.B2)        // t[1].Square(&x.C1.B2)
	t5 := e.ext2.Add(&x.C0.B1, &x.C1.B2) // t[5].Add(&x.C0.B1, &x.C1.B2)
	t2 := e.ext2.Square(t5)              //	t[2].Square(&t[5])
	t3 := e.ext2.Add(t0, t1)             // t[3].Add(&t[0], &t[1])
	t5 = e.ext2.Sub(t2, t3)              // t[5].Sub(&t[2], &t[3])
	t6 := e.ext2.Add(&x.C1.B0, &x.C0.B2) //	t[6].Add(&x.C1.B0, &x.C0.B2)
	t3 = e.ext2.Square(t6)               //	t[3].Square(&t[6])
	t2 = e.ext2.Square(&x.C1.B0)         // t[2].Square(&x.C1.B0)
	t6 = e.ext2.MulByNonResidue(t5)      //	t[6].MulByNonResidue(&t[5])
	t5 = e.ext2.Add(t6, &x.C1.B0)        //	t[5].Add(&t[6], &x.C1.B0).
	t5 = e.ext2.Double(t5)               // Double(&t[5])

	z10 := e.ext2.Add(t5, t6)        // z.C1.B0.Add(&t[5], &t[6])
	t4 := e.ext2.MulByNonResidue(t1) //		t[4].MulByNonResidue(&t[1])
	t5 = e.ext2.Add(t0, t4)          //t[5].Add(&t[0], &t[4])
	t6 = e.ext2.Sub(t5, &x.C0.B2)    //	t[6].Sub(&t[5], &x.C0.B2)
	t1 = e.ext2.Square(&x.C0.B2)     //t[1].Square(&x.C0.B2)
	t6 = e.ext2.Double(t6)           //	t[6].Double(&t[6])
	z02 := e.ext2.Add(t6, t5)        //		z.C0.B2.Add(&t[6], &t[5])
	t4 = e.ext2.MulByNonResidue(t1)  //		t[4].MulByNonResidue(&t[1])
	t5 = e.ext2.Add(t2, t4)          //		t[5].Add(&t[2], &t[4])
	t6 = e.ext2.Sub(t5, &x.C0.B1)    //	t[6].Sub(&t[5], &x.C0.B1)
	t6 = e.ext2.Double(t6)           //		t[6].Double(&t[6])
	z01 := e.ext2.Add(t6, t5)        //		z.C0.B1.Add(&t[6], &t[5])

	t0 = e.ext2.Add(t2, t1)       //	t[0].Add(&t[2], &t[1])
	t5 = e.ext2.Sub(t3, t0)       //	t[5].Sub(&t[3], &t[0])
	t6 = e.ext2.Add(t5, &x.C1.B2) //	t[6].Add(&t[5], &x.C1.B2)

	t6 = e.ext2.Double(t6) //	t[6].Double(&t[6])

	z12 := e.ext2.Add(t5, t6) // 	z.C1.B2.Add(&t[5], &t[6])

	return &E12{
		C0: E6{
			B0: z.C0.B0,
			B1: *z01,
			B2: *z02,
		},
		C1: E6{
			B0: *z10,
			B1: z.C1.B1,
			B2: *z12,
		},
	}

}

func (e ext12) One() *E12 {
	z000 := e.fp.One()
	zero := e.fp.Zero()
	return &E12{
		C0: E6{
			B0: E2{A0: *z000, A1: *zero},
			B1: E2{A0: *zero, A1: *zero},
			B2: E2{A0: *zero, A1: *zero},
		},
		C1: E6{
			B0: E2{A0: *zero, A1: *zero},
			B1: E2{A0: *zero, A1: *zero},
			B2: E2{A0: *zero, A1: *zero},
		},
	}
}

func (e ext12) MulBy034(z *E12, c0, c3, c4 *E2) *E12 {
	// var a, b, d E6
	a := e.ext6.MulByE2(&z.C0, c0) // a.MulByE2(&z.C0, c0)
	// b.Set(&z.C1)
	b := e.ext6.MulBy01(&z.C1, c3, c4) // b.MulBy01(c3, c4)
	c0 = e.ext2.Add(c0, c3)            // c0.Add(c0, c3)
	d := e.ext6.Add(&z.C0, &z.C1)      // d.Add(&z.C0, &z.C1)
	d = e.ext6.MulBy01(d, c0, c4)      // d.MulBy01(c0, c4)
	z1 := e.Add(a, b)                  // z.C1.Add(&a, &b).
	z1 = e.Neg(z1)                     //      Neg(&z.C1).
	z1 = e.Add(z1, d)                  //      Add(&z.C1, &d)
	z0 := e.MulByNonResidue(b)         // z.C0.MulByNonResidue(&b).
	z0 = e.Add(z0, a)                  //      Add(&z.C0, &a)
	return &E12{                       // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e ext12) Square(x *E12) *E12 {
	// var c0, c2, c3 E6
	c0 := e.ext6.Sub(&x.C0, &x.C1)      // c0.Sub(&x.C0, &x.C1)
	c3 := e.ext6.MulByNonResidue(&x.C1) // c3.MulByNonResidue(&x.C1).
	c3 = e.ext6.Neg(c3)                 //    Neg(&c3).
	c3 = e.ext6.Add(&x.C0, c3)          //    Add(&x.C0, &c3)
	c2 := e.ext6.Mul(&x.C0, &x.C1)      // c2.Mul(&x.C0, &x.C1)
	c0 = e.ext6.Mul(c0, c3)             // c0.Mul(&c0, &c3).
	c0 = e.ext6.Add(c0, c2)             //    Add(&c0, &c2)
	z1 := e.ext6.Double(c2)             // z.C1.Double(&c2)
	c2 = e.ext6.MulByNonResidue(c2)     // c2.MulByNonResidue(&c2)
	z0 := e.ext6.Add(c0, c2)            // z.C0.Add(&c0, &c2)
	return &E12{                        // return z
		C0: *z0,
		C1: *z1,
	}
}

func (e ext12) MulBy034by034(d0, d3, d4, c0, c3, c4 *E2) *E12 {
	// var tmp, x0, x3, x4, x04, x03, x34 E2
	x0 := e.ext2.Mul(c0, d0)          // x0.Mul(c0, d0)
	x3 := e.ext2.Mul(c3, d3)          // x3.Mul(c3, d3)
	x4 := e.ext2.Mul(c4, d4)          // x4.Mul(c4, d4)
	tmp := e.ext2.Add(c0, c4)         // tmp.Add(c0, c4)
	x04 := e.ext2.Add(d0, d4)         // x04.Add(d0, d4).
	x04 = e.ext2.Mul(x04, tmp)        // 	Mul(&x04, &tmp).
	x04 = e.ext2.Sub(x04, x0)         // 	Sub(&x04, &x0).
	x04 = e.ext2.Sub(x04, x4)         // 	Sub(&x04, &x4)
	tmp = e.ext2.Add(c0, c3)          // tmp.Add(c0, c3)
	x03 := e.ext2.Add(d0, d3)         // x03.Add(d0, d3).
	x03 = e.ext2.Mul(x03, tmp)        // 	Mul(&x03, &tmp).
	x03 = e.ext2.Sub(x03, x0)         // 	Sub(&x03, &x0).
	x03 = e.ext2.Sub(x03, x3)         // 	Sub(&x03, &x3)
	tmp = e.ext2.Add(c3, c4)          // tmp.Add(c3, c4)
	x34 := e.ext2.Add(d3, d4)         // x34.Add(d3, d4).
	x34 = e.ext2.Mul(x34, tmp)        // 	Mul(&x34, &tmp).
	x34 = e.ext2.Sub(x34, x3)         // 	Sub(&x34, &x3).
	x34 = e.ext2.Sub(x34, x4)         // 	Sub(&x34, &x4)
	z00 := e.ext2.MulByNonResidue(x4) // z.C0.B0.MulByNonResidue(&x4).
	z00 = e.ext2.Add(z00, x0)         // 	Add(&z.C0.B0, &x0)
	z01 := x3                         // z.C0.B1.Set(&x3)
	z02 := x34                        // z.C0.B2.Set(&x34)
	z10 := x03                        // z.C1.B0.Set(&x03)
	z11 := x04                        // z.C1.B1.Set(&x04)
	z12 := e.ext2.Zero()              // z.C1.B2.SetZero()
	return &E12{                      // return z
		C0: E6{
			B0: *z00,
			B1: *z01,
			B2: *z02,
		},
		C1: E6{
			B0: *z10,
			B1: *z11,
			B2: *z12,
		},
	}
}

func (e ext12) AssertIsEqual(x, y *E12) {
	e.ext6.AssertIsEqual(&x.C0, &y.C0)
	e.ext6.AssertIsEqual(&x.C1, &y.C1)
}

func (e ext12) AssertC0IsEqual(x, y *E12) {
	e.ext6.AssertIsEqual(&x.C0, &y.C0)
}

func (e ext12) nSquare(z *E12, n int) *E12 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquare(z)
	}
	return z
}
