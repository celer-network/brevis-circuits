package pairing_bls12381

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	*ext12
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[BLS12381Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		ext12: NewExt12(ba),
	}, nil
}

func (pr Pairing) DoubleStep(p *G2Projective) (*G2Projective, *LineEvaluation) {
	// var t1, A, B, C, D, E, EE, F, G, H, I, J, K fptower.E2
	A := pr.ext2.Mul(&p.X, &p.Y)          // A.Mul(&p.x, &p.y)
	A = pr.ext2.Halve(A)                  // A.Halve()
	B := pr.ext2.Square(&p.Y)             // B.Square(&p.y)
	C := pr.ext2.Square(&p.Z)             // C.Square(&p.z)
	D := pr.ext2.Double(C)                // D.Double(&C).
	D = pr.ext2.Add(D, C)                 // 	Add(&D, &C)
	E := pr.ext2.MulBybTwistCurveCoeff(D) // E.MulBybTwistCurveCoeff(&D)
	F := pr.ext2.Double(E)                // F.Double(&E).
	F = pr.ext2.Add(F, E)                 // 	Add(&F, &E)
	G := pr.ext2.Add(B, F)                // G.Add(&B, &F)
	G = pr.ext2.Halve(G)                  // G.Halve()
	H := pr.ext2.Add(&p.Y, &p.Z)          // H.Add(&p.y, &p.z).
	H = pr.ext2.Square(H)                 // 	Square(&H)
	t1 := pr.ext2.Add(B, C)               // t1.Add(&B, &C)
	H = pr.ext2.Sub(H, t1)                // H.Sub(&H, &t1)
	I := pr.ext2.Sub(E, B)                // I.Sub(&E, &B)
	J := pr.ext2.Square(&p.X)             // J.Square(&p.x)
	EE := pr.ext2.Square(E)               // EE.Square(&E)
	K := pr.ext2.Double(EE)               // K.Double(&EE).
	K = pr.ext2.Add(K, EE)                // 	Add(&K, &EE)
	px := pr.ext2.Sub(B, F)               // p.x.Sub(&B, &F).
	px = pr.ext2.Mul(px, A)               // 	Mul(&p.x, &A)
	py := pr.ext2.Square(G)               // p.y.Square(&G).
	py = pr.ext2.Sub(py, K)               // 	Sub(&p.y, &K)
	pz := pr.ext2.Mul(B, H)               // p.z.Mul(&B, &H)

	lr0 := I                  //	l.r0.Set(&I)
	lr1 := pr.ext2.Double(J)  //	l.r1.Double(&J).
	lr1 = pr.ext2.Add(lr1, J) // Add(&l.r1, &J)
	lr2 := pr.ext2.Neg(H)     // l.r2.Neg(&H)

	return &G2Projective{
			X: *px,
			Y: *py,
			Z: *pz,
		},
		&LineEvaluation{
			r0: *lr0,
			r1: *lr1,
			r2: *lr2,
		}
}

func (pr Pairing) AffineToProjective(Q *G2Affine) *G2Projective {
	// TODO: check point at infinity? We do not filter them in the Miller Loop neither.
	// if Q.X.IsZero() && Q.Y.IsZero() {
	// 	p.z.SetZero()
	// 	p.x.SetOne()
	// 	p.y.SetOne()
	// 	return p
	// }
	pz := pr.ext2.One()   // p.z.SetOne()
	px := &Q.X            // p.x.Set(&Q.X)
	py := &Q.Y            // p.y.Set(&Q.Y)
	return &G2Projective{ // return p
		X: *px,
		Y: *py,
		Z: *pz,
	}
}

func (pr Pairing) NegAffine(a *G2Affine) *G2Affine {
	px := &a.X              // p.X = a.X
	py := pr.ext2.Neg(&a.Y) // p.Y.Neg(&a.Y)
	return &G2Affine{       // return p
		X: *px,
		Y: *py,
	}
}

// Mul014By014 multiplication of sparse element (c0,c1,0,0,c4,0) by sparse element (d0,d1,0,0,d4,0)
func (e *ext12) Mul014By014(d0, d1, d4, c0, c1, c4 *E2) *E12 {
	//var tmp, x0, x1, x4, x04, x01, x14 E2
	x0 := e.ext2.Mul(c0, d0)   //x0.Mul(c0, d0)
	x1 := e.ext2.Mul(c1, d1)   //x1.Mul(c1, d1)
	x4 := e.ext2.Mul(c4, d4)   //x4.Mul(c4, d4)
	tmp := e.ext2.Add(c0, c4)  //tmp.Add(c0, c4)
	x04 := e.ext2.Add(d0, d4)  //x04.Add(d0, d4).
	x04 = e.ext2.Mul(x04, tmp) //	Mul(&x04, &tmp).
	x04 = e.ext2.Sub(x04, x0)  //	Sub(&x04, &x0).
	x04 = e.ext2.Sub(x04, x4)  //	Sub(&x04, &x4)
	tmp = e.ext2.Add(c0, c1)   //tmp.Add(c0, c1)
	x01 := e.ext2.Add(d0, d1)  //x01.Add(d0, d1).
	x01 = e.ext2.Mul(x01, tmp) //	Mul(&x01, &tmp).
	x01 = e.ext2.Sub(x01, x0)  //	Sub(&x01, &x0).
	x01 = e.ext2.Sub(x01, x1)  //	Sub(&x01, &x1)
	tmp = e.ext2.Add(c1, c4)   //tmp.Add(c1, c4)
	x14 := e.ext2.Add(d1, d4)  //x14.Add(d1, d4).
	x14 = e.ext2.Mul(x14, tmp) //	Mul(&x14, &tmp).
	x14 = e.ext2.Sub(x14, x1)  //	Sub(&x14, &x1).
	x14 = e.ext2.Sub(x14, x4)  //	Sub(&x14, &x4)

	z00 := *e.ext2.MulByNonResidue(x4) //z.C0.B0.MulByNonResidue(&x4).
	z00 = *e.ext2.Add(&z00, x0)        //	Add(&z.C0.B0, &x0)

	z01 := *x01           //z.C0.B1.Set(&x01)
	z02 := *x1            //z.C0.B2.Set(&x1)
	z10 := *e.ext2.Zero() //z.C1.B0.SetZero()
	z11 := *x04           //z.C1.B1.Set(&x04)
	z12 := *x14           //z.C1.B2.Set(&x14)

	return &E12{
		C0: E6{
			B0: z00,
			B1: z01,
			B2: z02,
		},
		C1: E6{
			B0: z10,
			B1: z11,
			B2: z12,
		},
	}
}

// MulBy014 multiplication by sparse element (c0, c1, 0, 0, c4)
func (pr *Pairing) MulBy014(z *E12, c0, c1, c4 *E2) *E12 {
	//var a, b E6
	//var d E2

	a := z.C0                        //a.Set(&z.C0)
	a = *pr.ext6.MulBy01(&a, c0, c1) //a.MulBy01(c0, c1)

	b := z.C1                   //b.Set(&z.C1)
	b = *pr.ext6.MulBy1(&b, c4) //b.MulBy1(c4)
	d := pr.ext2.Add(c1, c4)    //d.Add(c1, c4)

	z1 := pr.ext6.Add(&z.C1, &z.C0)   //z.C1.Add(&z.C1, &z.C0)
	z1 = pr.ext6.MulBy01(z1, c0, d)   //z.C1.MulBy01(c0, &d)
	z1 = pr.ext6.Sub(z1, &a)          //z.C1.Sub(&z.C1, &a)
	z1 = pr.ext6.Sub(z1, &b)          //z.C1.Sub(&z.C1, &b)
	z0 := pr.ext6.MulByNonResidue(&b) //z.C0.MulByNonResidue(&b)
	z0 = pr.ext6.Add(z0, &a)          //z.C0.Add(&z.C0, &a)

	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (pr Pairing) AddStep(p *G2Projective, a *G2Affine) (*G2Projective, *LineEvaluation) {
	// var Y2Z1, X2Z1, O, L, C, D, E, F, G, H, t0, t1, t2, J fptower.E2
	Y2Z1 := pr.ext2.Mul(&a.Y, &p.Z) // Y2Z1.Mul(&a.Y, &p.z)
	O := pr.ext2.Sub(&p.Y, Y2Z1)    // O.Sub(&p.y, &Y2Z1)
	X2Z1 := pr.ext2.Mul(&a.X, &p.Z) // X2Z1.Mul(&a.X, &p.z)
	L := pr.ext2.Sub(&p.X, X2Z1)    // L.Sub(&p.x, &X2Z1)
	C := pr.ext2.Square(O)          // C.Square(&O)
	D := pr.ext2.Square(L)          // D.Square(&L)
	E := pr.ext2.Mul(L, D)          // E.Mul(&L, &D)
	F := pr.ext2.Mul(&p.Z, C)       // F.Mul(&p.z, &C)
	G := pr.ext2.Mul(&p.X, D)       // G.Mul(&p.x, &D)
	t0 := pr.ext2.Double(G)         // t0.Double(&G)
	H := pr.ext2.Add(E, F)          // H.Add(&E, &F).
	H = pr.ext2.Sub(H, t0)          // 	Sub(&H, &t0)
	t1 := pr.ext2.Mul(&p.Y, E)      // t1.Mul(&p.y, &E)
	px := pr.ext2.Mul(L, H)         // p.x.Mul(&L, &H)
	py := pr.ext2.Sub(G, H)         // p.y.Sub(&G, &H).
	py = pr.ext2.Mul(py, O)         // 	Mul(&p.y, &O).
	py = pr.ext2.Sub(py, t1)        // 	Sub(&p.y, &t1)
	pz := pr.ext2.Mul(E, &p.Z)      // p.z.Mul(&E, &p.z)
	t2 := pr.ext2.Mul(L, &a.Y)      // t2.Mul(&L, &a.Y)
	J := pr.ext2.Mul(&a.X, O)       // J.Mul(&a.X, &O).
	J = pr.ext2.Sub(J, t2)          // 	Sub(&J, &t2)

	lr0 := J              // l.r0.Set(&J)
	lr1 := pr.ext2.Neg(O) // l.r1.Neg(&O)
	lr2 := L              // l.r2.Set(&L)

	return &G2Projective{
			X: *px,
			Y: *py,
			Z: *pz,
		}, &LineEvaluation{
			r0: *lr0,
			r1: *lr1,
			r2: *lr2,
		}
}

type LineEvaluation struct {
	r0 E2
	r1 E2
	r2 E2
}

var loopCounter = [64]int8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1}

func (pr Pairing) MillerLoop(p []*G1Affine, q []*G2Affine) (*GTEl, error) {
	n := len(p)
	if n == 0 || n != len(q) {
		return nil, fmt.Errorf("invalid inputs sizes")
	}

	// TODO: we have omitted filtering for infinity points.

	qProj := make([]*G2Projective, n)
	for k := 0; k < n; k++ {
		qProj[k] = pr.AffineToProjective(q[k]) // qProj[k].FromAffine(&q[k])
	}

	var l1, l2 *LineEvaluation
	result := pr.ext12.One() // var tmp, result GTEl

	// i == len(loopCounter) - 2
	for k := 0; k < n; k++ {
		qProj[k], l1 = pr.DoubleStep(qProj[k])               // qProj[k].DoubleStep(&l1)
		l1.r1 = *pr.ext12.ext2.MulByElement(&l1.r1, &p[k].X) // l1.r1.MulByElement(&l1.r1, &p[k].X)
		l1.r2 = *pr.ext12.ext2.MulByElement(&l1.r2, &p[k].Y) // l1.r2.MulByElement(&l1.r2, &p[k].Y)

		qProj[k], l2 = pr.AddStep(qProj[k], q[k]) // qProj[k].AddMixedStep(&l2, &q[k])
		// line eval
		l2.r1 = *pr.ext12.ext2.MulByElement(&l2.r1, &p[k].X) //l2.r1.MulByElement(&l2.r1, &p[k].X)
		l2.r2 = *pr.ext12.ext2.MulByElement(&l2.r2, &p[k].Y) //l2.r2.MulByElement(&l2.r2, &p[k].Y)

		// ℓ × ℓ
		lines := pr.ext12.Mul014By014(&l1.r0, &l1.r1, &l1.r2, &l2.r0, &l2.r1, &l2.r2)
		result = pr.ext12.Mul(result, lines)
	}

	for i := len(loopCounter) - 3; i >= 0; i-- {
		// (∏ᵢfᵢ)²
		result = pr.ext12.Square(result) //result.Square(&result)

		for k := 0; k < n; k++ {
			qProj[k], l1 = pr.DoubleStep(qProj[k])

			// line eval
			l1.r1 = *pr.ext2.MulByElement(&l1.r1, &p[k].X) //l1.r1.MulByElement(&l1.r1, &p[k].X)
			l1.r2 = *pr.ext2.MulByElement(&l1.r2, &p[k].Y) //l1.r2.MulByElement(&l1.r2, &p[k].Y)

			if loopCounter[i] == 0 {
				result = pr.MulBy014(result, &l1.r0, &l1.r1, &l1.r2) //result.MulBy014(&l1.r0, &l1.r1, &l1.r2)
			} else {
				qProj[k], l2 = pr.AddStep(qProj[k], q[k]) //qProj[k].AddMixedStep(&l2, &q[k])
				// line eval
				l2.r1 = *pr.ext12.ext2.MulByElement(&l2.r1, &p[k].X) //l2.r1.MulByElement(&l2.r1, &p[k].X)
				l2.r2 = *pr.ext12.ext2.MulByElement(&l2.r2, &p[k].Y) //	l2.r2.MulByElement(&l2.r2, &p[k].Y)
				// ℓ × ℓ
				lines := pr.Mul014By014(&l1.r0, &l1.r1, &l1.r2, &l2.r0, &l2.r1, &l2.r2) // lines.Mul014By014(&l1.r0, &l1.r1, &l1.r2, &l2.r0, &l2.r1, &l2.r2)
				// (ℓ × ℓ) × result
				result = pr.ext12.Mul(result, lines) //	result.Mul(&result, &lines)
			}
		}
	}

	// negative x₀
	result = pr.ext12.Conjugate(result)

	return result, nil
}

func (pr Pairing) FinalExponentiation(e *GTEl) *GTEl {
	// var result GT
	// result.Set(z)
	var t [3]*GTEl // var t [3]GT

	// easy part
	t[0] = pr.ext12.Conjugate(e)            // t[0].Conjugate(&result)
	result := pr.ext12.Inverse(e)           // result.Inverse(&result)
	t[0] = pr.ext12.Mul(t[0], result)       // t[0].Mul(&t[0], &result)
	result = pr.ext12.FrobeniusSquare(t[0]) // result.FrobeniusSquare(&t[0]).
	result = pr.ext12.Mul(result, t[0])     // 	Mul(&result, &t[0])

	// hard part 1
	t[0] = pr.ext12.CyclotomicSquare(result) // t[0].CyclotomicSquare(&result)
	t[1] = pr.ext12.ExptHalf(t[0])           // t[1].ExptHalf(&t[0])
	t[2] = pr.ext12.Conjugate(result)        //t[2].InverseUnitary(&result)
	t[1] = pr.ext12.Mul(t[1], t[2])          //	t[1].Mul(&t[1], &t[2])
	t[2] = pr.ext12.Expt(t[1])               //	t[2].Expt(&t[1])
	t[1] = pr.ext12.Conjugate(t[1])          //	t[1].InverseUnitary(&t[1])
	t[1] = pr.ext12.Mul(t[1], t[2])          //	t[1].Mul(&t[1], &t[2])
	t[2] = pr.ext12.Expt(t[1])               //	t[2].Expt(&t[1])
	t[1] = pr.ext12.Frobenius(t[1])          //	t[1].Frobenius(&t[1])
	t[1] = pr.ext12.Mul(t[1], t[2])          //	t[1].Mul(&t[1], &t[2])
	result = pr.ext12.Mul(result, t[0])      //	result.Mul(&result, &t[0])
	t[0] = pr.ext12.Expt(t[1])               //	t[0].Expt(&t[1])
	t[2] = pr.ext12.Expt(t[0])               //	t[2].Expt(&t[0])
	t[0] = pr.ext12.FrobeniusSquare(t[1])    //	t[0].FrobeniusSquare(&t[1])
	t[1] = pr.ext12.Conjugate(t[1])          //	t[1].InverseUnitary(&t[1])
	t[1] = pr.ext12.Mul(t[1], t[2])          //	t[1].Mul(&t[1], &t[2])
	t[1] = pr.ext12.Mul(t[1], t[0])          //	t[1].Mul(&t[1], &t[0])
	result = pr.ext12.Mul(result, t[1])      //	result.Mul(&result, &t[1])

	return result // return result
}

func (pr Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.FinalExponentiation(res)
	return res, nil
}
