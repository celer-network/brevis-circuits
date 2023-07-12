package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	pairing_bls12381 "github.com/celer-network/brevis-circuits/gadgets/pairing_bls12381"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/rs/zerolog/log"
)

func randomG1G2() (bls12381.G1Affine, bls12381.G2Affine) {
	_, _, G1AffGen, G2AffGen := bls12381.Generators()
	mod := bls12381.ID.ScalarField()
	s1, _ := rand.Int(rand.Reader, mod)
	s2, _ := rand.Int(rand.Reader, mod)
	var p bls12381.G1Affine
	p.ScalarMultiplication(&G1AffGen, s1)
	var q bls12381.G2Affine
	q.ScalarMultiplication(&G2AffGen, s2)
	return p, q
}

type PairCircuit struct {
	InG1 pairing_bls12381.G1Affine
	InG2 pairing_bls12381.G2Affine
	Res  pairing_bls12381.GTEl
}

func (c *PairCircuit) Define(api frontend.API) error {
	pairing, err := pairing_bls12381.NewPairing(api)
	if err != nil {
		return fmt.Errorf("new pairing: %w", err)
	}
	res, err := pairing.Pair([]*pairing_bls12381.G1Affine{&c.InG1}, []*pairing_bls12381.G2Affine{&c.InG2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	pairing.AssertIsEqual(res, &c.Res)
	return nil
}

func getPkAndVk() (groth16.ProvingKey, groth16.VerifyingKey) {

	pk := groth16.NewProvingKey(ecc.BN254)
	{
		f, _ := os.Open("./cubic.g16.pk")
		defer f.Close()
		_, err := pk.ReadFrom(f)
		if err != nil {
			panic(err)
		}
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)

	{
		f, _ := os.Open("./cubic.g16.vk")
		defer f.Close()
		_, err := vk.ReadFrom(f)
		if err != nil {
			panic(err)
		}
	}
	return pk, vk
}

func writePkAndVk(ccs constraint.ConstraintSystem) {
	fmt.Println("write pk and vk to file")
	pk, vk, _ := groth16.Setup(ccs)

	{
		f, err := os.Create("./cubic.g16.vk")
		if err != nil {
			panic(err)
		}

		_, err = vk.WriteTo(f)
		if err != nil {
			panic(err)
		}

		fmt.Println("vk write successfully")

	}

	{
		f, err := os.Create("./cubic.g16.pk")
		if err != nil {
			panic(err)
		}

		_, err = pk.WriteTo(f)
		if err != nil {
			panic(err)
		}

		fmt.Println("pk write successfully")
	}

	{
		f, err := os.Create("./contract.g16.sol")
		if err != nil {
			panic(err)
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			panic(err)
		}

		fmt.Println("sol write successfully")

	}
}

var signingRoot = [32]byte{
	244, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
	11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 254, 23, 24, 25, 26, 88, 28, 29, 30,
	31,
}

type Bls12381Hash2CurveCircuit struct {
	Msg [32]frontend.Variable `gnark:"data,public"` // 32 bytes, 512 bits
}

func (circuit *Bls12381Hash2CurveCircuit) Define(api frontend.API) error {
	ba, err := emulated.NewField[pairing_bls12381.BLS12381Fp](api)
	if err != nil {
		log.Err(err)
		return err
	}
	et2 := pairing_bls12381.NewExt2(ba)

	emx := pairing_bls12381.ExpandMsgXmd(api, circuit.Msg, 2)

	var u [2]*emulated.Element[pairing_bls12381.BLS12381Fp]
	for i := 0; i < 2; i++ {
		var overflowLimbs [8]frontend.Variable // 8bytes
		var val8Bytes [8]frontend.Variable
		for j := 0; j < 8; j++ {
			copy(val8Bytes[:], emx[64*(i+1)-8*(j+1):64*(i+1)-8*j])
			overflowLimbs[j] = pairing_bls12381.GetUint64From8Bytes(api, val8Bytes)
		}
		u[i] = pairing_bls12381.GetRawLimbsBy8Uint64(api, overflowLimbs)
	}

	e2 := pairing_bls12381.E2{
		A0: *u[0],
		A1: *u[1],
	}

	x, y := pairing_bls12381.MapElementToCurve2(api, e2)

	g2Affine := pairing_bls12381.G2Isogeny(api, &pairing_bls12381.G2Affine{
		X: *x, Y: *y,
	})

	g2Jac := pairing_bls12381.GetG2JacFromG2Affine(api, g2Affine)

	g2Jac = pairing_bls12381.ClearCofactor(api, *g2Jac)

	g2Affine = pairing_bls12381.GetG2AffineFromG2Jac(api, g2Jac)

	expectedg2AffineX := pairing_bls12381.E2{
		A0: emulated.ValueOf[pairing_bls12381.BLS12381Fp](fp.Element{8288150052162251671, 2982510425145065717, 1038446161708743066, 7090250654887277812, 7622650080444558773, 958313805603561234}),
		A1: emulated.ValueOf[pairing_bls12381.BLS12381Fp](fp.Element{13666391141814414167, 5488845954857000261, 13524290224112205623, 16438806396630091223, 2987796959364542135, 786538919498709043}),
	}
	et2.AssertIsEqual(&expectedg2AffineX, &g2Affine.X)
	expectedg2AffineY := pairing_bls12381.E2{
		A0: emulated.ValueOf[pairing_bls12381.BLS12381Fp](fp.Element{9308435701961680836, 7409394388844975394, 1512957003002505338, 8258019371879768333, 2306405822266797845, 1521124619517599736}),
		A1: emulated.ValueOf[pairing_bls12381.BLS12381Fp](fp.Element{13119932691052134287, 1875237080010855981, 585273779961404202, 236735867158830720, 5945086391267987300, 324336699594164309}),
	}
	et2.AssertIsEqual(&expectedg2AffineY, &g2Affine.Y)

	return nil
}

func main() {
	p, q := randomG1G2()
	res, _ := bls12381.Pair([]bls12381.G1Affine{p}, []bls12381.G2Affine{q})

	assignment := PairCircuit{
		InG1: pairing_bls12381.NewG1Affine(p),
		InG2: pairing_bls12381.NewG2Affine(q),
		Res:  pairing_bls12381.NewGTEl(res),
	}

	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &PairCircuit{})

	writePkAndVk(ccs)      //test marshal
	pk, vk := getPkAndVk() //test unmarshal

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, _ := groth16.Prove(ccs, pk, witness)
	err := groth16.Verify(proof, vk, publicWitness)
	fmt.Println(err)

	doHash2Curve()
}

func doHash2Curve() {
	log.Printf("start do hash to curve")
	// generate CompiledConstraintSystem
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Bls12381Hash2CurveCircuit{})
	if err != nil {
		log.Err(err)
	}

	// groth16 zkSNARK: Setup
	setupStart := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Err(err)
	}
	setUpDuration := time.Since(setupStart)
	fmt.Printf("setup duration:%d\n", setUpDuration)

	var msg [32]frontend.Variable
	for i, v := range signingRoot {
		msg[i] = v
	}
	assignment := Bls12381Hash2CurveCircuit{
		Msg: msg,
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		debug.PrintStack()
		log.Err(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Err(err)
	}
}
