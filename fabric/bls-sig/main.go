package main

import (
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"time"

	"fabric/bls-sig/core"
	"fabric/common"
	"gadgets/pairing_bls12381"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	// generate CompiledConstraintSystem
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.BlsSignatureVerifyCircuit{})
	if err != nil {
		log.Fatal("frontend.Compile")
	}

	// groth16 zkSNARK: Setup
	setupStart := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal("groth16.Setup")
	}
	setUpDuration := time.Since(setupStart)
	fmt.Printf("setup duration:%d\n", setUpDuration)

	var aggBits [common.LenOfValidators]frontend.Variable
	for i := 0; i < common.LenOfValidators; i++ {
		aggBits[i] = i % 2 // 1, 3... to sign
	}

	g1secrets, g1s, _, _ := common.RandomG1G2Affines()

	var vgs [common.LenOfValidators]pairing_bls12381.G1Affine
	for i := range g1s {
		vgs[i] = pairing_bls12381.NewG1Affine(g1s[i])
	}

	signingRoot := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	signingRootG2, err := bls12381.HashToG2(signingRoot, []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"))
	if err != nil {
		log.Fatal("HashToG2 failed...", err)
	}
	var signingRootVar [32]frontend.Variable
	for i := 0; i < 32; i++ {
		signingRootVar[i] = signingRoot[i]
	}

	var aggSign bls12381.G2Affine // default not set as infinitiy
	participantNum := 0
	for i := 0; i < common.LenOfValidators; i++ {
		if aggBits[i] == 1 {
			var sign bls12381.G2Affine
			sign.ScalarMultiplication(&signingRootG2, g1secrets[i])
			aggSign.Add(&aggSign, &sign)
			participantNum++
		}
	}

	assignment := core.BlsSignatureVerifyCircuit{
		Pubkeys:               vgs,
		AggBits:               aggBits,
		AggSig:                pairing_bls12381.NewG2Affine(aggSign),
		SigningRoot:           signingRootVar,
		ParticipantNum:        participantNum,
		SyncCommitteePoseidon: common.GenPoseidonRoot(vgs),
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		debug.PrintStack()
		log.Fatal("prove computation failed...", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("groth16 verify failed...")
	}

	f, err := os.Create("BlkVerifier.sol")
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	err = vk.ExportSolidity(f)
}
