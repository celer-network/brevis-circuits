package main

import (
	"fmt"
	"os"

	"github.com/celer-network/brevis-circuits/fabric/headers"

	"github.com/celer-network/brevis-circuits/common"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	numBlocks := 4
	w := headers.NewChunkProofCircuit(numBlocks)
	circuit := headers.NewChunkProofCircuit(numBlocks)
	fmt.Printf("%x\n", w.ChunkRoot)
	fmt.Printf("%x\n", w.PrevHash)
	fmt.Printf("%x\n", w.EndHash)
	fmt.Printf("%d\n", w.StartBlockNum)
	fmt.Printf("%d\n", w.EndBlockNum)

	fmt.Println("compile")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	check(err)

	fmt.Println("setup")
	pk, vk, err := groth16.Setup(cs)
	check(err)

	fmt.Println("gen witness")
	witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
	check(err)
	pubWitness, err := witness.Public()
	check(err)

	fmt.Println("prove")
	proof, err := groth16.Prove(cs, pk, witness)
	check(err)

	a, b, c, commitment := common.ExportProof(proof)
	fmt.Printf("a %+v\nb %+v\nc %+v\ncommit %+v\n", a, b, c, commitment)

	fmt.Println("verify")
	err = groth16.Verify(proof, vk, pubWitness)
	check(err)

	f, err := os.Create(fmt.Sprintf("EthChunkOf%dVerifier.sol", numBlocks))
	check(err)
	defer f.Close()

	err = vk.ExportSolidity(f)
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
