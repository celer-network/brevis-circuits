package common

import (
	"bytes"
	"math/big"
	"os"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/backend/groth16"
)

func ExportProof(proof groth16.Proof) (a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, commitment [2]*big.Int) {
	var buf bytes.Buffer
	const fpSize = 4 * 8
	_, err := proof.WriteRawTo(&buf)
	if err != nil {
		log.Error("groth16 verify failed...")
	}
	proofBytes := buf.Bytes()

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])
	commitment[0] = new(big.Int).SetBytes(proofBytes[fpSize*8 : fpSize*9])
	commitment[1] = new(big.Int).SetBytes(proofBytes[fpSize*9 : fpSize*10])
	return
}

func WriteVerifyingKey(vk groth16.VerifyingKey, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		log.Error("vk writing failed... ", err)
	}

	_, err = vk.WriteTo(f)
	if err != nil {
		log.Error("vk writing failed... ", err)
	}
}

func WriteProvingKey(pk groth16.ProvingKey, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		log.Error("pk writing open failed... ", err)
	}
	_, err = pk.WriteTo(f)
	if err != nil {
		log.Error("pk writing failed... ", err)
	}
}
