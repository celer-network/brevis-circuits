package main

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/celer-network/brevis-circuits/fabric/storage-proof/core"

	"github.com/celer-network/brevis-circuits/gadgets/keccak"
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

func main() {
	depth := 3

	keyRlpHexString := "290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563"
	keyHexLen := len(keyRlpHexString)
	var keyRlpHex [mpt.AccountKeyLength]frontend.Variable
	for i := 0; i < mpt.AccountKeyLength; i++ {
		if i < keyHexLen {
			intValue, _ := strconv.ParseInt(string(keyRlpHexString[i]), 16, 64)
			keyRlpHex[i] = intValue
		} else {
			keyRlpHex[i] = 0
		}
	}

	valueRlpHexString := "94bc50cbd395314a43302e3bf56677755e5a543a8c"
	valueRlpHexLen := len(valueRlpHexString)
	var valueRlpHex [mpt.MaxValueLengthForStorage]frontend.Variable
	for i := 0; i < mpt.MaxValueLengthForStorage; i++ {
		if i < valueRlpHexLen {
			intValue, _ := strconv.ParseInt(string(valueRlpHexString[i]), 16, 64)
			valueRlpHex[i] = intValue
		} else {
			valueRlpHex[i] = 0
		}
	}

	rootHashHexString := "1eb0e8ed889315b2a7f6e076d0939a6ed1fe4e3d9b0eeb366c47ec5e8a52fd3f"
	var rootHashHex [64]frontend.Variable
	for i := 0; i < 64; i++ {
		intValue, _ := strconv.ParseInt(string(rootHashHexString[i]), 16, 64)
		rootHashHex[i] = intValue
	}

	var keyFragmentStarts [mpt.StorageMPTMaxDepth]frontend.Variable
	for i := 0; i < mpt.StorageMPTMaxDepth; i++ {
		keyFragmentStarts[i] = i
		if i > depth-1 {
			keyFragmentStarts[i] = 64
		}
	}

	leafRlpHexString := "0xf7a0200decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594bc50cbd395314a43302e3bf56677755e5a543a8c"
	leafRlpBytes, _ := hexutil.Decode(leafRlpHexString)
	paddedLeafRlpBytes := keccak.Pad101Bytes(leafRlpBytes)

	leafRlpRoundIndex := keccak.GetKeccakRoundIndex(len(leafRlpHexString) - 2)

	var paddedLeafRlpHex [272]frontend.Variable
	for i, b := range paddedLeafRlpBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedLeafRlpHex[i*2] = n1
		paddedLeafRlpHex[i*2+1] = n2
	}

	var leafPathPrefixLength int // 20 0decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
	if (64-depth+1)%2 == 0 {
		leafPathPrefixLength = 2
	} else {
		leafPathPrefixLength = 1
	}

	/// Proofs without leaf level ---> accountProof[0:len(accountProof) - 1]
	nodeRlpHexStrings := []string{
		"0xf90211a0c7273e80156fbab619b5aaf0db75247e09200d0216775befd6acb3fe6890b313a076e3a772db17877b07198d35c4950304aa8f05404dbc238baa3909250553a343a03f514a91f964128f66006334f89375f6454b7bebf285dc41e40be933f2ab8940a0836470c578c35ec5dfa847d0c4e3f3ac0242e3e80a371732561a715e2631d6bea0b3b59aae62cf99c9944cba79692dadfd968ddc89f8b258c1970cd2c41d2946f7a05c65dce7c3957ad2ed39b4114ff2fa9862e657d61be5c1e42750bdd756573d8fa0b07f76f45160eb4efcaad56c74222ed1cc552f88284ae67bb067caed0601152da0c514504d65f66b75461e15f9d7daff3bcb7f8603a57064507526ff957d9929d7a01f3dbb57b8d7e82205967d9f48cf4319995b9b36f7c5b147c5667acf94aa8d9ea0167b5ac5f7539ba28090015631aad247254c9810f0a0d3511b57c0e98586c10ba091bcaed8e663f6de8ddac3d1133853a633b1b81772c77deb0f75ea3e4797b7a8a03b8c64f1885e7824b81f50ed11be36e4ec71010b058a1b9c9205bd2ffcc6624fa0a05ceed91445b71f0e422546d95ef6d74b02bdc989eea010c4ea81316f8f5498a019315d4c08011517963064d036227878e4bc7fb6040f0e77c01ad3f0ee8c366da043a89110322186f9b7beee526b633c27d52e38b9dfa82f36cad624f8afb56b98a04c2d14b66813e9a580b3aaaa7b2b6612b912f3aa8255ca1641e5490712b3618880",
		"0xf8d18080808080a0f7b56be8dd71e675bf18c14afe0936d94d8883b9bbfcaee55e261a0b1dae1ea580a0c81a7ed63fb141b3f0302002ec0d5dcedeab671835adc6bc4d7f17e030717dd980a0d0a95e510d498a8b510ea71f8842528f438fc7e43e996c27e87774a52bee2c1aa0ff1f3593598f45c98daa085532e5051fe09da692b75e03a881cf29b1411fa92480a09d65e3575d4d5b52401675206aac2a225ae72d9ef0044e521fd13af454925d9ea0fa5a015c91c948b3b811f3960cba4a588fad127ca6c1026f5ee5171273074cc4808080",
	}

	var nodeRlp [mpt.StorageMPTMaxDepth - 1][mpt.BranchNodeMaxBlockSize]frontend.Variable
	var nodeRlpRoundIndexes [mpt.StorageMPTMaxDepth - 1]frontend.Variable
	var nodePathPrefixLength [mpt.StorageMPTMaxDepth - 1]frontend.Variable
	var nodeTypes [mpt.StorageMPTMaxDepth - 1]frontend.Variable

	realDataLength := len(nodeRlpHexStrings)

	for i := 0; i < mpt.StorageMPTMaxDepth-1; i++ {
		if i < realDataLength {
			// Feed actual data
			rlpHexString := nodeRlpHexStrings[i]
			bytes, _ := hexutil.Decode(rlpHexString)
			paddedBytes := keccak.Pad101Bytes(bytes)
			var rlp [mpt.BranchNodeMaxBlockSize]frontend.Variable
			for i, b := range paddedBytes {
				n1 := b >> 4
				n2 := b & 0x0F
				rlp[i*2] = n1
				rlp[i*2+1] = n2
			}

			for j := len(paddedBytes) * 2; j < 272*4; j++ {
				rlp[j] = 0
			}

			nodeRlp[i] = rlp

			nodeRlpRoundIndexes[i] = keccak.GetKeccakRoundIndex(len(rlpHexString) - 2)
		} else {
			// Add placeholder data
			var empty [1088]frontend.Variable
			for j := 0; j < 1088; j++ {
				empty[j] = 0
			}
			nodeRlp[i] = empty
			nodeRlpRoundIndexes[i] = 0
		}

		// TODO: calculate prefix length and node types dynamically
		nodePathPrefixLength[i] = 0
		nodeTypes[i] = 0
	}

	output := 1

	leafRlpInBytes, _ := hexutil.Decode("0x" + valueRlpHexString)
	var storageInfo []byte
	rlp.Decode(bytes.NewReader(leafRlpInBytes), &storageInfo)

	valueBytes := hexutil.Encode(storageInfo)
	valueBytes = strings.ReplaceAll(valueBytes, "0x", "")

	valueHexLen := len(valueBytes)
	var valueHex [64]frontend.Variable
	for i := 0; i < 64; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueBytes[i]), 16, 64)
			valueHex[i] = intValue
		} else {
			valueHex[i] = 0
		}
	}

	assignment := core.StorageProofCircuit{
		StorageRoot:          rootHashHex,
		SlotHash:             keyRlpHex,
		Value:                valueRlpHex,
		KeyFragmentStarts:    keyFragmentStarts,
		LeafRlp:              paddedLeafRlpHex,
		LeafPathPrefixLength: leafPathPrefixLength,
		LeafRlpRoundIndex:    leafRlpRoundIndex,
		NodeRlp:              nodeRlp,
		NodeRoundIndexes:     nodeRlpRoundIndexes,
		NodePathPrefixLength: nodePathPrefixLength,
		NodeTypes:            nodeTypes,
		Depth:                depth,
		Output:               output,
		SlotValue:            valueHex,
		ValueLength:          valueHexLen,
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.StorageProofCircuit{})
	if err != nil {
		fmt.Println(err)
		return
	}
	pk, vk, err := groth16.Setup(ccs)

	if err != nil {
		log.Fatal("groth16.Setup")
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		debug.PrintStack()
		log.Fatal("prove computation failed...", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("groth16 verify failed...")
	}

}
