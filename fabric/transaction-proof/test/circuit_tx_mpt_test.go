package test

import (
	"strconv"
	"testing"

	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/core"

	"github.com/celer-network/brevis-circuits/gadgets/keccak"
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"golang.org/x/crypto/sha3"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func TestTransactionRoot(t *testing.T) {
	assert := test.NewAssert(t)

	depth := 5

	keyRlpHexString := "81be" // 133 --> 0x85 -- rlp --> 0x8185
	keyHexLen := len(keyRlpHexString)
	var keyRlpHex [core.TransactionMaxKeyHexLen]frontend.Variable
	for i := 0; i < core.TransactionMaxKeyHexLen; i++ {
		if i < keyHexLen {
			intValue, _ := strconv.ParseInt(string(keyRlpHexString[i]), 16, 64)
			keyRlpHex[i] = intValue
		} else {
			keyRlpHex[i] = 0
		}
	}

	valueRlpHexString := "02f87201238459682f00850c08132dc182fde794cfc912c945d634dc2c24d4c848d9a9f4046f9b1187b1a2bc2ec5000080c080a0d6060f3b02fccd8f8902727bbff58b88693c707f3b36b26a079f014d5ceb7cc6a00ee9e0d622d6f8e52b4ba2d79565985a2b218b85a307492834b8055a0fb3b5ff"
	valueHexLen := len(valueRlpHexString)
	var valueRlpHex [core.TransactionLeafMaxValueHexLen]frontend.Variable
	for i := 0; i < core.TransactionLeafMaxValueHexLen; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueRlpHexString[i]), 16, 64)
			valueRlpHex[i] = intValue
		} else {
			valueRlpHex[i] = 0
		}
	}

	rootHashHexString := "ffadf2a50d8aa20e19c37ea385864998231e6524d200425f076479629cb20d9c"
	var rootHashHex [64]frontend.Variable
	for i := 0; i < 64; i++ {
		intValue, _ := strconv.ParseInt(string(rootHashHexString[i]), 16, 64)
		rootHashHex[i] = intValue
	}

	var keyFragmentStarts [core.TransactionMPTMaxDepth]frontend.Variable
	for i := 0; i < core.TransactionMPTMaxDepth; i++ {
		keyFragmentStarts[i] = i
		if i > depth-1 {
			keyFragmentStarts[i] = 6
		}
	}

	leafRlpHexString := "0xf87820b87502f87201238459682f00850c08132dc182fde794cfc912c945d634dc2c24d4c848d9a9f4046f9b1187b1a2bc2ec5000080c080a0d6060f3b02fccd8f8902727bbff58b88693c707f3b36b26a079f014d5ceb7cc6a00ee9e0d622d6f8e52b4ba2d79565985a2b218b85a307492834b8055a0fb3b5ff"

	leafBytes, _ := hexutil.Decode(leafRlpHexString)
	hash := sha3.NewLegacyKeccak256()
	_, err := hash.Write(leafBytes)
	leafHashBytes := hash.Sum(nil)

	var leafHashPieces [2]frontend.Variable
	leafHashPieces[0] = leafHashBytes[0:16]
	leafHashPieces[1] = leafHashBytes[16:32]

	/// 64 - (depth - 1) ===> length of nibbles represented by branch/extension node
	/// depth = len(accountProof[])/len(storageProof[])
	var leafPathPrefixLength int // 20 67bce79287a24c5e8453dee4b1c363dfccc5960e98b02dc0f56374bf
	if (64-depth+1)%2 == 0 {
		leafPathPrefixLength = 2
	} else {
		leafPathPrefixLength = 1
	}

	/// Proofs without leaf level ---> accountProof[0:len(accountProof) - 1]
	nodeRlpHexStrings := []string{
		"0xf90131a0ea2961ec67a8fcb7d29bf73a35533135876af0876611f3bfdcbe6fd75ebac696a0d0e0f2571311d6e351dc2de28b0dccc27d4c2c8d2a6ca064d4f88f32dd29bc7da0331e205f6a1d22b2b29eaa1789626776be0898c3405451d73ab499cbf092c253a0264208423e431ed79f46e72078a844f4d7ca9f990d5bd8c8d83e3d1cb79e2b76a0f6b88e1daa8a1d7138fdd99d75174f935c2f78b700fbc1529aa35964302f8405a07d6d5d3784dcfb45b9d739b318f5f55bd1f69c08d691e6413ffa705cd3ac3aa5a0c6915b22afad96408bfd4911563325ae3a20638188730f39acdffc7bb2fbbac8a09cdfdbad6bb47c07e82b2e61a2a73b688ff7da1e7cc70fbec15f77f98c0ac155a01a6d7c5075950f04a6a1ede29ebad6a737c1cbef9e9dd4c942ce8f3be88a946d8080808080808080",
		"0xf851a0229cad5c99d5d2a7e8fd78384daba9fbbd35bfcda7fd5d5e103aedf9ba7fb165a0d6abb11a843ba7145e909467abbf0edbc2970f5a4c40291a463953814ab6cd0d808080808080808080808080808080",
		"0xf8b18080808080808080a0b1316f48cfd0734a779d44b129969b0dd387c358e4fdad80d9a4aef8a4700caaa0f583f5d8b553a39b623aadcae9976bc3fb2a9e431e43e17e9775f8b201cdb602a0f91fba2aa49aa6fc6a1bd87cf9cd6553df0e1259c83a4a1c83e5fbc83737faffa0ab85dffc274a009a58884a02db11d75401812f2f3f420e46fd8be155b347e686a03273d39aea93c890e93e062e3230480c478165b41508483fa34c405fbab5d8be80808080",
		"0xf90211a03406cd332df8151b7826fb766730df5d7475d9b01848542718bed9f145ab0020a00fb295b247fda12303b0d943946a4657c03b89c2af131cc932a5a3a3dbe0698ba0a8dd911a379846d7df4ad8a4866997fbe99dc5dfc59636e840ed6ac3a526ee83a0553fe3b72026ce7409af1bdc0db7f1907001514a31b30acf8c8c781a84a003f2a0c5470f0782b1e34732a21b43512c432738d73b6ccd28eeee98d05460109edfc6a0f5c4958411dfb0f5796db94f4de5c714e986f1cba9ae72fa6fb704e43b4e804fa095ddfdf008c94d61f05432e198b7eab55a8e7a8107379a4fbae9e64b885c420fa0cd346cf3b72661f8c9807856fa792adb749c75c7b7e36f3825e602cb565dab42a0429c4503708db8010fefc1b5fe21e101238c32f678fab35b92e09b43ccb404eba04d44c6ccbb1aba16ab294b2fbb3ab25376f3548e7a61487d5403a8c67ea3a483a0e9687506a3a79a8aa1f54ec1ce1a9b85f03acb8e2e799b95a6b8e75f85bba9f9a033a60bd585a2af364f23362ce9b56914b6f918f0b599ec92ae3f53767125d654a068c3b7f7d9f54acb6cccf3390540990c4fad6d27a32eee352f0dd8d117f6baa5a0fbd4e97b0adba69323a8f8ddf725e0efe2c1c7363aec05f4b9bd043b89240500a0a81bd9decf5d1c28e1867f700cc39dbd3543780c39c67134de095b1b5ddf577ca02b3f95543d4409ed3276d7906c44425d7269fa79f8cbc351b0e7391deb3f654380",
	}

	realDataLength := len(nodeRlpHexStrings)

	var nodeRlp [core.TransactionMPTMaxDepth - 1][mpt.BranchNodeMaxBlockSize]frontend.Variable
	var nodeRlpRoundIndexes [core.TransactionMPTMaxDepth - 1]frontend.Variable
	var nodePathPrefixLength [core.TransactionMPTMaxDepth - 1]frontend.Variable
	var nodeTypes [core.TransactionMPTMaxDepth - 1]frontend.Variable

	for i := 0; i < core.TransactionMPTMaxDepth-1; i++ {
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

		// TODO: add support for extension node
		//if i == 2 {
		//	nodePathPrefixLength[i] = 1
		//	nodeTypes[i] = 1
		//} else {
		nodePathPrefixLength[i] = 0
		nodeTypes[i] = 0
		//}
	}

	output := 1

	witness := &core.TransactionMptCircuit{
		Key:                  keyRlpHex,
		KeyLength:            frontend.Variable(4),
		Value:                valueRlpHex,
		RootHash:             rootHashHex,
		KeyFragmentStarts:    keyFragmentStarts,
		LeafHash:             leafHashPieces,
		LeafPathPrefixLength: leafPathPrefixLength,
		NodeRlp:              nodeRlp,
		NodePathPrefixLength: nodePathPrefixLength,
		NodeTypes:            nodeTypes,
		NodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		Depth:                depth,
		Output:               output,
	}

	err = test.IsSolved(&core.TransactionMptCircuit{
		// Key:                  make([]frontend.Variable, TransactionMaxKeyHexLen), // [AccountKeyLength]frontend.Variable,
		// Value:                make([]frontend.Variable, TransactionLeafMaxValueHexLen),
		// KeyFragmentStarts:    make([]frontend.Variable, MaxDepth),
		// NodePathPrefixLength: make([]frontend.Variable, MaxDepth-1),
		// NodeTypes:            make([]frontend.Variable, MaxDepth-1),
	}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
