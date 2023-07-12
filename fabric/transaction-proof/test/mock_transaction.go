package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"

	"github.com/celer-network/brevis-circuits/common"
	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/core"
	"github.com/celer-network/brevis-circuits/gadgets/keccak"
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

func GetTransactionMptProofWitness() core.TransactionMptCircuit {
	depth := 5

	keyRlpHexString := "8185" // 133 --> 0x85 -- rlp --> 0x8185
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

	valueRlpHexString := "02f901d30181b48405f5e100850faf9e23de830962b494c36442b4a4522e871399cd717abdd847ab11fe8880b90164883164560000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000002710fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27660fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9ad400000000000000000000000000000000000000000024c98fcd63f9edd999c2bbe0000000000000000000000000000000000000000000000000000000023c34600000000000000000000000000000000000000000002490b8629cad414ed17c31a0000000000000000000000000000000000000000000000000000000023ac5b490000000000000000000000006880129a290043e85eb6c67c3838d961a85956790000000000000000000000000000000000000000000000000000000064410203c080a0f78c707ba62590c6e4b222ea33c73c585ac7b1179397adf5aa0f80c7c0b63045a01a60736f6bc0effd5005723ae22f65ef92749eebbeed222f7149a8f091ef82bc"
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

	rootHashHexString := "e50d3bfc93e56bdd7bf37bc1f5a867cbcc6a302cce3f154284650d95eda84e7a"
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

	leafRlpHexString := "0xf901db20b901d702f901d30181b48405f5e100850faf9e23de830962b494c36442b4a4522e871399cd717abdd847ab11fe8880b90164883164560000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000002710fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27660fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9ad400000000000000000000000000000000000000000024c98fcd63f9edd999c2bbe0000000000000000000000000000000000000000000000000000000023c34600000000000000000000000000000000000000000002490b8629cad414ed17c31a0000000000000000000000000000000000000000000000000000000023ac5b490000000000000000000000006880129a290043e85eb6c67c3838d961a85956790000000000000000000000000000000000000000000000000000000064410203c080a0f78c707ba62590c6e4b222ea33c73c585ac7b1179397adf5aa0f80c7c0b63045a01a60736f6bc0effd5005723ae22f65ef92749eebbeed222f7149a8f091ef82bc"
	// pad leaf,And convert it to nibbles
	leafRlpBytes, _ := hexutil.Decode(leafRlpHexString)
	paddedLeafRlpBytes := keccak.Pad101Bytes(leafRlpBytes)

	var paddedLeafRlpHex [272 * core.TransactionProofKeccakRounds]frontend.Variable
	for i, b := range paddedLeafRlpBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedLeafRlpHex[i*2] = n1
		paddedLeafRlpHex[i*2+1] = n2
	}

	for i := len(paddedLeafRlpBytes) * 2; i < 272*core.TransactionProofKeccakRounds; i++ {
		paddedLeafRlpHex[i] = 0
	}

	// leafRlpRoundIndex := keccak.GetKeccakRoundIndex(len(leafRlpHexString) - 2)

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
		"0xf90131a006008e02e7886bf6c0e7bd73eefa0ba26c766046ee8eece0f1c38bb9d9eb3c6fa038c9de1239ebe8d0e9a91e02a5bf9a3bb0372cf80c20819366d852535ce717b8a0253385bbce2eab34ceb4d7bc3312d28d9c6ecbc2d20b4910ce3df731b7deefe2a0553b104a26dd0c7ad9159f4c243ba0f4564d3f72c30de9bbdd075fdfd3790ecaa00b7b069891b326e9dde48ed4896235650b0ca8829cf38893580bfe7021ae7d36a0c44446d7737423a1a45671ee07c515d102553c34969b6aa5510a0ab6c5396887a0f05cc96fd00d1b1c1bb735dd87040b91d8781bac75ac1196e3b01528177a5de9a014f5fb08cb0fec22a0e53b05cb606e7ec548e54fd983be9caee17f21b9b3add0a0dc57057e2ce6e3899024ac5884cc356622bf8be9ace97343516f0a3ef5a5c92d8080808080808080",
		"0xf851a08224f6bc371cd67f0801233068fff38ef6ac8d7767ba4b6e158019bb5175fad7a02f898539c66cf98e349d9c3df1b5354c78d2b43f306d7f4daf546d77ca9b1552808080808080808080808080808080",
		"0xe218a0caae4562211293571e9d837d4b2f1ad36566f5540b20b518e315d581623845c7",
		"0xf90131a093ce4f2441373b4033c87bd5a60e4cf50bb66ee9c0cd0463174c8b48d4f8021ba00f6457cc3175d8d28686ade17c46a977cb87a9be833b3127eb824be51f0c3872a052e18f40076d468b0ddb0a561ba8aa0f7303fdfbede920c4a9fcee67af088d58a0bfe5adeea0914e9e24037af8daa1ee890131819d77a40113e8f4c40898abbc78a0425e844c3ca2380fdd0c6b6902fa7d570d0efce6d00e4df7361058db2a84b023a0958c0c028b7a8fe0a3d5961620582cad1f557604937a104f77246246118a24c7a0f6fa22ff5962dfbe5ed810ec2ee72e3bebb708384b2869ae8fb0e6d168cbd387a02293143368314d71deeb53f975d8adcdbfd19b024c77886a566db2ec79f3d665a09e0afa2325a04bae0b2b30ce5d3d4de41919e0a88263a4c5b9815f95aa668bb38080808080808080",
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
		if i == 2 {
			nodePathPrefixLength[i] = 1
			nodeTypes[i] = 1
		} else {
			nodePathPrefixLength[i] = 0
			nodeTypes[i] = 0
		}
	}

	output := 1

	witness := core.TransactionMptCircuit{
		Key:               keyRlpHex,
		KeyLength:         frontend.Variable(4),
		Value:             valueRlpHex,
		RootHash:          rootHashHex,
		KeyFragmentStarts: keyFragmentStarts,
		// LeafRlp:              paddedLeafRlpHex,
		LeafPathPrefixLength: leafPathPrefixLength,
		// LeafRlpRoundIndex:    leafRlpRoundIndex,
		NodeRlp:              nodeRlp,
		NodePathPrefixLength: nodePathPrefixLength,
		NodeTypes:            nodeTypes,
		NodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		Depth:                depth,
		Output:               output,
		// OutputValueLength:    valueHexLen,
	}
	return witness
}

func GetTransactionProofWitness() core.TxHashCheckCircuit {
	depth := 5

	ec, err := ethclient.Dial("https://ethereum.blockpi.network/v1/rpc/public")
	if err != nil {
		log.Fatalln(err)
	}

	//bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(17066168))
	bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(17086605)) // 137 transactions, with ext nodes
	//bk, err := ec.BlockByNumber(context.Background(), new(big.Int).SetUint64(14194126)) // sunyi
	if err != nil {
		log.Fatal(err)
	}

	nodes, indexBuff, _, err := common.GetTransactionProof(bk, 133)
	leafnode := fmt.Sprintf("%x", nodes[len(nodes)-1])

	//keyRlpHexString := "8185" // 133
	keyRlpHexString := hex.EncodeToString(indexBuff)

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

	leafRlpHexString := "0x" + leafnode
	//fmt.Printf("leafRlpHexString: %s\n", leafRlpHexString)

	//leafRlpHexString := "0xf901db20b901d702f901d30181b48405f5e100850faf9e23de830962b494c36442b4a4522e871399cd717abdd847ab11fe8880b90164883164560000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000002710fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27660fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9ad400000000000000000000000000000000000000000024c98fcd63f9edd999c2bbe0000000000000000000000000000000000000000000000000000000023c34600000000000000000000000000000000000000000002490b8629cad414ed17c31a0000000000000000000000000000000000000000000000000000000023ac5b490000000000000000000000006880129a290043e85eb6c67c3838d961a85956790000000000000000000000000000000000000000000000000000000064410203c080a0f78c707ba62590c6e4b222ea33c73c585ac7b1179397adf5aa0f80c7c0b63045a01a60736f6bc0effd5005723ae22f65ef92749eebbeed222f7149a8f091ef82bc"
	// pad leaf,And convert it to nibbles
	leafRlpBytes, _ := hexutil.Decode(leafRlpHexString)
	paddedLeafRlpBytes := keccak.Pad101Bytes(leafRlpBytes)

	var paddedLeafRlpHex [272 * core.TransactionProofKeccakRounds]frontend.Variable
	for i, b := range paddedLeafRlpBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedLeafRlpHex[i*2] = n1
		paddedLeafRlpHex[i*2+1] = n2
	}

	for i := len(paddedLeafRlpBytes) * 2; i < 272*core.TransactionProofKeccakRounds; i++ {
		paddedLeafRlpHex[i] = 0
	}

	// leafRlpRoundIndex := keccak.GetKeccakRoundIndex(len(leafRlpHexString) - 2)

	// get decodevalue
	input, err := hexutil.Decode(leafRlpHexString)
	if err != nil {
		log.Error("Failed to decode node rlp", leafRlpHexString, err.Error())
	}
	var decodeValue [][]byte
	err = rlp.Decode(bytes.NewReader(input), &decodeValue)

	if err != nil {
		log.Error("Failed to decode", err)
	}
	prefixKey := hex.EncodeToString(decodeValue[0])

	var keyNibblesHexString string
	if prefixKey[0] == '2' {
		keyNibblesHexString = ""
	} else {
		keyNibblesHexString = string(prefixKey[1])
	}
	keyNibblesLen := len(keyNibblesHexString)
	var keyNibbles [core.TransactionLeafMaxKeyHexLen]frontend.Variable

	for i := 0; i < core.TransactionLeafMaxKeyHexLen; i++ {
		if i < keyNibblesLen {
			intValue, _ := strconv.ParseInt(string(keyNibblesHexString[i]), 16, 64)
			keyNibbles[i] = intValue
		} else {
			keyNibbles[i] = 0
		}
	}

	// transaction rlp
	valueHexString := hex.EncodeToString(decodeValue[1])
	//valueHexString := "02f901d30181b48405f5e100850faf9e23de830962b494c36442b4a4522e871399cd717abdd847ab11fe8880b90164883164560000000000000000000000006982508145454ce325ddbe47a25d4ec3d2311933000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000000000000000000000000000000000000000002710fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27660fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff9ad400000000000000000000000000000000000000000024c98fcd63f9edd999c2bbe0000000000000000000000000000000000000000000000000000000023c34600000000000000000000000000000000000000000002490b8629cad414ed17c31a0000000000000000000000000000000000000000000000000000000023ac5b490000000000000000000000006880129a290043e85eb6c67c3838d961a85956790000000000000000000000000000000000000000000000000000000064410203c080a0f78c707ba62590c6e4b222ea33c73c585ac7b1179397adf5aa0f80c7c0b63045a01a60736f6bc0effd5005723ae22f65ef92749eebbeed222f7149a8f091ef82bc"

	valueHexLen := len(valueHexString)
	var values [core.TransactionLeafMaxValueHexLen]frontend.Variable
	for i := 0; i < core.TransactionLeafMaxValueHexLen; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueHexString[i]), 16, 64)
			values[i] = intValue
		} else {
			values[i] = 0
		}
	}

	// mpt
	rootHashHexString := "e50d3bfc93e56bdd7bf37bc1f5a867cbcc6a302cce3f154284650d95eda84e7a"
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

	/// Proofs without leaf level ---> accountProof[0:len(accountProof) - 1]
	nodeRlpHexStrings := []string{
		"0xf90131a006008e02e7886bf6c0e7bd73eefa0ba26c766046ee8eece0f1c38bb9d9eb3c6fa038c9de1239ebe8d0e9a91e02a5bf9a3bb0372cf80c20819366d852535ce717b8a0253385bbce2eab34ceb4d7bc3312d28d9c6ecbc2d20b4910ce3df731b7deefe2a0553b104a26dd0c7ad9159f4c243ba0f4564d3f72c30de9bbdd075fdfd3790ecaa00b7b069891b326e9dde48ed4896235650b0ca8829cf38893580bfe7021ae7d36a0c44446d7737423a1a45671ee07c515d102553c34969b6aa5510a0ab6c5396887a0f05cc96fd00d1b1c1bb735dd87040b91d8781bac75ac1196e3b01528177a5de9a014f5fb08cb0fec22a0e53b05cb606e7ec548e54fd983be9caee17f21b9b3add0a0dc57057e2ce6e3899024ac5884cc356622bf8be9ace97343516f0a3ef5a5c92d8080808080808080",
		"0xf851a08224f6bc371cd67f0801233068fff38ef6ac8d7767ba4b6e158019bb5175fad7a02f898539c66cf98e349d9c3df1b5354c78d2b43f306d7f4daf546d77ca9b1552808080808080808080808080808080",
		"0xe218a0caae4562211293571e9d837d4b2f1ad36566f5540b20b518e315d581623845c7",
		"0xf90131a093ce4f2441373b4033c87bd5a60e4cf50bb66ee9c0cd0463174c8b48d4f8021ba00f6457cc3175d8d28686ade17c46a977cb87a9be833b3127eb824be51f0c3872a052e18f40076d468b0ddb0a561ba8aa0f7303fdfbede920c4a9fcee67af088d58a0bfe5adeea0914e9e24037af8daa1ee890131819d77a40113e8f4c40898abbc78a0425e844c3ca2380fdd0c6b6902fa7d570d0efce6d00e4df7361058db2a84b023a0958c0c028b7a8fe0a3d5961620582cad1f557604937a104f77246246118a24c7a0f6fa22ff5962dfbe5ed810ec2ee72e3bebb708384b2869ae8fb0e6d168cbd387a02293143368314d71deeb53f975d8adcdbfd19b024c77886a566db2ec79f3d665a09e0afa2325a04bae0b2b30ce5d3d4de41919e0a88263a4c5b9815f95aa668bb38080808080808080",
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
		if i == 2 {
			nodePathPrefixLength[i] = 1
			nodeTypes[i] = 1
		} else {
			nodePathPrefixLength[i] = 0
			nodeTypes[i] = 0
		}
	}

	blockHash := "0x88bd78528ea4fd5c232978ce51e43f41f0d76ce56e331147c1c9611282308799"
	hashRootBytes, _ := hexutil.Decode(blockHash)
	var hashRootPiece [2]frontend.Variable
	hashRootPiece[0] = hashRootBytes[0:16]
	hashRootPiece[1] = hashRootBytes[16:32]

	// ================ block header test data ======================
	blockRlpHex := "0xf90232a0e4fe56dbd9524d926dcad94a9822d55117ec2e7bbd8ef422b6f73bb577744d04a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a0ad49c89b24dcab9c78b764498b5b03bd38ff58da63cc498857d9b01ac8803b34a0e50d3bfc93e56bdd7bf37bc1f5a867cbcc6a302cce3f154284650d95eda84e7aa0a3b2a40fcccf0c76cf04c72d926218d8433ba48d4ecca22f9fca9d17f28da553b9010045a107017a0008803025742081140723706255031219284a09898000149319220c1033c109211a27cbb053d490331f0f8aa183089803bb8e06884236107a5180b340c4fadf9588ad681a462fca3208a8d384201045c8b880351a4e6e80c03205131a042813024aa083d01828a2103f55462201050c108c09f240975640d89185383b87503a1090403448210a809004095480249189400008492761626810102cab0e01021802a6873d8760e707f07c8b1c9c020261ee001680072d0701400422c59800122101803064048c1a04a14230c3c103c29408327730d559020100b02202bab3ac8b0004aa8204048481b5083097740e88091c0bc540501623d0003e5380840104b88d8401c9c380838b8786846440fb138f6265617665726275696c642e6f7267a036048306130c4dbd88c44a8312b9a647d3795ab9adc6066dfe1dd438c1fea411880000000000000000850bff0c9cb8a033a1ad772c352e8d7bf81bdd3fb803d3535b34f11ade0031789963dd0b6b109f"
	rlpBytes, _ := hexutil.Decode(blockRlpHex)
	paddedRlpBytes := keccak.Pad101Bytes(rlpBytes)

	var blockHeadRlpAsNibbles [mpt.EthBlockHeadMaxBlockHexSize]frontend.Variable
	for i, b := range paddedRlpBytes {
		blockHeadRlpAsNibbles[i*2] = b >> 4
		blockHeadRlpAsNibbles[i*2+1] = b & 0x0F
	}

	blkTime, _ := strconv.ParseInt("6440fb13", 16, 64)
	blkNumber, _ := strconv.ParseInt("0104B88D", 16, 64)

	witness := core.TxHashCheckCircuit{

		Key:               keyRlpHex,
		KeyLength:         frontend.Variable(keyHexLen),
		RootHash:          rootHashHex,
		KeyFragmentStarts: keyFragmentStarts,
		// LeafRlpRoundIndex:    leafRlpRoundIndex,
		NodeRlp:              nodeRlp,
		NodePathPrefixLength: nodePathPrefixLength,
		NodeTypes:            nodeTypes,
		NodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		Depth:                depth,
		// OutputValueLength:    valueHexLen,

		BlockHash:    hashRootPiece,
		BlockHashRlp: blockHeadRlpAsNibbles,

		BlockTime:   blkTime,
		BlockNumber: blkNumber,
	}
	return witness
}
