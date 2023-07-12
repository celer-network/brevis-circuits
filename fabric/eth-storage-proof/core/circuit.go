package core

import (
	"github.com/celer-network/brevis-circuits/gadgets/mpt"

	"github.com/consensys/gnark/frontend"
)

type EthAddressStorageProof struct {
	BlockHash                   [2]frontend.Variable `gnark:",public"`
	AddressProofKey             [2]frontend.Variable `gnark:",public"` // padded address hash
	Slot                        [2]frontend.Variable `gnark:",public"`
	SlotValue                   [2]frontend.Variable `gnark:",public"`
	BlockNumber                 frontend.Variable    `gnark:",public"`
	BlockHashRlp                [mpt.EthBlockHeadMaxBlockHexSize]frontend.Variable
	BlockRlpFieldNum            frontend.Variable
	BlockRoundIndex             frontend.Variable
	AddressKeyFragmentStarts    [mpt.AccountMPTMaxDepth]frontend.Variable // [addressMaxDepth]
	AddressRlp                  [mpt.MaxValueLengthForAccount]frontend.Variable
	AddressLeafRlp              [mpt.StorageLeafMaxBlockHexLen * 2]frontend.Variable // [addressMaxLeafRlpLength]
	AddressLeafRoundIndex       frontend.Variable
	AddressLeafPathPrefixLength frontend.Variable
	AddressNodeRlp              [mpt.AccountMPTMaxDepth - 1][mpt.StorageLeafMaxBlockHexLen * 4]frontend.Variable // [addressMaxDepth - 1][addressMaxBranchRlpLength]
	AddressNodeRlpRoundIndexes  [mpt.AccountMPTMaxDepth - 1]frontend.Variable
	AddressNodePathPrefixLength [mpt.AccountMPTMaxDepth - 1]frontend.Variable // [addressMaxDepth - 1]
	AddressNodeTypes            [mpt.AccountMPTMaxDepth - 1]frontend.Variable // [addressMaxDepth - 1]
	AddressDepth                frontend.Variable
	StorageKeyFragmentStarts    [mpt.StorageMPTMaxDepth]frontend.Variable // [storageMaxDepth]
	StorageValueRlp             [66]frontend.Variable
	StorageLeafRlp              [mpt.StorageLeafMaxBlockHexLen]frontend.Variable // [storageMaxLeafRlpLength]
	StorageLeafRoundIndex       frontend.Variable
	StorageLeafPathPrefixLength frontend.Variable
	StorageNodeRlp              [mpt.StorageMPTMaxDepth - 1][mpt.StorageLeafMaxBlockHexLen * 4]frontend.Variable // [storageMaxDepth - 1][storageMaxBranchRlpLength]
	StorageNodeRlpRoundIndex    [mpt.StorageMPTMaxDepth - 1]frontend.Variable
	StorageNodePathPrefixLength [mpt.StorageMPTMaxDepth - 1]frontend.Variable // [storageMaxDepth - 1]
	StorageNodeTypes            [mpt.StorageMPTMaxDepth - 1]frontend.Variable // [storageMaxDepth - 1]
	StorageProofDepth           frontend.Variable
}

func Recompose32ByteToNibbles(api frontend.API, trunk [2]frontend.Variable) [64]frontend.Variable {
	var trunkBits []frontend.Variable
	for i := 0; i < 2; i++ {
		bs := api.ToBinary(trunk[1-i], 128)
		trunkBits = append(trunkBits, bs...)
	}

	var nibbles [64]frontend.Variable
	for i := 0; i < 64; i++ {
		nibbles[i] = api.FromBinary(trunkBits[i*4 : (i+1)*4]...)
	}
	for i, j := 0, 64-1; i < j; i, j = i+1, j-1 {
		nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
	}
	return nibbles
}

func (c *EthAddressStorageProof) Define(api frontend.API) error {

	var addressNodeRlp [][]frontend.Variable
	for i := 0; i < len(c.AddressNodeRlp); i++ {
		addressNodeRlp = append(addressNodeRlp, c.AddressNodeRlp[i][:])
	}

	var storageNodeRlp [][]frontend.Variable
	for i := 0; i < len(c.StorageNodeRlp); i++ {
		storageNodeRlp = append(storageNodeRlp, c.StorageNodeRlp[i][:])
	}
	api.Println("BlockHash[0]:", c.BlockHash[0])
	api.Println("BlockHash[1]:", c.BlockHash[1])

	// recompose block hash to 64 frontend.variable
	blockHashNibbles := Recompose32ByteToNibbles(api, c.BlockHash)
	// fmt.Printf("blockHashNibbles:%v", blockHashNibbles)

	// recompose AddressProofKey
	api.Println("AddressProofKey[0]:", c.AddressProofKey[0])
	api.Println("AddressProofKey[1]:", c.AddressProofKey[1])
	addressProofKeyNibbles := Recompose32ByteToNibbles(api, c.AddressProofKey)

	api.Println("Slot[0]:", c.Slot[0])
	api.Println("Slot[1]:", c.Slot[1])
	slotNibbles := Recompose32ByteToNibbles(api, c.Slot)

	api.Println("Slot Value[0]", c.SlotValue[0])
	api.Println("Slot Value[1]", c.SlotValue[1])

	api.Println("BlockNumber", c.BlockNumber)

	var result = mpt.CheckEthAddressStorageProof(api,
		9,
		8,
		blockHashNibbles,
		c.BlockRlpFieldNum,
		c.BlockRoundIndex,
		addressProofKeyNibbles,
		slotNibbles,
		c.BlockHashRlp,
		c.AddressKeyFragmentStarts[:],
		c.AddressRlp,
		c.AddressLeafRlp[:],
		c.AddressLeafRoundIndex,
		c.AddressLeafPathPrefixLength,
		addressNodeRlp,
		c.AddressNodeRlpRoundIndexes,
		c.AddressNodePathPrefixLength[:],
		c.AddressNodeTypes[:],
		c.AddressDepth,
		c.StorageKeyFragmentStarts[:],
		c.StorageValueRlp,
		c.StorageLeafRlp[:],
		c.StorageLeafRoundIndex,
		c.StorageLeafPathPrefixLength,
		storageNodeRlp,
		c.StorageNodeRlpRoundIndex[:],
		c.StorageNodePathPrefixLength[:],
		c.StorageNodeTypes[:],
		c.StorageProofDepth,
	)
	api.AssertIsEqual(result.Output, 1)

	api.AssertIsEqual(c.BlockNumber, result.BlockNumber)

	for i := 0; i < 2; i++ {
		api.AssertIsEqual(c.SlotValue[i], result.SlotValue[i])
	}

	return nil
}
