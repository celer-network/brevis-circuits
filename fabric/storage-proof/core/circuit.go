package core

import (
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/consensys/gnark/frontend"
)

type StorageProofCircuit struct {
	StorageRoot          [64]frontend.Variable                        `gnark:",public"`
	SlotHash             [64]frontend.Variable                        `gnark:",public"`
	Value                [mpt.StorageMaxValueLength]frontend.Variable `gnark:",public"`
	KeyFragmentStarts    [mpt.StorageMPTMaxDepth]frontend.Variable
	LeafRlp              [mpt.StorageLeafMaxBlockHexLen]frontend.Variable
	LeafRlpRoundIndex    frontend.Variable
	LeafPathPrefixLength frontend.Variable
	NodeRlp              [mpt.StorageMPTMaxDepth - 1][272 * 4]frontend.Variable
	NodeRoundIndexes     [mpt.StorageMPTMaxDepth - 1]frontend.Variable
	NodePathPrefixLength [mpt.StorageMPTMaxDepth - 1]frontend.Variable
	NodeTypes            [mpt.StorageMPTMaxDepth - 1]frontend.Variable
	Depth                frontend.Variable

	// Output
	Output      frontend.Variable
	SlotValue   [64]frontend.Variable
	ValueLength frontend.Variable
}

func (c *StorageProofCircuit) Define(api frontend.API) error {
	var nodeRlp [][]frontend.Variable
	for i := 0; i < len(c.NodeRlp); i++ {
		nodeRlp = append(nodeRlp, c.NodeRlp[i][:])
	}
	result := mpt.CheckEthStorageProof(
		api,
		mpt.StorageMPTMaxDepth,
		c.StorageRoot,
		c.SlotHash,
		c.Value,
		c.KeyFragmentStarts[:],
		c.LeafRlp[:],
		c.LeafRlpRoundIndex,
		c.LeafPathPrefixLength,
		nodeRlp,
		c.NodeRoundIndexes[:],
		c.NodePathPrefixLength[:],
		c.NodeTypes[:],
		c.Depth,
	)

	api.AssertIsEqual(result.Output, c.Output)
	api.AssertIsEqual(result.ValueLength, c.ValueLength)

	for i := 0; i < len(c.SlotValue); i++ {
		api.AssertIsEqual(result.SlotValue[i], c.SlotValue[i])
	}

	return nil
}
