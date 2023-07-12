package core

import (
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/consensys/gnark/frontend"
)

type AccountProofCircuit struct {
	// Input
	StateRoot            [64]frontend.Variable `gnark:",public"`
	AddressHash          [64]frontend.Variable `gnark:",public"`
	KeyFragmentStarts    [mpt.AccountMPTMaxDepth]frontend.Variable
	AddressRlp           [228]frontend.Variable
	LeafRlp              [272 * 2]frontend.Variable // maxRlpLength = 304 ===> 272 * 2
	LeafRoundIndex       frontend.Variable
	LeafPathPrefixLength frontend.Variable
	NodeRlp              [mpt.AccountMPTMaxDepth - 1][272 * 4]frontend.Variable
	NodeRlpRoundIndexes  [mpt.AccountMPTMaxDepth - 1]frontend.Variable
	NodePathPrefixLength [mpt.AccountMPTMaxDepth - 1]frontend.Variable
	NodeTypes            [mpt.AccountMPTMaxDepth - 1]frontend.Variable
	Depth                frontend.Variable

	// Output
	StorageRoot [64]frontend.Variable `gnark:",public"`
}

func (c *AccountProofCircuit) Define(api frontend.API) error {
	var nodeRlp [][]frontend.Variable
	for i := 0; i < len(c.NodeRlp); i++ {
		nodeRlp = append(nodeRlp, c.NodeRlp[i][:])
	}
	result := mpt.CheckEthAccountProof(
		api,
		mpt.AccountMPTMaxDepth,
		c.StateRoot,
		c.AddressHash,
		c.KeyFragmentStarts[:],
		c.AddressRlp,
		c.LeafRlp[:],
		c.LeafRoundIndex,
		c.LeafPathPrefixLength,
		nodeRlp,
		c.NodeRlpRoundIndexes[:],
		c.NodePathPrefixLength[:],
		c.NodeTypes[:],
		c.Depth,
	)

	for i := 0; i < 64; i++ {
		api.AssertIsEqual(result.StorageRoot[i], c.StorageRoot[i])
	}

	return nil
}
