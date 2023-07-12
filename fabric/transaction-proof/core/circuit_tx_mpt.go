package core

import (
	"github.com/celer-network/brevis-circuits/gadgets/mpt"

	"github.com/consensys/gnark/frontend"
)

const TransactionMaxKeyHexLen = 6
const TransactionProofKeccakRounds = 13

const TransactionLeafMaxHexLen = 272 * TransactionProofKeccakRounds  //15000
const TransactionLeafMaxValueHexLen = TransactionLeafMaxHexLen - 170 //14830
const TransactionMPTMaxDepth = 6

type TransactionMptCircuit struct {
	Key                  [TransactionMaxKeyHexLen]frontend.Variable
	KeyLength            frontend.Variable
	Value                [TransactionLeafMaxValueHexLen]frontend.Variable
	RootHash             [64]frontend.Variable
	KeyFragmentStarts    [TransactionMaxKeyHexLen]frontend.Variable
	LeafHash             [2]frontend.Variable
	LeafPathPrefixLength frontend.Variable
	NodeRlp              [TransactionMPTMaxDepth - 1][272 * 4]frontend.Variable
	NodeRlpRoundIndexes  [TransactionMPTMaxDepth - 1]frontend.Variable
	NodePathPrefixLength [TransactionMPTMaxDepth - 1]frontend.Variable
	NodeTypes            [TransactionMPTMaxDepth - 1]frontend.Variable
	Depth                frontend.Variable
	Output               frontend.Variable
}

func (c *TransactionMptCircuit) Define(api frontend.API) error {
	var nodeRlp [][]frontend.Variable
	for i := 0; i < len(c.NodeRlp); i++ {
		nodeRlp = append(nodeRlp, c.NodeRlp[i][:])
	}

	result := mpt.CheckMPTInclusionNoBranchTermination(
		api,
		TransactionMPTMaxDepth,
		TransactionMaxKeyHexLen,
		c.Key[:],
		c.KeyLength,
		c.RootHash,
		c.KeyFragmentStarts[:],
		c.LeafHash,
		nodeRlp,
		c.NodeRlpRoundIndexes[:],
		c.NodePathPrefixLength[:],
		c.NodeTypes[:],
		c.Depth,
	)

	api.AssertIsEqual(result.Output, c.Output)
	return nil
}
