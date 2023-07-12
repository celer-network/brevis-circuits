package core

import (
	"math"
	"math/big"

	espcore "github.com/celer-network/brevis-circuits/fabric/eth-storage-proof/core"
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/celer-network/brevis-circuits/gadgets/rlp"

	"github.com/consensys/gnark/frontend"
)

const (
	ReceiptMPTProofMaxDepth     = 6
	ReceiptMPTRootHashLength    = 64
	ReceiptMPTProofKeyMaxLength = 6
)

type ReceiptProofCircuit struct {
	LeafHash    [2]frontend.Variable `gnark:",public"`
	BlockHash   [2]frontend.Variable `gnark:",public"`
	BlockNumber frontend.Variable    `gnark:",public"`
	BlockTime   frontend.Variable    `gnark:",public"`
	// mpt
	Key                  [ReceiptMPTProofKeyMaxLength]frontend.Variable
	KeyLength            frontend.Variable
	RootHash             [ReceiptMPTRootHashLength]frontend.Variable
	KeyFragmentStarts    [ReceiptMPTProofMaxDepth]frontend.Variable
	NodeRlp              [ReceiptMPTProofMaxDepth - 1][272 * 4]frontend.Variable
	NodeRlpRoundIndexes  [ReceiptMPTProofMaxDepth - 1]frontend.Variable
	NodePathPrefixLength [ReceiptMPTProofMaxDepth - 1]frontend.Variable
	NodeTypes            [ReceiptMPTProofMaxDepth - 1]frontend.Variable
	Depth                frontend.Variable

	BlockHashRlp    [mpt.EthBlockHeadMaxBlockHexSize]frontend.Variable
	BlockFieldsNum  frontend.Variable // block heard fields number
	BlockRoundIndex frontend.Variable
}

func (c *ReceiptProofCircuit) Define(api frontend.API) error {
	// mpt
	var nodeRlp [][]frontend.Variable
	for i := 0; i < len(c.NodeRlp); i++ {
		nodeRlp = append(nodeRlp, c.NodeRlp[i][:])
	}

	result := mpt.CheckMPTInclusionNoBranchTermination(
		api,
		ReceiptMPTProofMaxDepth,
		ReceiptMPTProofKeyMaxLength,
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

	api.AssertIsEqual(result.Output, 1)

	rlpBlockHashResult := mpt.CheckEthBlockHash(api, c.BlockHashRlp, c.BlockFieldsNum, c.BlockRoundIndex)
	blockHashNibbles := espcore.Recompose32ByteToNibbles(api, c.BlockHash)
	blockHashEqual := rlp.ArrayEqual(api, blockHashNibbles[:], rlpBlockHashResult.BlockHash[:], 64, 64)
	api.AssertIsEqual(blockHashEqual, 1)

	for i := 0; i < 64; i++ {
		api.AssertIsEqual(c.RootHash[i], rlpBlockHashResult.ReceiptsRoot[i])
	}

	blockNumberShift := rlp.ShiftRight(api, 8, 3, rlpBlockHashResult.BlockNumber[:], api.Sub(8, rlpBlockHashResult.BlockNumberLength))
	var blockNumber = frontend.Variable(0)
	for i := 0; i < 8; i++ {
		blockNumber = api.Add(blockNumber, api.Mul(blockNumberShift[i], big.NewInt(int64(math.Pow(16, float64(7-i))))))
	}
	api.AssertIsEqual(blockNumber, c.BlockNumber)

	var blkTimeSlice []frontend.Variable
	for i := 0; i < 8; i++ {
		blkTimeSlice = append(blkTimeSlice, api.ToBinary(rlpBlockHashResult.BlockTime[7-i], 4)...)
	}
	api.AssertIsEqual(api.FromBinary(blkTimeSlice...), c.BlockTime)

	return nil
}
