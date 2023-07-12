package core

import (
	"math"
	"math/big"

	espcore "github.com/celer-network/brevis-circuits/fabric/eth-storage-proof/core"

	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/celer-network/brevis-circuits/gadgets/rlp"

	"github.com/consensys/gnark/frontend"
)

const TransactionLeafMaxKeyHexLen = 64

type TxHashCheckCircuit struct {
	// verify block header(hash)
	LeafHash    [2]frontend.Variable `gnark:",public"` // hashed(keccak256) rlp leaf
	BlockHash   [2]frontend.Variable `gnark:",public"`
	BlockNumber frontend.Variable    `gnark:",public"`
	BlockTime   frontend.Variable    `gnark:",public"`

	// mpt
	Key                  [TransactionMaxKeyHexLen]frontend.Variable
	KeyLength            frontend.Variable
	RootHash             [64]frontend.Variable
	KeyFragmentStarts    [TransactionMPTMaxDepth]frontend.Variable
	NodeRlp              [TransactionMPTMaxDepth - 1][272 * 4]frontend.Variable
	NodeRlpRoundIndexes  [TransactionMPTMaxDepth - 1]frontend.Variable
	NodePathPrefixLength [TransactionMPTMaxDepth - 1]frontend.Variable
	NodeTypes            [TransactionMPTMaxDepth - 1]frontend.Variable
	Depth                frontend.Variable

	BlockHashRlp    [mpt.EthBlockHeadMaxBlockHexSize]frontend.Variable
	BlockFieldsNum  frontend.Variable // block header fields number
	BlockRoundIndex frontend.Variable
}

func (c *TxHashCheckCircuit) Define(api frontend.API) error {

	// mpt
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

	api.AssertIsEqual(result.Output, 1)

	rlpBlockHashResult := mpt.CheckEthBlockHash(api, c.BlockHashRlp, c.BlockFieldsNum, c.BlockRoundIndex)

	// rlpBlockHashResult.
	blockHashNibbles := espcore.Recompose32ByteToNibbles(api, c.BlockHash)
	blockHashEqual := rlp.ArrayEqual(api, blockHashNibbles[:], rlpBlockHashResult.BlockHash[:], 64, 64)
	api.AssertIsEqual(blockHashEqual, 1)

	for i := 0; i < 64; i++ {
		api.AssertIsEqual(c.RootHash[i], rlpBlockHashResult.TransactionsRoot[i])
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
