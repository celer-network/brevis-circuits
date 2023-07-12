package headers

import (
	"fmt"
	"math/big"

	util "github.com/celer-network/brevis-circuits/fabric/headers/headerutil"

	"github.com/celer-network/goutils/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func NewChunkProofCircuit(count int) *Circuit {
	hs := genHeaders(count)

	headersEncoded, roundIdxs, err := util.EncodeHeaders(hs, true)
	if err != nil {
		fmt.Printf("failed to encode headers: %s\n", err.Error())
		return nil
	}
	root, err := util.ComputeChunkRoot(hs)
	fmt.Printf("chunk root %x\n", root)
	if err != nil {
		log.Errorf("Failed to compute chunk root: %s\n", err.Error())
		return nil
	}
	chunkRoot := util.Hash2FV(root)
	fmt.Printf("prev hash %x\n", hs[0].ParentHash)
	prevHash := util.Hash2FV(hs[0].ParentHash[:])
	eh := hs[len(hs)-1].Hash()
	fmt.Printf("end hash %x\n", eh)
	endHash := util.Hash2FV(eh[:])

	return &Circuit{
		Headers:       headersEncoded,
		ChunkRoot:     chunkRoot,
		PrevHash:      prevHash,
		EndHash:       endHash,
		StartBlockNum: 1,
		EndBlockNum:   4,
		HashRoundIdxs: roundIdxs,
	}
}

func genHeaders(count int) []types.Header {
	hs := []types.Header{}
	prevHash := [32]byte{3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2}
	hs = append(hs, genHeader(prevHash, big.NewInt(1)))
	for i := 1; i < count; i++ {
		h := genHeader(hs[i-1].Hash(), big.NewInt(int64(i+1)))
		hs = append(hs, h)
	}
	return hs
}

func genHeader(parentHash [32]byte, number *big.Int) types.Header {
	n7 := new(big.Int).SetBytes([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	emptyHash := [32]byte{}
	return types.Header{
		ParentHash:      parentHash,
		UncleHash:       emptyHash,
		Coinbase:        [20]byte{},
		Root:            emptyHash,
		TxHash:          emptyHash,
		ReceiptHash:     emptyHash,
		Bloom:           [256]byte{},
		Difficulty:      n7,
		Number:          number,
		GasLimit:        0xffffffff,
		GasUsed:         0xffffffff,
		Time:            0xffffffff,
		Extra:           []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		MixDigest:       emptyHash,
		Nonce:           [8]byte{1, 1, 1, 1, 1, 1, 1, 1},
		BaseFee:         n7,
		WithdrawalsHash: (*common.Hash)(&emptyHash),
	}
}
