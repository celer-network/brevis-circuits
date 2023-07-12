package headerutil

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/celer-network/brevis-circuits/gadgets/keccak"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

func EncodeHeaders(headers []types.Header, dummyHeaders bool) (encoded [][]frontend.Variable, idxs []frontend.Variable, err error) {
	for i, header := range headers {
		ok := checkDynamicFieldLen(header)
		if !ok {
			return nil, nil, fmt.Errorf("dynamic field len check failed %+v", header)
		}
		if i > 0 && dummyHeaders {
			header.ParentHash = headers[i-1].Hash()
		}
		headerRLP, encodeError := rlp.EncodeToBytes(&header)

		if encodeError != nil {
			err = encodeError
			return
		}
		padded := keccak.Pad101Bytes(headerRLP)
		paddedBits := keccak.Bytes2BlockBits(padded)
		fv := []frontend.Variable{}
		for _, b := range paddedBits {
			fv = append(fv, b)
		}
		idxs = append(idxs, len(fv)/1088-1)
		zerosToPad := 5*1088 - len(paddedBits)
		for i := 0; i < zerosToPad; i++ {
			fv = append(fv, 0)
		}
		encoded = append(encoded, fv)
	}
	return
}

func ComputeChunkRoot(headers []types.Header) ([]byte, error) {
	var hashes [][]byte
	for _, h := range headers {
		hash := h.Hash()
		hashes = append(hashes, hash[:])
	}
	return keccakMerkleRoot(hashes)
}

func Hash2FV(h []byte) [2]frontend.Variable {
	return [2]frontend.Variable{
		new(big.Int).SetBytes(h[:16]),
		new(big.Int).SetBytes(h[16:]),
	}
}

func checkDynamicFieldLen(h types.Header) bool {
	hasErr := 0
	hasErr += checkLen("Difficulty", len(h.Difficulty.Bytes()), 7)
	hasErr += checkLen("Number", len(h.Number.Bytes()), 8)
	hasErr += checkLen("GasLimit", getUintByteLen(h.GasLimit), 4)
	hasErr += checkLen("GasUsed", getUintByteLen(h.GasUsed), 4)
	hasErr += checkLen("Time", getUintByteLen(h.Time), 4)
	hasErr += checkLen("BaseFee", len(h.BaseFee.Bytes()), 7)
	return hasErr == 0
}

func getUintByteLen(x uint64) int {
	i := 0
	for x > 0 {
		x /= 256
		i++
	}
	return i
}

func checkLen(field string, actual, max int) int {
	if actual > max {
		fmt.Println(fmt.Errorf("field %s len actual %d > max %d", field, actual, max))
		return 1
	}
	return 0
}

func keccakMerkleRoot(leaves [][]byte) ([]byte, error) {
	var hashes [][]byte
	if len(leaves) == 1 {
		return leaves[0], nil
	}

	if len(leaves)%2 == 1 {
		log.Error("Leaves length is odd to get keccak merkle root", len(leaves))
		errorMessage := fmt.Sprintf("Leaves length should be even: %d", len(leaves))
		err := errors.New(errorMessage)
		return []byte{}, err
	}
	for i := 0; i < len(leaves); i += 2 {
		data := append([]byte{}, leaves[i]...)
		data = append(data, leaves[i+1]...)
		hash := sha3.NewLegacyKeccak256()
		_, err := hash.Write(data)
		if err != nil {
			log.Errorf("Failed to write hash %s\n", err.Error())
			return []byte{}, err
		}
		hashes = append(hashes, hash.Sum(nil))
	}
	return keccakMerkleRoot(hashes)
}
