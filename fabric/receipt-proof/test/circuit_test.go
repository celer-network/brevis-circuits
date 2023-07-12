package test

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/core"
	"github.com/celer-network/brevis-circuits/fabric/receipt-proof/util"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/iden3/go-iden3-crypto/keccak256"
)

func TestGenerateReceiptMPTProof(t *testing.T) {
	assert := test.NewAssert(t)

	transactionHash := "0xcde39c41dce4a10417e5a268ae5cc608816547650b413a1ac182971f02399443"

	receiptProofData, err := util.GenerateReceiptMPTProof("https://ethereum.blockpi.network/v1/rpc/public", transactionHash)
	log.Infof("Proofs %+v", receiptProofData.MPTProofs)

	assert.NoError(err)

	for i := 0; i < len(receiptProofData.MPTProofs)-1; i++ {
		currentRlp := hexutil.MustDecode(receiptProofData.MPTProofs[i])
		var decoded [][]byte
		err = rlp.Decode(bytes.NewReader(currentRlp), &decoded)
		assert.NoError(err)

		nextRlpKeccak := keccak256.Hash(hexutil.MustDecode(receiptProofData.MPTProofs[i+1]))

		for indexx, valuexxx := range decoded {
			log.Infof("value %d : %s\n", indexx, hexutil.Encode(valuexxx))
		}

		if len(decoded) == 17 {
			if len(receiptProofData.MPTKey) == 0 {
				assert.Equal(hexutil.Encode(nextRlpKeccak), hexutil.Encode(decoded[0]))
			} else {
				nibble, err := strconv.Atoi(receiptProofData.MPTKey[i : i+1])
				assert.NoError(err)

				assert.Equal(nextRlpKeccak, decoded[nibble])
			}
		} else if len(decoded) == 2 {

		} else {
			assert.Fail("Rlp decoded length not matched ", len(decoded))
		}
	}
}

func TestReceiptCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	transactionHash := "0xcde39c41dce4a10417e5a268ae5cc608816547650b413a1ac182971f02399443"

	witness, err := util.GenerateReceiptCircuitProofWitness("https://ethereum.blockpi.network/v1/rpc/public", transactionHash)
	assert.NoError(err)

	err = test.IsSolved(&core.ReceiptProofCircuit{}, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
