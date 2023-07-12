package core

import (
	"github.com/celer-network/brevis-circuits/gadgets/rlp"
	"github.com/consensys/gnark/frontend"
)

const (
	MaxTxRlpHexLen  = 15000
	TxDataMaxHexLen = 14830 // MaxTxRlpHexLen - 170
)

type TransactionRlpCircuit struct {
	Nonce    [64]frontend.Variable              `gnark:",public"`
	GasPrice [64]frontend.Variable              `gnark:",public"`
	Gas      [64]frontend.Variable              `gnark:",public"`
	To       [40]frontend.Variable              `gnark:",public"`
	Value    [64]frontend.Variable              `gnark:",public"`
	Data     [TxDataMaxHexLen]frontend.Variable `gnark:",public"`
	V        [2]frontend.Variable               `gnark:",public"`
	R        [64]frontend.Variable              `gnark:",public"`
	S        [64]frontend.Variable              `gnark:",public"`

	TxRlpHexLen      frontend.Variable
	TxRlp            [MaxTxRlpHexLen]frontend.Variable
	TxRlpFieldHexLen [9]frontend.Variable
}

func (c *TransactionRlpCircuit) Define(api frontend.API) error {
	maxTxRlpHexLen := 15000
	maxArrayPrefix1HexLen := 2 * (rlp.LogCeil(maxTxRlpHexLen)/8 + 1)
	arrayCheckParamsTxRlp0 := &rlp.ArrayCheck{
		MaxHexLen:            15000, // TODO
		MaxFields:            9,
		ArrayPrefixMaxHexLen: maxArrayPrefix1HexLen,
		FieldMinHexLen:       []int{0, 0, 0, 40, 0, 0, 0, 64, 64},
		FieldMaxHexLen:       []int{64, 64, 64, 40, 64, TxDataMaxHexLen, 2, 64, 64},
	}

	out, txRlpHexLen, fieldHexLens, fields := arrayCheckParamsTxRlp0.RlpArrayCheck(api, c.TxRlp[:])
	api.AssertIsEqual(out, 1)
	api.AssertIsEqual(txRlpHexLen, c.TxRlpHexLen)
	api.AssertIsEqual(len(fieldHexLens), 9)
	for i, d := range fieldHexLens {
		api.AssertIsEqual(d, c.TxRlpFieldHexLen[i])
	}

	rlp.ArrayEqual(api, fields[0], c.Nonce[:], 64, fieldHexLens[0])
	rlp.ArrayEqual(api, fields[1], c.GasPrice[:], 64, fieldHexLens[1])
	rlp.ArrayEqual(api, fields[2], c.Gas[:], 64, fieldHexLens[2])
	rlp.ArrayEqual(api, fields[3], c.To[:], 40, fieldHexLens[3])
	rlp.ArrayEqual(api, fields[4], c.Value[:], 64, fieldHexLens[4])
	rlp.ArrayEqual(api, fields[5], c.Data[:], TxDataMaxHexLen, fieldHexLens[5])
	rlp.ArrayEqual(api, fields[6], c.V[:], 2, fieldHexLens[6])
	rlp.ArrayEqual(api, fields[7], c.R[:], 64, fieldHexLens[7])
	rlp.ArrayEqual(api, fields[8], c.S[:], 64, fieldHexLens[8])

	return nil
}
