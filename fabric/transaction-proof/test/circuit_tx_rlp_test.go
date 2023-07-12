package test

import (
	"strconv"
	"testing"

	"github.com/celer-network/brevis-circuits/fabric/transaction-proof/core"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestTransaction(t *testing.T) {
	assert := test.NewAssert(t)
	/*
		[
			"0x0121",
			"0x060db88400",
			"0x5208",
			"0x5550519d3ded948884ea0337e3524c24955115d2",
			"0xb8fdac5fe7f50000",
			"0x",
			"0x25",
			"0x1c47eb4a492ab4a0bf318e6d0ba95f7338d9c83cba3e9691b8ef025b98b84130",
			"0x355d0e6031059772febe31516068018280cebcbdfe21abf341189909e07dd3fd"
		]
	*/
	nonceStr := "0121"
	gasPriceStr := "060db88400"
	gasStr := "5208"
	toStr := "5550519d3ded948884ea0337e3524c24955115d2"
	valueStr := "b8fdac5fe7f50000"
	dataStr := ""
	vStr := "25"
	rStr := "1c47eb4a492ab4a0bf318e6d0ba95f7338d9c83cba3e9691b8ef025b98b84130"
	sStr := "355d0e6031059772febe31516068018280cebcbdfe21abf341189909e07dd3fd"

	txRlpStr := "f86e82012185060db88400825208945550519d3ded948884ea0337e3524c24955115d288b8fdac5fe7f500008025a01c47eb4a492ab4a0bf318e6d0ba95f7338d9c83cba3e9691b8ef025b98b84130a0355d0e6031059772febe31516068018280cebcbdfe21abf341189909e07dd3fd"

	// FieldMaxHexLen:       []int{64, 64, 64, 40, 64, maxTxRlpHexLen - 170, 2, 64, 64},
	var nonce [64]frontend.Variable
	var gasPrice [64]frontend.Variable
	var gas [64]frontend.Variable
	var to [40]frontend.Variable
	var value [64]frontend.Variable
	var data [core.TxDataMaxHexLen]frontend.Variable
	var v [2]frontend.Variable
	var r [64]frontend.Variable
	var s [64]frontend.Variable

	var txRlp [core.MaxTxRlpHexLen]frontend.Variable

	copy(nonce[:], GetHexArry(nonceStr, 64))
	copy(gasPrice[:], GetHexArry(gasPriceStr, 64))
	copy(gas[:], GetHexArry(gasStr, 64))
	copy(to[:], GetHexArry(toStr, 40))
	copy(value[:], GetHexArry(valueStr, 64))
	copy(data[:], GetHexArry(dataStr, core.TxDataMaxHexLen))
	copy(v[:], GetHexArry(vStr, 2))
	copy(r[:], GetHexArry(rStr, 64))
	copy(s[:], GetHexArry(sStr, 64))

	copy(txRlp[:], GetHexArry(txRlpStr, core.MaxTxRlpHexLen))

	txRlpFieldHexLens := [9]frontend.Variable{len(nonceStr), len(gasPriceStr), len(gasStr), len(toStr), len(valueStr),
		len(dataStr), len(vStr), len(rStr), len(sStr)}

	witness := core.TransactionRlpCircuit{
		Nonce:            nonce,
		GasPrice:         gasPrice,
		Gas:              gas,
		To:               to,
		Value:            value,
		Data:             data,
		V:                v,
		R:                r,
		S:                s,
		TxRlpHexLen:      len(txRlpStr),
		TxRlpFieldHexLen: txRlpFieldHexLens,
		TxRlp:            txRlp,
	}

	err := test.IsSolved(&core.TransactionRlpCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func GetHexArry(hexStr string, maxLen int) (res []frontend.Variable) {
	for i := 0; i < maxLen; i++ {
		if i < len(hexStr) {
			intValue, _ := strconv.ParseInt(string(hexStr[i]), 16, 64)
			res = append(res, intValue)
		} else {
			res = append(res, 0)
		}
	}
	return
}
