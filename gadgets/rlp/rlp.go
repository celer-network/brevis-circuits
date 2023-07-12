package rlp

import (
	"math"

	"github.com/consensys/gnark/frontend"
)

func RlpArrayPrefix(api frontend.API, in [2]frontend.Variable) (frontend.Variable, frontend.Variable, frontend.Variable) {

	//    // if starts with < 'c', then invalid
	lt1 := LessThan(api, in[0], 12)

	// if starts with == 'f'
	eq := api.IsZero(api.Sub(in[0], 15))

	lt2 := LessThan(api, in[1], 8)

	//	    isBig <== eq.out * (1 - lt2.out);
	isBig := api.Mul(eq, api.Sub(1, lt2))

	//var prefixVal = 16 * in[0] + in[1];
	prefixVal := api.Add(api.Mul(16, in[0]), in[1])
	//isValid <== 1 - lt1.out;
	isValid := api.Sub(1, lt1)
	//signal lenTemp;
	//lenTemp <== 2 * (prefixVal - 16 * 12) + 2 * isBig * (16 * 12 - 16 * 15 - 7);

	lenTemp := api.Mul(2, api.Sub(prefixVal, 192))
	lenTemp = api.Add(lenTemp, api.Mul(2, isBig, -55))
	//prefixOrTotalHexLen <== isValid * lenTemp;
	prefixOrTotalHexLen := api.Mul(isValid, lenTemp)

	return isBig, prefixOrTotalHexLen, isValid
}

func RlpFieldPrefix(api frontend.API, in [2]frontend.Variable) (frontend.Variable,
	frontend.Variable,
	frontend.Variable,
	frontend.Variable,
	frontend.Variable) {

	// if starts with < 'c'
	lt1 := LessThan(api, in[0], 12)

	// if starts with < '8', then literal

	lt2 := LessThan(api, in[0], 8)

	// if starts with 'b' and >= 8, then has length bytes
	eq := api.IsZero(api.Sub(in[0], 11))

	lt3 := LessThan(api, in[1], 8)

	// if is 'c0', then is an empty list
	eq1 := api.IsZero(api.Sub(in[0], 12))

	//	 component eq2 = IsEqual();

	eq2 := api.IsZero(in[1])

	//	  isLiteral <== lt2.out;

	isLiteral := lt2
	//    isBig <== eq.out * (1 - lt3.out);
	isBig := api.Mul(eq, api.Sub(1, lt3))
	//    isEmptyList <== eq1.out * eq2.out;
	isEmptyList := api.Mul(eq1, eq2)

	//	    var prefixVal = 16 * in[0] + in[1];
	prefixVal := api.Add(api.Mul(16, in[0]), in[1])

	//	    lenTemp <== 2 * (prefixVal - 16 * 8) + 2 * isBig * (16 * 8 - 16 * 11 - 7);
	lenTmp := api.Mul(2, api.Sub(prefixVal, 128))
	lenTmp = api.Add(lenTmp, api.Mul(2, isBig, -55))
	//    lenTemp2 <== (1 - isLiteral) * lenTemp;

	lenTemp2 := api.Mul(api.Sub(1, isLiteral), lenTmp)

	//	    prefixOrTotalHexLen <== (1 - isEmptyList) * lenTemp2;
	prefixOrTotalHexLen := api.Mul(lenTemp2, api.Sub(1, isEmptyList))

	//	    isValid <== lt1.out + isEmptyList - lt1.out * isEmptyList;

	isValid := api.Add(lt1, isEmptyList)
	isValid = api.Sub(isValid, api.Mul(lt1, isEmptyList))

	return isBig, isLiteral, prefixOrTotalHexLen, isValid, isEmptyList
}

func ShiftLeft(api frontend.API, nIn int, minShift int, maxShift int, in []frontend.Variable, shift frontend.Variable) []frontend.Variable {
	shiftBits := LogCeil(maxShift - minShift)

	// shift operations, shifts[shiftBits][nIn]
	var shifts [][]frontend.Variable

	for i := 0; i < shiftBits; i++ {
		shifts = append(shifts, make([]frontend.Variable, nIn))
	}

	var out []frontend.Variable

	if minShift == maxShift {
		for i := 0; i < nIn; i++ {
			out = append(out, in[(i+minShift)%nIn])
		}
	} else {
		b := api.Sub(shift, minShift)
		bn := api.ToBinary(b, shiftBits)
		for idx := 0; idx < shiftBits; idx++ {
			if idx == 0 {
				for j := 0; j < nIn; j++ {
					var tempIdx = (j + minShift + (1 << idx)) % nIn
					var tempIdx2 = (j + minShift) % nIn
					shift0j := api.Sub(in[tempIdx], in[tempIdx2])
					shift0j = api.Add(api.Mul(bn[idx], shift0j), in[tempIdx2])
					shifts[0][j] = shift0j
				}
			} else {
				for j := 0; j < nIn; j++ {
					var prevIdx = idx - 1
					var tempIdx = (j + (1 << idx)) % nIn
					//shifts[idx][j] <== bn[idx] * (shifts[prevIdx][tempIdx] - shifts[prevIdx][j]) + shifts[prevIdx][j];
					shiftsij := api.Sub(shifts[prevIdx][tempIdx], shifts[prevIdx][j])
					shiftsij = api.Add(api.Mul(bn[idx], shiftsij), shifts[prevIdx][j])
					shifts[idx][j] = shiftsij
				}
			}
		}
		for i := 0; i < nIn; i++ {
			out = append(out, shifts[shiftBits-1][i])
		}
	}
	return out
}

func ShiftRight(api frontend.API, nIn int, nInBits int, in []frontend.Variable, shift frontend.Variable) []frontend.Variable {

	// shifts[nInBits][nIn]
	var shifts [][]frontend.Variable

	// initialize shifts
	for i := 0; i < nInBits; i++ {
		shifts = append(shifts, make([]frontend.Variable, nIn))
	}

	shiftBits := api.ToBinary(shift, nInBits)

	for idx := 0; idx < nInBits; idx++ {
		if idx == 0 {

			sf := 1 << idx
			for j := 0; j < int(math.Min(float64(sf), float64(nIn))); j++ {
				shifts[0][j] = api.Sub(in[j], api.Mul(shiftBits[idx], in[j]))
			}
			for j := 1 << idx; j < nIn; j++ {
				tempIdx := j - (1 << idx)
				shifts0j := api.Mul(shiftBits[idx], api.Sub(in[tempIdx], in[j]))
				shifts[0][j] = api.Add(shifts0j, in[j])
			}
		} else {
			sf := 1 << idx
			for j := 0; j < int(math.Min(float64(sf), float64(nIn))); j++ {
				prevIdx := idx - 1
				shifts[idx][j] = api.Sub(shifts[prevIdx][j], api.Mul(shiftBits[idx], shifts[prevIdx][j]))
			}
			for j := 1 << idx; j < nIn; j++ {
				prevIdx := idx - 1
				tempIdx := j - (1 << idx)
				shiftsij := api.Sub(shifts[prevIdx][tempIdx], shifts[prevIdx][j])
				shifts[idx][j] = api.Add(api.Mul(shiftBits[idx], shiftsij), shifts[prevIdx][j])
			}
		}
	}

	var out []frontend.Variable
	for i := 0; i < nIn; i++ {
		out = append(out, shifts[nInBits-1][i])
	}

	return out
}

type ArrayCheck struct {
	MaxHexLen            int
	MaxFields            int
	ArrayPrefixMaxHexLen int
	FieldMinHexLen       []int
	FieldMaxHexLen       []int
}

// RlpArrayCheck rlp array length checker (1 layer data in trie), return the check result,
// the total length of the array length with rlp prefix in hex,
// array of each field hex length with rlp prefix
// array of each decoded-field hex length.
func (a *ArrayCheck) RlpArrayCheck(api frontend.API, in []frontend.Variable) (
	out frontend.Variable,
	totalRlpHexLen frontend.Variable,
	fieldHexLens []frontend.Variable,
	fields [][]frontend.Variable) {

	isBig, prefixOrTotalHexLen, isValid := RlpArrayPrefix(api, [2]frontend.Variable{in[0], in[1]})

	check := isValid

	lenSum := frontend.Variable(0)

	var temp = frontend.Variable(0)
	var totalArrayIn [][]frontend.Variable
	for idx := 0; idx < a.ArrayPrefixMaxHexLen; idx++ {
		temp = api.Add(api.Mul(16, temp), in[2+idx])
		if len(totalArrayIn) <= idx {
			totalArrayIn = append(totalArrayIn, make([]frontend.Variable, a.ArrayPrefixMaxHexLen))
		}
		totalArrayIn[0][idx] = temp
	}

	arrayRlpPrefix1HexLen := api.Mul(isBig, prefixOrTotalHexLen)

	// when isBig, the arrayRlpPrefix1HexLen = 2. if <55byte, arrayRlpPrefix1HexLen not exits
	sel := api.Mul(isBig, api.Sub(arrayRlpPrefix1HexLen, 1))
	totalArrayOut := Multiplexer(api, sel, 1, a.ArrayPrefixMaxHexLen, totalArrayIn)

	//	totalArrayHexLen = rlpArrayPrefix.prefixOrTotalHexLen + rlpArrayPrefix.isBig * (2 * totalArray.out[0] - rlpArrayPrefix.prefixOrTotalHexLen);
	totalArrayHexLen := api.Sub(api.Mul(2, totalArrayOut[0]), prefixOrTotalHexLen)
	totalArrayHexLen = api.Add(prefixOrTotalHexLen, api.Mul(isBig, totalArrayHexLen))

	totalRlpHexLen = api.Add(2, arrayRlpPrefix1HexLen, totalArrayHexLen)

	//shiftToField[nFields]
	var shiftToFieldOuts [][]frontend.Variable
	var shiftToFieldRlpsOuts [][]frontend.Variable

	for idx := 0; idx < a.MaxFields; idx++ {

		if idx == 0 {
			var shiftToFieldRlpsIn []frontend.Variable

			for j := 0; j < a.MaxHexLen; j++ {
				shiftToFieldRlpsIn = append(shiftToFieldRlpsIn, in[j])
			}
			shlOut := ShiftLeft(api, a.MaxHexLen, 0, a.ArrayPrefixMaxHexLen, shiftToFieldRlpsIn, api.Add(2, arrayRlpPrefix1HexLen))
			shiftToFieldRlpsOuts = append(shiftToFieldRlpsOuts, make([]frontend.Variable, len(shlOut)))
			shiftToFieldRlpsOuts[idx] = shlOut
		} else {
			var shiftToFieldRlpsIn []frontend.Variable
			for j := 0; j < a.MaxHexLen; j++ {
				shiftToFieldRlpsIn = append(shiftToFieldRlpsIn, shiftToFieldOuts[idx-1][j])
			}
			shlOut := ShiftLeft(api, a.MaxHexLen, a.FieldMinHexLen[idx-1], a.FieldMaxHexLen[idx-1], shiftToFieldRlpsIn, fieldHexLens[idx-1])
			shiftToFieldRlpsOuts = append(shiftToFieldRlpsOuts, make([]frontend.Variable, len(shlOut)))
			shiftToFieldRlpsOuts[idx] = shlOut
		}

		var shiftToFieldIn []frontend.Variable
		for j := 0; j < a.MaxHexLen; j++ {
			shiftToFieldIn = append(shiftToFieldIn, shiftToFieldRlpsOuts[idx][j])
		}

		fieldPrefixIsBig, fieldPrefixIsLiteral, fieldPrefixPrefixOrTotalHexLen, fieldPrefixIsValid, _ := RlpFieldPrefix(api, [2]frontend.Variable{shiftToFieldRlpsOuts[idx][0], shiftToFieldRlpsOuts[idx][1]})

		fieldRlpPrefix1HexLen := api.Mul(fieldPrefixIsBig, fieldPrefixPrefixOrTotalHexLen)

		lenPrefixMaxHexs := LogCeil(a.FieldMaxHexLen[idx]) / 8
		lenPrefixMaxHexs = (lenPrefixMaxHexs + 1) * 2
		shlToFieldShift := api.Mul(fieldPrefixIsLiteral, api.Add(2, fieldRlpPrefix1HexLen))
		shlToFieldShift = api.Sub(api.Add(2, fieldRlpPrefix1HexLen), shlToFieldShift)
		shiftToLeftOut := ShiftLeft(api, a.MaxHexLen, 0, lenPrefixMaxHexs, shiftToFieldIn, shlToFieldShift)

		shiftToFieldOuts = append(shiftToFieldOuts, make([]frontend.Variable, len(shiftToLeftOut)))
		shiftToFieldOuts[idx] = shiftToLeftOut

		fields = append(fields, make([]frontend.Variable, a.MaxHexLen))
		for j := 0; j < a.MaxHexLen; j++ {
			fields[idx][j] = shiftToLeftOut[j]
		}

		fieldHexLenMultiSelc := api.Mul(fieldPrefixIsBig, api.Sub(fieldRlpPrefix1HexLen, 1))

		var fieldHexLenMultiIn [][]frontend.Variable

		var tmp = frontend.Variable(0)
		fieldHexLenMultiIn = append(fieldHexLenMultiIn, make([]frontend.Variable, lenPrefixMaxHexs))
		for j := 0; j < lenPrefixMaxHexs; j++ {
			tmp = api.Add(api.Mul(16, tmp), shiftToFieldRlpsOuts[idx][2+j])
			fieldHexLenMultiIn[0][j] = tmp
		}
		fieldHexLenMultiOut := Multiplexer(api, fieldHexLenMultiSelc, 1, lenPrefixMaxHexs, fieldHexLenMultiIn)

		temp2 := api.Sub(api.Mul(fieldHexLenMultiOut[0], 2), fieldPrefixPrefixOrTotalHexLen)
		fieldTemp := api.Add(fieldPrefixPrefixOrTotalHexLen, api.Mul(fieldPrefixIsBig, temp2))

		fieldHexLen := api.Add(fieldTemp, api.Mul(2, fieldPrefixIsLiteral))
		fieldHexLen = api.Sub(fieldHexLen, api.Mul(fieldTemp, fieldPrefixIsLiteral))
		fieldHexLens = append(fieldHexLens, fieldHexLen)

		check = api.Add(check, fieldPrefixIsValid)

		//  lenSum = lenSum + 2 - 2 * fieldPrefix[idx].isLiteral + fieldRlpPrefix1HexLen[idx] + fieldHexLen[idx];
		lenSum = api.Sub(api.Add(lenSum, 2), api.Mul(2, fieldPrefixIsLiteral))
		lenSum = api.Add(lenSum, fieldRlpPrefix1HexLen, fieldHexLen)
	}

	lenCheck := api.IsZero(api.Sub(totalArrayHexLen, lenSum))

	out = api.IsZero(api.Sub(api.Add(check, lenCheck), api.Add(a.MaxFields, 2)))

	return
}

// BlkHeaderRlpCheck block header rlp length checker (1 layer data in trie), return the check result,
// the total length of the array length with rlp prefix in hex,
// array of each field hex length with rlp prefix
// array of each decoded-field hex length.
func (a *ArrayCheck) BlkHeaderRlpCheck(api frontend.API, in []frontend.Variable, FieldsNum frontend.Variable) (
	out frontend.Variable,
	totalRlpHexLen frontend.Variable,
	fieldHexLens []frontend.Variable,
	fields [][]frontend.Variable) {

	isBig, prefixOrTotalHexLen, isValid := RlpArrayPrefix(api, [2]frontend.Variable{in[0], in[1]})

	check := isValid

	lenSum := frontend.Variable(0)

	var temp = frontend.Variable(0)
	var totalArrayIn [][]frontend.Variable
	for idx := 0; idx < a.ArrayPrefixMaxHexLen; idx++ {
		temp = api.Add(api.Mul(16, temp), in[2+idx])
		if len(totalArrayIn) <= idx {
			totalArrayIn = append(totalArrayIn, make([]frontend.Variable, a.ArrayPrefixMaxHexLen))
		}
		totalArrayIn[0][idx] = temp
	}

	arrayRlpPrefix1HexLen := api.Mul(isBig, prefixOrTotalHexLen)

	// when isBig, the arrayRlpPrefix1HexLen = 2. if <55byte, arrayRlpPrefix1HexLen not exits
	sel := api.Mul(isBig, api.Sub(arrayRlpPrefix1HexLen, 1))
	totalArrayOut := Multiplexer(api, sel, 1, a.ArrayPrefixMaxHexLen, totalArrayIn)

	//	totalArrayHexLen = rlpArrayPrefix.prefixOrTotalHexLen + rlpArrayPrefix.isBig * (2 * totalArray.out[0] - rlpArrayPrefix.prefixOrTotalHexLen);
	totalArrayHexLen := api.Sub(api.Mul(2, totalArrayOut[0]), prefixOrTotalHexLen)
	totalArrayHexLen = api.Add(prefixOrTotalHexLen, api.Mul(isBig, totalArrayHexLen))

	totalRlpHexLen = api.Add(2, arrayRlpPrefix1HexLen, totalArrayHexLen)

	//shiftToField[nFields]
	var shiftToFieldOuts [][]frontend.Variable
	var shiftToFieldRlpsOuts [][]frontend.Variable

	for idx := 0; idx < a.MaxFields; idx++ {

		if idx == 0 {
			var shiftToFieldRlpsIn []frontend.Variable

			for j := 0; j < a.MaxHexLen; j++ {
				shiftToFieldRlpsIn = append(shiftToFieldRlpsIn, in[j])
			}
			shlOut := ShiftLeft(api, a.MaxHexLen, 0, a.ArrayPrefixMaxHexLen, shiftToFieldRlpsIn, api.Add(2, arrayRlpPrefix1HexLen))
			shiftToFieldRlpsOuts = append(shiftToFieldRlpsOuts, make([]frontend.Variable, len(shlOut)))
			shiftToFieldRlpsOuts[idx] = shlOut
		} else {
			var shiftToFieldRlpsIn []frontend.Variable
			for j := 0; j < a.MaxHexLen; j++ {
				shiftToFieldRlpsIn = append(shiftToFieldRlpsIn, shiftToFieldOuts[idx-1][j])
			}
			shlOut := ShiftLeft(api, a.MaxHexLen, a.FieldMinHexLen[idx-1], a.FieldMaxHexLen[idx-1], shiftToFieldRlpsIn, fieldHexLens[idx-1])
			shiftToFieldRlpsOuts = append(shiftToFieldRlpsOuts, make([]frontend.Variable, len(shlOut)))
			shiftToFieldRlpsOuts[idx] = shlOut
		}

		var shiftToFieldIn []frontend.Variable
		for j := 0; j < a.MaxHexLen; j++ {
			shiftToFieldIn = append(shiftToFieldIn, shiftToFieldRlpsOuts[idx][j])
		}

		fieldPrefixIsBig, fieldPrefixIsLiteral, fieldPrefixPrefixOrTotalHexLen, fieldPrefixIsValid, _ := RlpFieldPrefix(api, [2]frontend.Variable{shiftToFieldRlpsOuts[idx][0], shiftToFieldRlpsOuts[idx][1]})

		fieldRlpPrefix1HexLen := api.Mul(fieldPrefixIsBig, fieldPrefixPrefixOrTotalHexLen)

		lenPrefixMaxHexs := LogCeil(a.FieldMaxHexLen[idx]) / 8
		lenPrefixMaxHexs = (lenPrefixMaxHexs + 1) * 2
		shlToFieldShift := api.Mul(fieldPrefixIsLiteral, api.Add(2, fieldRlpPrefix1HexLen))
		shlToFieldShift = api.Sub(api.Add(2, fieldRlpPrefix1HexLen), shlToFieldShift)
		shiftToLeftOut := ShiftLeft(api, a.MaxHexLen, 0, lenPrefixMaxHexs, shiftToFieldIn, shlToFieldShift)

		shiftToFieldOuts = append(shiftToFieldOuts, make([]frontend.Variable, len(shiftToLeftOut)))
		shiftToFieldOuts[idx] = shiftToLeftOut

		fields = append(fields, make([]frontend.Variable, a.MaxHexLen))
		for j := 0; j < a.MaxHexLen; j++ {
			fields[idx][j] = shiftToLeftOut[j]
		}

		fieldHexLenMultiSelc := api.Mul(fieldPrefixIsBig, api.Sub(fieldRlpPrefix1HexLen, 1))

		var fieldHexLenMultiIn [][]frontend.Variable

		var tmp = frontend.Variable(0)
		fieldHexLenMultiIn = append(fieldHexLenMultiIn, make([]frontend.Variable, lenPrefixMaxHexs))
		for j := 0; j < lenPrefixMaxHexs; j++ {
			tmp = api.Add(api.Mul(16, tmp), shiftToFieldRlpsOuts[idx][2+j])
			fieldHexLenMultiIn[0][j] = tmp
		}
		fieldHexLenMultiOut := Multiplexer(api, fieldHexLenMultiSelc, 1, lenPrefixMaxHexs, fieldHexLenMultiIn)

		temp2 := api.Sub(api.Mul(fieldHexLenMultiOut[0], 2), fieldPrefixPrefixOrTotalHexLen)
		fieldTemp := api.Add(fieldPrefixPrefixOrTotalHexLen, api.Mul(fieldPrefixIsBig, temp2))

		idxLessThanMaxFields := LessThan(api, idx, FieldsNum)
		fieldHexLen := api.Add(fieldTemp, api.Mul(2, fieldPrefixIsLiteral))
		fieldHexLen = api.Sub(fieldHexLen, api.Mul(fieldTemp, fieldPrefixIsLiteral))
		fieldHexLen = api.Mul(fieldHexLen, idxLessThanMaxFields)
		fieldHexLens = append(fieldHexLens, fieldHexLen)

		check = api.Add(check, fieldPrefixIsValid)

		//  lenSum = lenSum + 2 - 2 * fieldPrefix[idx].isLiteral + fieldRlpPrefix1HexLen[idx] + fieldHexLen[idx];
		lenSum = api.Sub(api.Add(lenSum, 2), api.Mul(2, fieldPrefixIsLiteral))
		lenSum = api.Add(lenSum, fieldRlpPrefix1HexLen, fieldHexLen)
	}

	lenCheck := api.IsZero(api.Sub(totalArrayHexLen, lenSum))

	out = api.IsZero(api.Sub(api.Add(check, lenCheck), api.Add(a.MaxFields, 2)))

	return
}
