package core

import (
	"fabric/common"

	"gadgets/sha256"

	"github.com/consensys/gnark/frontend"
)

type SSZPhase0SyncCommittee struct {
	pubkeys         [common.LenOfValidators][common.LenOfPubkey]frontend.Variable
	aggregatePubkey [common.LenOfPubkey]frontend.Variable
	api             frontend.API
}

func New(api frontend.API, pubkeys [common.LenOfValidators][common.LenOfPubkey]frontend.Variable, aggregatePubkey [common.LenOfPubkey]frontend.Variable) SSZPhase0SyncCommittee {
	ret := SSZPhase0SyncCommittee{
		pubkeys,
		aggregatePubkey,
		api,
	}
	return ret
}

func (d *SSZPhase0SyncCommittee) Commitment() []frontend.Variable {
	var totalValidatorsSSZBytes [common.LenOfTotalValidatorsSSZBytes]frontend.Variable
	for i := range d.pubkeys {
		for j := 0; j < common.LenOfOnePubkeySSZBytes; j++ {
			if j < common.LenOfPubkey {
				totalValidatorsSSZBytes[i*common.LenOfOnePubkeySSZBytes+j] = d.pubkeys[i][j]
				d.api.AssertIsEqual(totalValidatorsSSZBytes[i*common.LenOfOnePubkeySSZBytes+j], d.pubkeys[i][j])
			} else {
				totalValidatorsSSZBytes[i*common.LenOfOnePubkeySSZBytes+j] = uint8(0)
			}
		}
	}

	var aggregateSSZBytes [common.LenOfOnePubkeySSZBytes]frontend.Variable
	for j := 0; j < common.LenOfOnePubkeySSZBytes; j++ {
		if j < common.LenOfPubkey {
			aggregateSSZBytes[j] = d.aggregatePubkey[j]
			d.api.AssertIsEqual(aggregateSSZBytes[j], d.aggregatePubkey[j])
		} else {
			aggregateSSZBytes[j] = uint8(0)
		}
	}

	validatorsSSZRoot := d.sszRoot(totalValidatorsSSZBytes[:])
	aggregateSSZRoot := d.sszRoot(aggregateSSZBytes[:])

	digest := sha256.New(d.api)
	digest.Write(validatorsSSZRoot)
	digest.Write(aggregateSSZRoot)

	return digest.Sum()
}

func (d *SSZPhase0SyncCommittee) sszRoot(input []frontend.Variable) (output []frontend.Variable) {
	lenOfInput := len(input)
	output = make([]frontend.Variable, lenOfInput/2)
	numParis := lenOfInput / 64
	for i := 0; i < numParis; i++ {
		digest := sha256.New(d.api)
		digest.Write(input[i*64 : (i+1)*64])
		copy(output[i*32:(i+1)*32], digest.Sum())
	}

	if numParis == 1 {
		return output
	} else {
		return d.sszRoot(output)
	}
}
