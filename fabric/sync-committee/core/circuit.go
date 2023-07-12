package core

import (
	"github.com/celer-network/brevis-circuits/fabric/common"

	"github.com/consensys/gnark/frontend"
)

type SyncCommitteeUpdateCircuit struct {
	Pubkeys         [common.LenOfValidators][common.LenOfPubkey]frontend.Variable
	AggregatePubkey [common.LenOfPubkey]frontend.Variable

	SyncCommitteeSSZ      [32]frontend.Variable `gnark:"data,public"`
	SyncCommitteePoseidon frontend.Variable     `gnark:",public"`
}

func (c *SyncCommitteeUpdateCircuit) Define(api frontend.API) error {
	sszPhase0SyncCommittee := New(api, c.Pubkeys, c.AggregatePubkey)
	sszCommitment := sszPhase0SyncCommittee.Commitment()
	for i := range c.SyncCommitteeSSZ {
		api.AssertIsEqual(c.SyncCommitteeSSZ[i], sszCommitment[i])
	}

	var pubkeysLimbs [common.LenOfTotalPoseidonNums]frontend.Variable
	for i := 0; i < common.LenOfValidators; i++ {
		// a pubkey to 6 limbs, 8 bytes per limb, reverse for little endian
		for j := 0; j < common.LimbsPerValidator; j++ {
			var bigNumSlice []frontend.Variable
			for k := common.LenOfPubkey - common.BytesPerLimb*j - 1; k > common.LenOfPubkey-common.BytesPerLimb*(j+1)-1; k-- {
				byteSlice := api.ToBinary(c.Pubkeys[i][k], 8)
				if k == 0 { // the first 3 bits should set back to 0 for poseidon hash, so that in overall 381 bits long
					byteSlice[7] = 0
					byteSlice[6] = 0
					byteSlice[5] = 0
				}
				bigNumSlice = append(bigNumSlice, byteSlice...)
			}
			pubkeysLimbs[i*common.LimbsPerValidator+j] = api.FromBinary(bigNumSlice...)
		}
	}
	poseidonPhase0SyncCommittee := NewPoseidon(api, pubkeysLimbs)
	api.AssertIsEqual(c.SyncCommitteePoseidon, poseidonPhase0SyncCommittee.Commitment())

	return nil
}
