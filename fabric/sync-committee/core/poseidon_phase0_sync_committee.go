package core

import (
	"github.com/celer-network/brevis-circuits/fabric/common"

	"github.com/consensys/gnark/frontend"
	poseidon "github.com/liyue201/gnark-circomlib/circuits"
)

type PoseidonPhase0SyncCommittee struct {
	pubkeysLimbs [common.LenOfTotalPoseidonNums]frontend.Variable
	api          frontend.API
}

func NewPoseidon(api frontend.API, pubkeysLimbs [common.LenOfTotalPoseidonNums]frontend.Variable) PoseidonPhase0SyncCommittee {
	ret := PoseidonPhase0SyncCommittee{
		pubkeysLimbs,
		api,
	}
	return ret
}

func (d *PoseidonPhase0SyncCommittee) Commitment() frontend.Variable {
	// max individual posiedon is 16
	totalPoseidons := common.LenOfTotalPoseidonNums/15 + 1
	var lastPoseidonHash frontend.Variable
	var currentPoseidonHash frontend.Variable
	for i := 0; i < totalPoseidons; i++ {
		if i == 0 {
			currentPoseidonHash = poseidon.Poseidon(d.api, d.pubkeysLimbs[i*15:i*15+15])
		} else if i == totalPoseidons-1 {
			currentPoseidonHash = poseidon.Poseidon(d.api, append(d.pubkeysLimbs[i*15:], lastPoseidonHash))
		} else {
			currentPoseidonHash = poseidon.Poseidon(d.api, append(d.pubkeysLimbs[i*15:i*15+15], lastPoseidonHash))
		}
		lastPoseidonHash = currentPoseidonHash
	}

	return currentPoseidonHash
}
