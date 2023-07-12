package core

import (
	"github.com/celer-network/brevis-circuits/fabric/common"
	sc "github.com/celer-network/brevis-circuits/fabric/sync-committee/core"
	"github.com/celer-network/brevis-circuits/gadgets/pairing_bls12381"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/weierstrass"
)

var (
	_, _, g1GenAff, _ = bls12381.Generators()
	G1Gen             = pairing_bls12381.NewG1Affine(g1GenAff)
	G1GenNeg          = pairing_bls12381.NewG1Affine(*g1GenAff.Neg(&g1GenAff))

	GtelOne = pairing_bls12381.NewGTEl(*new(bls12381.GT).SetOne())
)

type BlsSignatureVerifyCircuit struct {
	Pubkeys     [common.LenOfValidators]pairing_bls12381.G1Affine
	AggBits     [common.LenOfValidators]frontend.Variable
	AggSig      pairing_bls12381.G2Affine
	SigningRoot [32]frontend.Variable `gnark:",public"`

	ParticipantNum        frontend.Variable `gnark:",public"`
	SyncCommitteePoseidon frontend.Variable `gnark:",public"`
}

func (c *BlsSignatureVerifyCircuit) Define(api frontend.API) error {
	// 1. compute aggregate pubkey
	curve, err := weierstrass.New[pairing_bls12381.BLS12381Fp, pairing_bls12381.BLS12381Fr](api, weierstrass.GetCurveParams[pairing_bls12381.BLS12381Fp]())
	if err != nil {
		return err
	}

	var participantNum frontend.Variable = 0
	aggPubKey := &G1Gen // init aggPubKey
	for i, bit := range c.AggBits {
		aggPubKey = curve.Select(bit, curve.Add(aggPubKey, &c.Pubkeys[i]), aggPubKey)
		participantNum = api.Select(bit, api.Add(participantNum, 1), participantNum)
	}
	aggPubKey = curve.Add(aggPubKey, &G1GenNeg) // sub the init aggPubKey

	api.AssertIsEqual(c.ParticipantNum, participantNum)

	// 2. Verify sig
	paring, err := pairing_bls12381.NewPairing(api)
	if err != nil {
		return err
	}
	signingRootG2 := pairing_bls12381.HashToG2(api, c.SigningRoot)
	// fast ate pairing by check e(-G1, S) * e(PK, H) == 1
	res, err := paring.Pair([]*pairing_bls12381.G1Affine{&G1GenNeg, aggPubKey}, []*pairing_bls12381.G2Affine{&c.AggSig, signingRootG2})
	if err != nil {
		return err
	}
	paring.AssertIsEqual(res, &GtelOne)

	// 3. pub keys poseidon
	var pubkeysLimbs [common.LenOfTotalPoseidonNums]frontend.Variable
	for i := 0; i < common.LenOfValidators; i++ {
		for j := 0; j < common.LimbsPerValidator; j++ {
			pubkeysLimbs[i*common.LimbsPerValidator+j] = c.Pubkeys[i].X.Limbs[j]
			api.AssertIsEqual(pubkeysLimbs[i*common.LimbsPerValidator+j], c.Pubkeys[i].X.Limbs[j])
		}
	}
	poseidonValidators := sc.NewPoseidon(api, pubkeysLimbs)
	api.AssertIsEqual(c.SyncCommitteePoseidon, poseidonValidators.Commitment())

	return nil
}
