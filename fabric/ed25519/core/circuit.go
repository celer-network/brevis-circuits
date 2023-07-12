package core

import (
	edd25519 "github.com/celer-network/brevis-circuits/gadgets/ed25519"

	"github.com/consensys/gnark/frontend"
)

type Ed25519Circuit struct {
	Messages   [8][5]frontend.Variable `gnark:",public"`
	PublicKeys [8][2]frontend.Variable `gnark:",public"`
	PbPoints   [8]edd25519.PublicKey
	Signatures [8]edd25519.Signature
}

func (c *Ed25519Circuit) Define(api frontend.API) error {
	ed, _ := edd25519.NewEd25519(api)
	for i := 0; i < 8; i++ {
		_ = ed.Verify(c.PublicKeys[i][:], c.Signatures[i], c.Messages[i], c.PbPoints[i])
	}
	return nil
}
