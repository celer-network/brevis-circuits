package core

import (
	goEd25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	ed25519test "gadgets/ed25519/test"
	"math/big"
	"strings"
	"testing"

	"gadgets/ed25519"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func getInputData(N int) []byte {
	var base = "00"

	var inputStr = ""
	for i := 0; i < N; i++ {
		inputStr = inputStr + base
	}
	input, _ := hex.DecodeString(inputStr)

	return input
}

func TestVerify(t *testing.T) {
	assert := test.NewAssert(t)

	var pkPoints [8]ed25519.PublicKey
	var pks [8][2]frontend.Variable
	var sigs [8]ed25519.Signature
	var msgs [8][5]frontend.Variable

	var witness = &Ed25519Circuit{}
	for i := 0; i < 8; i++ {
		pub, priv, err := goEd25519.GenerateKey(nil)
		assert.NoError(err)

		A, err := (&ed25519test.Point{}).SetBytes(pub)
		assert.NoError(err)
		_A := (&ed25519test.Point{}).Negate(A)

		msg := getInputData(122)
		goSig := goEd25519.Sign(priv, msg)

		goSha512 := sha512.New()
		goSha512.Write(goSig[:32])
		goSha512.Write(pub)
		goSha512.Write(msg)
		hramDigest := goSha512.Sum(nil)

		//split 64 byte signature into two 32byte halves, first halve as point R, second half as S(integer)
		k, _ := ed25519test.NewScalar().SetUniformBytes(hramDigest)
		S, _ := ed25519test.NewScalar().SetCanonicalBytes(goSig[32:])
		R := (&ed25519test.Point{}).VarTimeDoubleScalarBaseMult(k, _A, S)

		eSig := &ed25519.Signature{
			R: *ed25519.NewEmulatedPoint(R),
			S: new(big.Int).SetBytes(ed25519.PutBigEndian(S.Bytes())),
		}
		ePublicKey := &ed25519.PublicKey{
			A: *ed25519.NewEmulatedPoint(A),
		}

		// compress 32byte public key to 2 frontend variable for bn254 field
		var pubBytes [32]byte
		for i := 0; i < 32; i++ {
			pubBytes[i] = pub[i]
		}
		pks[i][0] = pubBytes[:16]
		pks[i][1] = pubBytes[16:]

		pkPoints[i] = *ePublicKey
		sigs[i] = *eSig

		//122 byte -> 5
		var msgFv [5]frontend.Variable

		// compress message to 5 frontend variable for bn254 field
		for i := 0; i < 5; i++ {
			if i == 4 {
				msgFv[i] = msg[i*25:]
			} else {
				msgFv[i] = msg[i*25 : (i+1)*25]
			}
		}
		msgs[i] = msgFv
	}

	witness.PublicKeys = pks
	witness.Signatures = sigs
	witness.Messages = msgs
	witness.PbPoints = pkPoints

	err := test.IsSolved(witness, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestRealizeData(t *testing.T) {
	assert := test.NewAssert(t)

	keys := []string{
		"0xe17cbe9c20cdcfdf876b3b12978d3264a007fcaaa71c4cdb701d9ebc0323f44f",
		"0x184e7b103d34c41003f9b864d5f8c1adda9bd0436b253bb3c844bc739c1e77c9",
		"0x4d420aea843e92a0cfe69d89696dff6827769f9cb52a249af537ce89bf2a4b74",
		"0xbd03de9f8ab29e2800094e153fac6f696cfa512536c9c2f804dcb2c2c4e4aed6",
		"0x8f4a74a07351895ddf373057b98fae6dfaf2cd21f37a063e19601078fe470d53",
		"0xc80e9abef7ff439c10c68fe8f1303deddfc527718c3b37d8ba6807446e3c827a",
		"0x4d1be64f0e9a466c2e66a53433928192783e29f8fa21beb2133499b5ef770f60",
		"0x9142afcc691b7cc05d26c7b0be0c8b46418294171730e079f384fde2fa50bafc",
	}

	sigs := []string{
		"0xb0e8302287470606bcbff7c8d34226b68cec5fdd64a3183decd3cc22252acb3049d8dbbca04001791c686e2fa64b07bf07441deb7cef9bd6740ff485326e5e02",
		"0xaa47d03ed40671bceb6655433d183b5c8d83cd2d2ebc4da69c590601cae29332c8d46343d889942fb8071e1238654c15ba0b234ddee5d84a13132692d2951f09",
		"0xcdc069e42327da9377925dd712e759ab4c395d34897605a7a82b4b6e1c1aa2c67914233fc03f00ea0043f399fa5d94b1b0aeac11e608289e0e14d33d759c5d07",
		"0xb20093c1b8cecc628ce14339e17faf866675f287942205fccb7d27689545de74204eb068e39fc75360c7ce28103bb536c3f5f104b889e77054521575db687301",
		"0xb02b5e92ccc126ba69c65bd392030c5b7aaa4f906e877fd2518dd933056fa479e64473be5702395a290028006c7aacc80af72e5792f5af0f4c244bd903d84608",
		"0x98b541d6378d19657bfd034af57327bb57cbfd66ba66417e498700f3cac189f122821dddacdf93b945cbb59ae3fd722f6fb3e52a9b5b248bd60d585ce19f350a",
		"0x908d7f9c8f9fe52ef8a0b6eacf4d5a7b0bb85e149516b0dbb6f9f764d15fc20df3c8b4b811292f6d77e61bdf40e0b76c30e926d6fbb5148896c1be0709ca2e02",
		"0x800ef242ffd25e1a8b9c463054d800c7227de54514d600d9221a9eb57de5b84c04e14adb4a20ad99171b6ab0818a8fe219826f454dad23f864215141db13250d",
	}

	initial := "79080211c7b933020000000022480a2055552f335dcaead25b5b7abaab85dcaf82e15ff729b7e97681da9997ba7784da12240a2057a8f6f0a1022ec94eda4eb3f0b8f2a975ad1667ecbc6709b3a661b7b82cf3a710012a0c0880fd99a00610f7d5d5dc01321442696e616e63652d436861696e2d47616e676573,79080211c7b933020000000022480a2055552f335dcaead25b5b7abaab85dcaf82e15ff729b7e97681da9997ba7784da12240a2057a8f6f0a1022ec94eda4eb3f0b8f2a975ad1667ecbc6709b3a661b7b82cf3a710012a0c0880fd99a00610ee9feade01321442696e616e63652d436861696e2d47616e676573,79080211c7b933020000000022480a2055552f335dcaead25b5b7abaab85dcaf82e15ff729b7e97681da9997ba7784da12240a2057a8f6f0a1022ec94eda4eb3f0b8f2a975ad1667ecbc6709b3a661b7b82cf3a710012a0c0880fd99a0061081c3dcde01321442696e616e63652d436861696e2d47616e676573,79080211c7b933020000000022480a2055552f335dcaead25b5b7abaab85dcaf82e15ff729b7e97681da9997ba7784da12240a2057a8f6f0a1022ec94eda4eb3f0b8f2a975ad1667ecbc6709b3a661b7b82cf3a710012a0c0880fd99a00610f4f4abda01321442696e616e63652d436861696e2d47616e676573,79080211c7b933020000000022480a2055552f335dcaead25b5b7abaab85dcaf82e15ff729b7e97681da9997ba7784da12240a2057a8f6f0a1022ec94eda4eb3f0b8f2a975ad1667ecbc6709b3a661b7b82cf3a710012a0c0880fd99a00610d8a0e7ee01321442696e616e63652d436861696e2d47616e676573,79080211c7b933020000000022480a2055552f335dcaead25b5b7abaab85dcaf82e15ff729b7e97681da9997ba7784da12240a2057a8f6f0a1022ec94eda4eb3f0b8f2a975ad1667ecbc6709b3a661b7b82cf3a710012a0c0880fd99a00610f8e0d6de01321442696e616e63652d436861696e2d47616e676573,79080211c7b933020000000022480a2055552f335dcaead25b5b7abaab85dcaf82e15ff729b7e97681da9997ba7784da12240a2057a8f6f0a1022ec94eda4eb3f0b8f2a975ad1667ecbc6709b3a661b7b82cf3a710012a0c0880fd99a00610a7a58ef001321442696e616e63652d436861696e2d47616e676573,79080211c7b933020000000022480a2055552f335dcaead25b5b7abaab85dcaf82e15ff729b7e97681da9997ba7784da12240a2057a8f6f0a1022ec94eda4eb3f0b8f2a975ad1667ecbc6709b3a661b7b82cf3a710012a0c0880fd99a00610b991e3de01321442696e616e63652d436861696e2d47616e676573"
	datas := strings.Split(initial, ",")
	var dataWith0x = datas
	for i := 0; i < len(datas); i++ {
		dataWith0x[i] = "0x" + datas[i]
	}

	err := GenerateEd25519Proof(keys, dataWith0x, sigs)

	assert.NoError(err)
}

func GenerateEd25519Proof(pubKeys []string, messages []string, signatures []string) error {
	// generate CompiledConstraintSystem

	// circuit public input
	var assignment = &Ed25519Circuit{}
	var pkPoints [8]ed25519.PublicKey
	var pks [8][2]frontend.Variable
	var sigs [8]ed25519.Signature
	var msgs [8][5]frontend.Variable

	for i := 0; i < len(pubKeys); i++ {
		pub, err := hexutil.Decode(pubKeys[i])
		A, err := (&ed25519test.Point{}).SetBytes(pub)
		if err != nil {
			log.Fatal(err)
		}

		message, err := hexutil.Decode(messages[i])
		signature, err := hexutil.Decode(signatures[i])
		goSha512 := sha512.New()
		goSha512.Write(signature[:32])
		goSha512.Write(pub)
		goSha512.Write(message)
		hramDigest := goSha512.Sum(nil)

		// split 64 byte signature into two 32byte halves, first halve as point R, second half as S(integer)
		_A := (&ed25519test.Point{}).Negate(A)
		k, _ := ed25519test.NewScalar().SetUniformBytes(hramDigest)
		S, _ := ed25519test.NewScalar().SetCanonicalBytes(signature[32:])
		R := (&ed25519test.Point{}).VarTimeDoubleScalarBaseMult(k, _A, S)

		eSig := &ed25519.Signature{
			R: *ed25519.NewEmulatedPoint(R),
			S: new(big.Int).SetBytes(ed25519.PutBigEndian(S.Bytes())),
		}
		ePublicKey := &ed25519.PublicKey{
			A: *ed25519.NewEmulatedPoint(A),
		}
		pkPoints[i] = *ePublicKey

		// compress 32byte public key to 2 frontend variable for bn254 field
		var pubBytes [32]byte
		for i := 0; i < 32; i++ {
			pubBytes[i] = pub[i]
		}
		pks[i][0] = pubBytes[:16]
		pks[i][1] = pubBytes[16:]

		sigs[i] = *eSig

		//122 byte -> 5
		var msgFv [5]frontend.Variable

		// compress message to 5 frontend variable for bn254 field
		for i := 0; i < 5; i++ {
			if i == 4 {
				msgFv[i] = message[i*25:]
			} else {
				msgFv[i] = message[i*25 : (i+1)*25]
			}
		}
		msgs[i] = msgFv
	}

	assignment.Signatures = sigs
	assignment.PublicKeys = pks
	assignment.Messages = msgs
	assignment.PbPoints = pkPoints

	return test.IsSolved(assignment, assignment, ecc.BN254.ScalarField())
}
