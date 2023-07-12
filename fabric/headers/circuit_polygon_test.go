package headers

import (
	"fmt"
	"math/big"
	"testing"

	util "github.com/celer-network/brevis-circuits/fabric/headers/headerutil"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestPolygonCircuit(t *testing.T) {
	w := NewPolygonChunkProofCircuit()
	circuit := NewPolygonChunkProofCircuit()
	err := test.IsSolved(circuit, w, ecc.BN254.ScalarField())
	check(err)

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	check(err)
	fmt.Println("constraints", cs.GetNbConstraints())
}

func NewPolygonChunkProofCircuit() *PolygonCircuit {
	hs := polygonHeaders()

	headersEncoded, roundIdxs, err := util.EncodeHeaders(hs, false)
	if err != nil {
		fmt.Printf("failed to encode headers: %s\n", err.Error())
		return nil
	}
	root, err := util.ComputeChunkRoot(hs)
	fmt.Printf("chunk root %x\n", root)
	if err != nil {
		log.Errorf("Failed to compute chunk root: %s\n", err.Error())
		return nil
	}
	chunkRoot := util.Hash2FV(root)
	fmt.Printf("prev hash %x\n", hs[0].ParentHash)
	prevHash := util.Hash2FV(hs[0].ParentHash[:])
	eh := hs[len(hs)-1].Hash()
	fmt.Printf("end hash %x\n", eh)
	endHash := util.Hash2FV(eh[:])

	return &PolygonCircuit{
		Headers:       headersEncoded,
		ChunkRoot:     chunkRoot,
		PrevHash:      prevHash,
		EndHash:       endHash,
		StartBlockNum: 44121528,
		EndBlockNum:   44121531,
		HashRoundIdxs: roundIdxs,
	}
}

func polygonHeaders() []types.Header {
	var headers []types.Header

	var bloom [256]byte
	bloomBytes := hexutil.MustDecode("0x10b0545a732010d83c590538b22001e0381348140dc2e80cf531103285b01835ea081038de0b2191e1d114b3325ab0053a39c6fe9e7b76f26eb48a4669a4fe881449c0a91a82c808407a450d252120aa1eb73c645366f4b99a0fa011ca211600242c2412836024a3207799c02901eb0972001906e82cd529e212e8921508406e35171544164c09824a1414362cea22201c0bbcc3ac5b102c07902ac8046a088b2e0540a7f2a1836662030d45dd988744cb7a022388a851edb6c32025a03c0a6689049c03ba12184122094c3b24999040c876aae81a088530a8f1871b50247084b278c9d40c25089af005b2a0d26bfe28e610c4297010535398111840cf94fc7a")
	copy(bloom[:], bloomBytes)
	headers = append(headers, types.Header{
		ParentHash:  common.HexToHash("0xbc34a79e8d36e3bda5feea4dd20e27d40e7504a679f27c676fc63097771ace5f"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    [20]byte{},
		Root:        common.HexToHash("0x58d5cf70c90fb3924542c90a53a982d1bd14ec2ab8a4bf9789b28243428b50bd"),
		TxHash:      common.HexToHash("0xe07a1fd0400940313a51d9bdc6d6fedb78892b1e5c956cdda41339a69b6355f5"),
		ReceiptHash: common.HexToHash("0x5aa1341ce95573599056ab42844c3128eaa60030b67d25813d21e0607a99ee9f"),
		Bloom:       bloom,
		Difficulty:  new(big.Int).SetBytes(hexutil.MustDecode("0x16")),
		Number:      new(big.Int).SetBytes(hexutil.MustDecode("0x02a13db8")),
		GasLimit:    new(big.Int).SetBytes(hexutil.MustDecode("0x01c9c380")).Uint64(),
		GasUsed:     new(big.Int).SetBytes(hexutil.MustDecode("0xa68a4d")).Uint64(),
		Time:        new(big.Int).SetBytes(hexutil.MustDecode("0x649155f3")).Uint64(),
		Extra:       hexutil.MustDecode("0xd682030983626f7288676f312e31392e31856c696e757800000000000000000025f7c50d0d67278abeb04542930bae4d06f3ca44e13df3df3fe019120726e7824476535422ef9751e3ef92f1864c5dbfc33486d3cad6c73451a713f37940d8da01"),
		MixDigest:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Nonce:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0}, //0x0000000000000000
		BaseFee:     new(big.Int).SetBytes(hexutil.MustDecode("0x1fd52f7730")),
	})
	bloomBytes = hexutil.MustDecode("0x94fc1004710851bd1819438000a14100220162018881a14499364173aaa290940088b218c51328110a510030221a110706b1c548c56a660328106503832024081047d46b781248e80011544df3aa338813857465e1426800d46b26a5a2200a9363bc4605ce180480a44bf9441002580842c43841288a5401e201e81390aa0437391304840408c08188407721d22c08643d190c862802a034a7708300020400823645500051a883d4600b81040984e394d54c40a320082b0c18410021073f2f6c84a49e1210634989052128300c3b1011e067281d9460a634c631814a50923a041a9190d01071810a508515805040ba22a01090dd8392b2a905168020129c2843")
	copy(bloom[:], bloomBytes)
	headers = append(headers, types.Header{
		ParentHash:  common.HexToHash("0xa4301f5c0ad5d6ad891950dc4f675524116bcd9ffe7194fb1e74b740b3a1729b"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    [20]byte{},
		Root:        common.HexToHash("0x0373b6ddb280d605fb052fc63cb11db109259ac71e4022009f26ca70d6d1ffd1"),
		TxHash:      common.HexToHash("0x850b2ed0178fcfea3668450080cd25e7f1d44e63635fd0572205c2a4c6576ab6"),
		ReceiptHash: common.HexToHash("0x63964872e81906de70f47c2c05806799e7a54a842960b56939e2da49f2e1d24c"),
		Bloom:       bloom,
		Difficulty:  new(big.Int).SetBytes(hexutil.MustDecode("0x16")),
		Number:      new(big.Int).SetBytes(hexutil.MustDecode("0x02a13db9")),
		GasLimit:    new(big.Int).SetBytes(hexutil.MustDecode("0x01c9c380")).Uint64(),
		GasUsed:     new(big.Int).SetBytes(hexutil.MustDecode("0x7485b7")).Uint64(),
		Time:        new(big.Int).SetBytes(hexutil.MustDecode("0x649155f5")).Uint64(),
		Extra:       hexutil.MustDecode("0xd682030983626f7288676f312e31392e31856c696e7578000000000000000000b3eb996b48aed383cc6c5519082f6d5769c843efdfc0143cc5a642e2980497a73fcbb7ff0fbaaa45b3c0b70cc7c81fd771d11e518bd3e3addb9b0a25b754e57b00"),
		MixDigest:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Nonce:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0}, //0x0000000000000000
		BaseFee:     new(big.Int).SetBytes(hexutil.MustDecode("0x1f4a755e22")),
	})
	bloomBytes = hexutil.MustDecode("0x20a01560702116c8092831a4c4a0710b9e23d24208c1648d54ba90aa8c8118108555512cc432849814529910eed692330191e32084c626081cd2613a05a4b94a205b420aa800d90903d3000d94ea34ec142e9e28830a236071896874972422ff42ac2003a2042c2000c768208a084908005c2896368a1a61e129ae908258a04b062b500c020800804a899e046c822200107114b1a80b12150b445760840108907201c81150010b4811a0312c7c908400514281e22802080004800420080eac44ab11148f38d40c17900101160a085c2e5af29e2a4448860a8039842c8648334bb83188a3148319088015899845193174e0087708141d80f38a454c03425eaa00")
	copy(bloom[:], bloomBytes)
	headers = append(headers, types.Header{
		ParentHash:  common.HexToHash("0x74365de7b091809958dd4e3c697ccf373625aac8737c0c070348aa10a1dc21dc"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    [20]byte{},
		Root:        common.HexToHash("0xc3bf0b42ba508fd0bdcb43dbcd591a098ffd1d7ca8bc05c5e89e06c23a0f378c"),
		TxHash:      common.HexToHash("0xd88c9fff77902b786894baf8b405bca57a398bd9dd0b4022936440f10299bc7c"),
		ReceiptHash: common.HexToHash("0x0a8bf37e716f7e981235a092e9a901d64fc99dcad114243b1875358cb0ab01c3"),
		Bloom:       bloom,
		Difficulty:  new(big.Int).SetBytes(hexutil.MustDecode("0x16")),
		Number:      new(big.Int).SetBytes(hexutil.MustDecode("0x02a13dba")),
		GasLimit:    new(big.Int).SetBytes(hexutil.MustDecode("0x01c9c380")).Uint64(),
		GasUsed:     new(big.Int).SetBytes(hexutil.MustDecode("0x7da133")).Uint64(),
		Time:        new(big.Int).SetBytes(hexutil.MustDecode("0x649155f7")).Uint64(),
		Extra:       hexutil.MustDecode("0xd682030983626f7288676f312e31392e31856c696e7578000000000000000000105923339cd692ba360c118be2b99f9ab2065ed97429dcfc83ff5b0dd31bb6ff1e1914b04b9d8a09ccd4121069d051a9c06d04418c3f499b775df3c0d2eb268700"),
		MixDigest:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Nonce:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0}, //0x0000000000000000
		BaseFee:     new(big.Int).SetBytes(hexutil.MustDecode("0x1e54af3a64")),
	})
	bloomBytes = hexutil.MustDecode("0x50121c4e7041905e54283c75b193ab08812807cc380020ac79048d360999381c08f6b2a4e69a2abf50a5d219aa531659201dca400096f059a459c1028bf96c48203f5a4838260c1c682f638da42912e998a1a3e2e74eba4150c32e508b1e27213b58c67096b2962138c6984215029e581a25442898983a15a734c2f264181a67a5978b22068cafa848240761580201201433b59b498170648e0c0d259045e12b3a6559921c83d2c270bf800cfda76230b12361c32a0a0416a23a0062b2962ccad5843f92462b04805399ad080f82a50454c711545d0be723f335c11e15a429520131818057f251ac80eba06ae1353238c01c60f923792529c1601994021cc40f")
	copy(bloom[:], bloomBytes)
	headers = append(headers, types.Header{
		ParentHash:  common.HexToHash("0x42f74242ea276bea9572765385fb13c3c21ec03362450c08957f719ad44d9d20"),
		UncleHash:   common.HexToHash("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
		Coinbase:    [20]byte{},
		Root:        common.HexToHash("0xd5e44386cdd16908692ab9dcd825c65a8e12508b2e2ec7cdcd4939fe7f69b22f"),
		TxHash:      common.HexToHash("0x6e2e3621e165c32cb3ec27847709bbccf0769d7526441731e421664925c019fb"),
		ReceiptHash: common.HexToHash("0xdd943408656b527aea5a7a2e13c75adbe258dbfce2b4894f46ac8f815ecc97bf"),
		Bloom:       bloom,
		Difficulty:  new(big.Int).SetBytes(hexutil.MustDecode("0x16")),
		Number:      new(big.Int).SetBytes(hexutil.MustDecode("0x02a13dbb")),
		GasLimit:    new(big.Int).SetBytes(hexutil.MustDecode("0x01c9c380")).Uint64(),
		GasUsed:     new(big.Int).SetBytes(hexutil.MustDecode("0x017e5bae")).Uint64(),
		Time:        new(big.Int).SetBytes(hexutil.MustDecode("0x649155f9")).Uint64(),
		Extra:       hexutil.MustDecode("0xd682030983626f7288676f312e31392e31856c696e7578000000000000000000bed7b08a2d32c7c28734f9a44ec77f513579ab954166aaa095bc8df916cada2549f9c3f8ec28b2f5f6e6f7119814355135c9518cf5c6dec565b6917f0d30934f00"),
		MixDigest:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Nonce:       [8]byte{0, 0, 0, 0, 0, 0, 0, 0}, //0x0000000000000000
		BaseFee:     new(big.Int).SetBytes(hexutil.MustDecode("0x1d79c2e95d")),
	})

	return headers
}
