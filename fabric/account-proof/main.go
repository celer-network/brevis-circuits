package main

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"strconv"

	"github.com/celer-network/brevis-circuits/fabric/account-proof/core"
	"github.com/celer-network/brevis-circuits/gadgets/keccak"
	"github.com/celer-network/brevis-circuits/gadgets/mpt"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

type AccountInfo struct {
	Nonce       []byte
	Balance     []byte
	StorageRoot []byte
	CodeHash    []byte
}

func main() {

	depth := 9

	keyRlpHexString := "8d2a6e4b67bce79287a24c5e8453dee4b1c363dfccc5960e98b02dc0f56374bf"
	keyHexLen := len(keyRlpHexString)
	var keyRlpHex [mpt.AccountKeyLength]frontend.Variable
	for i := 0; i < mpt.AccountKeyLength; i++ {
		if i < keyHexLen {
			intValue, _ := strconv.ParseInt(string(keyRlpHexString[i]), 16, 64)
			keyRlpHex[i] = intValue
		} else {
			keyRlpHex[i] = 0
		}
	}

	valueRlpHexString := "f8440280a01eb0e8ed889315b2a7f6e076d0939a6ed1fe4e3d9b0eeb366c47ec5e8a52fd3fa0cc34a85a74e46f422c2b06b16156799b7c313a71390b4465cbc463bd99d76764"
	valueHexLen := len(valueRlpHexString)
	var valueRlpHex [mpt.MaxValueLengthForAccount]frontend.Variable
	for i := 0; i < mpt.MaxValueLengthForAccount; i++ {
		if i < valueHexLen {
			intValue, _ := strconv.ParseInt(string(valueRlpHexString[i]), 16, 64)
			valueRlpHex[i] = intValue
		} else {
			valueRlpHex[i] = 0
		}
	}

	accountProofRootHashHexString := "f72182306fb66caffdf8100fc8ba2941c86bcbd63e4cfb2215a9bbff05bccf77"
	var accountProofRootHashHex [64]frontend.Variable
	for i := 0; i < 64; i++ {
		intValue, _ := strconv.ParseInt(string(accountProofRootHashHexString[i]), 16, 64)
		accountProofRootHashHex[i] = intValue
	}

	var keyFragmentStarts [mpt.AccountMPTMaxDepth]frontend.Variable
	for i := 0; i < mpt.AccountMPTMaxDepth; i++ {
		keyFragmentStarts[i] = i
		if i > depth-1 {
			keyFragmentStarts[i] = 64
		}
	}

	leafRlpHexString := "0xf8669d2067bce79287a24c5e8453dee4b1c363dfccc5960e98b02dc0f56374bfb846f8440280a01eb0e8ed889315b2a7f6e076d0939a6ed1fe4e3d9b0eeb366c47ec5e8a52fd3fa0cc34a85a74e46f422c2b06b16156799b7c313a71390b4465cbc463bd99d76764"
	// pad leaf,And convert it to nibbles
	leafRlpBytes, _ := hexutil.Decode(leafRlpHexString)
	paddedLeafRlpBytes := keccak.Pad101Bytes(leafRlpBytes)

	var paddedLeafRlpHex [272 * 2]frontend.Variable
	for i, b := range paddedLeafRlpBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		paddedLeafRlpHex[i*2] = n1
		paddedLeafRlpHex[i*2+1] = n2
	}

	for i := len(paddedLeafRlpBytes) * 2; i < 272*2; i++ {
		paddedLeafRlpHex[i] = 0
	}

	leafRlpRoundIndex := keccak.GetKeccakRoundIndex(len(leafRlpHexString) - 2)

	/// 64 - (depth - 1) ===> length of nibbles represented by branch/extension node
	/// depth = len(accountProof[])/len(storageProof[])
	var leafPathPrefixLength int // 20 67bce79287a24c5e8453dee4b1c363dfccc5960e98b02dc0f56374bf
	if (64-depth+1)%2 == 0 {
		leafPathPrefixLength = 2
	} else {
		leafPathPrefixLength = 1
	}

	/// Proofs without leaf level ---> accountProof[0:len(accountProof) - 1]
	nodeRlpHexStrings := []string{
		"0xf90211a0406e0bf09bd3457c926220d59e64bb17f0b418fae4b6b284fea6ce075418fd8ea0461a6c921ebb815af6cddcc9300d5ad7b1b9ee53ac4faf0befef0cf2108af8f9a0f263c22c9d19c7fb6a0a2c4d17b39dffc90bddc3b4bc9d93250d04365fd1ab67a03909f80af3c1ea2f04a0b7798e3dd9a98b047d65700048c89d20a17913e408f8a0d7d80424bba51b84612945f8694358776bc55f08c6555b893c7b564b83c64ea8a0c2e11ce682b3b0e6514d5b21ea7383d2f7932c196ae204283c74def594cdb3c3a0be70688b104365a36d70a6117701557c2ab8bb18addf31e07e0a533e8fbb362aa071a8d6d5974cbf118c930783ab9daaa25d1d98fb1d91f4be935f6781f132e4a9a0f364b1317fcd0c322eb9e2cf0f04bc252d95d32cb12fd9f2ca9c25bef7aa8c3aa08974454ddd9640774901e4b9a360cd620af2c91749fbc7dff49ca5a958dc7b75a02a9376bd5d7428c8626ab5a97c41569b53fcb115e909d5e58b03c8b2144a38a2a03d61ff8a74c9a31a39b28fa329e527fba9986c779cdb2577c73bbe7511819c34a098665890978208c5614ee4404f278f97246b4a5e52453512dae8da6fc66e6827a093910d6ff3511c4c2f45665ffa647f994597b4e886e32a5b882badd3ded533d7a013c2a41a4d056a2d90499934bc429ab36799bf3d453e6d2648d6f3ba18ca4a31a0e4d7a6f3b0d8078e49a9fd95f6f5bc0003fb4043dfeda52290bf2b7241be143680",
		"0xf90211a0bb4a7c71496885d65960cbd9a58e894db20c101c8d76b6c7e6dd67d91eb1bd79a0ff9e0c0377cc2bb3c9b045e86aa4fb05a0229cc8b0de9fc771390b8f22bb7fe3a02b4ee21a2503d789a661c7a83e90bcca4ee89b393aa28989030c26b46f44ab7da0d51d137f9c1773be45c4126e0dfdead8feb649999670349c7eeac64de27a065ca0008496b4ebbbaff4950b6a69456efab276f0e943fe0a2c64104e07f87d48cb17a09c1ae8bcb0bb13c08429bdda11ddf044d85902dd881a145d23aaa043244501ada0b3c9d0bdab3da2f23409cbe405ca72e7c5ef930726bde0597afaca840f882c1aa0d14f493f457a53906686f8f238c09e0ba0b0ad801d43cdbc09204337fa7d8815a01819c9f65968140d0c4400145cfdd55466009cbfb101735d9bec4ab3ff298812a020acbfc6442ca9dd306bc737c1c7a2a6d657d94e70c4f870afa1b892f3567074a0b3e5e9bbaaca9d8224cd35a226f3ca3f672a6628da3d1f535548f221d191b65aa0a71651deab79eae3ae854990dad7867d05692cf59638a49375d1e8876330b9c4a07d425f76898d80bb9dd1a5809cc6d860b370322e2858c9424c3816988b3d36baa02712ec3edd3c9b4ba5a2c3c54552948e44fae0176ff91093a7bea2287322e444a0d6d91e277fa890428a80e32cfa6534070cf624d452e573b7b090d29660433b7ea0fdf781ebd4e006bbf706acc76ba0b4797c0e166af57c7bd148c1910ec7bd002780",
		"0xf90211a0bf35ef2b1747663bbd99b4f024e536abc2c06c88844fc92ad8ca488a2bc98ca6a0b1a63f2a0b574991c25e23aabac7b18050350c5bb8911118d98fff10dcf08d78a001f2bbfd87bdb4f8c3ec2deb3cf997250c3a4a04c2da627d1fac8c38cac8642fa092fd1bb246a0836b56edc3ae3a2196941ea8f0e34d5163ee725353c4f732ebe0a0427ffbf84124b4dd5330bfacaa0e4dfa8ed603fc1704da85f877edec2eae6759a05da578180ab8a77d24b2c122048b0e63c26dc8d304342590eb6daf5c90c402a6a03d1a80e9381c868e2a68b7d139571430b432b3c13689ad8bb4881e192ac2de8da0f658cfda1291c656ea8875e99f615da82a67ed843ee3514ba4ce176fc8180283a069ae5d08910bb436e9e98fd377e4e92322756138fa1e5be74fe05f97022db23aa01590eecaf4fc4cce7d4f598c5aee837b0509d9479de89302b2ac5a2ec68b5509a0a39f6c3334eabf836fbca44956f2f92f11fdfce355c3f320dff8c0999137f1cfa0e53fe6b5e10de49951bffb04b27bb231168a7cb25e4e974eab51fc3d794935bba085832791c6484617851d4559e4ce85b36e1d76ab82eea4a7dbe86bba69a4b2f8a06c91d9bd58e52c54a1cfc4207671a599af1174563d71ec37045e84559b196d57a00ff514c28b443a23e04cb1fd455ea35deba6b73b36e059bf8d39902c12e38051a0c24260f4c3ddeef7d1dab75b1df229822221fe5f6f78321631032e19e0f051fc80",
		"0xf90211a0b86e955848e314c2676c4f76657856ee890620e733e3ecb75805f0bbefb88fcea08a4b8f6eda73d2ceee028640695faf84e8a4a83fee244657f3ca00489f9e8f44a04dc9d8729e99e90e19b6879e1916467e0b8e548710c36cc66f20df4dea100ca0a098dc59d1869e7e23915e89258645a4d7671606b0d0968712a05152a9e4750ddea04192a645bde6551be4ee1edd3e010623c8d39e3c809847e0f1848e7837cdff27a056903dbf4cf25878b17db6031c1455582393cb91044f8d3b0c57944037b2be30a0327802c81547edfd3c1fbd3f53e4ffd58881711f96251cd8517579ed1c49543aa04c76f42207ddc50b1bb256dccae24216e690014c1809121f7ef3faa3a42ae2e0a00d8bc046ccb4613aaeb5133597615f9a928b379d16929ffcd200f90433b74981a03dce146747bf8ecfa10bbd50a23b85cb4f775c69bc70c96f6be4c94334e8c04ba01d55f45fc0efa28785da1f5256a8654f4e87c91f9c2eea4bb1db17576de73924a07ad28eb9cbc828c4ce435fd196ca27bb290f343c9597efe728422342cd94709fa072e0f611ff71fd32f33f54cc13c536a347307feac35a26c51b01090555691a74a0561bccf70e06055f5cc48af996ae7ef5beef40ff950aa0ec50d0b90bab1d846fa056621a1346d700083b96c7af0780d1a4857759ebed32c43cfc15c037c464d7ada043790b0d0a0ec17e676b00f41521038bb8f706f2e913d85fc25925c0984d90b880",
		"0xf90211a001528bb59f2d89e238daddf866c27f27f29aaf84fdbecdb7f870526d343d83c1a08d0e8f1f7b28e9044e41862e5fa18aa410a3ff775c7895c45cd0eb1ae44d9e06a05fbfb568d0f8c232698569c835dfb63848c7e51d28e7a5dc396470f2778fb2efa084aa1cb3c9985af2aab7e5f8809b72ba90e596ce936309b30c799702f2267255a04fe7b20d0705b18e0cf7aecd56631eeba442b4b122b44f244698181632590035a02ba0f78ff7bc99ea415f98fb1a2ff9fe0c84ef0a49aefb455e24b4a1d3ab7a30a0737106e5264d248d51cde695e6a3f622eafa10f524f9cd12ebb75ee5e41520d3a0ed2c2f0d00c53e62bae05969e543d6aa42af3858231e45da4ce80ff1c297d25ca0153f203c405d75220d9d5061372607b5b8ad4753283f5e2e47e6c5bb474618e6a0fc759da45db9ab2e910f04cc13e4d556bf97d62d7f3f60fba4c3e9a24ffa00d9a07a2b6d77fcff0e1c9996d217b44867680f267a7aa867d4769bb3d43f5682a79ba020c48436738940da37047d95707c29ef8bc962aef8f6d29555bcb851ae5f7d3da027b22aab664516a5f3682da36abc058808865b2c0ed578e798d8c004d3a636cea0510e0d0637544112fa15c575caaae025bb7c80c064b7b8a6a64dabaca35f10bca0b6dc0e22de8398fdf52bac5db6fd857a43540912e5eb82cf90e4284535bdb3e9a0c763176691af1a2922c2238936fa6a39cf9cdd7666c55c82fc868d30ea73aff380",
		"0xf90211a06e5930cb8f539f2ef96106c29d30030fb310ec8f8edeb83d5fd8f08caf5a0d3da01fa663887877e0d6e0f0d8e9debe2e9174ddeab5c841b60f2a05e3186cd0a9fca0dfc0df65274d9cbf39834f4ea27e5f7a41a7bbedbbb92f5831d00ac4d3cd4b64a08d3e8dc1b7c2ad8fca1e3214c6c83571b6f3b476aeb82858e26cf11cdb6e8b02a0a6267791bb89eeec6441f1a09e6c8bfd600d590d2e77c07c14a5ce230d115310a00059bdb448ff05c289efad56d7bf565d21b9466afec808bd009bf01aa01b89aea0f899eb064de30dc6f13154c34825b6c613e219d00813a7f3c9b5888f43e9a3a7a02fa64d5fdb11b9c405305298d11883563228466b4e7154359e4c40d5a936cbe1a01abd563ff42b415d266330299e37575d8319fe7afcd10313658402dde269446ba046f679b90d046666e9ac1df74f65a7b461ee7d7a76e5b935fb54cc1c72a3230da03ea9f0a7484361992da5a05f32cd45720eef60400707e15735f06b6f6dddd812a000577ed4088fd13dba6c700e4ae19931dc512c0220784c0f8fd52097d6238878a00d4e7b6593a3af2ad8117fe49d9968e18b07ee5ed81ba1d21c4209473028ef7ca0be988fecfbc375f070ab28820ae86467a2c959ca759ac56494d2ecc304ca6d71a08a22572b0dab9a0715629df7cd7a19219a96debd5f4ce887087f3714faa6d240a01baee95a323a6ae44246072ae1226229c21355117c4721fe879552a97982cf0e80",
		"0xf90191a0c22efe4967760047a503780c2e80d215329d3fc4d3c22562c938eb6991d3b259a0cf5923019519a9adf08334f59b31ef1cab3f3b28c070a0b760338687e90cabfea0af61a174641b841c35c1eaa23e72817749a39fe1e58eb9097e592e266f6ffd25a07553261c4cfacae12d04d14dcb597a0f94d6b817eeb797fb78c9e1c76a26716ea05683bcb1b9b81418f5607856f92972327531143b944cd6ffec6a471d3fb1b2fba0f04f7ffd5b21c59cb563398b2d75522320a99807f22cdd62f9b5d2b86b387491a0fba61dc248f33faa6da6f1c856e339451e0f6e833f2e09434c3a4180b018229ba0a21faea6eddf94568efe7770430cbc01b56da0ede5e1a1d098e8c243c3546d82a027983cfaeb169218677cf2a6d8cf42ff924458178fb2d12093407aac6440de70a0989609d1a0a49e000c5cc293f973658fc37d5839ae2979d35a6c0e78d4470154a0c40bfdc33b2f7d200ce6b61370c2890fa0b202be3904130da68e63b6ab86089e808080a0f9e70d6e5a4f1d50008588c4e4d28985a83009f853edd2c29edc56576b4f11e48080",
		"0xf85180808080a0deaab39c886e0601409672763ab78663fbc0aa328689b2c553eb1515b4c4e460808080808080a00c7eab0286642501eb5d88954aa73ba3bd67a8b79137972c774f6212b4f697578080808080",
	}

	realDataLength := len(nodeRlpHexStrings)

	var nodeRlp [mpt.AccountMPTMaxDepth - 1][mpt.BranchNodeMaxBlockSize]frontend.Variable
	var nodeRlpRoundIndexes [mpt.AccountMPTMaxDepth - 1]frontend.Variable
	var nodePathPrefixLength [mpt.AccountMPTMaxDepth - 1]frontend.Variable
	var nodeTypes [mpt.AccountMPTMaxDepth - 1]frontend.Variable

	for i := 0; i < mpt.AccountMPTMaxDepth-1; i++ {
		if i < realDataLength {
			// Feed actual data
			rlpHexString := nodeRlpHexStrings[i]
			bytes, _ := hexutil.Decode(rlpHexString)
			paddedBytes := keccak.Pad101Bytes(bytes)
			var rlp [mpt.BranchNodeMaxBlockSize]frontend.Variable
			for i, b := range paddedBytes {
				n1 := b >> 4
				n2 := b & 0x0F
				rlp[i*2] = n1
				rlp[i*2+1] = n2
			}

			for j := len(paddedBytes) * 2; j < 272*4; j++ {
				rlp[j] = 0
			}

			nodeRlp[i] = rlp

			nodeRlpRoundIndexes[i] = keccak.GetKeccakRoundIndex(len(rlpHexString) - 2)
		} else {
			// Add placeholder data
			var empty [1088]frontend.Variable
			for j := 0; j < 1088; j++ {
				empty[j] = 0
			}
			nodeRlp[i] = empty
			nodeRlpRoundIndexes[i] = 0
		}

		// TODO: calculate prefix length and node types dynamically
		nodePathPrefixLength[i] = 0
		nodeTypes[i] = 0
	}

	leafRlpInBytes, _ := hexutil.Decode("0x" + valueRlpHexString)
	var accountInfo AccountInfo
	rlp.Decode(bytes.NewReader(leafRlpInBytes), &accountInfo)
	log.Info(accountInfo.Nonce, accountInfo.Balance, accountInfo.StorageRoot, accountInfo.CodeHash)

	var storageRoot [64]frontend.Variable
	for i := 0; i < 32; i++ {
		value := accountInfo.StorageRoot[i]
		storageRoot[i*2] = value / 16
		storageRoot[i*2+1] = value % 16
	}

	assignment := core.AccountProofCircuit{
		// Input
		StateRoot:            accountProofRootHashHex,
		AddressHash:          keyRlpHex,
		KeyFragmentStarts:    keyFragmentStarts,
		AddressRlp:           valueRlpHex,
		LeafRlp:              paddedLeafRlpHex,
		LeafRoundIndex:       leafRlpRoundIndex,
		LeafPathPrefixLength: leafPathPrefixLength,
		NodeRlp:              nodeRlp,
		NodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		NodePathPrefixLength: nodePathPrefixLength,
		NodeTypes:            nodeTypes,
		Depth:                depth,

		// Output
		StorageRoot: storageRoot,
	}

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &core.AccountProofCircuit{})

	if err != nil {
		fmt.Println(err)
		return
	}
	pk, vk, err := groth16.Setup(ccs)

	if err != nil {
		log.Fatal("groth16.Setup")
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		debug.PrintStack()
		log.Fatal("prove computation failed...", err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("groth16 verify failed...")
	}
}
