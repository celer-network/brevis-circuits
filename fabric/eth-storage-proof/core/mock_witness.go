package core

import (
	"bytes"
	"math/big"
	"strconv"

	"github.com/celer-network/brevis-circuits/gadgets/keccak"
	"github.com/celer-network/brevis-circuits/gadgets/mpt"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rlp"
)

type AccountInfo struct {
	Nonce       []byte
	Balance     []byte
	StorageRoot []byte
	CodeHash    []byte
}

func GetEthAddressProofTestWitness() *EthAddressStorageProof {
	// test data:
	// block number 0x103f9e8
	// get proof "params":["0x881D40237659C251811CEC9c364ef91dC08D300C", ["0x1"], "0x103f9e8"]

	// ================ block header test data ======================
	blockRlpHex := "0xf9022fa0b0ff4a0678831b194b50d4147cef9cd4e360e8ac4569a8ccdcfee81f40d82acda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794690b9a9e9aa1c9db991c7721a92d351db4fac990a054820fb8648ea7eacfcdd0668e1a8afbe933341e787d0a09636ac19e11d8ec18a0bffc95ed579c768622108e9d04f8b8f7ee2629d19b016c865848da6639be70dca094c810c747828c9bebcb56c31ec854d1753d37c07bc87081be01a0699117b444b9010075a7e50fff80a746fae996a9c340da630b29104bd3062a11063915f5d645451a1ec743408605052001193b9dd342bdd893890863ab6bbcec0a9c3b03796c6cf19c967f21e53aadaa7ba37b4c12d943648a100191da67594ad270642ccc3c6e23db801f2052478b232d193818e4cdac45a69868f6099c9e8d4276465981ec1c65d1ab2fd24566fa4634cd6c0987be138e7910f5ef0943caf8792d27e80e31b3049abd64ef1192e1c3245349e895b5ade8a77404c0e79bfa0a206eeb6e9a8a5a42f18e4242ba4524450c60b46aa5df3f34d1494b87aebf28944c7f3d069828fbe3b77cbf68488c908624499fefa4e02813a53c0a584dbf6e566fc999c3c1f1d68180840103f9e88401c9c38083f70ce7846437ce7f8c406275696c64657230783639a04f5e3a77c67e55193fc97590474c6a09fe530f231d02ba6ba6c79e00fdc23a568800000000000000008508b5987915a0c3c77de387b43bdb4e36871270f1255e0f1d6255b00b87476e8a1bcb15d53788"

	// 0x67c5d26ae6ef00adcf970d9b1876f0eaec41f94d88b7a0299e9d6109cdd9bcd8
	rlpBytes, _ := hexutil.Decode(blockRlpHex)

	paddedRlpBytes := keccak.Pad101Bytes(rlpBytes)

	var blockHeadRlpAsNibbles [mpt.EthBlockHeadMaxBlockHexSize]frontend.Variable
	for i, b := range paddedRlpBytes {
		blockHeadRlpAsNibbles[i*2] = b >> 4
		blockHeadRlpAsNibbles[i*2+1] = b & 0x0F
	}

	blockHash := "0x67c5d26ae6ef00adcf970d9b1876f0eaec41f94d88b7a0299e9d6109cdd9bcd8"
	hashRootBytes, _ := hexutil.Decode(blockHash)
	var hashRootPiece [2]frontend.Variable
	hashRootPiece[0] = hashRootBytes[0:16]
	hashRootPiece[1] = hashRootBytes[16:32]

	// ============================ account proof data ===================================
	/// Proofs without leaf level ---> accountProof[0:len(accountProof) - 1]
	nodeRlpHexStrings := []string{
		"0xf90211a0e3110754189284defdd03b488d55abecd554ba4d8193470b6e9ca34876b80072a06f98da6d74cefc4a45e5377b5da2141a822d458d4286229a99f26ad0fb8b493aa0fe80fe312f15a1729087b791d8b822354ee3325e9246b6ee84ff33a3b532f6c9a0dea74e9fb72aacac34754937191990966a67446dc4226f29c6ec89aaf3299695a0ca8a42c52fa84c8a88563c69f77431622a265e661f5e4ae9d5e4815538dfc77fa0d660fa1a0e72b166aff495498f42a085cf4eae5e73c1ac6a4ac821802b2bce69a02b04202be9ca006c43e79471f2faa7e06b5fafa48b1ac92cc2b6d5bb41fc2442a0b4c88c8b5cbf109bdb0837f8aed81a72b243878646c23079a05995491d431722a037863b3af0da58ae338e60cffab7566921236a1bbf65a115645ad3c920a40e9da0612df50622b0b0f364bb60e48682a4681356a441573595e23554fff68259cf46a0482d22c05e5a266ef01ce12e77aaf30c1a9a11db986060bf42032586d3464ac0a0b0df7f3af131e0f15f8dd67d5c6ce2338db631e17bec1da8eecf27305a008fa3a0194a1a0f67e34fe0cef2d0b66294e60b96e145bce38fb8c35b0e7be3f82b7b79a01f1361cd02b112673f64731219a2702dc4e069d08c3b50891443b0da97c1b83ca0181db8397c1511dbbd084f76daa017eec381f1587ab86e84fcd74d41c8372910a0d93b704d391c3636470ee62edd85a2abd750023ca2535d1bf9488be578d0dc9580",
		"0xf90211a0e1bdc5bbef44d07d9d35480c49d42b852edcfb6f3303eddfacf1367edab23ce8a0f4aa297c0fb5ca2684a36a85d64d3888681501811af70c0aad98bbc4fec268fba0ad1fc99b36736ccb0352c1f042105ee2ce8379e99938b2fb9e5ebe6ceb4b892ea08d33b424ef0f4252dac03c0e34f6912e40e3bfcb7f1c5497a646d9616fd8b7aaa0b199ca64440e80cd661d789897ec088abbe83e06169598833e3fe52e9b387afda03931b6191c3fa7d48cd66395671b7c943d2b4645a84c3f1f0385e4db3f54cf0ca0ad98d09af8ea9cd90a03a58b26c90aa4942f943686fa3d07f50049414764f5eca0085cb16f394859e14259619b3496962722ea09a4bdbe1de10678415efc57d138a0a04843c4d71f2df3cb3e9dbccce1236ac9ad2e8d451f24803cc9f723b5ec3a2ba067605686e0190d9a123cc290a96875f39f87cf1930c48be2c7e6b505005e2daca015cb59fed275bde05ebc10d675eda309b621845714a38ea58dfa764de4f359faa02806c2c974da2d61b2ca8fe1c36594cfd819b9c9df9c3740ae74cc68b99e47f9a021a9bbf09c1d4488bb055109867379e153fc06684abdbe92f4b26c062864d33ea09ca3a789f2e2aca8e1b9df4f78ababa740e1096089d0ce28c1d25b1866060fbea07cd58136d968b884213249c571fc1df31d48d949056e6591a7b249f1aa25972ca07039caabd2f09ddefae13d706b7d4ef9f22bce01602e053feaf208175181bb2980",
		"0xf90211a02a002e581b5efd537a2e63ff8e0c6c5314998b743696d8b127f3186d79af0804a032a504d61ed06e49207658ef4091774eba145dd173eecd9f6a231a24606f7f66a0bc4fc90407fd0b87fd0b32fb03a570e0fad0f3d22aaddcb70dafb1b1d7238208a0339198149e5d807d179cd96c57ebdde3a3cae075c1e31226003c49469862ed9fa0372561ce70143ca6571a4d6c4a7cd6ff0a4e69f007ccd7a9f4d624d05e068f12a0eb807590bbfabef1b2c476cbd6593344a59ad4e47d27b056ea424ef65166df51a0ef0397475bb25ce0eefd65e99c8eeefa8d7dfc4dde75ec1aa879eb437053a060a07ee3e8e3584c22975d62d2f32473830ac128768e985fd134f772e2f5b8f92ed3a063216eb043cd5caa89ca46e8370abfb419d0b549e6acb1761e2f3d80df9c47cea0b211f71d696fdeb391fc4b0baa8f9677ddd38dc835484a297fc15fbdd91d7d4ea0e22808b60c2bba0f769ca51a9a86712243f71282d043b9a0233705fb48456dbfa08e9ad70e1ce4101d6c7417af47c3fe738f575f9af0208646f66458b0ce56c25aa026483da5baa6f6376847bfec2be743fc912ffee0cf7715aa02960445385b3cfda0be6a831d2285e60d59d97142ccf1b9cc1cd6d4ccf706413804fda1121789c96da0c2e8a671109d59b6e1d2ba18501af33aa3742fd8f8e26f84d348d3b1120f81aea05cd84dd416367d74d647bc6814d9beb3f8be1fe5499240522f08ddf4834fa79180",
		"0xf90211a0587218d05231edec4a6e4de8c43bd2eec6556592e469537d6435aead88327528a0da5948ea3023ac4f3c78f9aa241555ec24686f521f0fe66eec48f0e5e00e97efa06036fd0dad817410a85d11199b3453549c808be440080df5f06b6952407a67aba0c139304424191ceb1483812467f3818050a4149f00374a13d138c1909ff6e387a0b150f8653b42596b01df2167249c0813d3b5c14e4de9edc862308e200aac90d0a099a31c1952d43f0faa943a31cb8c057d8c4680ab9a8d1190e26719f35a82c9e8a0c95d5f0e3cf68c4ae0e3b8da26c96b7b8f988d033f4be7c8119a02d48ce89cb9a097613250fdacd1823dcbe6e5bd136434bc9edb255ffe5c0ffb073c3a73f7fc61a08181ec42b5672db56b5fec03dbc2a97257470d8cca180cd882eeae3dd5fb07b7a084fa69cd6ab963e1f02d29d0613d72771cc010ad127def9b7109d30d568d86e5a0141a6daedac20c6105794c5014ebb5f8d723944e0841a07324cdda14e22bfbeca030d0e68343a4e9e7505e6252b09ef4ab11d1d623d62088c8e1d28d7b5beff847a0a810c336f6d608765d11713af20db8528c77b06e8ba56aa92ed7b960163b860ba0d6d72fc5f59c11df94fe3d803e3e80ad9d35fb11ab57bb5413bc358ce4317a56a014376a1e611fc67bd2127e6b20b2c6ee88c27fddbdf450faed85af68b712eb1ca073304843e73c0fb8c5faf4c3f6e61e4fb8c19fdca8c731cff9de4858a23f892780",
		"0xf90211a0eb459e0068f7a786053968a242621a436c110c7dfec2504758ffbb8152df1bcba0df9415f3323f9ba2e1fd3a28a2a824cd4f9a1bb2bf8155d08d6212bdf30f75d9a02c3ccef32a07b00396dc2bce3cb9f258d25e75d192a6340e7c742d2727a9456aa048afa9f584d6c90445f034fb086bf9fbb00f3c90806513f86a7255c4a191e679a0e834cef27ba60ced90166b0dd946a97c42b160f8dbe40d2f951a9649c6f11048a0b50e87e0f6753b8fc6b4f9e05c190f69226bf87db0e2b2217b3d1030a4197efda0989bbf71aa676fc692d5b2cf4dcc49eab736aa6f7fcd8bdee127e0d43b77fc0ca03fc2e3823c14258a4b906ccc54ecc71b60ea10ac3932ae63069542f64512da5ca0e476c9b65a9251866fa53917e2c1e5920b85ed1edbd31e623f1453d268c24b8ba0b36420c530b80aeeaa8150418739ec35db7425a5eecb43edc1211a505e8f7964a09044fbe1ea88fb4d6a29eb8fcac6d24b07dd65921fecedb524b339de703947e8a0fef0cc9f6298a7954d34d5becfdef70128916d1a2c701842484d8fb8673f45e0a0044c724bdef3685389a851c8446ba257ef84ac5f7242cc834246e890eeb67f88a0f66cdc1f8f732dbfcb3451a9c9213a7dcb94c712d4e633b1d4df8d123ec2dc80a06af029bd811706608c2c8cd41df0f862278a90c3ce8bd1322aa6396f0328c52aa05c35dcc4e8e58c735918f78cef249d76f09a84a2d7a0288e1db535abd6cc8b9780",
		"0xf90211a00b5822ecea30c20731a5f2fd95ef36d83355f3b342d7c2046d6ce6535028970aa0d09cffc4d0af700f884f355673058125fecb8aa8440b850400edb0aed903c26da04e3f41344d62c926e88dd8c572a9b06eb6d40d54a68190c665b0ac05687c12f7a0bae8c6131e917c8fc7991b3627cb56fa2c2b01f372b27107dc9dcbdcf395c976a09b4c818c2a520e17350a77fd5ded1a74c4e94592472495c9a037b5a8052d4003a0abfa7d80b7e8d0925667fd9aee49e5b970b04a92a81a03eca1583d77cca278e6a0b5cb5ae30c1934bfd32579f1d852b3532e033bb0c4dfc6845f53c2617623f17fa0c7f232cdaf874977ff736476a035858e8e1e595db64dd35c43f499d573be4936a0493dd89fe9eae5b86ede62bae9cc5ddecdb24e7c4610ba63f3b8511b16a2a1dea0db312bc75189a1e264e30612bcef8b6a721058d5eb9c4f958377ba4b1470aa16a035f6f55fc61b802212aef6d1aa094390b6cc0263d05f453f34c66930245fefd5a009553805722b75a92372a3c25a4136b7446fe21e3c2cfa21c33e0abe44ed4cdba0b12bc454a659b55e36f52069c9b4e8cb85e1e8c0cef8f74426379a1f44375704a04a04c47e16ecf523163961d5d3c8018340d24e193550bdccffbcff91b58223eda0557a64e65eb99efbaa50c4cbe56df4fffa2084e53fe17b35ace020ef1c90dad4a02268c08e7603f3e3fd9a8a1311a7d08a649ef7bbd394ffd942ceebf3ebf5e44d80",
		"0xf9013180a0616f466053f01c2c103775b76b0c9547f5839e55617a4d61c5d3a463c882383aa0d15ee7006c4d4cd5f4a702fbd112399abca3df889e0fa3cc7e1c20f1f180d23e8080a07c58c2d01f9420ddb2fb8639c82ec7ff267bcfbf49eecd9e5a9b0966d9a37f51a0ac0890c2539cf91e5fa1b33c5aa8367ddcb04e3fc865994d4722f718827205fd80a01757cf1793c1420b486d5e45316d4ffc1809fda5197897afcffb3e130b754834a0a23c05a5a8f9d0db67bfa43f97a5c9aafbdda34c9b236c3114e753a3403ede39a0908e21ccaae061a950dd75f68ce3bc375ae1d9ce137897ca37bd21a4ff9c290ba07a140996704380378e802596e2bc9d17684bd6bfefc5161927a7dbbfba7846b68080a0c439ea63a71d280613439a03eedb8a70df9f62a946988a905508063080ea94958080",
	}

	addressDepth := len(nodeRlpHexStrings) + 1

	// keccak256 address as the account proof rlp key
	addressHash := "0xe6421abff3b5bb3c807e27089b297419fb09d898a94c8dacd695825e8d803c38"
	addressBytes, _ := hexutil.Decode(addressHash)
	var addressPiece [2]frontend.Variable
	addressPiece[0] = addressBytes[0:16]
	addressPiece[1] = addressBytes[16:32]

	valueRlpHexString := "f84c018891a55d622bd2bb4aa0223ffdd6234ec3e83c9dbe8e31e6b7fde781c791b894b9a310878f98a84e4702a0d2b0c127b5a063e6adb2049fd927777ec7d5344a44ffad27767e461acd55b499"
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

	var keyFragmentStarts [mpt.AccountMPTMaxDepth]frontend.Variable
	for i := 0; i < mpt.AccountMPTMaxDepth; i++ {
		keyFragmentStarts[i] = i
		if i > addressDepth-1 {
			keyFragmentStarts[i] = 64
		}
	}

	leafRlpHexString := "0xf86e9d3ff3b5bb3c807e27089b297419fb09d898a94c8dacd695825e8d803c38b84ef84c018891a55d622bd2bb4aa0223ffdd6234ec3e83c9dbe8e31e6b7fde781c791b894b9a310878f98a84e4702a0d2b0c127b5a063e6adb2049fd927777ec7d5344a44ffad27767e461acd55b499"
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

	leafPathPrefixLength := getRlpLeafPrefixLength(leafRlpHexString)

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

	// ========================== Storage Proof Data ==================================

	/// Proofs without leaf level ---> accountProof[0:len(accountProof) - 1]
	storageNodeRlpHexStrings := []string{
		"0xf90211a0be79bbef25a2b13624d5aaf665950e0be83299193f35d36af2b00a183338c7b3a080db53bc5f7dacd48bebf5803513573943e25b7ab005d37d0b2bab046ae16958a09597c33258c3b2e945a178fb9f3a92e8d621ee47176c3d55aa0b7929601000c8a04f151a33a2142558feda42d8dfd71e043a33ebbc3d8e43a7fa848ec40df6bbf8a054eb55c4ff861cc32714c2f36d2ab00f8d6ca4db24a0fe4bb48a25400df4349aa0074ed9a4362bf650c11f49a5acef73a3183fe9baea59db47396ce3c59e9b0004a01eef9043cf815b1833a2900f1df267b5039f156db84c99443dd8758b1e99025fa02a87a9450cf036d1979ca200112be663d9cd8b949b3d45bb39e03d75ad363a70a09eecc4c9ec41ccaef498afced2847d3e17346216dabf1fa1bd47cc3cf8c2e3cca098abad147ca54d0c03fa04cb67de17156b9d6de4bed98b7903aebe11ce2da962a0f8ef94b146ea4f542f94d00b6247b6c5ff34f1beffeffdf61313b9f563a3b4ffa0ceeb657762022c9400137a115d311da47aef1a242e0d6217decc4f97ba802db0a03a012b654e5ba97c0f4d6dfb79c7bd8ffedb25d5ba2c4ad0d6182b72b721b9e6a004a82bfe7ade9412a7519b074bc2a902cfe250fdc3e4451cdd9b4830bbe721aea0737cdda4e17c7eaefddea05d3cf99a0329ffe2b191273c4df55dd677d2c1388ca017952a4981333fbb5ce8065391d50f2c97494ceb70c5be3d34327ee44ca748d580",
		"0xf90211a086c83be69861ddf8429e10af5aa3701daaa19b83f172fcbd28613777e823ddfda01fa03fe781a5a5361ea5dd2959780c986d85e747c295a80f7e660221fdb32e44a0ba41572e37848227cc136f731a0f18f41cc009f65e8b1779489cccbd0ad31b16a076f6bfdc159974032798967892ae93c8e442a910222669bde69196a5c27a0967a0e87ebce92139b94a0ab6ea545a404ba6631d28a5577a20738cd2c6ec83c680f7a0bd3000ec765defe6e3327282cced5b35758ef75c6e2c9b2fc232a66d567dc849a0d7276c4af30762726a88de3aa1567677fbd8be5b56fc3bf5b01cc815fd66b474a021989ab3713bb868a4285545e3ef68971993c77e6d8b9d7e0f1c1ef0b9bb66e1a0151db5ae88d11e02045084684ef31a3f08f6f475b2df2d3741706695fe689090a056296d0f599201ab90072ea138381a3581cba0cd2523d2fdcef1e949b9796f11a0959d42cb889c66d83520644bdc2d359eebe537da041ef8244c93f9da2e960f3fa0f66724632cbf74fd70d04f7153832631626ea22770aff1b0f4d9a019a9d62508a0ece10a0092d56e577979c46a07baccd851d2d548c5ebeac1731eba0408f76a7fa09f9b71f292e35a2973fff7fbd40a32b8882823472781b22ffa103466fd135ae7a00e6b4244d52a085322e9771d785c233f04150053972839f3eb329ab9929fb91fa0b409c2ee813ee34103fa0dfa40d2174a72aa58f254980054482329c92cec2bea80",
		"0xf90211a05096ae22a8fce7df8d45d7174ee8e5ca3506594354a043e284759930d6ee0994a094afd5bdc51d3bf166214db63955b11b64e4916c69b14079550814635c01cec6a0a9138935dd99f74fc4ca067bd4dfc1212c3845b34900dfeb7bb3f4e93319b5aca0c5df5d789c003f003582bf1d6f3eea723a6f3815b0dfdc58778041809a3a32dea0538e0ec772fdd077c0a584b2443a2f3c8b4a5e8352986cbc75a55225098a86d0a0e0a958fdd3dffc73c4bb2ea296a1d944e648bee3a65a42a670f52598302fcdb7a0b37b29e5eb35dd874244e1a15254da471611f046255e7f07186b5a832af946a7a03fdfa036432d433f8a7b3f652bb47d0ec084aea179bd23e05609e1b006d01ad9a0c0ccbfcde91354bab9c0735b081341ac0f6f860fb148c3c65ede6132fb2f7d4ba0acc2ccda89608ffb5377b71f7875c194f98ea5b4b0b68b9b9e49b1403fb0b554a05329f6a52e5af0896b797a3a077332ee7f53da164e099e69c87afa28607bae72a0812fb84f7d474e9ecc54f43d647ae4c63bde2798f077e921f105815ccc5052cba0e4d373afc58e2912eaedffc8a5f0ba0f03f70f0024e2b77c5085efe84ae552a6a05176a72068c40dd1c9255c6f4f0e148cf1161e920932034427c43343b04a0a75a0b03f557fe62b6de6127b696439794ded785c6d6681e826f588aef15ac7f9bd99a0a96dd96057e008b6d29126c97fe7084ec5422ed8dc0a9b30a4b4b46c2fa6f11580",
		"0xf90211a0f5ae1a6ce144d85d80d73fbe4f5a4ee817bc53d2ad823bbffa4e31c8f364d83ea0f06a0cbfa6d00d1acf4ae675dbbc406eb0f16ced226cc1d9458d0cae1079206fa070aa2f34d8fc2049aae9ff6e9ee1d510471b9ac6f9a94e3374560faee161e569a03eb1ec7a2f394bb8c668b67852d94187c05aa9c57ff585da954b85d68a550e2ea068238480fa6c1048d93cd8e6737d990311d9906715bba2cd46db5d04e260085ea0c73f36e6cb9ea40c2e07c5ca8ab7af07aaa1377870b74d40e301ec495b048abba0305a943b08b3757235ff17304b6e01135f61a72df82eba513014bb3bcc7b19dca0be11e1fbe840565be9004480ff279d79638451b6a377438ea692ecd436f3f265a08f5d1564eb586469cca8213765bedf95c4b1882d7cda7941d715c5077cb6acd4a004a7c0b66387e9424a8fcb4649369a7854d81bad4a0dd6d101b3d0431301da5fa0e685c21a078e26ecd58371971133ff780241c99872969383c54b2cc3c89273e6a0deab39923099ed12d3558af269cff70e4cd027954c07ba28233603fa425bff03a0eb3efedebae0914abd7b19d91bb6167f7b073d2e0c7d0fc517d785567a131c36a03d674266c160065389ae6b3270fdad7eedbb1f5b44db74df11ea1d2c5be1a243a037a900f52b9490cd72b1b701441c3264af88ca379bb5068a38b747eb933597caa00a9ea2d409d844c151456013dca2d4fafd5cd6355e7ba137c9c3ec73c65632fe80",
		"0xf8d18080a0f9be7c17de345b523e5d9568cb6f26c854d73ef3e882e6af23ee833f0510d52b8080a0542aa8570d4008344b7f2654df9ffd95d0d98f62c4ff3dd9d30c2e18b696c3ae80a067b5689f960a0a27d7f6007d653884d2dcdef406544ca5aaebeb89a117844e3f80a0812bd6ad9a9f19ddc271b0456f207ca0cf41edd070cebd0782ec14d89a66facf8080a04685e9074d76098f1c9c0cf91b384b0ce4d8233f6a84d969db62f1df7e26c9aa8080a01a523d1382b3819a0a63aa565d87fcf271c1f3a08e911e2aa74a6081e3cadcca80",
	}

	storageProofDepth := len(storageNodeRlpHexStrings) + 1

	storageKeyRlpHexString := "0xc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b"
	storageKeyRlpBytes, _ := hexutil.Decode(storageKeyRlpHexString)
	var storagekeyRlpPiece [2]frontend.Variable
	storagekeyRlpPiece[0] = storageKeyRlpBytes[0:16]
	storagekeyRlpPiece[1] = storageKeyRlpBytes[16:32]

	storageValueRlpHexString := "a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	storageValueRlpHexLen := len(storageValueRlpHexString)
	var storageValueRlpHex [mpt.MaxValueLengthForStorage]frontend.Variable
	for i := 0; i < mpt.MaxValueLengthForStorage; i++ {
		if i < storageValueRlpHexLen {
			intValue, _ := strconv.ParseInt(string(storageValueRlpHexString[i]), 16, 64)
			storageValueRlpHex[i] = intValue
		} else {
			storageValueRlpHex[i] = 0
		}
	}

	storageRootHashHexString := "223ffdd6234ec3e83c9dbe8e31e6b7fde781c791b894b9a310878f98a84e4702"
	var storageRootHashHex [64]frontend.Variable
	for i := 0; i < 64; i++ {
		intValue, _ := strconv.ParseInt(string(storageRootHashHexString[i]), 16, 64)
		storageRootHashHex[i] = intValue
	}

	var storageKeyFragmentStarts [mpt.StorageMPTMaxDepth]frontend.Variable
	for i := 0; i < mpt.StorageMPTMaxDepth; i++ {
		storageKeyFragmentStarts[i] = i
		if i > addressDepth-1 {
			storageKeyFragmentStarts[i] = 64
		}
	}

	storageLeafRlpHexString := "0xf8419e3a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85ba1a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	storageLeafRlpBytes, _ := hexutil.Decode(storageLeafRlpHexString)
	storagePaddedLeafRlpBytes := keccak.Pad101Bytes(storageLeafRlpBytes)

	storageLeafRlpRoundIndex := keccak.GetKeccakRoundIndex(len(storageLeafRlpHexString) - 2)

	var storagePaddedLeafRlpHex [272]frontend.Variable
	for i, b := range storagePaddedLeafRlpBytes {
		n1 := b >> 4
		n2 := b & 0x0F

		storagePaddedLeafRlpHex[i*2] = n1
		storagePaddedLeafRlpHex[i*2+1] = n2
	}

	storageLeafPathPrefixLength := getRlpLeafPrefixLength(storageLeafRlpHexString)

	var storageNodeRlp [mpt.StorageMPTMaxDepth - 1][mpt.BranchNodeMaxBlockSize]frontend.Variable
	var storageNodeRlpRoundIndexes [mpt.StorageMPTMaxDepth - 1]frontend.Variable
	var storageNodePathPrefixLength [mpt.StorageMPTMaxDepth - 1]frontend.Variable
	var storageNodeTypes [mpt.StorageMPTMaxDepth - 1]frontend.Variable

	storageRealDataLength := len(storageNodeRlpHexStrings)

	for i := 0; i < mpt.StorageMPTMaxDepth-1; i++ {
		if i < storageRealDataLength {
			// Feed actual data
			rlpHexString := storageNodeRlpHexStrings[i]
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

			storageNodeRlp[i] = rlp

			storageNodeRlpRoundIndexes[i] = keccak.GetKeccakRoundIndex(len(rlpHexString) - 2)
		} else {
			// Add placeholder data
			var empty [1088]frontend.Variable
			for j := 0; j < 1088; j++ {
				empty[j] = 0
			}
			storageNodeRlp[i] = empty
			storageNodeRlpRoundIndexes[i] = 0
		}

		// TODO: calculate prefix length and node types dynamically
		storageNodePathPrefixLength[i] = 0
		storageNodeTypes[i] = 0
	}

	storageLeafRlpInBytes, _ := hexutil.Decode("0x" + storageValueRlpHexString)
	var storageInfo []byte
	rlp.Decode(bytes.NewReader(storageLeafRlpInBytes), &storageInfo)

	var storageSlotValueByte [32]byte
	for i := 0; i < len(storageInfo); i++ {
		storageSlotValueByte[i] = storageInfo[i]
	}

	for i := len(storageInfo); i < 32; i++ {
		storageSlotValueByte[i] = 0
	}

	var storageSlotValuePiece [2]frontend.Variable
	storageSlotValuePiece[0] = storageSlotValueByte[0:16]
	storageSlotValuePiece[1] = storageSlotValueByte[16:32]

	witness := &EthAddressStorageProof{
		BlockHash:                   hashRootPiece,
		AddressProofKey:             addressPiece,
		Slot:                        storagekeyRlpPiece,
		SlotValue:                   storageSlotValuePiece,
		BlockNumber:                 big.NewInt(17037800),
		BlockRlpFieldNum:            17,
		BlockRoundIndex:             4,
		BlockHashRlp:                blockHeadRlpAsNibbles,
		AddressKeyFragmentStarts:    keyFragmentStarts,
		AddressRlp:                  valueRlpHex,
		AddressLeafRlp:              paddedLeafRlpHex,
		AddressLeafRoundIndex:       leafRlpRoundIndex,
		AddressLeafPathPrefixLength: leafPathPrefixLength,
		AddressNodeRlp:              nodeRlp,
		AddressNodeRlpRoundIndexes:  nodeRlpRoundIndexes,
		AddressNodePathPrefixLength: nodePathPrefixLength,
		AddressNodeTypes:            nodeTypes,
		AddressDepth:                addressDepth,
		StorageKeyFragmentStarts:    storageKeyFragmentStarts,
		StorageValueRlp:             storageValueRlpHex,
		StorageLeafRlp:              storagePaddedLeafRlpHex,
		StorageLeafRoundIndex:       storageLeafRlpRoundIndex,
		StorageLeafPathPrefixLength: storageLeafPathPrefixLength,
		StorageNodeRlp:              storageNodeRlp,
		StorageNodePathPrefixLength: storageNodePathPrefixLength,
		StorageNodeRlpRoundIndex:    storageNodeRlpRoundIndexes,
		StorageNodeTypes:            storageNodeTypes,
		StorageProofDepth:           storageProofDepth,
	}

	return witness
}

func getRlpLeafPrefixLength(leafRlp string) (pathPrefixLength int) {
	input, err := hexutil.Decode(leafRlp)

	if err != nil {
		log.Error("Failed to decode leaf rlp", leafRlp, err.Error())
	}

	var decodeValue [][]byte
	err = rlp.Decode(bytes.NewReader(input), &decodeValue)

	if err != nil {
		log.Error("Failed to decode", err)
	}

	if len(decodeValue) == 2 {
		if decodeValue[0][0] == 32 {
			pathPrefixLength = 2
		} else {
			pathPrefixLength = 1
		}
		return
	}

	log.Error("Failed to decide leaf type", leafRlp, decodeValue)

	pathPrefixLength = 0
	return
}
