package common

const (
	LenOfValidators              = 512
	LenOfPubkey                  = 48
	LenOfOnePubkeySSZBytes       = 64
	LenOfTotalValidatorsSSZBytes = LenOfOnePubkeySSZBytes * LenOfValidators
	LimbsPerValidator            = 6
	BytesPerLimb                 = LenOfPubkey / LimbsPerValidator
	LenOfTotalPoseidonNums       = LenOfValidators * LimbsPerValidator
)
