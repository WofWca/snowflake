package consenthandshake

const RequestHeader = "Are-You-A-Snowflake-Server"
const ResponseHeader = "I-Am-A-Snowflake-Server"
const MaxChallengeLengthBits = 256
const MaxChallengeLengthBytes = MaxChallengeLengthBits / 8
const MaxChallengeLengthHexChars = MaxChallengeLengthBits / 4

var ChallengeKey = [MaxChallengeLengthBytes]byte{
	'S', 'n', 'o', 'w', 'f', 'l', 'a', 'k', 'e',
	' ',
	's', 'e', 'r', 'v', 'e', 'r',
	' ',
	'I',
	' ',
	'a', 'm',
	' ',
	'i', 'n', 'd', 'e', 'e', 'd',
	'!',
	' ',
	':', ')',
}

// Mutates dst by XORing it with src.
// If the arguments have different length, assumes 0s for the remaining part.
func XorBytes(dst []byte, src []byte) {
	// So that it doesn't panic with "index out of range".
	length := min(len(src), len(dst))
	for i := 0; i < length; i++ {
		dst[i] ^= src[i]
	}
}
