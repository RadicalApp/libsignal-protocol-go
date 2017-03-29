package fingerprint

import (
	"fmt"
	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
)

// NewDisplay will return a new displayable fingerprint.
func NewDisplay(localFingerprint, remoteFingerprint []byte) *Display {
	return &Display{
		localFingerprintNumbers:  displayStringFor(localFingerprint),
		remoteFingerprintNumbers: displayStringFor(remoteFingerprint),
	}
}

// Display is a structure for displayable fingerprints.
type Display struct {
	localFingerprintNumbers  string
	remoteFingerprintNumbers string
}

// DisplayText will return a string of the fingerprint numbers.
func (d *Display) DisplayText() string {
	if d.localFingerprintNumbers < d.remoteFingerprintNumbers {
		return d.localFingerprintNumbers + d.remoteFingerprintNumbers
	}
	return d.remoteFingerprintNumbers + d.localFingerprintNumbers
}

// displayStringFor will return a displayable string representation
// of the given fingerprint.
func displayStringFor(fingerprint []byte) string {
	return encodedChunk(fingerprint, 0) +
		encodedChunk(fingerprint, 5) +
		encodedChunk(fingerprint, 10) +
		encodedChunk(fingerprint, 15) +
		encodedChunk(fingerprint, 20) +
		encodedChunk(fingerprint, 25)
}

// encodedChunk will return an encoded string of the given hash.
func encodedChunk(hash []byte, offset int) string {
	chunk := bytehelper.Bytes5ToInt64(hash, offset) % 100000
	return fmt.Sprintf("%05d", chunk)
}
