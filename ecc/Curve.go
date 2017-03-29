package ecc

import (
	"crypto/rand"
	"errors"
	"github.com/RadicalApp/complete"
	"github.com/RadicalApp/libsignal-protocol-go/logger"
	"golang.org/x/crypto/curve25519"
	"io"
)

// DjbType is the Diffie-Hellman curve type (curve25519) created by D. J. Bernstein.
const DjbType = 0x05

// DecodePoint will take the given bytes and offset and return an ECPublicKeyable object.
// This is used to check the byte at the given offset in the byte array for a special
// "type" byte that will determine the key type. Currently only DJB EC keys are supported.
func DecodePoint(bytes []byte, offset int) (ECPublicKeyable, error) {
	keyType := bytes[offset] & 0xFF

	switch keyType {
	case DjbType:
		keyBytes := [32]byte{}
		copy(keyBytes[:], bytes[offset+1:])
		return NewDjbECPublicKey(keyBytes), nil
	default:
		return nil, errors.New("Bad key type: " + string(keyType))
	}
}

// GenerateKeyPair returns an EC Key Pair.
func GenerateKeyPair() (*ECKeyPair, error) {
	logger.Debug("Generating EC Key Pair...")
	// Get cryptographically secure random numbers.
	random := rand.Reader

	// Create a byte array for our public and private keys.
	var private, public [32]byte

	// Generate some random data
	_, err := io.ReadFull(random, private[:])
	if err != nil {
		return nil, err
	}

	// Documented at: http://cr.yp.to/ecdh.html
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	curve25519.ScalarBaseMult(&public, &private)

	// Put data into our keypair struct
	djbECPub := NewDjbECPublicKey(public)
	djbECPriv := NewDjbECPrivateKey(private)
	keypair := NewECKeyPair(djbECPub, djbECPriv)

	logger.Debug("Returning keypair: ", keypair)

	return keypair, nil
}

// VerifySignature verifies that the message was signed with the given key.
func VerifySignature(signingKey ECPublicKeyable, message []byte, signature [64]byte) bool {
	logger.Debug("Verifying signature of bytes: ", message)
	publicKey := signingKey.PublicKey()
	valid := verify(publicKey, message, &signature)
	logger.Debug("Signature valid: ", valid)
	return valid
}

// VerifySignatureAsync verifies that a message was signed with the given key asyncronously.
func VerifySignatureAsync(signingKey ECPublicKeyable, message []byte, signature [64]byte, completion complete.Completionable) {
	go func() {
		r := VerifySignature(signingKey, message, signature)
		if r == false {
			completion.OnFailure("Signature invalid")
			return
		}
		result := complete.NewResult(r)
		completion.OnSuccess(&result)
	}()
}

// CalculateSignature signs a message with the given private key.
func CalculateSignature(signingKey ECPrivateKeyable, message []byte) [64]byte {
	logger.Debug("Signing bytes with signing key")
	// Get cryptographically secure random numbers.
	var random [64]byte
	r := rand.Reader
	io.ReadFull(r, random[:])

	// Get the private key.
	privateKey := signingKey.Serialize()

	// Sign the message.
	signature := sign(&privateKey, message, random)
	return *signature
}

// CalculateSignatureAsync signs a message with the given private key asyncronously.
func CalculateSignatureAsync(signingKey ECPrivateKeyable, message []byte, completion complete.Completionable) {
	go func() {
		signature := CalculateSignature(signingKey, message)
		if signature == [64]byte{} {
			completion.OnFailure("Error calculating signature")
			return
		}
		result := complete.NewResult(signature)
		completion.OnSuccess(&result)
	}()
}
