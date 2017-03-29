package tests

import (
	"encoding/base64"
	"github.com/RadicalApp/libsignal-protocol-go/ecc"
	"github.com/RadicalApp/libsignal-protocol-go/kdf"
	"github.com/RadicalApp/libsignal-protocol-go/logger"
	"testing"
)

// TestSharedSecret tests the key derivation function's ability to
// calculate a shared secret given two pairs of ECDH keys.
func TestSharedSecret(t *testing.T) {
	logger.Configure("sharedsecret_test.go")
	logger.Info("Testing identity key generation...")
	b64 := base64.StdEncoding.EncodeToString

	// Generate an keypair for Alice
	aliceKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Error("Error generating identity keys")
	}
	alicePrivateKey := aliceKeyPair.PrivateKey().Serialize()
	p := aliceKeyPair.PublicKey()
	alicePublicKey := p.PublicKey()
	logger.Info("  Alice PrivateKey: ", b64(alicePrivateKey[:]))
	logger.Info("  Alice PublicKey: ", b64(alicePublicKey[:]))

	// Generate an keypair for Bob
	bobKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Error("Error generating identity keys")
	}
	bobPrivateKey := bobKeyPair.PrivateKey().Serialize()
	p = bobKeyPair.PublicKey()
	bobPublicKey := p.PublicKey()
	logger.Info("  Bob PrivateKey: ", b64(bobPrivateKey[:]))
	logger.Info("  Bob PublicKey: ", b64(bobPublicKey[:]))

	// Calculate the shared secret as Alice.
	aliceSharedSecret := kdf.CalculateSharedSecret(bobPublicKey, alicePrivateKey)
	aliceHashedSecret, _ := kdf.DeriveSecrets(aliceSharedSecret[:], nil, []byte("Dust"), 64)
	logger.Info("Alice Shared Secret: ", b64(aliceSharedSecret[:]))
	logger.Info("Alice Hashed Secret: ", b64(aliceHashedSecret))

	// Calculate the shared secret as Bob.
	bobSharedSecret := kdf.CalculateSharedSecret(alicePublicKey, bobPrivateKey)
	bobHashedSecret, _ := kdf.DeriveSecrets(bobSharedSecret[:], nil, []byte("Dust"), 64)
	logger.Info("Bob Shared Secret: ", b64(bobSharedSecret[:]))
	logger.Info("Bob Hashed Secret: ", b64(bobHashedSecret))

	// Check to make sure Alice and Bob calculated the same shared secret.
	if b64(aliceSharedSecret[:]) != b64(bobSharedSecret[:]) {
		logger.Error("Computed secrets do not match: ", b64(aliceSharedSecret[:]), " != ", b64(bobSharedSecret[:]))
		t.Fail()
	}

	// Check to make sure that Alice and Bob also hashed the same secret the same way using KDF.
	if b64(aliceHashedSecret) != b64(bobHashedSecret) {
		logger.Error("Hashed secrets do not match: ", b64(aliceHashedSecret), " != ", b64(bobHashedSecret))
		t.Fail()
	}
}
