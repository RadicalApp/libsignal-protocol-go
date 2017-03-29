package tests

import (
	"github.com/RadicalApp/complete"
	"github.com/RadicalApp/libsignal-protocol-go/ecc"
	"github.com/RadicalApp/libsignal-protocol-go/logger"
	"github.com/RadicalApp/libsignal-protocol-go/util/keyhelper"
	"sync"
	"testing"
)

// TestIdentityKeys checks generating, signing, and verifying of identity keys.
func TestIdentityKeys(t *testing.T) {
	logger.Info("Testing identity key generation...")

	// Generate an identity keypair
	identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Error("Error generating identity keys")
	}
	privateKey := identityKeyPair.PrivateKey()
	publicKey := identityKeyPair.PublicKey()
	logger.Info("  Identity KeyPair:", identityKeyPair)

	// Sign the text "Hello" with the identity key
	message := []byte("Hello")
	unsignedMessage := []byte("SHIT!")
	logger.Info("Signing bytes:", message)
	signature := ecc.CalculateSignature(privateKey, message)
	logger.Info("  Signature:", signature)

	// Validate the signature using the private key
	//valid := ecc.Verify(publicKey.PublicKey().PublicKey(), message, &signature)
	logger.Info("Verifying signature against bytes:", message)
	valid := ecc.VerifySignature(publicKey.PublicKey(), message, signature)
	logger.Info("  Valid signature:", valid)
	if !(valid) {
		t.Error("Signature verification failed.")
	}

	// Try checking the signature on text that is different
	logger.Info("Verifying signature against unsigned bytes:", unsignedMessage)
	valid = ecc.VerifySignature(publicKey.PublicKey(), unsignedMessage, signature)
	logger.Info("  Valid signature:", valid)
	if valid {
		t.Error("Signature verification should have failed here.")
	}

}

// TestIdentityKeysAsync tries to test creation of identity keys in an async way.
func TestIdentityKeysAsync(t *testing.T) {
	logger.Info("Testing async generation of identity keys...")

	// Create a waitgroup to wait for async tasks to finish for this test
	wg := sync.WaitGroup{}
	wg.Add(1)

	// Generate completion handlers for key generation.
	success := func(r *complete.Result) {
		logger.Info(r)
		wg.Done()
	}
	failure := func(err string) {
		logger.Error(err)
		wg.Done()
	}
	completion := complete.NewCompletion(
		success,
		failure,
	)

	// Create identity keys asyncronously
	keyhelper.GenerateIdentityKeyPairAsync(completion)

	// Wait for wg to call "Done()" method.
	wg.Wait()

}
