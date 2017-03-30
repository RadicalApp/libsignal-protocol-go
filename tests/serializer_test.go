package tests

import (
	"fmt"
	"github.com/RadicalApp/libsignal-protocol-go/keys/prekey"
	"github.com/RadicalApp/libsignal-protocol-go/logger"
	"github.com/RadicalApp/libsignal-protocol-go/session"
	"github.com/RadicalApp/libsignal-protocol-go/state/record"
	"github.com/kr/pretty"
	"testing"
)

// TestSerializing tests serialization and deserialization of Signal objects.
func TestSerializing(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Create a PreKeyBundle from Bob's prekey records and other
	// data.
	retrivedPreKey := prekey.NewBundle(
		bob.registrationID,
		bob.deviceID,
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
	)

	// Process Bob's retrieved prekey to establish a session.
	alice.sessionBuilder.ProcessBundle(retrivedPreKey)

	// Create a session cipher to encrypt messages to Bob.
	plaintextMessage := []byte("Hello!")
	sessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	sessionCipher.Encrypt(plaintextMessage)

	// Serialize our session so it can be stored.
	loadedSession := alice.sessionStore.LoadSession(bob.address)
	serializedSession := loadedSession.Serialize()
	logger.Debug(string(serializedSession))

	// Try deserializing our session back into an object.
	deserializedSession, err := record.NewSessionFromBytes(serializedSession, serializer.Session, serializer.State)
	if err != nil {
		logger.Error("Failed to deserialize session.")
		t.FailNow()
	}

	fmt.Printf("Original Session Record: %# v\n", pretty.Formatter(loadedSession))
	fmt.Printf("Deserialized Session Record: %# v\n", pretty.Formatter(deserializedSession))

}
