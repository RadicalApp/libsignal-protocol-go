package tests

import (
	"github.com/RadicalApp/libsignal-protocol-go/keys/prekey"
	"github.com/RadicalApp/libsignal-protocol-go/logger"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/session"
	"testing"
)

// TestSessionBuilder checks building of a session.
func TestSessionBuilder(t *testing.T) {

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
	logger.Debug("Fetching Bob's prekey with ID: ", bob.preKeys[0].ID())
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

	// Process Bob's retrived prekey to establish a session.
	logger.Debug("Building sender's (Alice) session...")
	err := alice.sessionBuilder.ProcessBundle(retrivedPreKey)
	if err != nil {
		logger.Error("Unable to process retrieved prekey bundle")
		t.FailNow()
	}

	// Create a session cipher to encrypt messages to Bob.
	plaintextMessage := []byte("Hello!")
	logger.Info("Plaintext message: ", string(plaintextMessage))
	sessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	message, err := sessionCipher.Encrypt(plaintextMessage)
	if err != nil {
		logger.Error("Unable to encrypt message: ", err)
		t.FailNow()
	}

	logger.Info("Encrypted message: ", message)

	///////////// RECEIVER SESSION CREATION ///////////////

	// Emulate receiving the message as JSON over the network.
	logger.Debug("Building message from bytes on Bob's end.")
	receivedMessage, err := protocol.NewPreKeySignalMessageFromBytes(message.Serialize(), serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		logger.Error("Unable to emulate receiving message as JSON: ", err)
		t.FailNow()
	}

	// Create a session builder
	logger.Debug("Building receiver's (Bob) session...")
	unsignedPreKeyID, err := bob.sessionBuilder.Process(receivedMessage)
	if err != nil {
		logger.Error("Unable to process prekeysignal message: ", err)
		t.FailNow()
	}
	logger.Debug("Got PreKeyID: ", unsignedPreKeyID)

	// Try and decrypt the message
	bobSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	msg, err := bobSessionCipher.Decrypt(receivedMessage.WhisperMessage())
	if err != nil {
		logger.Error("Unable to decrypt message: ", err)
		t.FailNow()
	}
	logger.Info("Decrypted message: ", string(msg))
	if string(msg) != string(plaintextMessage) {
		logger.Error("Decrypted string does not match - Encrypted: ", string(plaintextMessage), " Decrypted: ", string(msg))
		t.FailNow()
	}

	// Send a response to Alice
	plaintextResponse := []byte("oui!")
	response, err := bobSessionCipher.Encrypt(plaintextResponse)
	if err != nil {
		logger.Error("Unable to encrypt response: ", err)
		t.FailNow()
	}

	logger.Info("Encrypted response: ", response)

	responseMessage, err := protocol.NewSignalMessageFromBytes(response.Serialize(), serializer.SignalMessage)
	if err != nil {
		logger.Error("Unable to emulate receiving response as JSON: ", err)
		t.FailNow()
	}

	deResponse, err := sessionCipher.Decrypt(responseMessage)
	if err != nil {
		logger.Error("Unable to decrypt response from Bob")
		t.FailNow()
	}
	logger.Info("Decrypted response: ", string(deResponse))
	if string(deResponse) != string(plaintextResponse) {
		logger.Error("Decrypted string does not match - Encrypted: ", string(plaintextResponse), " Decrypted: ", string(deResponse))
		t.FailNow()
	}
}

// TestSessionRoundtrip checks sending messages back and forth from users.
func TestSessionRoundtrip(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	///////////// SENDER SESSION CREATION ///////////////

	// Create a PreKeyBundle from Bob's prekey records and other
	// data.
	logger.Debug("Fetching Bob's prekey with ID: ", bob.preKeys[0].ID())
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

	// Process Bob's retrived prekey to establish a session.
	logger.Debug("Building sender's (Alice) session...")
	err := alice.sessionBuilder.ProcessBundle(retrivedPreKey)
	if err != nil {
		logger.Error("Unable to process retrieved prekey bundle")
		t.FailNow()
	}

	// Create a session cipher to encrypt messages to Bob.
	aliceSessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	aliceMessageStrings1, aliceMessages1 := sendMessages(1000, aliceSessionCipher, serializer, t)

	///////////// RECEIVER SESSION CREATION ///////////////

	// Create a session builder
	logger.Debug("Building receiver's (Bob) session...")
	unsignedPreKeyID, err := bob.sessionBuilder.Process(aliceMessages1[0].(*protocol.PreKeySignalMessage))
	if err != nil {
		logger.Error("Unable to process prekeysignal message: ", err)
		t.FailNow()
	}
	logger.Debug("Got PreKeyID: ", unsignedPreKeyID)

	// Try and decrypt the message
	bobSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	/////////// ROUND TRIP 1 ////////////
	receiveMessages(aliceMessages1, aliceMessageStrings1, bobSessionCipher, t)

	// Let Bob encrypt and send some messages.
	bobMessageStrings1, bobMessages1 := sendMessages(1000, bobSessionCipher, serializer, t)

	// Let Alice decrypt the messages from Bob.
	receiveMessages(bobMessages1, bobMessageStrings1, aliceSessionCipher, t)

	/////////// ROUND TRIP 2 ////////////
	aliceMessageStrings2, aliceMessages2 := sendMessages(1000, aliceSessionCipher, serializer, t)
	receiveMessages(aliceMessages2, aliceMessageStrings2, bobSessionCipher, t)

	bobMessageStrings2, bobMessages2 := sendMessages(1000, bobSessionCipher, serializer, t)
	receiveMessages(bobMessages2, bobMessageStrings2, aliceSessionCipher, t)

	/////////// ROUND TRIP 3 ////////////
	aliceMessageStrings3, aliceMessages3 := sendMessages(1000, aliceSessionCipher, serializer, t)
	receiveMessages(aliceMessages3, aliceMessageStrings3, bobSessionCipher, t)

	bobMessageStrings3, bobMessages3 := sendMessages(1000, bobSessionCipher, serializer, t)
	receiveMessages(bobMessages3, bobMessageStrings3, aliceSessionCipher, t)
}

// TestSessionOutOfOrder checks sending messages out of order.
func TestSessionOutOfOrder(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	///////////// SENDER SESSION CREATION ///////////////

	// Create a PreKeyBundle from Bob's prekey records and other
	// data.
	logger.Debug("Fetching Bob's prekey with ID: ", bob.preKeys[0].ID())
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

	// Process Bob's retrived prekey to establish a session.
	logger.Debug("Building sender's (Alice) session...")
	err := alice.sessionBuilder.ProcessBundle(retrivedPreKey)
	if err != nil {
		logger.Error("Unable to process retrieved prekey bundle")
		t.FailNow()
	}

	// Create a session cipher to encrypt messages to Bob.
	aliceSessionCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	aliceMessageStrings, aliceMessages := sendMessages(4, aliceSessionCipher, serializer, t)

	///////////// RECEIVER SESSION CREATION ///////////////

	// Create a session builder
	logger.Debug("Building receiver's (Bob) session...")
	unsignedPreKeyID, err := bob.sessionBuilder.Process(aliceMessages[3].(*protocol.PreKeySignalMessage))
	if err != nil {
		logger.Error("Unable to process prekeysignal message: ", err)
		t.FailNow()
	}
	logger.Debug("Got PreKeyID: ", unsignedPreKeyID)

	// Try and decrypt the message
	bobSessionCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	/////////// ROUND TRIP 1 ////////////
	receiveMessages([]protocol.CiphertextMessage{aliceMessages[3]}, []string{aliceMessageStrings[3]}, bobSessionCipher, t)
	receiveMessages([]protocol.CiphertextMessage{aliceMessages[0]}, []string{aliceMessageStrings[0]}, bobSessionCipher, t)

}

// sendMessages will generate and return a list of plaintext and encrypted messages.
func sendMessages(count int, cipher *session.Cipher, serializer *serialize.Serializer, t *testing.T) ([]string, []protocol.CiphertextMessage) {
	texts := []string{
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.",
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.",
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.",
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
	}
	messageStrings := make([]string, count)
	for i := 0; i < count; i++ {
		messageStrings[i] = texts[i%len(texts)]
	}

	messages := make([]protocol.CiphertextMessage, count)
	for i, str := range messageStrings {
		msg := encryptMessage(str, cipher, serializer, t)
		messages[i] = msg
	}

	return messageStrings, messages
}

// receiveMessages is a helper function to receive a bunch of encrypted messages and decrypt them.
func receiveMessages(messages []protocol.CiphertextMessage, messageStrings []string, cipher *session.Cipher, t *testing.T) {
	for i, receivedMessage := range messages {
		msg := decryptMessage(receivedMessage, cipher, t)
		if messageStrings[i] != msg {
			logger.Error("Decrypted message does not match original: ", messageStrings[i], " != ", msg)
			t.FailNow()
		}
	}
}

// encryptMessage is a helper function to send encrypted messages with the given cipher.
func encryptMessage(message string, cipher *session.Cipher, serializer *serialize.Serializer, t *testing.T) protocol.CiphertextMessage {
	plaintextMessage := []byte(message)
	logger.Info("Encrypting message: ", string(plaintextMessage))
	encrypted, err := cipher.Encrypt(plaintextMessage)
	if err != nil {
		logger.Error("Unable to encrypt message: ", err)
		t.FailNow()
	}
	logger.Info("Encrypted message: ", encrypted)

	// Emulate receiving the message as JSON over the network.
	logger.Debug("Building message from bytes to emulate sending over the network.")
	var encryptedMessage protocol.CiphertextMessage
	switch encrypted.(type) {
	case *protocol.PreKeySignalMessage:
		encryptedMessage, err = protocol.NewPreKeySignalMessageFromBytes(encrypted.Serialize(), serializer.PreKeySignalMessage, serializer.SignalMessage)
	case *protocol.SignalMessage:
		encryptedMessage, err = protocol.NewSignalMessageFromBytes(encrypted.Serialize(), serializer.SignalMessage)
	}

	if err != nil {
		logger.Error("Unable to emulate receiving message as JSON: ", err)
		t.FailNow()
	}

	return encryptedMessage
}

// decryptMessage is a helper function to decrypt messages of a session.
func decryptMessage(message protocol.CiphertextMessage, cipher *session.Cipher, t *testing.T) string {
	switch message.(type) {
	case *protocol.PreKeySignalMessage:
		return decryptMessage(message.(*protocol.PreKeySignalMessage).WhisperMessage(), cipher, t)
	}

	msg, err := cipher.Decrypt(message.(*protocol.SignalMessage))
	if err != nil {
		logger.Error("Unable to decrypt message: ", err)
		t.FailNow()
	}
	logger.Info("Decrypted message: ", string(msg))

	return string(msg)
}
