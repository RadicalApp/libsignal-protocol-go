package tests

import (
	"github.com/RadicalApp/libsignal-protocol-go/groups"
	"github.com/RadicalApp/libsignal-protocol-go/logger"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"testing"
)

// TestGroupSessionBuilder checks building of a group session.
func TestGroupSessionBuilder(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	charlie := newUser("Charlie", 3, serializer)
	groupName := "123"

	// ***** Alice Send *****

	// Create a session builder to create a session between Alice -> Bob.
	aliceSenderKeyName := protocol.NewSenderKeyName(groupName, alice.address)
	skdm, err := alice.groupBuilder.Create(aliceSenderKeyName)
	if err != nil {
		logger.Error("Unable to create group session")
		t.FailNow()
	}
	aliceSendingCipher := groups.NewGroupCipher(alice.groupBuilder, aliceSenderKeyName, alice.senderKeyStore)

	// Encrypt some messages to send with Alice's group cipher
	logger.Debug("Alice sending messages to Bob...")
	alicePlainMessages, aliceEncryptedMessages := sendGroupMessages(1000, aliceSendingCipher, serializer, t)
	logger.Debug("Alice sending messages to Charlie...")
	alicePlainMessages2, aliceEncryptedMessages2 := sendGroupMessages(1000, aliceSendingCipher, serializer, t)

	// Build bob's side of the session.
	bob.groupBuilder.Process(aliceSenderKeyName, skdm)
	receivingBobCipher := groups.NewGroupCipher(bob.groupBuilder, aliceSenderKeyName, bob.senderKeyStore)
	charlie.groupBuilder.Process(aliceSenderKeyName, skdm)
	receivingCharlieCipher := groups.NewGroupCipher(charlie.groupBuilder, aliceSenderKeyName, charlie.senderKeyStore)

	// Decrypt the messages sent by alice.
	logger.Debug("Bob receiving messages from Alice...")
	receiveGroupMessages(aliceEncryptedMessages, alicePlainMessages, receivingBobCipher, t)
	logger.Debug("Charlie receiving messages from Alice...")
	receiveGroupMessages(aliceEncryptedMessages2, alicePlainMessages2, receivingCharlieCipher, t)

	// ***** Bob Send *****

	// Create a session builder for sending messages between Bob -> Alice.
	bobSenderKeyName := protocol.NewSenderKeyName(groupName, bob.address)
	skdm, err = bob.groupBuilder.Create(bobSenderKeyName)
	if err != nil {
		logger.Error("Unable to create group session")
		t.FailNow()
	}
	bobSendingCipher := groups.NewGroupCipher(bob.groupBuilder, bobSenderKeyName, bob.senderKeyStore)

	// Encrypt some messages to send with Bob's group cipher
	logger.Debug("Bob sending messages to Alice...")
	bobPlainMessages, bobEncryptedMessages := sendGroupMessages(1000, bobSendingCipher, serializer, t)
	bobPlainMessages2, bobEncryptedMessages2 := sendGroupMessages(1000, bobSendingCipher, serializer, t)

	// Build alice's side of the session.
	alice.groupBuilder.Process(bobSenderKeyName, skdm)
	receivingAliceCipher := groups.NewGroupCipher(alice.groupBuilder, bobSenderKeyName, alice.senderKeyStore)
	charlie.groupBuilder.Process(aliceSenderKeyName, skdm)
	receivingCharlieCipher = groups.NewGroupCipher(charlie.groupBuilder, aliceSenderKeyName, charlie.senderKeyStore)

	// Decrypt the messages sent by bob.
	logger.Debug("Alice receiving messages from Bob...")
	receiveGroupMessages(bobEncryptedMessages, bobPlainMessages, receivingAliceCipher, t)
	logger.Debug("Charlie receiving messages from Bob...")
	receiveGroupMessages(bobEncryptedMessages2, bobPlainMessages2, receivingCharlieCipher, t)
}

// sendGroupMessages will generate and return a list of plaintext and encrypted messages.
func sendGroupMessages(count int, cipher *groups.GroupCipher, serializer *serialize.Serializer, t *testing.T) ([]string, []protocol.CiphertextMessage) {
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
		msg := encryptGroupMessage(str, cipher, serializer, t)
		messages[i] = msg
	}

	return messageStrings, messages
}

// receiveMessages is a helper function to receive a bunch of encrypted messages and decrypt them.
func receiveGroupMessages(messages []protocol.CiphertextMessage, messageStrings []string, cipher *groups.GroupCipher, t *testing.T) {
	for i, receivedMessage := range messages {
		msg := decryptGroupMessage(receivedMessage, cipher, t)
		if messageStrings[i] != msg {
			logger.Error("Decrypted message does not match original: ", messageStrings[i], " != ", msg)
			t.FailNow()
		}
	}
}

// encryptMessage is a helper function to send encrypted messages with the given cipher.
func encryptGroupMessage(message string, cipher *groups.GroupCipher, serializer *serialize.Serializer, t *testing.T) protocol.CiphertextMessage {
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
	case *protocol.SenderKeyMessage:
		message := encrypted.(*protocol.SenderKeyMessage)
		encryptedMessage, err = protocol.NewSenderKeyMessageFromBytes(message.SignedSerialize(), serializer.SenderKeyMessage)
		if err != nil {
			logger.Error("Unable to emulate receiving message as JSON: ", err)
			t.FailNow()
		}
	}
	logger.Info(encryptedMessage)

	return encryptedMessage
}

// decryptMessage is a helper function to decrypt messages of a session.
func decryptGroupMessage(message protocol.CiphertextMessage, cipher *groups.GroupCipher, t *testing.T) string {
	senderKeyMessage := message.(*protocol.SenderKeyMessage)
	//if !ok {
	//	logger.Error("Wrong message type in decrypting group message.")
	//	t.FailNow()
	//}

	msg, err := cipher.Decrypt(senderKeyMessage)
	if err != nil {
		logger.Error("Unable to decrypt message: ", err)
		t.FailNow()
	}
	logger.Info("Decrypted message: ", string(msg))

	return string(msg)
}
