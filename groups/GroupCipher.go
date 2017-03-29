package groups

import (
	"errors"
	"github.com/RadicalApp/libsignal-protocol-go/cipher"
	"github.com/RadicalApp/libsignal-protocol-go/ecc"
	"github.com/RadicalApp/libsignal-protocol-go/groups/ratchet"
	"github.com/RadicalApp/libsignal-protocol-go/groups/state/record"
	"github.com/RadicalApp/libsignal-protocol-go/groups/state/store"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"strconv"
)

// NewGroupCipher will return a new group message cipher that can be used for
// encrypt/decrypt operations.
func NewGroupCipher(builder *SessionBuilder, senderKeyID *protocol.SenderKeyName,
	senderKeyStore store.SenderKey) *GroupCipher {

	return &GroupCipher{
		senderKeyID:    senderKeyID,
		senderKeyStore: senderKeyStore,
		sessionBuilder: builder,
	}
}

// GroupCipher is the main entry point for group encrypt/decrypt operations.
// Once a session has been established, this can be used for
// all encrypt/decrypt operations within that session.
type GroupCipher struct {
	senderKeyID    *protocol.SenderKeyName
	senderKeyStore store.SenderKey
	sessionBuilder *SessionBuilder
}

// Encrypt will take the given message in bytes and return encrypted bytes.
func (c *GroupCipher) Encrypt(plaintext []byte) (protocol.CiphertextMessage, error) {
	// Load the sender key based on id from our store.
	keyRecord := c.senderKeyStore.LoadSenderKey(c.senderKeyID)
	senderKeyState, err := keyRecord.SenderKeyState()
	if err != nil {
		return nil, err
	}

	// Get the message key from the senderkey state.
	senderKey, err := senderKeyState.SenderChainKey().SenderMessageKey()
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext.
	ciphertext, err := cipher.Encrypt(senderKey.Iv(), senderKey.CipherKey(), plaintext)
	if err != nil {
		return nil, err
	}

	senderKeyMessage := protocol.NewSenderKeyMessage(
		senderKeyState.KeyID(),
		senderKey.Iteration(),
		ciphertext,
		senderKeyState.SigningKey().PrivateKey(),
		c.sessionBuilder.serializer.SenderKeyMessage,
	)

	senderKeyState.SetSenderChainKey(senderKeyState.SenderChainKey().Next())
	c.senderKeyStore.StoreSenderKey(c.senderKeyID, keyRecord)

	return senderKeyMessage, nil
}

// Decrypt decrypts the given message using an existing session that
// is stored in the senderKey store.
func (c *GroupCipher) Decrypt(senderKeyMessage *protocol.SenderKeyMessage) ([]byte, error) {
	keyRecord := c.senderKeyStore.LoadSenderKey(c.senderKeyID)

	if keyRecord.IsEmpty() {
		return nil, errors.New("No sender key for: " + c.senderKeyID.GroupID())
	}

	// Get the senderkey state by id.
	senderKeyState, err := keyRecord.GetSenderKeyStateByID(senderKeyMessage.KeyID())
	if err != nil {
		return nil, err
	}

	// Verify the signature of the senderkey message.
	verified := c.verifySignature(senderKeyState.SigningKey().PublicKey(), senderKeyMessage)
	if !verified {
		return nil, errors.New("Sender Key State failed verification with given pub key!")
	}

	senderKey, err := c.getSenderKey(senderKeyState, senderKeyMessage.Iteration())
	if err != nil {
		return nil, err
	}

	// Decrypt the message ciphertext.
	plaintext, err := cipher.Decrypt(senderKey.Iv(), senderKey.CipherKey(), senderKeyMessage.Ciphertext())
	if err != nil {
		return nil, err
	}

	// Store the sender key by id.
	c.senderKeyStore.StoreSenderKey(c.senderKeyID, keyRecord)

	return plaintext, nil
}

// verifySignature will verify the signature of the senderkey message with
// the given public key.
func (c *GroupCipher) verifySignature(signingPubKey ecc.ECPublicKeyable,
	senderKeyMessage *protocol.SenderKeyMessage) bool {

	return ecc.VerifySignature(signingPubKey, senderKeyMessage.Serialize(), senderKeyMessage.Signature())
}

func (c *GroupCipher) getSenderKey(senderKeyState *record.SenderKeyState, iteration uint32) (*ratchet.SenderMessageKey, error) {
	senderChainKey := senderKeyState.SenderChainKey()
	if senderChainKey.Iteration() > iteration {
		if senderKeyState.HasSenderMessageKey(iteration) {
			return senderKeyState.RemoveSenderMessageKey(iteration), nil
		}
		i1 := strconv.Itoa(int(senderChainKey.Iteration()))
		i2 := strconv.Itoa(int(iteration))
		return nil, errors.New("Received message with old counter: " + i1 + ", " + i2)
	}

	if iteration-senderChainKey.Iteration() > 2000 {
		return nil, errors.New("Over 2000 messages into the future!")
	}

	for senderChainKey.Iteration() < iteration {
		senderMessageKey, err := senderChainKey.SenderMessageKey()
		if err != nil {
			return nil, err
		}
		senderKeyState.AddSenderMessageKey(senderMessageKey)
		senderChainKey = senderChainKey.Next()
	}

	senderKeyState.SetSenderChainKey(senderChainKey.Next())
	return senderChainKey.SenderMessageKey()
}
