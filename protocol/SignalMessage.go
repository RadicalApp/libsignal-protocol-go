package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"github.com/RadicalApp/libsignal-protocol-go/ecc"
	"github.com/RadicalApp/libsignal-protocol-go/keys/identity"
	"github.com/RadicalApp/libsignal-protocol-go/logger"
	"github.com/RadicalApp/libsignal-protocol-go/util/bytehelper"
	"strconv"
)

const macLength int = 8

// SignalMessageSerializer is an interface for serializing and deserializing
// SignalMessages into bytes. An implementation of this interface should be
// used to encode/decode the object into JSON, Protobuffers, etc.
type SignalMessageSerializer interface {
	Serialize(signalMessage *SignalMessageStructure) []byte
	Deserialize(serialized []byte) (*SignalMessageStructure, error)
}

// NewSignalMessageFromBytes will return a Signal Ciphertext message from the given
// bytes using the given serializer.
func NewSignalMessageFromBytes(serialized []byte, serializer SignalMessageSerializer) (*SignalMessage, error) {
	// Use the given serializer to decode the signal message.
	signalMessageStructure, err := serializer.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return NewSignalMessageFromStruct(signalMessageStructure, serializer)
}

// NewSignalMessageFromStruct returns a Signal Ciphertext message from the
// given serializable structure.
func NewSignalMessageFromStruct(structure *SignalMessageStructure, serializer SignalMessageSerializer) (*SignalMessage, error) {
	// Throw an error if the given message structure is an unsupported version.
	if structure.Version <= UnsupportedVersion {
		err := "Legacy message: " + strconv.Itoa(structure.Version)
		return nil, errors.New(err)
	}

	// Throw an error if the given message structure is a future version.
	if structure.Version > CurrentVersion {
		err := "Unknown version: " + strconv.Itoa(structure.Version)
		return nil, errors.New(err)
	}

	// Throw an error if the structure is missing critical fields.
	if structure.CipherText == nil || structure.RatchetKey == nil {
		err := "Incomplete message."
		return nil, errors.New(err)
	}

	// Create the signal message object from the structure.
	whisperMessage := &SignalMessage{structure: *structure, serializer: serializer}

	// Generate the ECC key from bytes.
	var err error
	whisperMessage.senderRatchetKey, err = ecc.DecodePoint(structure.RatchetKey, 0)
	if err != nil {
		return nil, err
	}

	return whisperMessage, nil
}

// NewSignalMessage returns a Signal Ciphertext message.
func NewSignalMessage(messageVersion int, counter, previousCounter uint32, macKey []byte,
	senderRatchetKey ecc.ECPublicKeyable, ciphertext []byte, senderIdentityKey,
	receiverIdentityKey *identity.Key, serializer SignalMessageSerializer) (*SignalMessage, error) {

	// Build the signal message structure with the given data.
	structure := &SignalMessageStructure{
		Version:         messageVersion,
		Counter:         counter,
		PreviousCounter: previousCounter,
		RatchetKey:      senderRatchetKey.Serialize(),
		CipherText:      ciphertext,
	}

	// Get the message authentication code from the serialized structure.
	mac, err := getMac(
		messageVersion, senderIdentityKey, receiverIdentityKey,
		macKey, serializer.Serialize(structure),
	)
	if err != nil {
		return nil, err
	}
	structure.Mac = mac

	// Generate a SignalMessage with the structure.
	whisperMessage, err := NewSignalMessageFromStruct(structure, serializer)
	if err != nil {
		return nil, err
	}

	return whisperMessage, nil
}

// SignalMessageStructure is a serializeable structure of a signal message
// object.
type SignalMessageStructure struct {
	RatchetKey      []byte
	Counter         uint32
	PreviousCounter uint32
	CipherText      []byte
	Version         int
	Mac             []byte
}

// SignalMessage is a cipher message that contains a message encrypted
// with the Signal protocol.
type SignalMessage struct {
	structure        SignalMessageStructure
	senderRatchetKey ecc.ECPublicKeyable
	serializer       SignalMessageSerializer
}

// SenderRatchetKey returns the SignalMessage's sender ratchet key. This
// key is used for ratcheting the chain forward to negotiate a new shared
// secret that cannot be derived from previous chains.
func (s *SignalMessage) SenderRatchetKey() ecc.ECPublicKeyable {
	return s.senderRatchetKey
}

// MessageVersion returns the message version this SignalMessage supports.
func (s *SignalMessage) MessageVersion() int {
	return s.structure.Version
}

// Counter will return the SignalMessage counter.
func (s *SignalMessage) Counter() uint32 {
	return s.structure.Counter
}

// Body will return the SignalMessage's ciphertext in bytes.
func (s *SignalMessage) Body() []byte {
	return s.structure.CipherText
}

// VerifyMac will return an error if the message's message authentication code
// is invalid. This should be used on SignalMessages that have been constructed
// from a sent message.
func (s *SignalMessage) VerifyMac(messageVersion int, senderIdentityKey,
	receiverIdentityKey *identity.Key, macKey []byte) error {

	// Create a copy of the message without the mac. We'll use this to calculate
	// the message authentication code.
	structure := s.structure
	signalMessage, err := NewSignalMessageFromStruct(&structure, s.serializer)
	if err != nil {
		return err
	}
	signalMessage.structure.Mac = nil

	// Calculate the message authentication code from the serialized structure.
	ourMac, err := getMac(
		messageVersion,
		senderIdentityKey,
		receiverIdentityKey,
		macKey,
		signalMessage.Serialize(),
	)
	if err != nil {
		logger.Error(err)
		return err
	}

	// Get the message authentication code that was sent to us as part of
	// the signal message structure.
	theirMac := s.structure.Mac

	logger.Debug("Verifying macs...")
	logger.Debug("  Our MAC: ", ourMac)
	logger.Debug("  Their MAC: ", theirMac)

	// Return an error if our calculated mac doesn't match the mac sent to us.
	if !hmac.Equal(ourMac, theirMac) {
		return errors.New("Bad Mac!")
	}

	return nil
}

// Serialize will return the Signal Message as bytes.
func (s *SignalMessage) Serialize() []byte {
	return s.serializer.Serialize(&s.structure)
}

// Structure will return a serializeable structure of the Signal Message.
func (s *SignalMessage) Structure() *SignalMessageStructure {
	structure := s.structure
	return &structure
}

// Type will return the type of Signal Message this is.
func (s *SignalMessage) Type() uint32 {
	return WHISPER_TYPE
}

// getMac will calculate the mac using the given message version, identity
// keys, macKey and SignalMessageStructure. The MAC key is a private key held
// by both parties that is concatenated with the message and hashed.
func getMac(messageVersion int, senderIdentityKey, receiverIdentityKey *identity.Key,
	macKey, serialized []byte) ([]byte, error) {

	mac := hmac.New(sha256.New, macKey[:])

	if messageVersion >= 3 {
		mac.Write(senderIdentityKey.PublicKey().Serialize())
		mac.Write(receiverIdentityKey.PublicKey().Serialize())
	}

	mac.Write(serialized)

	fullMac := mac.Sum(nil)

	return bytehelper.Trim(fullMac, macLength), nil
}
