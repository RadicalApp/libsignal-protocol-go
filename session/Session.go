// Package session provides the methods necessary to build sessions
package session

import (
	"errors"
	"github.com/RadicalApp/libsignal-protocol-go/ecc"
	"github.com/RadicalApp/libsignal-protocol-go/keys/prekey"
	"github.com/RadicalApp/libsignal-protocol-go/logger"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"github.com/RadicalApp/libsignal-protocol-go/ratchet"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/state/record"
	"github.com/RadicalApp/libsignal-protocol-go/state/store"
	"github.com/RadicalApp/libsignal-protocol-go/util/medium"
	"github.com/RadicalApp/libsignal-protocol-go/util/optional"
)

// Define error constants used for error messages.
const untrustedIdentityError string = "Untrusted identity"
const noSignedPreKeyError string = "No signed prekey!"
const invalidSignatureError string = "Invalid signature on device key!"
const nilOneTimePreKeyError string = "Prekey store returned a nil one time prekey! Was the key already processed?"

// NewBuilder constructs a session builder.
func NewBuilder(sessionStore store.Session, preKeyStore store.PreKey,
	signedStore store.SignedPreKey, identityStore store.IdentityKey,
	remoteAddress *protocol.SignalAddress, serializer *serialize.Serializer) *Builder {

	builder := Builder{
		sessionStore:      sessionStore,
		preKeyStore:       preKeyStore,
		signedPreKeyStore: signedStore,
		identityKeyStore:  identityStore,
		remoteAddress:     remoteAddress,
		serializer:        serializer,
	}

	return &builder
}

// NewBuilderFromSignal Store constructs a session builder using a
// SignalProtocol Store.
func NewBuilderFromSignal(signalStore store.SignalProtocol,
	remoteAddress *protocol.SignalAddress, serializer *serialize.Serializer) *Builder {

	builder := Builder{
		sessionStore:      signalStore,
		preKeyStore:       signalStore,
		signedPreKeyStore: signalStore,
		identityKeyStore:  signalStore,
		remoteAddress:     remoteAddress,
		serializer:        serializer,
	}

	return &builder
}

// Builder is responsible for setting up encrypted sessions.
// Once a session has been established, SessionCipher can be
// used to encrypt/decrypt messages in that session.
//
// Sessions are built from one of three different vectors:
//   * PreKeyBundle retrieved from a server.
//   * PreKeySignalMessage received from a client.
//   * KeyExchangeMessage sent to or received from a client.
//
// Sessions are constructed per recipientId + deviceId tuple.
// Remote logical users are identified by their recipientId,
// and each logical recipientId can have multiple physical
// devices.
type Builder struct {
	sessionStore      store.Session
	preKeyStore       store.PreKey
	signedPreKeyStore store.SignedPreKey
	identityKeyStore  store.IdentityKey
	remoteAddress     *protocol.SignalAddress
	serializer        *serialize.Serializer
}

// Process builds a new session from a session record and pre
// key signal message.
func (b *Builder) Process(message *protocol.PreKeySignalMessage) (unsignedPreKeyID *optional.Uint32, err error) {

	// Load or create session record for this session.
	sessionRecord := b.sessionStore.LoadSession(b.remoteAddress)

	// Check to see if the keys are trusted.
	theirIdentityKey := message.IdentityKey()
	if !(b.identityKeyStore.IsTrustedIdentity(b.remoteAddress, theirIdentityKey)) {
		return nil, errors.New(untrustedIdentityError)
	}

	// Use version 3 of the signal/axolotl protocol.
	unsignedPreKeyID, err = b.processV3(sessionRecord, message)
	if err != nil {
		return nil, err
	}

	// Save the identity key to our identity store.
	b.identityKeyStore.SaveIdentity(b.remoteAddress, theirIdentityKey)

	// Return the unsignedPreKeyID
	return unsignedPreKeyID, nil
}

// ProcessV3 builds a new session from a session record and pre key
// signal message. After a session is constructed in this way, the embedded
// SignalMessage can be decrypted.
func (b *Builder) processV3(sessionRecord *record.Session,
	message *protocol.PreKeySignalMessage) (unsignedPreKeyID *optional.Uint32, err error) {

	logger.Debug("Processing message with PreKeyID: ", message.PreKeyID())

	// Check to see if we've already set up a session for this V3 message.
	sessionExists := sessionRecord.HasSessionState(
		message.MessageVersion(),
		message.BaseKey().Serialize(),
	)
	if sessionExists {
		logger.Warning("We've already setup a session for this V3 message, letting bundled message fall through...")
		return nil, nil
	}

	// Load our signed prekey from our signed prekey store.
	ourSignedPreKeyRecord := b.signedPreKeyStore.LoadSignedPreKey(message.SignedPreKeyID())
	ourSignedPreKey := ourSignedPreKeyRecord.KeyPair()

	// Build the parameters of the session.
	parameters := ratchet.NewEmptyReceiverParameters()
	parameters.SetTheirBaseKey(message.BaseKey())
	parameters.SetTheirIdentityKey(message.IdentityKey())
	parameters.SetOurIdentityKeyPair(b.identityKeyStore.GetIdentityKeyPair())
	parameters.SetOurSignedPreKey(ourSignedPreKey)
	parameters.SetOurRatchetKey(ourSignedPreKey)

	// Set our one time pre key with the one from our prekey store
	// if the message contains a valid pre key id
	if message.PreKeyID() != nil {
		oneTimePreKey := b.preKeyStore.LoadPreKey(message.PreKeyID().Value)
		if oneTimePreKey == nil {
			logger.Error(nilOneTimePreKeyError)
			return nil, errors.New(nilOneTimePreKeyError)
		}
		parameters.SetOurOneTimePreKey(oneTimePreKey.KeyPair())
	} else {
		parameters.SetOurOneTimePreKey(nil)
	}

	// If this is a fresh record, archive our current state.
	if !sessionRecord.IsFresh() {
		sessionRecord.ArchiveCurrentState()
	}

	///////// Initialize our session /////////
	sessionState := sessionRecord.SessionState()
	derivedKeys, sessionErr := ratchet.CalculateReceiverSession(parameters)
	if sessionErr != nil {
		return nil, sessionErr
	}
	sessionState.SetVersion(protocol.CurrentVersion)
	sessionState.SetRemoteIdentityKey(parameters.TheirIdentityKey())
	sessionState.SetLocalIdentityKey(parameters.OurIdentityKeyPair().PublicKey())
	sessionState.SetSenderChain(parameters.OurRatchetKey(), derivedKeys.ChainKey)
	sessionState.SetRootKey(derivedKeys.RootKey)

	// Set the session's registration ids and base key
	sessionState.SetLocalRegistrationID(b.identityKeyStore.GetLocalRegistrationId())
	sessionState.SetRemoteRegistrationID(message.RegistrationID())
	sessionState.SetSenderBaseKey(message.BaseKey().Serialize())

	// Remove the PreKey from our store and return the message prekey id if it is valid.
	if message.PreKeyID() != nil && message.PreKeyID().Value != medium.MaxValue {
		logger.Debug("Removing preKey from our prekey store: ", message.PreKeyID().Value)
		b.preKeyStore.RemovePreKey(message.PreKeyID().Value)
		return message.PreKeyID(), nil
	}
	return nil, nil
}

// ProcessBundle builds a new session from a PreKeyBundle retrieved
// from a server.
func (b *Builder) ProcessBundle(preKey *prekey.Bundle) error {
	// Check to see if the keys are trusted.
	if !(b.identityKeyStore.IsTrustedIdentity(b.remoteAddress, preKey.IdentityKey())) {
		return errors.New(untrustedIdentityError)
	}

	// Check to see if the bundle has a signed pre key.
	if preKey.SignedPreKey() == nil {
		return errors.New(noSignedPreKeyError)
	}

	// Verify the signature of the pre key
	preKeyPublic := preKey.IdentityKey().PublicKey()
	preKeyBytes := preKey.SignedPreKey().Serialize()
	preKeySignature := preKey.SignedPreKeySignature()
	if !ecc.VerifySignature(preKeyPublic, preKeyBytes, preKeySignature) {
		return errors.New(invalidSignatureError)
	}

	// Load our session and generate keys.
	sessionRecord := b.sessionStore.LoadSession(b.remoteAddress)
	ourBaseKey, err := ecc.GenerateKeyPair()
	if err != nil {
		return err
	}
	theirSignedPreKey := preKey.SignedPreKey()
	theirOneTimePreKey := preKey.PreKey()
	theirOneTimePreKeyID := preKey.PreKeyID()

	// Build the parameters of the session
	parameters := ratchet.NewEmptySenderParameters()
	parameters.SetOurBaseKey(ourBaseKey)
	parameters.SetOurIdentityKey(b.identityKeyStore.GetIdentityKeyPair())
	parameters.SetTheirIdentityKey(preKey.IdentityKey())
	parameters.SetTheirSignedPreKey(theirSignedPreKey)
	parameters.SetTheirRatchetKey(theirSignedPreKey)
	parameters.SetTheirOneTimePreKey(theirOneTimePreKey)

	// If this is a fresh record, archive our current state.
	if !sessionRecord.IsFresh() {
		sessionRecord.ArchiveCurrentState()
	}

	///////// Initialize our session /////////
	sessionState := sessionRecord.SessionState()
	derivedKeys, sessionErr := ratchet.CalculateSenderSession(parameters)
	if sessionErr != nil {
		return sessionErr
	}
	// Generate an ephemeral "ratchet" key that will be advertised to
	// the receiving user.
	sendingRatchetKey, keyErr := ecc.GenerateKeyPair()
	if keyErr != nil {
		return keyErr
	}
	sendingChain, chainErr := derivedKeys.RootKey.CreateChain(
		parameters.TheirRatchetKey(),
		sendingRatchetKey,
	)
	if chainErr != nil {
		return chainErr
	}

	// Calculate the sender session.
	sessionState.SetVersion(protocol.CurrentVersion)
	sessionState.SetRemoteIdentityKey(parameters.TheirIdentityKey())
	sessionState.SetLocalIdentityKey(parameters.OurIdentityKey().PublicKey())
	sessionState.AddReceiverChain(parameters.TheirRatchetKey(), derivedKeys.ChainKey.Current())
	sessionState.SetSenderChain(sendingRatchetKey, sendingChain.ChainKey)
	sessionState.SetRootKey(sendingChain.RootKey)

	// Update our session record with the unackowledged prekey message
	sessionState.SetUnacknowledgedPreKeyMessage(
		theirOneTimePreKeyID,
		preKey.SignedPreKeyID(),
		ourBaseKey.PublicKey(),
	)

	// Set the local registration ID based on the registration id in our identity key store.
	sessionState.SetLocalRegistrationID(
		b.identityKeyStore.GetLocalRegistrationId(),
	)

	// Set the remote registration ID based on the given prekey bundle registrationID.
	sessionState.SetRemoteRegistrationID(
		preKey.RegistrationID(),
	)

	// Set the sender base key in our session record state.
	sessionState.SetSenderBaseKey(
		ourBaseKey.PublicKey().Serialize(),
	)

	// Store the session in our session store and save the identity in our identity store.
	b.sessionStore.StoreSession(b.remoteAddress, sessionRecord)
	b.identityKeyStore.SaveIdentity(b.remoteAddress, preKey.IdentityKey())

	return nil
}
