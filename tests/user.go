package tests

import (
	"github.com/RadicalApp/libsignal-protocol-go/groups"
	"github.com/RadicalApp/libsignal-protocol-go/keys/identity"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/session"
	"github.com/RadicalApp/libsignal-protocol-go/state/record"
	"github.com/RadicalApp/libsignal-protocol-go/util/keyhelper"
)

// user is a structure for a signal user.
type user struct {
	name     string
	deviceID uint32
	address  *protocol.SignalAddress

	identityKeyPair *identity.KeyPair
	registrationID  uint32

	preKeys      []*record.PreKey
	signedPreKey *record.SignedPreKey

	sessionStore      *InMemorySession
	preKeyStore       *InMemoryPreKey
	signedPreKeyStore *InMemorySignedPreKey
	identityStore     *InMemoryIdentityKey
	senderKeyStore    *InMemorySenderKey

	sessionBuilder *session.Builder
	groupBuilder   *groups.SessionBuilder
}

// buildSession will build a session with the given address.
func (u *user) buildSession(address *protocol.SignalAddress, serializer *serialize.Serializer) {
	u.sessionBuilder = session.NewBuilder(
		u.sessionStore,
		u.preKeyStore,
		u.signedPreKeyStore,
		u.identityStore,
		address,
		serializer,
	)
}

// buildGroupSession will build a group session using sender keys.
func (u *user) buildGroupSession(serializer *serialize.Serializer) {
	u.groupBuilder = groups.NewGroupSessionBuilder(u.senderKeyStore, serializer)
}

// newUser creates a new signal user for session testing.
func newUser(name string, deviceID uint32, serializer *serialize.Serializer) *user {
	signalUser := &user{}

	// Generate an identity keypair
	signalUser.identityKeyPair, _ = keyhelper.GenerateIdentityKeyPair()

	// Generate a registration id
	signalUser.registrationID = keyhelper.GenerateRegistrationID()

	// Generate PreKeys
	signalUser.preKeys, _ = keyhelper.GeneratePreKeys(0, 100, serializer.PreKeyRecord)

	// Generate Signed PreKey
	signalUser.signedPreKey, _ = keyhelper.GenerateSignedPreKey(signalUser.identityKeyPair, 0, serializer.SignedPreKeyRecord)

	// Create all our record stores using an in-memory implementation.
	signalUser.sessionStore = NewInMemorySession(serializer)
	signalUser.preKeyStore = NewInMemoryPreKey()
	signalUser.signedPreKeyStore = NewInMemorySignedPreKey()
	signalUser.identityStore = NewInMemoryIdentityKey(signalUser.identityKeyPair, signalUser.registrationID)
	signalUser.senderKeyStore = NewInMemorySenderKey()

	// Put all our pre keys in our local stores.
	for i := range signalUser.preKeys {
		signalUser.preKeyStore.StorePreKey(
			signalUser.preKeys[i].ID().Value,
			record.NewPreKey(signalUser.preKeys[i].ID().Value, signalUser.preKeys[i].KeyPair(), serializer.PreKeyRecord),
		)
	}

	// Store our's own signed prekey
	signalUser.signedPreKeyStore.StoreSignedPreKey(
		signalUser.signedPreKey.ID(),
		record.NewSignedPreKey(
			signalUser.signedPreKey.ID(),
			signalUser.signedPreKey.Timestamp(),
			signalUser.signedPreKey.KeyPair(),
			signalUser.signedPreKey.Signature(),
			serializer.SignedPreKeyRecord,
		),
	)

	// Create a remote address that we'll be building our session with.
	signalUser.name = name
	signalUser.deviceID = deviceID
	signalUser.address = protocol.NewSignalAddress(name, deviceID)

	// Create a group session builder
	signalUser.buildGroupSession(serializer)

	return signalUser
}
