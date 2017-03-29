package tests

import (
	groupRecord "github.com/RadicalApp/libsignal-protocol-go/groups/state/record"
	"github.com/RadicalApp/libsignal-protocol-go/keys/identity"
	"github.com/RadicalApp/libsignal-protocol-go/protocol"
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/state/record"
)

// Define some in-memory stores for testing.

// IdentityKeyStore
func NewInMemoryIdentityKey(identityKey *identity.KeyPair, localRegistrationID uint32) *InMemoryIdentityKey {
	return &InMemoryIdentityKey{
		trustedKeys:         make(map[*protocol.SignalAddress]*identity.Key),
		identityKeyPair:     identityKey,
		localRegistrationID: localRegistrationID,
	}
}

type InMemoryIdentityKey struct {
	trustedKeys         map[*protocol.SignalAddress]*identity.Key
	identityKeyPair     *identity.KeyPair
	localRegistrationID uint32
}

func (i *InMemoryIdentityKey) GetIdentityKeyPair() *identity.KeyPair {
	return i.identityKeyPair
}

func (i *InMemoryIdentityKey) GetLocalRegistrationId() uint32 {
	return i.localRegistrationID
}

func (i *InMemoryIdentityKey) SaveIdentity(address *protocol.SignalAddress, identityKey *identity.Key) {
	i.trustedKeys[address] = identityKey
}

func (i *InMemoryIdentityKey) IsTrustedIdentity(address *protocol.SignalAddress, identityKey *identity.Key) bool {
	trusted := i.trustedKeys[address]
	return (trusted == nil || trusted.Fingerprint() == identityKey.Fingerprint())
}

// PreKeyStore
func NewInMemoryPreKey() *InMemoryPreKey {
	return &InMemoryPreKey{
		store: make(map[uint32]*record.PreKey),
	}
}

type InMemoryPreKey struct {
	store map[uint32]*record.PreKey
}

func (i *InMemoryPreKey) LoadPreKey(preKeyID uint32) *record.PreKey {
	return i.store[preKeyID]
}

func (i *InMemoryPreKey) StorePreKey(preKeyID uint32, preKeyRecord *record.PreKey) {
	i.store[preKeyID] = preKeyRecord
}

func (i *InMemoryPreKey) ContainsPreKey(preKeyID uint32) bool {
	_, ok := i.store[preKeyID]
	return ok
}

func (i *InMemoryPreKey) RemovePreKey(preKeyID uint32) {
	delete(i.store, preKeyID)
}

// SessionStore
func NewInMemorySession(serializer *serialize.Serializer) *InMemorySession {
	return &InMemorySession{
		sessions:   make(map[*protocol.SignalAddress]*record.Session),
		serializer: serializer,
	}
}

type InMemorySession struct {
	sessions   map[*protocol.SignalAddress]*record.Session
	serializer *serialize.Serializer
}

func (i *InMemorySession) LoadSession(address *protocol.SignalAddress) *record.Session {
	if i.ContainsSession(address) {
		return i.sessions[address]
	}
	sessionRecord := record.NewSession(i.serializer.Session, i.serializer.State)
	i.sessions[address] = sessionRecord

	return sessionRecord
}

func (i *InMemorySession) GetSubDeviceSessions(name string) []uint32 {
	var deviceIDs []uint32

	for key := range i.sessions {
		if key.Name() == name && key.DeviceID() != 1 {
			deviceIDs = append(deviceIDs, key.DeviceID())
		}
	}

	return deviceIDs
}

func (i *InMemorySession) StoreSession(remoteAddress *protocol.SignalAddress, record *record.Session) {
	i.sessions[remoteAddress] = record
}

func (i *InMemorySession) ContainsSession(remoteAddress *protocol.SignalAddress) bool {
	_, ok := i.sessions[remoteAddress]
	return ok
}

func (i *InMemorySession) DeleteSession(remoteAddress *protocol.SignalAddress) {
	delete(i.sessions, remoteAddress)
}

func (i *InMemorySession) DeleteAllSessions() {
	i.sessions = make(map[*protocol.SignalAddress]*record.Session)
}

// SignedPreKeyStore
func NewInMemorySignedPreKey() *InMemorySignedPreKey {
	return &InMemorySignedPreKey{
		store: make(map[uint32]*record.SignedPreKey),
	}
}

type InMemorySignedPreKey struct {
	store map[uint32]*record.SignedPreKey
}

func (i *InMemorySignedPreKey) LoadSignedPreKey(signedPreKeyID uint32) *record.SignedPreKey {
	return i.store[signedPreKeyID]
}

func (i *InMemorySignedPreKey) LoadSignedPreKeys() []*record.SignedPreKey {
	var preKeys []*record.SignedPreKey

	for _, record := range i.store {
		preKeys = append(preKeys, record)
	}

	return preKeys
}

func (i *InMemorySignedPreKey) StoreSignedPreKey(signedPreKeyID uint32, record *record.SignedPreKey) {
	i.store[signedPreKeyID] = record
}

func (i *InMemorySignedPreKey) ContainsSignedPreKey(signedPreKeyID uint32) bool {
	_, ok := i.store[signedPreKeyID]
	return ok
}

func (i *InMemorySignedPreKey) RemoveSignedPreKey(signedPreKeyID uint32) {
	delete(i.store, signedPreKeyID)
}

func NewInMemorySenderKey() *InMemorySenderKey {
	return &InMemorySenderKey{
		store: make(map[*protocol.SenderKeyName]*groupRecord.SenderKey),
	}
}

type InMemorySenderKey struct {
	store map[*protocol.SenderKeyName]*groupRecord.SenderKey
}

func (i *InMemorySenderKey) StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) {
	i.store[senderKeyName] = keyRecord
}

func (i *InMemorySenderKey) LoadSenderKey(senderKeyName *protocol.SenderKeyName) *groupRecord.SenderKey {
	return i.store[senderKeyName]
}
