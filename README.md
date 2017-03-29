[![GoDoc](https://godoc.org/github.com/RadicalApp/goquery?status.png)](https://godoc.org/github.com/RadicalApp/libsignal-protocol-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/RadicalApp/libsignal-protocol-go)](https://goreportcard.com/report/github.com/RadicalApp/libsignal-protocol-go)
[![License](https://img.shields.io/aur/license/yaourt.svg)](https://www.gnu.org/licenses/quick-guide-gplv3.en.html)
[![Twitter](https://img.shields.io/badge/twitter-@DustMessaging-blue.svg?style=flat)](https://twitter.com/dustmessaging)

libsignal-protocol-go
=====================

Libsignal-protocol-go is a Go implementation of the Signal Client Protocol.


Documentation
-------------

- [API Reference](https://godoc.org/github.com/RadicalApp/libsignal-protocol-go)

For more information on how the Signal Protocol works:    
- [Double Ratchet](https://whispersystems.org/docs/specifications/doubleratchet/)
- [X3DH Key Agreement](https://whispersystems.org/docs/specifications/x3dh/)
- [XEdDSA Signature Schemes](https://whispersystems.org/docs/specifications/xeddsa/)


Installation
------------

Install the Signal library using the "go get" command:

    go get github.com/RadicalApp/libsignal-protocol-go/...


Usage
-----

## Install time
At install time, a signal client needs to generate its identity keys, registration id, and prekeys.

```go
import (
	"github.com/RadicalApp/libsignal-protocol-go/serialize"
	"github.com/RadicalApp/libsignal-protocol-go/session"
	"github.com/RadicalApp/libsignal-protocol-go/state/record"
	"github.com/RadicalApp/libsignal-protocol-go/util/keyhelper"
)

...

// Create a serializer that will be responsible for converting objects into
// storeable and transportable bytes.
serializer := serialize.NewJSONSerializer()

// Generate an identity keypair
identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
if err != nil {
    panic("Unable to generate identity key pair!")
}

// Generate a registration id
registrationID := keyhelper.GenerateRegistrationID(false)

// Generate PreKeys
preKeys, err := keyhelper.GeneratePreKeys(0, 100, serializer.PreKeyRecord)
if err != nil {
    panic("Unable to generate pre keys!")
}

// Generate Signed PreKey
signedPreKey, err := keyhelper.GenerateSignedPreKey(identityKeyPair, 0, serializer.SignedPreKeyRecord)
if err != nil {
    panic("Unable to generate signed prekey!")
}

// Create durable stores for sessions, prekeys, signed prekeys, and identity keys.
// These should be implemented yourself and follow the store interfaces.
sessionStore      := NewSessionStore()
preKeyStore       := NewPreKeyStore()
signedPreKeyStore := NewSignedPreKeyStore()
identityStore     := NewIdentityKeyStore(identityKeyPair, registrationID)

// Put all our pre keys in our local stores.
for i := range preKeys {
	preKeyStore.StorePreKey(
		preKeys[i].ID().Value,
		record.NewPreKey(preKeys[i].ID().Value, preKeys[i].KeyPair(), serializer.PreKeyRecord),
	)
}

// Store our own signed prekey
signedPreKeyStore.StoreSignedPreKey(
	signedPreKey.ID(),
	record.NewSignedPreKey(
		signedPreKey.ID(),
		signedPreKey.Timestamp(),
		signedPreKey.KeyPair(),
		signedPreKey.Signature(),
		serializer.SignedPreKeyRecord,
	),
)
```

## Building a session

A signal client needs to implement four interfaces: `IdentityKeyStore`, `PreKeyStore`, `SignedPreKeyStore`,
and `SessionStore`. These will manage loading and storing of identity, prekeys, signed prekeys, and
session state.

Once those are implemented, you can build a session in this way:

```go
// Instantiate a SessionBuilder for a remote recipientId + deviceId tuple.
sessionBuilder := session.NewBuilder(
	sessionStore,
	preKeyStore,
	signedPreKeyStore,
	identityStore,
	address,
	serializer,
)

// Build a session with a PreKey retrieved from the server.
sessionBuilder.ProcessBundle(retrievedPreKey)

// Encrypt a message to send.
sessionCipher := session.NewCipher(sessionBuilder, address)
message, err := sessionCipher.Encrypt([]byte{"Hello world!"})
if err != nil {
    panic("Unable to encrypt message!")
}

// Send the message with your own deliver method. The deliver method should be
// your own implementation for sending an encrypted message to someone.
deliver(message.serialize())
```

## Using your own stores

In order to use the Signal library, you must first implement your own stores for persistent
storage of keys, session state, etc. To get started, you can implement in-memory stores for
testing. Note that for production application, you will need to write store implementations
that can store persistently.

Here is an example of an in-memory implementation of the Identity Key Store:

```go
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
```

## Using your own serializer

The Go implementation of the Signal library uses serializer interfaces for encoding and decoding
data for use in sending data objects over the network and local storage. This allows users of
the Signal library to use their own serialization format (such as JSON, Protobuffers, etc.). It
also allows more flexibility for future serialization formats that might be better than the
current ones available.

Currently the library includes a JSON implementation of serializing all Signal data structures.
If you want to write a new serialization implementation, you will need to write structures
that implement the interfaces for each object and write a constructor function to create a
new `Serializer` object using your implementations.

A serializer must implement the serializer interfaces for the following structs:

* `protocol.SignalMessage`
* `protocol.PreKeySignalMessage`
* `protocol.SenderKeyMessage`
* `protocol.SenderKeyDistributionMessage`
* `record.SignedPreKey`
* `record.PreKey`
* `record.State`
* `record.Session`
* `record.SenderKey`
* `record.SenderKeyState`

Here is an example of the constructor function for a `Serializer` that uses JSON implementations:

```go
import "github.com/RadicalApp/libsignal-protocol-go/serializer"

// NewJSONSerializer will return a serializer for all Signal objects that will
// be responsible for converting objects to and from JSON bytes.
func NewJSONSerializer() *serializer.Serializer {
	serializer := serializer.NewSerializer()

	serializer.SignalMessage = &JSONSignalMessageSerializer{}
	serializer.PreKeySignalMessage = &JSONPreKeySignalMessageSerializer{}
	serializer.SignedPreKeyRecord = &JSONSignedPreKeyRecordSerializer{}
	serializer.PreKeyRecord = &JSONPreKeyRecordSerializer{}
	serializer.State = &JSONStateSerializer{}
	serializer.Session = &JSONSessionSerializer{}
	serializer.SenderKeyMessage = &JSONSenderKeyMessageSerializer{}
	serializer.SenderKeyDistributionMessage = &JSONSenderKeyDistributionMessageSerializer{}
	serializer.SenderKeyRecord = &JSONSenderKeySessionSerializer{}
	serializer.SenderKeyState = &JSONSenderKeyStateSerializer{}

	return serializer
}
```
