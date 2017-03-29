package fingerprint

// NewFingerprint will return a new Fingerprint structure.
func NewFingerprint(displayFingerprint *Display) *Fingerprint {
	return &Fingerprint{
		fingerprintDisplay: displayFingerprint,
	}
}

// Fingerprint is a structure for returning a displayable and scannable
// fingerprint for identity verification.
type Fingerprint struct {
	fingerprintDisplay *Display
	fingerprintScan    string
}

// Display will return a fingerprint display structure for getting a
// string representation of given keys.
func (f *Fingerprint) Display() *Display {
	return f.fingerprintDisplay
}

// Scan will return a fingerprint scan structure for getting a scannable
// representation of given keys.
func (f *Fingerprint) Scan() string {
	return f.fingerprintScan
}
