// Package emrtd is an Arandu module that examines, on the server, the data an
// eMRTD chip (ICAO Doc 9303) gave a device, and answers with evidence.
//
// The chip is read elsewhere: a browser cannot read it, and a native app or
// SDK on the device runs BAC or PACE, reads EF.COM, EF.SOD and the data
// groups, and relays the Active Authentication response and what it observed
// of Chip Authentication. This package parses those files with bounded,
// tolerant parsers, runs Passive Authentication against the CSCA trust store
// the application configures (data group hashes, the SOD signature, the
// Document Signer's chain, validity and revocation), checks the MRZ, compares
// it with the printed page, and checks the Active Authentication signature
// over the server's challenge.
//
// It decides nothing. Every check is an Outcome -- passed, failed,
// not_present or unverifiable -- with its reason, and the Report has no field
// that stands for the others. A key on a curve the Go standard library does
// not implement, Brainpool above all, makes the checks that need it
// unverifiable, never passed.
//
// It owns no table, serves no route, reads no file and opens no connection.
// It is written with the Go standard library alone.
//
// An application builds it once in bootstrap/app.go and registers it there.
// There is no service provider, no container and no discovery.
package emrtd

import (
	"time"

	"github.com/arandu-io/framework/foundation"
	fhttp "github.com/arandu-io/framework/http"
)

// Module is what the application registers, and what holds the trust store.
type Module struct {
	trust *TrustStore
	now   func() time.Time
}

// Compile-time proof that the module honors the contract it claims.
var _ foundation.Module = (*Module)(nil)

// New returns the module with the trust store of cfg, or the reason it cannot
// be built.
//
// It returns an error rather than carrying on, because everything it refuses
// -- a certificate that does not parse, a master list whose signature fails or
// whose signer no anchor issued -- is a configuration mistake, and one found
// at boot costs one restart instead of every chain afterwards.
func New(cfg Config) (*Module, error) {
	trust, err := cfg.TrustStore()
	if err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Module{trust: trust, now: now}, nil
}

// Name is the module identifier: a lowercase slug, stable, no spaces.
func (m *Module) Name() string { return "emrtd" }

// Routes registers nothing.
//
// Chip data is personal and biometric data, and reaches this module only
// through the application's own controllers, behind its policy, with the
// challenge the application issued for that session.
func (m *Module) Routes(*fhttp.Router) {}

// TrustStore is the module's trust store.
func (m *Module) TrustStore() *TrustStore { return m.trust }

// Examine examines the input against the module's trust store, at the
// module's clock when opts.Time is zero.
func (m *Module) Examine(in Input, opts Options) *Report {
	if opts.Time.IsZero() {
		opts.Time = m.now()
	}
	return Examine(in, m.trust, opts)
}
