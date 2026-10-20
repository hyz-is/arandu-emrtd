package emrtd

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Config is what the application passes in: the trust it chose, as bytes.
//
// The package reads no environment variable and no file. The application
// keeps its CSCA certificates and master lists where it keeps files (in KUAA,
// a private Cloudflare R2 bucket), loads them, and hands the bytes here.
type Config struct {
	// CSCACertificates is CSCA certificate DERs the application pins, such as
	// the ones an issuing state publishes.
	CSCACertificates [][]byte
	// MasterLists is CSCA master list DERs (.ml files). Each one's CMS
	// signature must pass. With MasterListAnchors set, each one's signer must
	// also have been issued by one of them.
	MasterLists [][]byte
	// MasterListAnchors is CSCA certificate DERs that issue master list
	// signers, such as the CSCA of the state that publishes the list.
	MasterListAnchors [][]byte
	// PinnedMasterListSHA256 is the hex SHA-256 of master lists accepted
	// without a signature check this package can run: a list signed with a
	// Brainpool key is unverifiable here, and the application that pins its
	// digest takes the list as it downloaded it. A failed signature is never
	// accepted, pinned or not.
	PinnedMasterListSHA256 []string
	// DocumentSigners is Document Signer certificate DERs for SODs that do
	// not carry their own.
	DocumentSigners [][]byte
	// CRLs is CSCA certificate revocation list DERs.
	CRLs [][]byte
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

// TrustStore builds the trust store the configuration describes.
func (c Config) TrustStore() (*TrustStore, error) {
	now := c.Now
	if now == nil {
		now = time.Now
	}
	at := now()
	t := NewTrustStore()
	for i, der := range c.CSCACertificates {
		if _, err := t.AddCSCA(der); err != nil {
			return nil, fmt.Errorf("CSCA certificate %d: %w", i, err)
		}
	}
	var anchors []*Certificate
	for i, der := range c.MasterListAnchors {
		a, err := ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("master list anchor %d: %w", i, err)
		}
		anchors = append(anchors, a)
	}
	pinned := make([]string, 0, len(c.PinnedMasterListSHA256))
	for _, p := range c.PinnedMasterListSHA256 {
		pinned = append(pinned, strings.ToLower(strings.TrimSpace(p)))
	}
	for i, der := range c.MasterLists {
		ml, err := ParseMasterList(der)
		if err != nil {
			return nil, fmt.Errorf("master list %d: %w", i, err)
		}
		isPinned := slices.Contains(pinned, ml.SHA256)
		switch ml.Signature.Outcome {
		case OutcomePassed:
		case OutcomeUnverifiable:
			if !isPinned {
				return nil, fmt.Errorf("master list %d: its signature cannot be checked here (%s) and its SHA-256 %s is not pinned", i, ml.Signature.Reason, ml.SHA256)
			}
		default:
			return nil, fmt.Errorf("master list %d: its signature does not verify (%s)", i, ml.Signature.Reason)
		}
		if len(anchors) > 0 && !isPinned {
			if check := ml.CheckSigner(anchors, at); check.Outcome != OutcomePassed {
				return nil, fmt.Errorf("master list %d: no anchor issued its signer (%s)", i, check.Reason)
			}
		}
		t.AddMasterList(ml)
	}
	for i, der := range c.DocumentSigners {
		if _, err := t.AddDocumentSigner(der); err != nil {
			return nil, fmt.Errorf("document signer %d: %w", i, err)
		}
	}
	for i, der := range c.CRLs {
		if err := t.AddCRL(der); err != nil {
			return nil, fmt.Errorf("CRL %d: %w", i, err)
		}
	}
	return t, nil
}
