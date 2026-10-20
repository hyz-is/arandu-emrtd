package emrtd

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"slices"
	"sync"
	"time"
)

// TrustStore is the CSCA certificates, the extra Document Signer certificates
// and the CRLs Passive Authentication is checked against.
//
// What goes into it is the application's decision: CSCA certificates pinned
// from an issuing state's publication, or the certificates of a master list
// it chose to trust. Nothing here fetches anything. It is safe for
// concurrent use; it is meant to be built once, at boot, and read from then
// on.
type TrustStore struct {
	mu      sync.RWMutex
	cscas   []*Certificate
	signers []*Certificate
	crls    []*revocationList
}

type revocationList struct {
	list       *x509.RevocationList
	sigAlg     pkix.AlgorithmIdentifier
	rawIssuer  []byte
	thisUpdate time.Time
	nextUpdate time.Time
	revoked    map[string]time.Time
}

// NewTrustStore returns an empty trust store.
func NewTrustStore() *TrustStore { return &TrustStore{} }

// AddCSCA parses a CSCA certificate DER and trusts it.
func (t *TrustStore) AddCSCA(der []byte) (*Certificate, error) {
	c, err := ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	t.AddCertificates(c)
	return c, nil
}

// AddCertificates trusts already parsed CSCA certificates, such as those of a
// master list. A certificate already in the store is not added twice.
func (t *TrustStore) AddCertificates(certs ...*Certificate) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	added := 0
	for _, c := range certs {
		if c == nil || slices.ContainsFunc(t.cscas, func(d *Certificate) bool { return d.SHA256 == c.SHA256 }) {
			continue
		}
		t.cscas = append(t.cscas, c)
		added++
	}
	return added
}

// AddMasterList trusts every certificate of a master list and returns how
// many were new. Checking the list first -- its Signature, and CheckSigner
// against the anchors the application holds -- is the caller's; New does it
// for the module's configuration.
func (t *TrustStore) AddMasterList(m *MasterList) int {
	if m == nil {
		return 0
	}
	return t.AddCertificates(m.Certificates...)
}

// AddDocumentSigner adds a Document Signer certificate for SODs that do not
// carry their own, as the ICAO PKD distributes them. It is not trusted by
// being here: its chain to a CSCA is checked like any other.
func (t *TrustStore) AddDocumentSigner(der []byte) (*Certificate, error) {
	c, err := ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !slices.ContainsFunc(t.signers, func(d *Certificate) bool { return d.SHA256 == c.SHA256 }) {
		t.signers = append(t.signers, c)
	}
	return c, nil
}

// AddCRL adds a CSCA's certificate revocation list DER. Its signature is
// checked when it is used, against the CSCA that issued the Document Signer.
func (t *TrustStore) AddCRL(der []byte) error {
	if len(der) > MaxCRLSize {
		return tooLarge("CRL of %d bytes", len(der))
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return malformed("CRL: %v", err)
	}
	var outer rawCertificate
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) > 0 {
		return malformed("CRL")
	}
	crl := &revocationList{
		list:       list,
		sigAlg:     outer.SignatureAlgorithm,
		rawIssuer:  list.RawIssuer,
		thisUpdate: list.ThisUpdate.UTC(),
		nextUpdate: list.NextUpdate.UTC(),
		revoked:    map[string]time.Time{},
	}
	for _, e := range list.RevokedCertificateEntries {
		if e.SerialNumber != nil {
			crl.revoked[e.SerialNumber.Text(16)] = e.RevocationTime.UTC()
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.crls = append(t.crls, crl)
	return nil
}

// CSCAs is the trusted CSCA certificates.
func (t *TrustStore) CSCAs() []*Certificate {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return slices.Clone(t.cscas)
}

// Len is the number of trusted CSCA certificates.
func (t *TrustStore) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.cscas)
}

func (t *TrustStore) documentSigners() []*Certificate {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return slices.Clone(t.signers)
}

func (t *TrustStore) crlsFor(issuer *Certificate) []*revocationList {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []*revocationList
	for _, c := range t.crls {
		if bytes.Equal(c.rawIssuer, issuer.rawSubject) {
			out = append(out, c)
			continue
		}
		if a := canonicalName(c.rawIssuer); a != "" && a == canonicalName(issuer.rawSubject) {
			out = append(out, c)
		}
	}
	return out
}

// chainTo checks that one certificate of pool issued c: the names and key
// identifiers agree, the issuer is a CA allowed to sign certificates, and c's
// signature verifies with its key. It returns the issuer that did, or the
// most informative outcome of the candidates that did not.
func chainTo(c *Certificate, pool []*Certificate, at time.Time) (sigResult, *Certificate) {
	var candidates []*Certificate
	for _, p := range pool {
		if c.issuedBy(p) {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return sigResult{OutcomeUnverifiable, ReasonCSCANotFound, "no trusted certificate is named as the issuer"}, nil
	}
	// Among several (a key rollover, a link certificate), the one valid at
	// the evaluation time is tried first.
	slices.SortStableFunc(candidates, func(a, b *Certificate) int {
		va, vb := a.validAt(at) == "", b.validAt(at) == ""
		switch {
		case va && !vb:
			return -1
		case vb && !va:
			return 1
		}
		return 0
	})
	best := sigResult{OutcomeUnverifiable, ReasonCSCANotFound, "no trusted certificate is named as the issuer"}
	rank := func(r sigResult) int {
		switch r.outcome {
		case OutcomeFailed:
			return 2
		case OutcomeUnverifiable:
			if r.reason == ReasonCSCANotFound {
				return 0
			}
			return 1
		}
		return 3
	}
	for _, issuer := range candidates {
		var res sigResult
		switch {
		case issuer.ca != 1:
			res = sigResult{OutcomeFailed, ReasonIssuerNotCA, "the certificate named as issuer is not a CA"}
		case issuer.keyUsage >= 0 && issuer.keyUsage&keyUsageCertSign == 0:
			res = sigResult{OutcomeFailed, ReasonKeyUsage, "the issuer's key usage does not allow signing certificates"}
		default:
			res = c.signedBy(issuer)
		}
		if res.outcome == OutcomePassed {
			return res, issuer
		}
		if rank(res) > rank(best) {
			best = res
		}
	}
	return best, nil
}

// revocation checks the Document Signer against the CRLs of its CSCA.
func (t *TrustStore) revocation(ds, csca *Certificate, at time.Time) Check {
	const name = CheckDocumentSignerRevocation
	lists := t.crlsFor(csca)
	if len(lists) == 0 {
		return notPresent(name, FileSOD, ReasonNoCRL, "no CRL of the issuing CSCA is in the trust store")
	}
	if csca.keyUsage >= 0 && csca.keyUsage&keyUsageCRLSign == 0 {
		return unverifiable(name, FileSOD, ReasonKeyUsage, "the issuing CSCA's key usage does not allow signing CRLs")
	}
	var verified []*revocationList
	var last sigResult
	for _, l := range lists {
		last = checkSignature(csca.Key, l.sigAlg, 0, l.list.RawTBSRevocationList, l.list.Signature)
		if last.outcome == OutcomePassed {
			verified = append(verified, l)
		}
	}
	if len(verified) == 0 {
		return unverifiable(name, FileSOD, ReasonCRLSignature, "no CRL of the issuing CSCA has a signature that verifies here: "+last.detail)
	}
	serial := ds.serial.Text(16)
	for _, l := range verified {
		if when, ok := l.revoked[serial]; ok {
			return failed(name, FileSOD, ReasonRevoked, "a CRL of the issuing CSCA revokes the Document Signer certificate since "+when.Format(time.RFC3339))
		}
	}
	newest := verified[0]
	for _, l := range verified[1:] {
		if l.thisUpdate.After(newest.thisUpdate) {
			newest = l
		}
	}
	if !newest.nextUpdate.IsZero() && at.After(newest.nextUpdate) {
		return passed(name, FileSOD, ReasonCRLStale, "no CRL revokes it, and the newest one was due for an update on "+newest.nextUpdate.Format(time.RFC3339))
	}
	return passed(name, FileSOD, "", "")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
