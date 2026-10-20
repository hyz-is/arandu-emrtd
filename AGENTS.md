# Working on Arandu eMRTD

This is an Arandu package that examines, on the server, the files an ICAO Doc
9303 chip gave a device -- EF.COM, EF.SOD, the data groups, EF.CardAccess, the
Active Authentication response -- and answers with a Report of evidence. It
was built for KUAA's reading of the Brazilian passport chip; the reading itself
happens in a native app or SDK on the device, never here.
It is a Go module somebody `go get`s and registers by hand in their own
`bootstrap/app.go`. There is no service provider, no container and no
discovery.

Read `.agents/skills/` before writing code. Each skill is a procedure, and the
one you need is named by the situation you are in.

## The rules

A change that breaks one is not merged.

1. **No decisions.** Every check is an `Outcome` (`passed`, `failed`,
   `not_present`, `unverifiable`) with a `Reason`. No verdict, no score, no
   boolean in a Report, no field standing for the others.
   `tests/Unit/decision_test.go` holds it.
2. **Unverifiable is never passed.** A key on Brainpool or any curve the
   standard library does not implement, an algorithm not implemented, a CSCA
   missing, a DG15 key Passive Authentication did not cover: the check is
   `unverifiable`, with its reason.
3. **Standard library only**, besides the Arandu framework. `gmrtd` is not
   used: its dependency `osanderson/brainpool` carries no licence file. A new
   dependency needs a verified permissive licence and a reason.
4. **Bounded, tolerant parsing.** No parser panics; every one holds the limits
   of `tlv.go`. A parser change runs its fuzz target beyond the seed corpus.
5. **Synthetic data only.** Every key, certificate, SOD and data group of a
   test is generated in the test run, for the invented state Utopia. No byte
   read from a real document, ever -- not in a fixture, a log or an example.
6. **No personal data in a Detail.** The face image and keys are `json:"-"`.
7. **Nothing fetched, nothing stored.** No network, no file, no environment
   variable: the application hands the bytes in. `arandu.mod.toml` says so and
   `tests/Unit/audit_test.go` checks it.

## The gates

Nothing is finished until all of them exit zero.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
CGO_ENABLED=0 go build ./...
go vet ./...
go test -race -count=1 ./...
```

Logs of local runs go in `tmp/`, which git ignores. `aru doctor` reads
applications, not libraries; run here it exits 1 with "this is not an Arandu
project", which is why the audit test exists.

## What this repository holds

```
module.go        registration: Name, Routes (none), TrustStore, Examine; the package doc
config.go        Config and the trust store it builds
report.go        Input, Options, Report, Examine: every check in order
outcome.go       Outcome, CheckName, Reason, Check
tlv.go           the BER-TLV reader and every parsing limit
lds.go           tags, data group numbers, EF.COM
mrz.go           DG1, the MRZ (TD1, TD2, TD3), check digits, CompareMRZ
dg2.go           the face images of DG2 (ISO/IEC 19794-5)
securityinfo.go  DG14 and EF.CardAccess
publickey.go     SubjectPublicKeyInfo: RSA, NIST EC named or explicit, Brainpool named
signature.go     PKCS #1 v1.5, PSS, ECDSA DER and plain
certificate.go   X.509 parsed without crypto/x509, so any curve is read
cms.go           CMS SignedData and its signer
sod.go           EF.SOD and the LDSSecurityObject
masterlist.go    CSCA master lists
truststore.go    TrustStore, CRLs, the chain step
active.go        NewChallenge, ISO/IEC 9796-2 and ECDSA Active Authentication
chip.go          the Chip Authentication claim
oids.go          every object identifier
errors.go        ErrMalformed, ErrTooLarge, ErrUnsupported
```

Tests live under `tests/Unit` (MRZ known answers, TLV limits, EF.COM, PACE
names, the decision rule, the audit, the structure, the release files) and
`tests/Feature` (the synthetic PKI and chip in `fixture_test.go`, every check
of Examine, Active and Chip Authentication, master lists, and the fuzz
targets).

## Writing code

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, log messages, and the names and messages of tests.
The README is in Brazilian Portuguese, with identifiers in English.

Every exported symbol carries a doc comment, and the comment documents the
symbol and nothing else.

Tests go under `tests/`, in a capitalized category directory declaring a
lowercase external package: `tests/Unit` holds `package unit_test`,
`tests/Feature` holds `package feature_test`.

Agent instructions live only in this file and in `.agents/skills/`; there is no
instruction file named after a vendor.
