---
name: emrtd-package
description: Install, wire and use the Arandu eMRTD package (Go, Arandu) in an application. Use when the request is to "verify a passport chip", "Passive Authentication", "check the SOD", "eMRTD", "ICAO 9303", "NFC passport", "Active Authentication challenge", "CSCA master list", "go get github.com/hyz-is/arandu-emrtd", "wire it into bootstrap/app.go", "what does unverifiable mean", "unsupported_curve", "key_not_authenticated", or when a project's go.mod already requires github.com/hyz-is/arandu-emrtd. Covers the wiring, the input contract, the challenge, and what each outcome proves.
license: MIT
metadata:
  audience: app
---

# Using Arandu eMRTD

A module that examines the files a device read from an ICAO Doc 9303 chip and
answers with a Report of checks. It decides nothing. The chip is read by a
native app or SDK on the device; a browser cannot.

## Install

```bash
go get github.com/hyz-is/arandu-emrtd@v0.1.0
```

## The wiring, and where it goes

All of it is in `bootstrap/app.go`, before `k.Register`, with bytes the
application loaded from its own storage:

```go
	emrtdModule, err := emrtd.New(emrtd.Config{
		CSCACertificates:  cscaDERs,
		MasterLists:       masterListDERs,
		MasterListAnchors: anchorDERs,
		CRLs:              crlDERs,
	})
	if err != nil {
		return App{}, err
	}
	k.Register(emrtdModule)
```

## The input

- Every file is the elementary file exactly as read: tag and length included.
- The Active Authentication challenge comes from `emrtd.NewChallenge()` when
  the reading session opens, is kept server-side with that session, and is
  passed back from the server's copy -- never from what the device sends. One
  response per challenge.
- `PrintedMRZ` is the OCR of the printed page, or empty.

## Reading the Report

Require the outcomes the decision needs, and treat anything but
`OutcomePassed` as not passed. A minimum for "the chip data is the issuer's":
`data_group_hash` for every group used, `sod_signature`,
`document_signer_chain`, `document_signer_validity`. For "this is the
physical chip": `active_authentication` too. `unverifiable` with
`unsupported_curve` means a Brainpool key this package cannot compute with;
it is not a pass. Keep the Report as evidence: its JSON leaves out the face
image and keys, and its Details carry no personal data.
