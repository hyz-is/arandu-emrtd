# Security policy

## Supported versions

The latest minor release of Arandu eMRTD receives security fixes. Older minor
releases do not: a published Go module version is immutable, so a fix is a new
release rather than a moved tag.

## Reporting a vulnerability

Report it privately, through GitHub's advisory form:

<https://github.com/hyz-is/arandu-emrtd/security/advisories/new>

Do not open a public issue and do not describe the problem in a pull request.
A report that arrives in public is a report every reader of this repository can
act on before there is a release to upgrade to.

Include what you need to reproduce it: the version, the call, and synthetic
bytes that trigger it. Never send data read from a real document.

Expect an acknowledgement within a few days. If the report is confirmed, the
fix, the release and the advisory are published together, and you are credited
unless you ask not to be.

## What is in scope

Anything that makes a check pass when what it checks does not hold, or makes
the package misbehave on hostile input. In particular:

- a data group, an SOD signature, a chain, a revocation or an Active
  Authentication reported `passed` for altered, forged, replayed or
  unauthenticated data;
- a key or a curve this package cannot compute with reported as anything but
  `unverifiable`;
- a Document Signer chained to a certificate that is not in the trust store,
  or that is not a CA;
- input -- a chip file, a certificate, a master list, a CRL, a signature --
  that panics, loops, or takes memory or time beyond the documented limits;
- a Report whose JSON carries the face image or a key, or a Detail that
  repeats personal data.

## What is not

- What the device does with the chip: BAC, PACE, Chip Authentication and
  secure messaging run there.
- Which CSCAs and master lists the application chooses to trust, and how it
  keeps the challenge and the Report. Those are the application's.
