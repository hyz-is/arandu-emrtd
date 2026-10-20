# Contributing

Thank you for considering a contribution.

## Before you open a pull request

Run the gates. They are what CI runs, and a pull request that fails one of
them fails for everybody who pulls after it.

```bash
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
CGO_ENABLED=0 go build ./...
go vet ./...
go test -race -count=1 ./...
```

A change to a parser also runs its fuzz target beyond the seed corpus:
`go test ./tests/Feature -run '^$' -fuzz '^FuzzParseSOD$' -fuzztime 30s`.

## What a change has to keep true

1. **Nothing here decides.** A check answers an outcome and a reason; a
   verdict, a score or a boolean in a Report belongs to the application.
2. **Unverifiable is never passed.** A key, a curve or an algorithm this
   package cannot compute with makes the check `unverifiable`.
3. **No parser panics,** and every one holds the limits in `tlv.go`.
4. **Standard library only,** besides the framework. A new dependency needs
   its licence verified and a reason the standard library cannot serve.
5. **`arandu.mod.toml` matches the code.**

Every fixture is synthetic and generated in the test run: test CSCAs and
Document Signers of the invented state Utopia, invented MRZs, an 8x8 gradient
as the face. No byte read from a real document is ever a fixture.

## Style

Everything in the source is in English: identifiers, doc comments, internal
comments, error messages, log messages, and the names and messages of tests.

Every exported symbol carries a doc comment saying what it does, and nothing
else: no dates, no issue numbers, no references to other repositories.

## Commits

One commit per logical change. Formatting is not mixed with behaviour.

## Reporting a vulnerability

Do not open an issue. See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence, the same as the rest of github.com/hyz-is/arandu-emrtd.
