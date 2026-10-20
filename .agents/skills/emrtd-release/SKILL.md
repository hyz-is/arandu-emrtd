---
name: emrtd-release
description: Get the Arandu eMRTD package green, declared and published. Use when the request is to "run the gates", "check it builds", "the tests fail", "run the fuzzers", "go build says the directory prefix does not contain modules listed in go.work", "aru doctor says this is not an Arandu project", "update arandu.mod.toml", "add a dependency", "bump the framework", "tag a release", "publish it", "write the changelog", or before opening a pull request. Covers the gates, the fuzz runs, what the manifest declares and who checks it, the dependency rule, the public name, and the immutability of a published version.
license: MIT
---

# Getting it green and out

## The gates

Nothing is finished until all of them exit zero. Logs go in `tmp/`.

```sh
export GOWORK=off
gofmt -l $(find . -name '*.go' -not -path '*/testdata/*' -not -name '*.kyse.go')
go build ./...
CGO_ENABLED=0 go build ./...
go vet ./...
go test -race -count=1 ./...
```

`GOWORK=off` because this checkout may sit beside a Go workspace that does not
list it. The package is pure Go; the `CGO_ENABLED=0` build holds that.

The fuzz targets run over their seeds in `go test`. Beyond them:

```sh
for f in $(go test ./tests/Feature -list '^Fuzz' | grep '^Fuzz'); do
  go test ./tests/Feature -run '^$' -fuzz "^$f\$" -fuzztime 30s
done
```

The progress line may show `0/sec` for seconds at a time: workers report in
batches. A crash writes the input under `tests/Feature/testdata/fuzz/`; it
is synthetic by construction, and it is committed with the fix.

`aru doctor` is not a gate: it reads applications and exits 1 here.

## What the manifest declares

```toml
name = "hyz-is/emrtd"
framework = ">= 0.56"
profiles = ["conventional", "performance"]

[permissions]
network = false
filesystem = false
exec = false
migrations = false
```

`tests/Unit/audit_test.go` compares the four permissions with what the code
calls. The `framework` floor is a second declaration of `go.mod`'s
requirement; `tests/Unit/release_test.go` keeps them together.

## Dependencies

The standard library and `github.com/arandu-io/framework`, nothing else. A
new one needs a permissive licence verified in its repository (a licence file,
not a README line), for it and for everything it pulls in, and a reason the
standard library cannot serve. `gmrtd` failed this.

## The public name

The module path `github.com/hyz-is/arandu-emrtd` and the manifest name
`hyz-is/emrtd` are provisional. Nothing is created, pushed or tagged until the
owner confirms the name. The repository is then created in `hyz-is` from the
template `arandu-io/package-skeleton`, and this history is rebased onto the
template's first commit.

## Publishing

A published Go module version is immutable; a mistake is corrected by another
release. Before tagging: the gates pass, the fuzzers ran, `arandu.mod.toml`
matches the code, `CHANGELOG.md` has `## [x.y.z] - <date>` (the `unreleased`
placeholder replaced by the date) and `UPGRADE.md` has `## vx.y.z`. The CI step
`api diff against the last release` fails unless `UPGRADE.md` names each
incompatible change.

Two changes break an installer without touching a signature: a check that
changes outcome for the same input (applications require outcomes), and a
renamed `Reason`.
