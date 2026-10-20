# Skills

Procedures an assistant follows when working on this package.

They live in `.agents/skills/<name>/SKILL.md`, which is the path the coding
assistants read from. It is one directory rather than a file per vendor, so a
skill written once is read by whatever this package is being written with.

Each file opens with frontmatter carrying a `name` and a `description`. The
`name` has to equal the directory name exactly, or the skill is not loaded. The
description names the situation you are in rather than the topic it covers.

| skill | when it fires |
| --- | --- |
| `emrtd-module` | changing a parser, a check, the trust store, Active or Chip Authentication, the Report |
| `emrtd-release` | the gates, the fuzz runs, the manifest, a dependency, a version, a tag |
| `emrtd-vault-notes` | writing the note, the gap or the journal entry, when this checkout sits inside the Arandu Obsidian vault |
| `emrtd-package` | installing and wiring this package **into an application** |

The last one has a different audience: it travels with the package so that an
assistant working in the application that runs `go get` has the wiring, the
input contract and the meaning of each outcome in front of it. Its frontmatter
says so, under `metadata`, with `audience: app`, which is what
`aru skills:sync` reads; no other skill here carries it.

`emrtd-vault-notes` fires on a condition: it applies only when `MOC-arandu.md`,
`plans/cmd/audit-vault/` and `45-modules/` are actually beside this checkout.

## Why these exist

The common failure modes are a check that passes what it could not compute
(a Brainpool signature reported valid), a boolean or a verdict in the Report,
a parser that trusts a length, a fixture copied from a real document, and an
Active Authentication accepted with a challenge the device echoed back. None
belongs here.
