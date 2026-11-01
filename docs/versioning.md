# Version policy

KONE separates automatic development prereleases from reviewed stable tags. Builds record a calculated version; automation never commits a version bump back to `master`.

## Decide the next stable version

Use Conventional Commit PR titles so merge/squash messages preserve the change type:

| Change since the preceding stable release | One cumulative bump |
| --- | --- |
| `fix:`, or maintenance without a feature/breaking change | Patch: `0.4.0` → `0.4.1` |
| At least one `feat:` | Minor: `0.4.0` → `0.5.0` |
| `!` in the type or a `BREAKING CHANGE:` / `BREAKING-CHANGE:` footer, while 0.x | Minor: `0.4.0` → `0.5.0` |
| The same breaking declaration, after 1.0 | Major: `1.4.0` → `2.0.0` |

The highest level across the entire unreleased first-parent range wins once. Several feature merges before a stable release still propose one minor bump. Standard merge commits use the Conventional Commit title retained in their body; squash commits use their own title. PR title validation runs with quality checks.

`VERSION` contains a pending minimum version, initially `0.4.0`. It is a floor, not an already-published stable baseline. This bootstraps the revived project despite old non-SemVer tags such as `v0.1`. After publishing `v0.4.0`, normal calculation proposes `0.4.1` or `0.5.0` from the subsequent changes. Only canonical `vMAJOR.MINOR.PATCH` tags on strict ancestors of the source SHA count as stable baselines; a tag at the source itself is excluded so automation can validate that very tag. Unrelated branch tags do not affect the calculation.

An exceptional reviewed override can be recorded as `Release-As: 0.8.0` in the commit message. It is immutable source history rather than a mutable GitHub label. A commit may contain only one such footer, and it cannot lower the calculated version; earlier overrides remain a minimum until subsequent changes exceed them. Normal releases need no override.

## Development identity and retries

For each first-parent commit added to master, automation derives:

```text
version: 0.5.0-dev.20261101.87.g0123456789ab
tag:    v0.5.0-dev.20261101.87.g0123456789ab
```

The date is the commit's UTC date, `87` is its first-parent count, and the suffix identifies its SHA. Several merges on one day get different identities. A batched push qualifies every first-parent SHA separately. Commit time/history make a fresh calculation deterministic; the workflow needs full history and tags.

Once published, the version context in `release.json` is reused for that SHA's development retries. Adding an ancestor stable tag cannot rename an existing development release. A source with no published release may be recalculated against current stable refs. Public assets remain immutable; only automation-owned unpublished drafts may be repaired.

Stable publication is a new final-version build: its suggested tag is calculated against the current ancestral stable tags, even when the preceding development release used an older baseline. Recheck the suggested tag when another stable release has been published meanwhile; freezing development identity does not reserve a future stable version.

Read-only local inspection:

```sh
just ci release-version json
just ci release-version next-tag HEAD
```

Local daily build/package tasks use the same calculated development version unless explicitly supplied a version for a controlled build. They never publish or qualify a release.

## Publish a stable tag

1. Review a published development release and its exact full master SHA.
2. Inspect that SHA's suggested next tag, then create and push that exact canonical tag (for example `v0.5.0`). Creating a stable tag is a deliberate maintainer action, not an automatic side effect of merging a PR.
3. The tag workflow verifies master ancestry, the calculated version and complete published development evidence, then rebuilds the exact source with the final version and repeats all CI gates before publishing stable assets.

Development binaries are never renamed into a stable release. A tag at a different SHA or an unexpected version fails validation. Old source revisions whose workflow does not yet handle tag pushes can instead use **Verified releases → Run workflow → master → stable**, with the same full SHA/tag checks. Signing, native hardware acceptance, withdrawal and rollback boundaries are described in [verified releases](releases.md).
