# Releasing artoo

The one procedure for versions and releases. Any agent or person who
commits to artoo follows it exactly; [AGENTS.md](../AGENTS.md) defers to
this file.

## 1. Version rules

- [SemVer 2.0.0](https://semver.org). **The annotated tag `vX.Y.Z` on
  `main` is the single source of a release's version.** No file states
  it and no commit bumps it: `build.zig` derives `artoo --version` from
  the nearest release tag with `git describe` (`src/version_tag.zig`).
  `build.zig.zon` `.version` stays `0.0.0`, a field Zig requires.
- For a CLI the public API is what scripts and agents rely on: command
  and flag names, exit codes, `-o json` fields, config keys and their
  meaning.
- What a build reports:

  | Built from | `artoo --version` |
  | --- | --- |
  | the tagged commit `v0.7.0` | `0.7.0` |
  | 5 commits after `v0.6.0` | `0.7.0-dev.5+abc1234` (the next MINOR) |
  | 3 commits after `v0.7.0-rc.1` | `0.7.0-rc.1.dev.3+abc1234` |
  | a tree without Git history | `0.0.0-unknown`, or `-Dversion=X.Y.Z` |

  SemVer orders every dev build after the release before it and before
  the next one, so `artoo update` treats it correctly (SPEC §18).
- CI and the release workflow check out full history (`fetch-depth: 0`)
  so the tags are there.

### Which number moves

Decided from the Conventional Commits since the last tag:

| Since the last release | Before 1.0.0 (now) | From 1.0.0 |
| --- | --- | --- |
| Something breaks: a command or flag renamed or removed, an exit code's meaning changed, a `-o json` field removed or renamed, a config change that needs `config init` again (commit marked `feat!:`/`fix!:` or with a `BREAKING CHANGE:` footer) | MINOR (`0.3.0` → `0.4.0`) | MAJOR |
| Something new, nothing breaks: a command, flag, JSON field, config key, VM role (`feat:`) | MINOR | MINOR |
| Fixes only (`fix:`, `perf:`; `docs:`, `test:`, `refactor:`, `ci:`, `chore:` alone never require a release) | PATCH (`0.3.0` → `0.3.1`) | PATCH |

Dev builds always assume a MINOR (`0.3.0-dev.N` after `0.2.0`); if the
release turns out to be a PATCH, the tag simply says `v0.2.1`. 1.0.0 is released when the command set and
`-o json` are meant to stay stable; that decision is the operator's.

The config file's and `-o json`'s `schema_version` are separate
counters, raised only with a breaking format change — which is also a
breaking release above.

### Pre-releases

When a release needs a live soak first: `X.Y.Z-rc.N` (`0.4.0-rc.1`,
`-rc.2`, …), released exactly like a release (§3) with that tag. The
workflow marks any tag with a `-` as a GitHub pre-release. The final
`X.Y.Z` is a new tag, on the same commit or a later one.

## 2. Who

- **A release happens only on the operator's explicit "release"** for a
  named version (or "release" with the version left to these rules —
  then state the chosen version and why before starting).
- Agents choose the version by §1, push the tag and verify. There is no
  release pull request: what is released is `main` as merged.
- Releases are cut from `main` only. There are no release branches;
  fixes go to `main` and ship in the next PATCH.

## 3. Steps

For version `X.Y.Z` (example `0.7.0`):

1. **Check `main`.** It is green (every change reached it through a pull
   request whose CI passed) and current; `make test` passes on it. List
   the changes and confirm the bump (§1):

   ```console
   git switch main && git pull --ff-only
   git log "$(git describe --abbrev=0 --match 'v[0-9]*')"..HEAD --oneline
   make test
   ```

2. **Tag** `main`'s HEAD — annotated, never lightweight (`git describe`
   and the workflow ignore lightweight tags), never another commit:

   ```console
   git tag -a vX.Y.Z -m "artoo X.Y.Z"
   zig build && ./zig-out/bin/artoo --version   # must say "artoo X.Y.Z"
   git push origin vX.Y.Z
   ```

3. **The workflow** `.github/workflows/release.yml` runs on the tag: it
   refuses a tag that is not annotated or not on `main`, runs the
   checks, builds the archives (`scripts/release-binaries.sh`), refuses
   a build whose `--version` is not the tag, and creates the GitHub
   release `artoo X.Y.Z` with notes generated from the commits. Watch
   it: `gh run watch`.
4. **Verify** the release before announcing it:

   ```console
   gh release view vX.Y.Z --json assets --jq '.assets[].name'
   ```

   Exactly five assets: `artoo-X.Y.Z-aarch64-macos.tar.gz`,
   `-x86_64-macos`, `-aarch64-linux`, `-x86_64-linux` and `SHA256SUMS`.
   Download one archive and `SHA256SUMS` into an empty directory,
   `shasum -a 256 -c --ignore-missing SHA256SUMS`, unpack, and check that
   `artoo --version` prints `artoo X.Y.Z`.
5. **Install** the release on the operator's workstation (`make install`
   on the tag, or the archive) only if they ask.

Nothing follows on `main`: its next build reports the next dev version
by itself.

## 4. When something goes wrong

- **A pushed tag is never moved, deleted or re-pushed**, and a published
  release is never replaced. If the release is wrong, fix it on `main`
  and release the next PATCH.
- The workflow fails before creating the release (a lightweight tag, a
  tag off `main`, failing checks, a version mismatch): delete nothing;
  fix on `main` and release the next PATCH. A
  transient failure (runner, network) may be re-run with
  `gh run rerun --failed`; the upload step is idempotent (`--clobber`).
- An asset is missing or broken: re-run the workflow for that tag; if
  the archives themselves are wrong, release the next PATCH.

## 5. No changelog file

Release notes come from the Conventional Commits, so commit messages are
written for the release notes: one line, imperative, scoped where it
helps (`feat(watch): …`, `fix(vm): …`).
