# Releasing artoo

The one procedure for versions and releases. Any agent or person who
commits to artoo follows it exactly; [AGENTS.md](../AGENTS.md) defers to
this file.

## 1. Version rules

- [SemVer 2.0.0](https://semver.org). `build.zig.zon` `.version` is the
  single source of `artoo --version`; nothing else states the current
  version.
- For a CLI the public API is what scripts and agents rely on: command
  and flag names, exit codes, `-o json` fields, config keys and their
  meaning.
- **`main` always carries the next version with `-dev`**: after `0.1.0`
  is released, `main` says `0.2.0-dev`. A `-dev` build reports its
  commit as build metadata (`0.2.0-dev+b75b55c`, from `build.zig`); a
  release build reports the plain version.
- A version without `-dev` exists only in the commit that is tagged.

### Which number moves

Decided from the Conventional Commits since the last tag:

| Since the last release | Before 1.0.0 (now) | From 1.0.0 |
| --- | --- | --- |
| Something breaks: a command or flag renamed or removed, an exit code's meaning changed, a `-o json` field removed or renamed, a config change that needs `config init` again (commit marked `feat!:`/`fix!:` or with a `BREAKING CHANGE:` footer) | MINOR (`0.3.0` → `0.4.0`) | MAJOR |
| Something new, nothing breaks: a command, flag, JSON field, config key, VM role (`feat:`) | MINOR | MINOR |
| Fixes only (`fix:`, `perf:`; `docs:`, `test:`, `refactor:`, `ci:`, `chore:` alone never require a release) | PATCH (`0.3.0` → `0.3.1`) | PATCH |

The next `-dev` on `main` always assumes a MINOR (`0.3.0-dev` after
`0.2.0`); if the release turns out to be a PATCH, the release commit
sets `0.2.1` instead. 1.0.0 is released when the command set and
`-o json` are meant to stay stable; that decision is the operator's.

The config file's and `-o json`'s `schema_version` are separate
counters, raised only with a breaking format change — which is also a
breaking release above.

### Pre-releases

When a release needs a live soak first: `X.Y.Z-rc.N` (`0.4.0-rc.1`,
`-rc.2`, …), released exactly like a release (§3) from a commit that
sets that version. The workflow marks any tag with a `-` as a GitHub
pre-release. The final `X.Y.Z` follows from a new release commit.

## 2. Who

- **A release happens only on the operator's explicit "release"** for a
  named version (or "release" with the version left to these rules —
  then state the chosen version and why before starting).
- Agents prepare the pull requests, push the tag after the release pull
  request is merged, and verify. Merging is the operator's unless they
  said "merge" for that pull request.
- Releases are cut from `main` only. There are no release branches;
  fixes go to `main` and ship in the next PATCH.

## 3. Steps

For version `X.Y.Z` (example `0.2.0`), with `main` green and current:

1. **Release pull request.** Branch `chore/release-X.Y.Z` from `main`.
   One commit `chore(release): X.Y.Z` that changes only
   `build.zig.zon` `.version` from `X.Y.Z-dev` (or the next `-dev`) to
   `X.Y.Z`. `make test` passes. Open the pull request with the title
   `chore(release): X.Y.Z`; the body lists the notable changes since the
   last tag (`git log vPREV..main --oneline`) and the reason for the
   bump (§1). CI must pass.
2. **Merge** (operator, rebase-merge), then update the local `main`.
3. **Tag** the merged release commit on `main` — annotated, never
   lightweight, never on another commit:

   ```console
   git switch main && git pull --ff-only
   grep '\.version' build.zig.zon          # must say "X.Y.Z"
   git tag -a vX.Y.Z -m "artoo X.Y.Z"
   git push origin vX.Y.Z
   ```

4. **The workflow** `.github/workflows/release.yml` runs on the tag: it
   refuses a tag that does not match `build.zig.zon`, runs the checks,
   builds the archives (`scripts/release-binaries.sh`) and creates the
   GitHub release `artoo X.Y.Z` with notes generated from the commits.
   Watch it: `gh run watch`.
5. **Verify** the release before announcing it:

   ```console
   gh release view vX.Y.Z --json assets --jq '.assets[].name'
   ```

   Exactly five assets: `artoo-X.Y.Z-aarch64-macos.tar.gz`,
   `-x86_64-macos`, `-aarch64-linux`, `-x86_64-linux` and `SHA256SUMS`.
   Download one archive and `SHA256SUMS` into an empty directory,
   `shasum -a 256 -c --ignore-missing SHA256SUMS`, unpack, and check that
   `artoo --version` prints `artoo X.Y.Z`.
6. **Back to `-dev`.** Branch `chore/X.Y+1.0-dev`, one commit
   `chore: X.Y+1.0-dev` setting `.version` to the next MINOR with `-dev`
   (`0.3.0-dev`), pull request, merge. `main` is never left on a plain
   release version.
7. **Install** the release on the operator's workstation (`make install`
   on the tag, or the archive) only if they ask.

## 4. When something goes wrong

- **A pushed tag is never moved, deleted or re-pushed**, and a published
  release is never replaced. If the release is wrong, fix it on `main`
  and release the next PATCH.
- The workflow fails before creating the release (tag mismatch, failing
  checks): delete nothing; fix on `main` and release the next PATCH. A
  transient failure (runner, network) may be re-run with
  `gh run rerun --failed`; the upload step is idempotent (`--clobber`).
- An asset is missing or broken: re-run the workflow for that tag; if
  the archives themselves are wrong, release the next PATCH.

## 5. No changelog file

Release notes come from the Conventional Commits, so commit messages are
written for the release notes: one line, imperative, scoped where it
helps (`feat(watch): …`, `fix(vm): …`).
