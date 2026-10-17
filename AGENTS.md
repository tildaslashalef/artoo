# AGENTS.md

## Purpose

This repository develops **`artoo`**, a native Zig 0.17 CLI that manages a
home lab: a Proxmox VE host, a UniFi gateway (Integration API) and a
Cloudflare zone — guests, names, an edge VM, a subnet router and a
watchdog.

| Document | Owns |
| --- | --- |
| [docs/SPEC.md](docs/SPEC.md) | artoo's approved design (commands, output, secrets, transport, mutation pipeline, testing) and the API facts the code depends on (§17). Read completely before CLI design or implementation work. |
| [docs/GUIDE.md](docs/GUIDE.md) | How an agent operates a lab with artoo and SSH: approvals, prerequisites, commands by task, credentials, troubleshooting. |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | From zero to a first guest: Proxmox and UniFi prerequisites, configuration, credentials. |
| [docs/RELEASING.md](docs/RELEASING.md) | Version rules and the release procedure. Follow it exactly. |

If `AGENTS.local.md` exists (gitignored), read it first: it points to the
operator's private lab record — the approval boundary, the work queue and
hand-off, the lab's own facts. Facts live with their owner document; Git
history holds chronology — do not create dated duplicate reports.

## Keep the repository generic

artoo is public. Nothing about a particular lab enters this repository:
no host or guest names of a real lab, LAN addresses beyond the documented
examples, domains, user names, device models, photos, plans or live-run
diaries. Examples use `pve` / `pve.home.arpa` / `192.168.1.10` for the
host, `192.168.1.1` for the gateway, `example.com` / `lab.example.com`,
and curated guest names (`bespin` edge, `scarif` watchdog, `dagobah`
router, `naboo`, `hoth`). A lab's own values belong in
`~/.artoo/config.json`, never in defaults, tests or docs.
`make leak-check` (part of `make test`) refuses the private words listed
in `../homelab/private-terms` (or `$ARTOO_PRIVATE_TERMS`) when that list
exists.

## Working on a live lab

- Operating the Proxmox host or the gateway — with artoo or SSH — follows
  [docs/GUIDE.md](docs/GUIDE.md). Every live mutation needs the operator's
  explicit approval of a concrete plan (target, current state, intended
  change, impact, rollback, validation). No task, checkbox or CLI feature
  authorizes a change by itself.
- Use the **installed** binary (`~/.local/bin/artoo`) against the live lab;
  after code changes run `make install` first.

## Zig implementation rules

- Zig 0.17.0; verify compiler and stdlib facts against the installed lib
  (`lib/std` of the Zig installation) and `doc/langref.html` before writing
  code that uses them. Never trust memory of pre-0.17/I/O-rework APIs.
- Zero third-party Zig packages for v1; stdlib only. The sanctioned escape
  hatch is a libcurl adapter only if the TLS spike fails — never shell out with
  secrets.
- Every public function takes explicit `Allocator` (+ `Io`); no globals; one
  arena per invocation for parsed data. No `catch unreachable`, no panics on
  command paths; `errdefer` for acquired resources.
- Per-module error sets mapped to exit codes only in `main`. Command registry
  is a comptime table that also generates help, so help cannot drift.
- API work starts from the official documents (SPEC §17): the UniFi
  OpenAPI export and the Proxmox schema (`apidoc.js`), kept outside this
  repository in `../homelab/api/` (vendor files; tests that need them skip
  without them). `artoo gw spec` must stay drift-free.
- Build: `zig build`, `zig build test` (offline unit/behavior tests, colocated
  `test` blocks) and `zig fmt --check build.zig src` must pass before
  **every** commit; Linux cross-builds (`-Dtarget=x86_64-linux`,
  `aarch64-linux`) must compile — `make test` runs all of it plus the leak
  check. Live runs follow SPEC §13: scripts in `scripts/live/` (host from
  `PVE_SSH`), disposable ledger-owned resources (`~/.artoo/live-ledger.txt`),
  abort on the first failed guard. Generated binaries and caches stay
  ignored; VM disks, ISOs, captures and disposable inputs never enter the
  repository.

## Mutation safety (applies to every CLI domain)

- Never silently mutate gateway or host state. Before a mutation: validate
  locally, build a redacted typed plan, render it, confirm, send once, track
  the outcome, verify intended state. Read-only commands never prompt.
- `-y`/`--yes` skips only the interactive prompt; never validation or planning.
  Non-interactive execution without `--yes` refuses. `--dry-run` sends no
  writes and never claims server acceptance.
- Bulk deletion, forced deletion, firewall/network changes, and generic
  mutating requests are high-impact; make their scope unmistakable.
- Deletion/rollback/forced stop additionally require explicit target
  acknowledgement (typed name, or `--confirm TARGET` non-interactively).
- Asynchronous operations are tracked by returned UPID with `exitstatus`
  checks and resource-state verification; `stopped` alone is not success.
  Never retry writes; an ambiguous timeout is reported as unknown.
- Redaction happens before data reaches logging or rendering; never offer a
  raw secret-bearing output mode.
- The Proxmox host and the gateway are never publicly exposed (SPEC §9.6):
  no public DNS record, tunnel, Funnel or edge route to them, by name or
  address — derived from the configuration (node, endpoints, SSH host,
  guest gateway, `guests.reserved_names`); artoo enforces it without an
  override. Services on the watchdog and the search gateway are never
  public either (SPEC §9.9).

## Credentials and TLS

- Secrets come only from artoo's `SecretStore` at request time (SPEC §6:
  macOS Keychain via `/usr/bin/security`; Linux Secret Service, or a 0600
  file on headless Linux), service `artoo`, accounts `pve`, `unifi`,
  `cloudflare`, `guest/<name>`.
- Never print, log, serialize, cache, persist, shell-interpolate, or include a
  secret in exception text; never accept one as an ordinary CLI option or
  environment variable.
- Verify TLS by default via the mkcert public root; no insecure mode.
- Configs hold non-secret settings only. `~/.artoo/config.json` for artoo.
- Never ask the operator for a password or to paste a secret into the
  session; secrets are entered by the operator into a hidden prompt or
  piped (never displayed).

## Git, branches and releases

- **`main` is always green and installable.** It changes only through pull
  requests whose CI (`.github/workflows/ci.yml`: macOS and Linux, `zig build
  test fmt cross`) passed; CI runs on pull requests only, not again on
  `main` after the merge.
- **Documentation-only changes go straight to `main`**: a change that
  touches only Markdown documents (`*.md`, `docs/`) — no code, build, CI,
  scripts, payload or embedded files — is committed directly on `main`
  and pushed, without a branch or pull request. The commit rules below
  still apply. A change that mixes docs with anything else follows the
  branch rules.
- **One branch per task group**, from current `main`: `feat/…`, `fix/…`,
  `refactor/…`, `docs/…`, `test/…`, `ci/…`, `chore/…` plus a short slug
  (`fix/cli-polish`). A group bundles related tasks with the same approval
  profile (offline, read-only live, or one approved live plan), so no
  task waits on another's approval; each task is its own verified
  commit. One branch → one pull request; a branch that depends on
  another starts after that one is merged.
- **Commits:** inspect `git status` and the staged diff before every commit
  and run the relevant checks first. Commit each coherent, verified unit
  immediately; one-line Conventional Commit messages. Do not amend, squash,
  rewrite or combine commits unless explicitly asked; never bypass hooks.
- **Pull requests** (`gh pr create`): title as a Conventional Commit;
  body — what and why, how it was verified (tests; live runs with their
  SPEC section and approval), what is pending. Rebased on `main` before
  merging; merged with **rebase-merge** (linear history, unit commits kept).
- **Who does what:** the agent may push its branches and open pull
  requests. Merging into `main`, tagging, releases, force-pushes and
  repository settings are the operator's — or the agent's only on an
  explicit "merge"/"release" for that pull request or version.
- **Versions and releases** follow [docs/RELEASING.md](docs/RELEASING.md)
  exactly: SemVer with `build.zig.zon` as the single source, `main` on
  the next `-dev`, which commit type bumps which number (0.y.z until
  1.0.0), the release and `-dev` pull requests, annotated `vX.Y.Z` tags
  on `main`, verifying the five release assets, and never moving a
  pushed tag. A release happens only on the operator's explicit
  "release". No CHANGELOG file: release notes come from the
  Conventional Commits.
- **Live runs** use the branch's installed build (`make install` on the
  branch) under the same approvals as always.
