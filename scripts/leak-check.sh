#!/usr/bin/env bash
# Refuse private words in the tree (AGENTS.md, "Keep the repository
# generic"). The list itself is private: one term per line, matched
# case-insensitively as whole words, # comments; default
# ../homelab/private-terms, or $ARTOO_PRIVATE_TERMS. Without a list the
# check is skipped (a fresh clone has none). Tracked and untracked
# non-ignored files are checked, so it also runs before the first commit.
#
# Usage: scripts/leak-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
terms=${ARTOO_PRIVATE_TERMS:-../homelab/private-terms}
if [[ ! -f $terms ]]; then
  echo "leak-check: no term list at $terms — skipped"
  exit 0
fi
list=$(mktemp)
trap 'rm -f "$list"' EXIT
grep -v '^[[:space:]]*#' "$terms" | sed '/^[[:space:]]*$/d' > "$list"
if git rev-parse --git-dir >/dev/null 2>&1; then
  files=$(git ls-files --cached --others --exclude-standard)
else
  files=$(find . -type f -not -path './.zig-cache/*' -not -path './zig-out/*' -not -path './.git/*')
fi
[[ -n $files ]] || { echo "leak-check: no files"; exit 0; }
# Only files that exist (a tracked file may be deleted in the worktree);
# hits are judged by output, not by grep's exit status.
# shellcheck disable=SC2086
files=$(for f in $files; do if [[ -f $f ]]; then printf '%s\n' "$f"; fi; done)
hits=$(printf '%s\n' $files | tr '\n' '\0' | xargs -0 grep -nIiwF -f "$list" -- || true)
if [[ -n $hits ]]; then
  echo "leak-check: private terms found:" >&2
  printf '%s\n' "$hits" >&2
  exit 1
fi
echo "leak-check: clean ($(wc -l < "$list" | tr -d ' ') terms, $(printf '%s\n' $files | wc -l | tr -d ' ') files)"
