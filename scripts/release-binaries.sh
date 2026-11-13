#!/bin/sh
# Release archives for artoo (AGENTS.md, Git): one ReleaseSafe binary per
# target, packed as artoo-<version>-<target>.tar.gz with LICENSE and
# README.md, plus SHA256SUMS. Used by .github/workflows/release.yml on a
# pushed v* tag, and by hand for a release made before the workflow.
#
#   scripts/release-binaries.sh DIST_DIR
#
# Run from a checkout of the tag. artoo links no libc, so every target is
# cross-compiled from one machine. The version is the annotated release
# tag at HEAD (docs/RELEASING.md §1); anything else is refused.
set -eu

dist=${1:?usage: release-binaries.sh DIST_DIR}
targets="aarch64-macos x86_64-macos x86_64-linux aarch64-linux"

tag=$(git describe --exact-match --match 'v[0-9]*' HEAD 2>/dev/null) || {
	echo "release-binaries: HEAD is not at an annotated release tag v*" >&2
	exit 2
}
version=${tag#v}

mkdir -p "$dist"
dist=$(cd "$dist" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for t in $targets; do
	zig build -Doptimize=ReleaseSafe -Dtarget="$t" --prefix "$work/$t"
	name="artoo-$version-$t"
	mkdir "$work/$name"
	cp "$work/$t/bin/artoo" LICENSE README.md "$work/$name/"
	tar -C "$work" -czf "$dist/$name.tar.gz" "$name"
done

(cd "$dist" && shasum -a 256 artoo-"$version"-*.tar.gz > SHA256SUMS)
echo "release-binaries: $version → $dist"
cat "$dist/SHA256SUMS"
