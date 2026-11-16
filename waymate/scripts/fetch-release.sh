#!/usr/bin/env bash
# fetch-release.sh VERSION downloads a WAYMATE release (a tag such as
# waymate-v0.1.0) from GitHub to the laptop, into ~/.waymate/releases/VERSION,
# and checks its SHA256SUMS. The playbook pushes it from there, so the VM
# never downloads from abroad. A release is about 190 MB; in Iran, use a VPN.
set -euo pipefail
version="$1"
dir="${WAYMATE_HOME:-$HOME/.waymate}/releases/$version"
mkdir -p "$dir"
gh release download "$version" --repo alakiani/ways --dir "$dir" --skip-existing
cd "$dir"
if command -v sha256sum >/dev/null 2>&1; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi
echo "release $version is in $dir"
