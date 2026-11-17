#!/bin/sh
# Prints "<release asset> <expected SHA-256>" for the CPU architecture the image is being built for.
# Opengrep ships a separate static binary per architecture, each pinned by its own checksum (docs/VERSIONS.md).
# usage: select-asset.sh <sha256 of opengrep_linux_x86> <sha256 of opengrep_linux_aarch64>
set -eu
case "$(uname -m)" in
  x86_64 | amd64) echo "opengrep_linux_x86 $1" ;;
  aarch64 | arm64) echo "opengrep_linux_aarch64 $2" ;;
  *) echo "select-asset: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
