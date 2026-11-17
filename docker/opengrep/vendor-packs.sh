#!/bin/sh
# Copies the rule files of the extra packs into the per-language layout the scan loads:
#   <dest>/<language>/x-<pack>/...   (language names are LabSecurity's: csharp, javascript, python, ...)
# usage: vendor-packs.sh <gitlab-sast-rules checkout> <trailofbits semgrep-rules checkout> <dest>
set -eu
GL="$1"; TOB="$2"; DEST="$3"

# Copy every YAML file that defines rules (test targets and mapping files are dropped).
copy_rules() { # <source dir> <destination dir>
  [ -d "$1" ] || return 0
  find "$1" -type f \( -name '*.yml' -o -name '*.yaml' \) | while read -r f; do
    grep -q '^rules:' "$f" || continue
    rel="${f#"$1"/}"
    mkdir -p "$2/$(dirname "$rel")"
    cp "$f" "$2/$rel"
  done
}

# GitLab sast-rules: the repository is MIT, except rules/gitlab (GitLab EE license, NOT vendored). Rules in
# rules/lgpl* come from LGPL-3.0 sources; lgpl-cc adds the Commons Clause (no selling): fine for an internal lab.
for lang in csharp go java javascript python; do
  copy_rules "$GL/$lang" "$DEST/$lang/x-gitlab-sast-rules/mit"
done
for kind in lgpl lgpl-cc; do
  for lang in java javascript kotlin php python ruby; do
    copy_rules "$GL/rules/$kind/$lang" "$DEST/$lang/x-gitlab-sast-rules/$kind"
  done
done

# Trail of Bits semgrep-rules (AGPL-3.0: internal use only; nothing here is redistributed or offered as a service).
for pair in go:go javascript:javascript python:python ruby:ruby jvm:java jvm:kotlin hcl:terraform; do
  copy_rules "$TOB/${pair%%:*}" "$DEST/${pair##*:}/x-trailofbits-semgrep-rules"
done
