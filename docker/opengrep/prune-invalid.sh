#!/bin/sh
# Build-time check: Opengrep aborts the whole run on a single rule it cannot parse, which would silently disable every
# rule of the language. For each language directory: scan a throw-away target, delete the rule files reported as
# "Rule parse error", repeat until clean, and record the exclusions in <rules dir>/EXCLUDED (reviewed in docs/RULES.md).
# usage: prune-invalid.sh <rules dir>
set -eu
RULES="$1"
TARGET="$(mktemp -d)"
echo 'placeholder' > "$TARGET/placeholder.txt"
: > "$RULES/EXCLUDED"
for dir in "$RULES"/*/; do
  lang="$(basename "$dir")"
  round=0
  while [ "$round" -lt 25 ]; do
    round=$((round + 1))
    out="$(mktemp)"
    (cd "$TARGET" && opengrep scan --config "$dir" --json --quiet . > "$out" 2>/dev/null) || true
    ids="$(grep -o '"type": *"Rule parse error", *"rule_id": *"[^"]*"' "$out" | sed 's/.*"rule_id": *"//; s/"$//' | sort -u)"
    rm -f "$out"
    [ -n "$ids" ] || break
    for id in $ids; do
      short="${id##*.}"
      # The reported id is <directory path>.<rule id>; the rule id is the part after the last directory segment.
      rule="${id#opt.labsec.rules."${lang}".}"
      file="$(grep -rlE "^[[:space:]-]*id:[[:space:]]*['\"]?${short}['\"]?[[:space:]]*$" "$dir" 2>/dev/null | head -n 1 || true)"
      if [ -n "$file" ]; then
        echo "${file#"$RULES"/} ${rule}" >> "$RULES/EXCLUDED"
        rm -f "$file"
      else
        echo "cannot locate the file of rule ${id}" >&2
        exit 1
      fi
    done
  done
  [ "$round" -lt 25 ] || { echo "prune-invalid: ${lang} did not converge" >&2; exit 1; }
done
rm -rf "$TARGET"
