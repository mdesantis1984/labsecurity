# Opengrep v2.0.0 (released 2026-11-13). The binary's Sigstore signature was verified on 2026-11-17 with
# cosign v3.0.2 verify-blob (identity: github.com/opengrep/opengrep/.github/workflows/*,
# issuer: token.actions.githubusercontent.com). The x86 SHA-256 below pins that verified artifact. The aarch64 binary
# (Apple Silicon, Linux arm64) is pinned by the SHA-256 GitHub reports for the release asset, checked on 2026-11-17
# against a fresh download; its Sigstore signature was not verified (docs/VERSIONS.md).
FROM docker.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

ARG OPENGREP_VERSION=v2.0.0
ARG OPENGREP_SHA256_X86=37e93f4da5fd04a18c5c1febbdd12f7e98dfccd4d0c9cf2593bcb25eeb462da0
ARG OPENGREP_SHA256_AARCH64=6257b65423a744b704af2ff9beeb8f222c2f6925236af386b56b031d4c06d6d8

# Community rules, vendored at build time from a pinned commit (git verifies the commit hash).
# Only rule files under a `security/` directory of the supported languages are kept; test targets are dropped.
# The repository ships under the Commons Clause License Condition: fine for this self-hosted, non-resold lab.
ARG OPENGREP_RULES_COMMIT=f1d2b562b414783763fd02a6ed2736eaed622efa
ARG RULE_LANGS="csharp typescript javascript python go java kotlin php ruby dockerfile"
# Extra packs, pinned by commit (verified 2026-11-17):
#  - GitLab sast-rules, repository MIT (rules/gitlab, under the GitLab EE license, is NOT vendored; rules/lgpl* are LGPL-3.0).
#  - Trail of Bits semgrep-rules, AGPL-3.0, internal use only. Not vendored: semgrep/semgrep-rules (Semgrep Rules License).
ARG GITLAB_SAST_RULES_COMMIT=83144bd2ec7d3200cda96347fa923f81c8ad8413
ARG TRAILOFBITS_RULES_COMMIT=31390b3a99c04c81522d1b37c8d1900aa2dd4094

COPY select-asset.sh /usr/local/bin/
RUN set -eu \
 && apk add --no-cache ca-certificates curl git libstdc++ gcompat \
 && set -- $(select-asset.sh "${OPENGREP_SHA256_X86}" "${OPENGREP_SHA256_AARCH64}") \
 && curl -fsSL -o /usr/local/bin/opengrep \
      "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/$1" \
 && echo "$2  /usr/local/bin/opengrep" | sha256sum -c - \
 && chmod 0755 /usr/local/bin/opengrep \
 && adduser -D -u 10001 scanner

RUN set -eu \
 && git init -q /tmp/rules-src \
 && git -C /tmp/rules-src fetch -q --depth 1 https://github.com/opengrep/opengrep-rules.git "${OPENGREP_RULES_COMMIT}" \
 && git -C /tmp/rules-src checkout -q FETCH_HEAD \
 && test "$(git -C /tmp/rules-src rev-parse HEAD)" = "${OPENGREP_RULES_COMMIT}" \
 && mkdir -p /opt/labsec/rules \
 && cd /tmp/rules-src \
 && for lang in ${RULE_LANGS}; do \
      find "${lang}" -type f \( -name '*.yaml' -o -name '*.yml' \) -path '*/security/*' | while read -r f; do \
        if grep -q '^rules:' "$f"; then mkdir -p "/opt/labsec/rules/$(dirname "$f")" && cp "$f" "/opt/labsec/rules/$f"; fi; \
      done; \
    done \
 && cp LICENSE /opt/labsec/rules/LICENSE \
 && echo "${OPENGREP_RULES_COMMIT}" > /opt/labsec/rules/COMMIT \
 && cd / && rm -rf /tmp/rules-src \
 && chmod -R a+rX /opt/labsec

COPY vendor-packs.sh prune-invalid.sh /usr/local/bin/
RUN set -eu \
 && fetch() { git init -q "$1" && git -C "$1" fetch -q --depth 1 "$2" "$3" && git -C "$1" checkout -q FETCH_HEAD \
      && test "$(git -C "$1" rev-parse HEAD)" = "$3"; } \
 && fetch /tmp/gl https://gitlab.com/gitlab-org/security-products/sast-rules.git "${GITLAB_SAST_RULES_COMMIT}" \
 && fetch /tmp/tob https://github.com/trailofbits/semgrep-rules.git "${TRAILOFBITS_RULES_COMMIT}" \
 && vendor-packs.sh /tmp/gl /tmp/tob /opt/labsec/rules \
 && mkdir -p /opt/labsec/licenses \
 && cp /tmp/gl/LICENSE /opt/labsec/licenses/gitlab-sast-rules.LICENSE \
 && cp /tmp/gl/rules/lgpl/LICENSE /opt/labsec/licenses/gitlab-sast-rules-lgpl.LICENSE \
 && cp /tmp/tob/LICENSE /opt/labsec/licenses/trailofbits-semgrep-rules.LICENSE \
 && printf 'gitlab-sast-rules %s\ntrailofbits-semgrep-rules %s\n' "${GITLAB_SAST_RULES_COMMIT}" "${TRAILOFBITS_RULES_COMMIT}" > /opt/labsec/rules/PACKS \
 && cd / && rm -rf /tmp/gl /tmp/tob \
 && prune-invalid.sh /opt/labsec/rules \
 && chmod -R a+rX /opt/labsec

USER scanner
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/opengrep"]
