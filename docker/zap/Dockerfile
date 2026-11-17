# ZAP stable 2.17.0 plus the beta scan rule add-ons (not bundled in the stable image).
# Versions, URLs and SHA-256 come from the ZAP marketplace manifest (zaproxy/zap-admin ZapVersions-2.17.xml), verified 2026-11-17.
# Alpha rule packs are NOT installed: alpha means experimental and unstable by ZAP's own definition.
FROM docker.io/zaproxy/zap-stable:2.17.0@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af

ARG PSCANRULES_BETA_VERSION=50
ARG PSCANRULES_BETA_SHA256=a979f7cd5d8be10e0338b417e006ec1e2f6ec79101010d570ddb5199892e921b
ARG ASCANRULES_BETA_VERSION=67
ARG ASCANRULES_BETA_SHA256=81e84d592b1f7ad803470bcc8d8b659d4f7e21370546a482b606207e57a7db69

USER root
RUN set -eu \
 && base=https://github.com/zaproxy/zap-extensions/releases/download \
 && curl -fsSL -o /zap/plugin/pscanrulesBeta-beta-${PSCANRULES_BETA_VERSION}.zap \
      "${base}/pscanrulesBeta-v${PSCANRULES_BETA_VERSION}/pscanrulesBeta-beta-${PSCANRULES_BETA_VERSION}.zap" \
 && echo "${PSCANRULES_BETA_SHA256}  /zap/plugin/pscanrulesBeta-beta-${PSCANRULES_BETA_VERSION}.zap" | sha256sum -c - \
 && curl -fsSL -o /zap/plugin/ascanrulesBeta-beta-${ASCANRULES_BETA_VERSION}.zap \
      "${base}/ascanrulesBeta-v${ASCANRULES_BETA_VERSION}/ascanrulesBeta-beta-${ASCANRULES_BETA_VERSION}.zap" \
 && echo "${ASCANRULES_BETA_SHA256}  /zap/plugin/ascanrulesBeta-beta-${ASCANRULES_BETA_VERSION}.zap" | sha256sum -c - \
 && chown zap:zap /zap/plugin/pscanrulesBeta-beta-*.zap /zap/plugin/ascanrulesBeta-beta-*.zap
USER zap
