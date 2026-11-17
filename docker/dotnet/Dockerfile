# Digest re-verified 2026-11-17 against mcr.microsoft.com (the tag was re-pushed; the earlier digest no longer resolves).
# .NET SDK 10.0.404 with SonarScanner for .NET 12.1.0 and three extra Roslyn analyzer packages.
# Pass 1 (security SARIF for DefectDojo): the SDK's built-in analyzers (CA2100, CA23xx, CA3xxx, CA5xxx) and
# SecurityCodeScan.VS2019. Pass 2 (quality, SonarQube external issues): AnalysisMode=All, Meziantou.Analyzer, Roslynator.Analyzers.
FROM mcr.microsoft.com/dotnet/sdk:10.0.404@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1 \
    PATH="${PATH}:/opt/dotnet-tools"

# Installed outside /root so the container can run as the invoking host user (no root-owned files in the work copy).
RUN dotnet tool install --tool-path /opt/dotnet-tools dotnet-sonarscanner --version 12.1.0 \
 && chmod -R a+rX /opt/dotnet-tools

# Analyzer packages: fetched at build time from api.nuget.org and pinned by version AND SHA-256 (verified 2026-11-17).
# They form a local NuGet feed, so a pass never downloads analyzers at scan time.
#   Meziantou.Analyzer 3.0.341        MIT
#   Roslynator.Analyzers 5.0.1        Apache-2.0
#   SecurityCodeScan.VS2019 5.6.7     LGPL-3.0-or-later (unmaintained since 2022; kept only while it loads and fires on .NET 10)
ARG MEZIANTOU_SHA256=094d584a2eda0a6240b687fe4418008d21a1ca0fdd3be44f943f1d301c86d5e7
ARG ROSLYNATOR_SHA256=c34f0658e9219bcf615a70215be64bb9333ecfbfb6c60dd8cc7ef7be50edf580
ARG SCS_SHA256=2f81fefee60123b03dfc4d00328f7ae9967d98bd8dd4277ef7221d312a9eb08d
RUN set -eu \
 && mkdir -p /opt/labsec/nuget-feed \
 && cd /opt/labsec/nuget-feed \
 && curl -fsSL -o meziantou.analyzer.3.0.341.nupkg "https://api.nuget.org/v3-flatcontainer/meziantou.analyzer/3.0.341/meziantou.analyzer.3.0.341.nupkg" \
 && curl -fsSL -o roslynator.analyzers.5.0.1.nupkg "https://api.nuget.org/v3-flatcontainer/roslynator.analyzers/5.0.1/roslynator.analyzers.5.0.1.nupkg" \
 && curl -fsSL -o securitycodescan.vs2019.5.6.7.nupkg "https://api.nuget.org/v3-flatcontainer/securitycodescan.vs2019/5.6.7/securitycodescan.vs2019.5.6.7.nupkg" \
 && printf '%s  %s\n' "${MEZIANTOU_SHA256}" meziantou.analyzer.3.0.341.nupkg "${ROSLYNATOR_SHA256}" roslynator.analyzers.5.0.1.nupkg "${SCS_SHA256}" securitycodescan.vs2019.5.6.7.nupkg | sha256sum -c - \
 && chmod -R a+rX /opt/labsec

COPY labsec.globalconfig labsec.targets labsec-quality.targets /opt/labsec/
RUN chmod a+r /opt/labsec/*
WORKDIR /work
