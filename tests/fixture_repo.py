"""Builds a deliberately vulnerable git repository in a temp directory (test data only).

Planted problems: string-concatenated SQL (C#), Angular innerHTML, a fake high-entropy token that is
committed and then removed (so it only exists in history) and an outdated npm dependency with known CVEs.
One sample per rule source added later: weak crypto and insecure randomness (SDK analyzers, SecurityCodeScan, Meziantou),
ESLint security and Angular rules, Python deserialization / eval (GitLab sast-rules, Trail of Bits), connection-string,
appsettings and Keycloak credentials (custom Gitleaks rules) and a Dockerfile that runs as root (Trivy misconfig).
Nothing here is a real credential: every one is random text generated when the fixture is built, never a literal.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import string
import subprocess
from pathlib import Path

PROGRAM_VULNERABLE = """\
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;

var app = WebApplication.CreateBuilder(args).Build();

app.MapGet("/users", (HttpRequest request) =>
{
    var name = request.Query["name"].ToString();
    using var connection = new SqliteConnection("Data Source=:memory:");
    connection.Open();
    var command = connection.CreateCommand();
    command.CommandText = "SELECT id FROM users WHERE name = '" + name + "'";
    using var reader = command.ExecuteReader();
    return reader.Read() ? "found" : "missing";
});

app.Run();
"""

PROGRAM_FIXED = PROGRAM_VULNERABLE.replace(
    "command.CommandText = \"SELECT id FROM users WHERE name = '\" + name + \"'\";",
    "command.CommandText = \"SELECT id FROM users WHERE name = $name\";\n"
    "    command.Parameters.AddWithValue(\"$name\", name);",
)

CSPROJ = """\
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Data.Sqlite" Version="9.0.0" />
  </ItemGroup>
</Project>
"""

COMPONENT = """\
import { Component, ElementRef } from '@angular/core';

@Component({ selector: 'app-root', templateUrl: './app.component.html' })
export class AppComponent {
  constructor(private readonly host: ElementRef) {}

  render(html: string): void {
    this.host.nativeElement.innerHTML = html;
  }

  run(code: string): void {
    eval(code);
  }
}
"""

COMPONENT_HTML = """\
<div (click)="render('x')">click me</div>
<img src="logo.png">
"""

LEGACY_JS = """\
function load(name) {
  return require(name);
}
"""

CRYPTO_CS = """\
using System.Security.Cryptography;

public static class Crypto
{
    public static byte[] Hash(byte[] data)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    public static int Token() => new Random().Next();
}
"""

TOOL_PY = """\
import pickle
import subprocess

import pandas as pd


def load(blob, expression, command):
    pd.eval(expression)
    subprocess.call(command, shell=True)
    return pickle.loads(blob)
"""

DOCKERFILE = """\
FROM alpine:3.20
ADD https://example.invalid/tool.tar.gz /opt/
RUN apk add curl
CMD ["sh"]
"""

PACKAGE_JSON = '{"name": "fixture-web", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}}\n'
PACKAGE_LOCK = """\
{
  "name": "fixture-web",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "fixture-web", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}},
    "node_modules/lodash": {
      "version": "4.17.15",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"
    }
  }
}
"""


HOSTING_CS = """\
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

public static class Hosting
{
    public static void Configure(WebApplication app, HttpResponse response)
    {
        app.UseDeveloperExceptionPage();
        response.Cookies.Append("sid", "x", new CookieOptions { Secure = false, HttpOnly = false });
#pragma warning disable SYSLIB0014
        ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true;
#pragma warning restore SYSLIB0014
    }
}
"""
# Samples for the LabSecurity own rules (rules/opengrep and labsec/standards.py). No credential in any of them.
APPSETTINGS_PRODUCTION = '{"ConnectionStrings": {"Default": "Host=db;Database=app;SSL Mode=Disable"}}\n'
TUNNEL_YML = "ingress:\n  - hostname: app.example.invalid\n    service: https://localhost:8443\n    originRequest:\n      noTLSVerify: true\n  - service: http_status:404\n"
MAIN_BICEP = "@secure()\nparam adminPassword string = 'placeholder-value'\noutput storageId string = 'x'\n"
SECURITY_TS = """\
import { provideHttpClient, withNoXsrfProtection } from '@angular/common/http';

export const providers = [provideHttpClient(withNoXsrfProtection())];

export function remember(value: string): void {
  localStorage.setItem('user_password', value);
}
"""
NPMRC = "strict-ssl=false\n"


def fake_token() -> str:
    alphabet = string.ascii_letters + string.digits
    return "ghp_" + "".join(secrets.choice(alphabet) for _ in range(36))


def random_text(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def appsettings(password: str, client_secret: str, signing_key: str) -> str:
    return (
        "{\n"
        '  "ConnectionStrings": {"Default": "Host=db;Database=app;Username=app;Password=%s;SSL Mode=Require"},\n'
        '  "Authentication": {"ClientSecret": "%s"},\n'
        '  "Jwt": {"SigningKey": "%s"}\n'
        "}\n"
    ) % (password, client_secret, signing_key)


def keycloak_realm(client_secret: str) -> str:
    return '{"realm": "demo", "clients": [{"clientId": "web", "secret": "%s"}]}\n' % client_secret


def git(repo: Path, *args: str) -> None:
    env = dict(
        os.environ,
        GIT_AUTHOR_NAME="fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
    )
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def write(repo: Path, rel: str, content: str) -> None:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)


def build_fixture(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    git(repo, "init", "-q", "-b", "main")
    write(repo, "Api/Api.csproj", CSPROJ)
    write(repo, "Api/Program.cs", PROGRAM_VULNERABLE)
    write(repo, "web/package.json", PACKAGE_JSON)
    write(repo, "web/package-lock.json", PACKAGE_LOCK)
    write(repo, "web/src/app/app.component.ts", COMPONENT)
    write(repo, "web/src/app/app.component.html", COMPONENT_HTML)
    write(repo, "web/src/legacy.js", LEGACY_JS)
    write(repo, "Api/Crypto.cs", CRYPTO_CS)
    write(repo, "Api/Hosting.cs", HOSTING_CS)
    write(repo, "Api/appsettings.Production.json", APPSETTINGS_PRODUCTION)
    write(repo, "deploy/tunnel.yml", TUNNEL_YML)
    write(repo, "infra/main.bicep", MAIN_BICEP)
    write(repo, "web/src/app/security.ts", SECURITY_TS)
    write(repo, "web/.npmrc", NPMRC)
    write(repo, "Api/appsettings.json", appsettings(random_text(20), random_text(32), random_text(40)))
    write(repo, "keycloak/realm-export.json", keycloak_realm(random_text(32)))
    write(repo, "scripts/tool.py", TOOL_PY)
    write(repo, "deploy/Dockerfile", DOCKERFILE)
    write(repo, "deploy/settings.txt", f"github_token={fake_token()}\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "initial import")
    (repo / "deploy" / "settings.txt").unlink()
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "remove settings file")


def fix_sql_injection(repo: Path) -> None:
    write(repo, "Api/Program.cs", PROGRAM_FIXED)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "use a parameter")


def tree_digest(root: Path) -> str:
    """Hash of every file (path, mode, content) including .git: proves the repo was not touched."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode())
        if path.is_symlink():
            digest.update(os.readlink(path).encode())
        elif path.is_file():
            digest.update(oct(path.stat().st_mode).encode())
            digest.update(path.read_bytes())
        else:
            digest.update(b"dir")
    return digest.hexdigest()
