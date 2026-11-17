# Standards-based rule catalog (research input for T11)

Source: read-only research task mwkwe1lb-7-ff3w, 2026-11-17. Citations were written from memory. Parent link check 2026-11-17: all 20 OWASP Cheat Sheet and 20 Microsoft Learn links return HTTP 200 after fixing two (JSON_Web_Token_for_Java -> JSON_Web_Token; xml-security-considerations -> api/system.xml.xmlreadersettings.dtdprocessing); angular.dev/best-practices/security 200. ASVS 5.0.0 requirement IDs: use the official machine-readable ASVS 5.0.0 release (https://github.com/OWASP/ASVS, `5.0/docs_en/`, 345 requirements). CWE Top 25 2025: https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html. Section-level content of each citation is still to be confirmed by T11 when writing each rule.

# Opengrep rule catalog: C# / ASP.NET Core 10 / Angular 22 / config

**Verification status.** I did not retrieve any pages in this run, so none of the citations below were checked against the live page. All the CWE numbers and URLs come from memory.

- **Cheat sheets:** URLs follow the pattern `https://cheatsheetseries.owasp.org/cheatsheets/<Name>_Cheat_Sheet.html`. I abbreviate this as **CS:`<Name>`**.
- **Microsoft Learn:** abbreviated as **MS:`<path>`**, relative to `https://learn.microsoft.com/en-us/`.
- **Angular:** the guide is `https://angular.dev/best-practices/security`, abbreviated **NG-SEC**.
- **ASVS 5.0:** I cite chapters only (V1 Encoding/Sanitization, V3 Web Frontend, V4 API, V5 File Handling, V6 Authentication, V7 Session, V8 Authorization, V9 Self-contained Tokens, V10 OAuth/OIDC, V11 Cryptography, V12 Secure Communication, V13 Configuration, V14 Data Protection, V16 Logging). Individual requirement IDs (V#.#.#) are **UNVERIFIED** and need to be pulled from the 5.0 PDF or the GitHub JSON before the rules ship.
- **OWASP Top 10 2025:** I use A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software/Data Integrity Failures, A09 Logging/Alerting Failures, A10 Mishandling of Exceptional Conditions. The numbering is **UNVERIFIED**.
- **Form key:** P = Opengrep pattern, T = taint rule, R = regex (json/yaml/conf/Dockerfile), S = semantic, config-aware pattern.
- **Severity:** C = Critical, H = High, M = Medium, L = Low.
- **False-positive risk:** lo = low, med = medium, hi = high.

## 1. C# / ASP.NET Core / EF Core / Npgsql / Keycloak

### Authentication and JWT (ASVS V9/V10/V7)

| id | detect | refs | sev | FP | form |
|---|---|---|---|---|---|
| labsec.cs.jwt-validate-issuer-off | `ValidateIssuer = false` | CWE-287; MS:aspnet/core/security/authentication; CS:JSON_Web_Token (claims validation); A07 | H: tokens from any issuer are accepted | lo | P |
| labsec.cs.jwt-validate-audience-off | `ValidateAudience = false` | CWE-287; same refs | H: token confusion between clients (Keycloak `aud`) | lo | P |
| labsec.cs.jwt-validate-lifetime-off | `ValidateLifetime = false` | CWE-613; same refs | H | lo | P |
| labsec.cs.jwt-signing-key-off | `ValidateIssuerSigningKey = false` | CWE-347; same refs | C: forged tokens accepted | lo | P |
| labsec.cs.jwt-require-signed-off | `RequireSignedTokens = false` | CWE-347 | C | lo | P |
| labsec.cs.jwt-require-expiry-off | `RequireExpirationTime = false` | CWE-613 | M | lo | P |
| labsec.cs.jwt-signature-validator-bypass | `SignatureValidator = (t, p) => new JwtSecurityToken(t)` or `new JsonWebToken(t)` | CWE-347 | C | med | P |
| labsec.cs.jwt-read-without-validate | `ReadJwtToken(`/`new JwtSecurityToken(` used for authz decisions; no `ValidateToken` in the same method | CWE-345 | H | hi | P (UNVERIFIED as a reliable rule) |
| labsec.cs.jwt-clockskew-large | `ClockSkew = TimeSpan.FromHours/Days(...)` or a large value | CWE-613 | L | med | P |
| labsec.cs.jwt-require-https-metadata-off | `RequireHttpsMetadata = false` | CWE-319; MS:aspnet/core/security/authentication/configure-jwt-bearer-authentication (UNVERIFIED path) | H outside Development; M if wrapped in `IsDevelopment()` | med | P (exclude Development blocks) |
| labsec.cs.jwt-hardcoded-key | `new SymmetricSecurityKey(Encoding.*.GetBytes("literal"))` | CWE-798; CS:Secrets_Management | H | lo | P/T |
| labsec.cs.jwt-save-token-sensitive | `SaveToken = true` | CWE-522 | L: information only | med | P |
| labsec.cs.jwt-validation-params-default-missing | `AddJwtBearer` with no `Authority`/`TokenValidationParameters` | CWE-287 | M | hi | S (UNVERIFIED) |
| labsec.cs.jwt-alg-none | `ValidAlgorithms` contains `"none"`, or `SecurityAlgorithms.None` | CWE-327 | H | lo | P |
| labsec.cs.oidc-validate-all-off | `ValidateIssuer/Audience = false` in the `AddOpenIdConnect` block | CWE-287 | H | lo | P |
| labsec.cs.oidc-nonce-pkce-off | `UsePkce = false` | CWE-352 | M | lo | P (UNVERIFIED ASVS V10) |
| labsec.cs.oidc-getclaims-userinfo | `SecurityTokenValidator`/`MapInboundClaims` left on | CWE-285 | L | hi | skip |

### Authorization and access control (ASVS V8; OWASP A01)

| id | detect | refs | sev | FP | form |
|---|---|---|---|---|---|
| labsec.cs.minimalapi-no-authz | `app.Map(Get/Post/Put/Delete/Patch)(…)` with no `.RequireAuthorization()`, group authz, or fallback policy | CWE-862, CWE-306; MS:aspnet/core/fundamentals/minimal-apis | H | **hi**: group-level auth and `FallbackPolicy` are not visible per-call | S. Report only when the project has `AddAuthorization` and no `FallbackPolicy`/`RequireAuthorization` on the group. Not reliably static. |
| labsec.cs.allowanonymous-sensitive | `.AllowAnonymous()` or `[AllowAnonymous]` on routes matching `admin|user|delete|export|token|internal` | CWE-862 | H | med | P + metavariable-regex |
| labsec.cs.authz-fallback-allow | `FallbackPolicy = null`/`AuthorizationPolicyBuilder` with `RequireAssertion(_ => true)` | CWE-862 | H | lo | P |
| labsec.cs.role-from-request | `ClaimsPrincipal` built from `Request.Headers/Query`, or `User.IsInRole` compared to request input | CWE-639 | H | med | T |
| labsec.cs.idor-entity-by-id | `db.X.Find(id)`/`FirstOrDefault(x => x.Id == id)` from the route with no owner or tenant filter | CWE-639; A01 | M | **hi** | NOT reliably static (heuristic only) |
| labsec.cs.mass-assignment-entity-bind | `MapPost(..., (Entity e, Db db) => db.Add(e))`, or an EF entity as a handler parameter bound from the body | CWE-915; CS:Mass_Assignment | M | med | P |
| labsec.cs.mass-assignment-tryupdate | `TryUpdateModelAsync(` without `include` | CWE-915 | M | med | P |
| labsec.cs.mvc-bind-all | `[Bind]`-less binding to a domain entity with `IsAdmin`/`Role` properties | CWE-915 | L | hi | skip |

### CORS, cookies, CSRF, headers, errors

| id | detect | refs | sev | FP | form |
|---|---|---|---|---|---|
| labsec.cs.cors-any-credentials | `AllowAnyOrigin()` combined with `AllowCredentials()`, or `SetIsOriginAllowed(_ => true)` plus `AllowCredentials()` | CWE-942; MS:aspnet/core/security/cors; CS:HTML5_Security (CORS section, UNVERIFIED anchor) | H. Core rejects the first combination at runtime but not the second. | lo | P |
| labsec.cs.cors-any-origin | `AllowAnyOrigin()` | CWE-942 | M (L for public APIs) | med | P |
| labsec.cs.cors-wildcard-origin | `WithOrigins("*")`, or `WithOrigins` that includes `null` | CWE-942 | M | lo | P |
| labsec.cs.cors-before-auth-order | `UseCors` after `UseAuthorization` | CWE-942 | L | med | NOT reliably static |
| labsec.cs.cookie-httponly-off | `HttpOnly = false`, or `HttpOnly = HttpOnlyPolicy.None` | CWE-1004; MS:aspnet/core/security/authentication/cookie | M | lo | P |
| labsec.cs.cookie-secure-off | `Secure = false`, `CookieSecurePolicy.None`, `CookieSecurePolicy.SameAsRequest` | CWE-614 | M | lo | P |
| labsec.cs.cookie-samesite-none | `SameSite = SameSiteMode.None` | CWE-1275; CWE-352 | M | med | P |
| labsec.cs.csrf-ignore | `[IgnoreAntiforgeryToken]`, `.DisableAntiforgery()` on a state-changing minimal endpoint | CWE-352; MS:aspnet/core/security/anti-request-forgery; CS:Cross-Site_Request_Forgery_Prevention | H when cookie auth is used; L for bearer-only APIs | med | P (UNVERIFIED: whether `DisableAntiforgery` is the exact 10.0 API) |
| labsec.cs.csrf-no-validate-token | `[HttpPost]` on an MVC action with no `[ValidateAntiForgeryToken]`/`AutoValidateAntiforgeryTokenAttribute` | CWE-352 | M | hi | S |
| labsec.cs.devexception-prod | `UseDeveloperExceptionPage()` outside an `IsDevelopment()` branch | CWE-209; CWE-215; MS:aspnet/core/fundamentals/error-handling | M | lo | P (`pattern-not-inside` an `IsDevelopment` check) |
| labsec.cs.detailed-errors | `.UseSetting("detailedErrors","true")`, `ShowExceptionDetails`, `ex.ToString()` / `ex.StackTrace` returned in `Results.*`/`Content` | CWE-209 | M | med | T |
| labsec.cs.hsts-missing | No `UseHsts()` / `UseHttpsRedirection()` anywhere in Program.cs | CWE-319; MS:aspnet/core/security/enforcing-ssl | L | hi | S (project-level) |
| labsec.cs.hsts-short | `MaxAge = TimeSpan.FromSeconds(<31536000)` | CWE-319 | L | med | P |
| labsec.cs.https-redirect-off | `RequireHttps = false` / `HttpsRedirectionOptions` disabled | CWE-319 | M | lo | P |
| labsec.cs.allowedhosts-wildcard | `UseSetting("AllowedHosts","*")` | CWE-20 (host header); MS:aspnet/core/fundamentals/servers/kestrel/host-filtering | L | hi | P |
| labsec.cs.kestrel-server-header | `AddServerHeader = true` (the default) | CWE-200 | L | med | P |

### Injection (A05)

| id | detect | refs | sev | FP | form |
|---|---|---|---|---|---|
| labsec.cs.ef-fromsqlraw-interp | `FromSqlRaw(` / `ExecuteSqlRaw(` / `SqlQueryRaw(` with `$"…"`, `+`, or `string.Format`, or any non-literal argument | CWE-89; MS:ef/core/querying/sql-queries (section "Passing parameters"); CS:SQL_Injection_Prevention | C | lo | T (sources: query, route, body, headers; sinks: Raw variants; sanitizers: parameter objects) |
| labsec.cs.ef-fromsqlinterpolated-ok | Safe-list: `FromSql($"…")` and `FromSqlInterpolated`. Flag only when the argument is a pre-built string variable. | CWE-89 | – | – | negative pattern |
| labsec.cs.npgsql-cmd-concat | `new NpgsqlCommand(` / `CommandText =` built from concatenation or interpolation | CWE-89 | C | lo | T |
| labsec.cs.dapper-concat | `Query(`/`Execute(` (Dapper) with an interpolated/concatenated SQL argument | CWE-89 | C | lo | T |
| labsec.cs.ado-sqlcommand-concat | `SqlCommand`/`DbCommand` with a concatenated command string | CWE-89 | C | lo | T |
| labsec.cs.xpath-injection | `SelectNodes/Evaluate(` with request input | CWE-643 | M | lo | T |
| labsec.cs.ldap-injection | `DirectorySearcher.Filter` / `new DirectoryEntry(` with concatenated input | CWE-90 | H | lo | T |
| labsec.cs.cmd-injection | `Process.Start(`/`ProcessStartInfo{FileName/Arguments}` with a non-constant value; `UseShellExecute = true` | CWE-78; CS:OS_Command_Injection_Defense | H | med | T (sources: request) |
| labsec.cs.path-traversal | `Path.Combine(`, `File.ReadAllText/OpenRead`, `PhysicalFile`, `Results.File` with request input and no `GetFullPath` + `StartsWith` check. Note `Path.Combine` discards earlier segments when a later one is rooted. | CWE-22; MS:dotnet/standard/io/file-path-formats (UNVERIFIED); CS:File_Upload | H | med | T |
| labsec.cs.zip-slip | `ZipArchiveEntry.FullName` combined with a path and `ExtractToFile` without a prefix check | CWE-22 | H | med | P/T |
| labsec.cs.open-redirect | `Redirect(`, `Results.Redirect(`, `LocalRedirect` is safe, `Response.Redirect(` with request input and no `Url.IsLocalUrl` | CWE-601; MS:aspnet/core/security/preventing-open-redirects; CS:Unvalidated_Redirects_and_Forwards | M | lo | T |
| labsec.cs.ssrf | `HttpClient.GetAsync/SendAsync/new Uri(` / `HttpRequestMessage` with request-derived URL | CWE-918; CS:Server_Side_Request_Forgery_Prevention | H | med | T |
| labsec.cs.xss-html-content | `Results.Content(…, "text/html")`, `Content(..., "text/html")`, `Html.Raw(`, `new HtmlString(`, or `MarkupString` with request input | CWE-79; MS:aspnet/core/security/cross-site-scripting; CS:Cross_Site_Scripting_Prevention | H | med | T |
| labsec.cs.razor-raw | `@Html.Raw(`, Blazor `(MarkupString)` | CWE-79 | M | med | P |
| labsec.cs.log-injection | `logger.Log*(` with `$"…"` containing request input (CRLF) | CWE-117; CS:Logging (section "Event attributes / sanitization") | L | hi | T |
| labsec.cs.regex-redos | `new Regex(` with request-derived pattern; no `matchTimeout` | CWE-1333 | M | med | T/P |
| labsec.cs.xxe-dtd | `XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }`, `XmlResolver = new XmlUrlResolver()`, `XmlDocument` with a resolver, `XmlTextReader` (older default) | CWE-611; CS:XML_External_Entity_Prevention; MS:dotnet/api/system.xml.xmlreadersettings.dtdprocessing (UNVERIFIED) | H | lo | P |
| labsec.cs.xslt-script | `XsltSettings(true, true)` / `enableScript: true` | CWE-611; CWE-94 | H | lo | P |

### Deserialization, crypto, TLS, secrets, logging

| id | detect | refs | sev | FP | form |
|---|---|---|---|---|---|
| labsec.cs.binaryformatter | `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter` | CWE-502; MS:dotnet/standard/serialization/binaryformatter-security-guide; CS:Deserialization | C | lo | P |
| labsec.cs.json-typenamehandling | `TypeNameHandling.All/Auto/Objects/Arrays` | CWE-502; CS:Deserialization | H | lo | P |
| labsec.cs.stj-polymorphic-unsafe | `JsonDerivedType` on a base type that accepts any type: UNVERIFIED as a risk | CWE-502 | L | hi | skip |
| labsec.cs.xmlserializer-type | `new XmlSerializer(Type.GetType(userInput))`, `Type.GetType` / `Activator.CreateInstance` with request input | CWE-470; CWE-502 | H | lo | T |
| labsec.cs.weak-hash-md5 | `MD5.Create()`, `MD5.HashData`, `new MD5CryptoServiceProvider`, `HashAlgorithm.Create("MD5")` | CWE-328; CWE-327; CS:Cryptographic_Storage | M (H if used for passwords) | med | P |
| labsec.cs.weak-hash-sha1 | `SHA1.Create()`, `SHA1.HashData`, `SHA1Managed`, `SHA1CryptoServiceProvider`, `HashAlgorithmName.SHA1` | CWE-328 | M | med | P |
| labsec.cs.weak-cipher | `DES`, `TripleDES`, `RC2`, `Aes` with `CipherMode.ECB` | CWE-327 | H | lo | P |
| labsec.cs.static-iv-key | `aes.IV = new byte[16]`, `aes.Key = Encoding…GetBytes("literal")` | CWE-329; CWE-321 | H | lo | P |
| labsec.cs.insecure-random | `new Random()` / `Random.Shared` flowing into tokens, passwords, codes, or session IDs. Match by variable name (`token|otp|password|secret|nonce`). | CWE-330; CWE-338; CS:Cryptographic_Storage; MS: `RandomNumberGenerator` | M | **hi** | T/P (name heuristic) |
| labsec.cs.password-hash-weak | A password hashed with plain SHA256/512 and no KDF; `Rfc2898DeriveBytes` with iterations below 600000 (UNVERIFIED current OWASP figure for PBKDF2-HMAC-SHA256) | CWE-916; CS:Password_Storage | H | med | P |
| labsec.cs.rsa-small-key | `RSA.Create(1024)`, `new RSACryptoServiceProvider(1024)` | CWE-326 | M | lo | P |
| labsec.cs.rsa-pkcs1-encrypt | `RSAEncryptionPadding.Pkcs1` | CWE-780 | L | lo | P |
| labsec.cs.tls-validation-off | `ServerCertificateCustomValidationCallback = (…) => true`, `DangerousAcceptAnyServerCertificateValidator`, `ServerCertificateValidationCallback += … => true`, `RemoteCertificateValidationCallback` returning true | CWE-295; MS:dotnet/fundamentals/networking/http/httpclient-guidelines (UNVERIFIED) | H | lo | P |
| labsec.cs.tls-legacy-protocol | `SslProtocols.Ssl2/Ssl3/Tls/Tls11`, `ServicePointManager.SecurityProtocol = …` | CWE-326; CWE-327 | M | lo | P |
| labsec.cs.httpclient-no-timeout | `new HttpClient()` per request (socket exhaustion) | CWE-400 | L | med | P |
| labsec.cs.hardcoded-secret | Literals assigned to names matching `password|secret|apikey|connectionstring|token` | CWE-798; CS:Secrets_Management; MS:aspnet/core/security/app-secrets | H | med | P + metavariable-regex + entropy (Gitleaks overlap) |
| labsec.cs.log-sensitive | `Log*(` with variables or properties named `password|token|secret|authorization|cookie|jwt|ssn` | CWE-532; CS:Logging (section "Data to exclude") | M | med | T/P |
| labsec.cs.log-http-body | `EnableSensitiveDataLogging()` (EF), or `HttpLoggingFields.All` / `RequestBody`, `RequestHeaders` without the redaction list | CWE-532; MS:ef/core/logging-events-diagnostics | M | lo | P |
| labsec.cs.dataprotection-keys | `AddDataProtection()` without `PersistKeysTo…`, or keys persisted to the filesystem in a container | CWE-320; MS:aspnet/core/security/data-protection/configuration | L | hi | S |
| labsec.cs.ratelimit-missing | No `AddRateLimiter` / `UseRateLimiter` and a login/token endpoint exists | CWE-307; CWE-770; MS:aspnet/core/performance/rate-limit | M | hi | S, project-level, NOT reliably static |
| labsec.cs.file-upload-unvalidated | `IFormFile` saved using `FileName` without extension/size checks | CWE-434; CWE-22; CS:File_Upload | H | med | T |
| labsec.cs.empty-catch | `catch { }` swallowing exceptions in an auth path | CWE-390; A10 | L | hi | P |
| labsec.cs.exception-fail-open | `catch` returning `true`/`Results.Ok` in authorization/validation code | CWE-636 | M | hi | P (heuristic) |

### Connection strings (C# code and config)

| id | detect | refs | sev | FP | form |
|---|---|---|---|---|---|
| labsec.cs.npgsql-trust-cert | `Trust Server Certificate=true`, `TrustServerCertificate=true` | CWE-295; Npgsql docs https://www.npgsql.org/doc/security.html (UNVERIFIED) | H | lo | R |
| labsec.cs.npgsql-ssl-disable | `SSL Mode=Disable`, `Ssl Mode=Allow/Prefer` (anything below Require/VerifyFull) | CWE-319 | H | lo | R |
| labsec.cs.npgsql-pw-inline | `Password=<literal>` in a connection string in code or config | CWE-798; CS:Secrets_Management | H | lo | R |
| labsec.cs.npgsql-superuser | `Username=postgres` / `User ID=postgres` | CWE-250 | M | med | R |

## 2. TypeScript / Angular 22

All cite NG-SEC plus CS:DOM_based_XSS_Prevention and CS:Cross_Site_Scripting_Prevention.

| id | detect | refs | sev | FP | form |
|---|---|---|---|---|---|
| labsec.ts.bypass-security-trust | `bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl` | CWE-79; NG-SEC section "Trusting safe values" | H (C if the argument comes from `route.snapshot`/HTTP) | med | P (T for severity) |
| labsec.ts.innerhtml-binding | `[innerHTML]="expr"` in a template where expr is non-literal. Angular sanitizes it, so this is only informational. | CWE-79; NG-SEC section "Sanitization and security contexts" | L | hi | P (html) |
| labsec.ts.innerhtml-native | `nativeElement.innerHTML =`, `outerHTML =`, `insertAdjacentHTML(`, `document.write(` | CWE-79; NG-SEC section "Direct use of the DOM APIs" | H | lo | P |
| labsec.ts.renderer-innerhtml | `renderer.setProperty(el,'innerHTML',…)`, `setAttribute(el,'on…')`, `setAttribute(…,'srcdoc')` | CWE-79 | H | lo | P |
| labsec.ts.dom-sink-eval | `eval(`, `new Function(`, `setTimeout("string")`, `setInterval("string")` | CWE-95 | H | lo | P |
| labsec.ts.nativeelement-access | Any `ElementRef.nativeElement` use | CWE-79; NG-SEC | L | **hi** | P (noisy; opt-in) |
| labsec.ts.sanitize-misuse | `sanitizer.sanitize(SecurityContext.NONE, …)`, or a `sanitize` result later passed to `bypassSecurityTrust*` | CWE-79 | M | lo | P |
| labsec.ts.url-binding-dynamic | `[href]`/`[src]` bound to a user-controlled value without validating the scheme (`javascript:`) | CWE-79; CWE-601 | M | hi | T |
| labsec.ts.template-injection | Runtime-built templates: `Component({template: ` + variable), `createComponent` from a string template, JIT `compileModuleAndAllComponentsAsync` | CWE-94; NG-SEC section "Use the Ahead-of-Time (AOT) template compiler" (the page says to avoid generating templates by concatenating user input) | H | lo | P |
| labsec.ts.xsrf-disabled | `withNoXsrfProtection()`, `HttpClientXsrfModule.disable()`, custom `withXsrfConfiguration` with an empty `cookieName`/`headerName` | CWE-352; NG-SEC section "HttpClient XSRF/CSRF security" | M | lo | P |
| labsec.ts.token-localstorage | `localStorage.setItem('…token…'`, `sessionStorage.setItem(…)` with `token|jwt|access_token|refresh` | CWE-922; CWE-922 with XSS amplification; CS:HTML5_Security (section "Local Storage") | M | med | P (metavariable-regex) |
| labsec.ts.oidc-lib-storage | `oidc-client(-ts)` `userStore: new WebStorageStateStore({store: localStorage})`; `angular-oauth2-oidc` `setStorage(localStorage)`; `useRefreshToken` with no rotation (UNVERIFIED) | CWE-922 | M | med | P |
| labsec.ts.location-assign | `window.location = x`, `location.href =`, `location.assign/replace(x)` with non-literal x | CWE-601; CS:DOM_based_XSS_Prevention | M | med | T (sources: `route.snapshot.queryParams`, `ActivatedRoute`, `location.search/hash`) |
| labsec.ts.postmessage-star | `postMessage(…, '*')` | CWE-345; CS:HTML5_Security (section "Web Messaging") | M | lo | P |
| labsec.ts.message-no-origin | `addEventListener('message', …)` with no `event.origin` check | CWE-346 | M | med | P (`pattern-not` on the origin check) |
| labsec.ts.target-blank | `target="_blank"` without `rel="noopener"` (and `noreferrer`) | CWE-1022 | L | lo | P (html). Modern browsers imply noopener, so this is low value. |
| labsec.ts.iframe-src-bound | `<iframe [src]=…>`, `srcdoc` bound | CWE-1021; CWE-79 | M | med | P |
| labsec.ts.json-parse-untrusted | `JSON.parse(` of storage, URL, or message data without schema validation | CWE-502; CWE-20 | L | **hi** | P (opt-in) |
| labsec.ts.http-insecure-url | `http://` literal in `HttpClient`/environment API URL (not localhost) | CWE-319 | M | med | R |
| labsec.ts.hardcoded-secret | `clientSecret`, `apiKey`, `password` literals in `environment*.ts` (Keycloak public clients have no secret) | CWE-798; CS:Secrets_Management | H | med | P |
| labsec.ts.oidc-implicit-flow | `responseType: 'token'` / `'id_token token'` | CWE-522; OAuth BCP (RFC 9700, UNVERIFIED) | M | lo | P |
| labsec.ts.oidc-strict-off | `strictDiscoveryDocumentValidation: false`, `skipIssuerCheck: true`, `requireHttps: false`, `disableAtHashCheck: true`, `skipSubjectCheck` | CWE-345 | H | lo | P |
| labsec.ts.console-sensitive | `console.log(token|password|…)` | CWE-532 | L | med | P |
| labsec.ts.regex-dynamic | `new RegExp(userInput)` | CWE-1333 | L | med | T |
| labsec.ts.prototype-pollution | `Object.assign(target, JSON.parse(…))`, a deep-merge helper (lodash `merge`, `defaultsDeep`) over user input | CWE-1321 | M | hi | T |
| labsec.ts.trusted-types-off | Not detectable per file (see section 4). A partial check: `trustedTypes.createPolicy('default', { createHTML: s => s })` | CWE-79; NG-SEC section "Trusted Types" | M | lo | P |
| labsec.ts.sw-nonce-eval | `unsafe-eval` or `unsafe-inline` literal in code-set CSP meta tags | CWE-693; CS:Content_Security_Policy | M | lo | P |
| labsec.ts.angular-universal-ssrf | SSR code `fetch(req.query.x)` / Express handler with a request-derived URL | CWE-918 | H | med | T |

## 3. Config files

| id | detect | refs | sev | FP | form |
|---|---|---|---|---|---|
| labsec.cfg.appsettings-password | `"…Password=…;"` or `"Password": "<non-empty>"` in `appsettings*.json` (exclude `appsettings.Development.json` at lower severity) | CWE-798; MS:aspnet/core/security/app-secrets; CS:Secrets_Management | H | lo | R |
| labsec.cfg.appsettings-secret-keys | Keys matching `Secret|ApiKey|ClientSecret|PrivateKey|Token|SigningKey` with non-empty, non-placeholder values | CWE-798 | H | med | R |
| labsec.cfg.appsettings-allowedhosts | `"AllowedHosts": "*"` | CWE-20; MS:aspnet/core/fundamentals/servers/kestrel/host-filtering | L | hi | R |
| labsec.cfg.appsettings-loglevel-debug | `"Default": "Debug|Trace"` in production-named files | CWE-532 | L | med | R |
| labsec.cfg.appsettings-detailed-errors | `"DetailedErrors": true` | CWE-209 | M | lo | R |
| labsec.cfg.appsettings-https-meta | `"RequireHttpsMetadata": false` | CWE-319 | H | lo | R |
| labsec.cfg.appsettings-http-authority | `"Authority": "http://…"` (non-localhost) | CWE-319 | H | lo | R |
| labsec.cfg.appsettings-kestrel-http | `"Url": "http://0.0.0.0:…"`, plain HTTP endpoint with no TLS | CWE-319 | L | med | R |
| labsec.cfg.docker-latest | `FROM x:latest`, or `FROM x` with no tag | CWE-1104; Docker best practices https://docs.docker.com/build/building/best-practices/ (UNVERIFIED anchor); CIS Docker 4.x (UNVERIFIED) | L | lo | R |
| labsec.cfg.docker-no-user | No `USER` directive, or the final `USER root`/`USER 0` | CWE-250; CIS Docker 4.1 (UNVERIFIED number) | M | lo | R (multi-line; a rule on the whole file) |
| labsec.cfg.docker-add-url | `ADD https?://…` | CWE-494; CIS Docker 4.9 (UNVERIFIED) | M | lo | R |
| labsec.cfg.docker-curl-sh | `curl … | sh|bash`, `wget … | sh` | CWE-494; CWE-829 | H | lo | R |
| labsec.cfg.docker-secret-env | `ENV|ARG` named `PASSWORD|SECRET|TOKEN|KEY` with a value | CWE-798; CWE-538 | H | med | R |
| labsec.cfg.docker-apt-no-recommends | `apt-get install` without `--no-install-recommends`, or no `rm -rf /var/lib/apt/lists` | CWE-1104 | L | med | R (optional, hygiene) |
| labsec.cfg.docker-expose-ssh | `EXPOSE 22` | CWE-284 | M | lo | R |
| labsec.cfg.docker-copy-secrets | `COPY .env`, `COPY id_rsa`, `COPY *.pem` | CWE-538 | H | lo | R |
| labsec.cfg.docker-healthcheck-missing | No `HEALTHCHECK` | CIS Docker 4.6 (UNVERIFIED) | L | med | R (optional) |
| labsec.cfg.compose-privileged | `privileged: true` | CWE-250; CIS Docker 5.4 (UNVERIFIED) | H | lo | R/yaml |
| labsec.cfg.compose-docker-sock | A mount of `/var/run/docker.sock` | CWE-250; CIS Docker 5.31 (UNVERIFIED) | H | lo | R/yaml |
| labsec.cfg.compose-host-network | `network_mode: host`, `pid: host`, `ipc: host` | CWE-250 | H | lo | R/yaml |
| labsec.cfg.compose-port-all | `ports: "5432:5432"` or `"0.0.0.0:…"` for db/cache ports (5432, 6379, 27017, 9200) | CWE-668; CIS Docker 5.13 (UNVERIFIED) | M | med | R/yaml. Recommend `127.0.0.1:` binding. |
| labsec.cfg.compose-cap-add | `cap_add: [SYS_ADMIN|ALL|NET_ADMIN]`, `security_opt: seccomp:unconfined|apparmor:unconfined`, `no-new-privileges:false` | CWE-250 | H | lo | R/yaml |
| labsec.cfg.compose-env-secret | `environment:` with literal `POSTGRES_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`, `KC_DB_PASSWORD`, `*_SECRET` | CWE-798 | H | med | R/yaml |
| labsec.cfg.compose-keycloak-dev | `start-dev` in a Keycloak command, `KC_HOSTNAME_STRICT: false`, `KC_HTTP_ENABLED: true`, `KC_PROXY: none` in non-dev compose | CWE-1188; Keycloak production guide https://www.keycloak.org/server/configuration-production (UNVERIFIED) | M | med | R/yaml |
| labsec.cfg.compose-read-only-missing | No `read_only: true`, no `user:` | CIS Docker 5.12 (UNVERIFIED) | L | hi | skip or opt-in |
| labsec.cfg.nginx-server-tokens | `server_tokens on;` or no `server_tokens off;` | CWE-200; CS:HTTP_Headers; A02 | L | med | R |
| labsec.cfg.nginx-missing-headers | A `server`/`location` block without `add_header` for `X-Content-Type-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options` / `frame-ancestors`, `Referrer-Policy`, `Permissions-Policy` | CWE-693; CWE-1021; CS:HTTP_Headers; CS:Content_Security_Policy | M | hi (`include` snippets, inheritance quirks of `add_header`) | R at file level; also verify with ZAP |
| labsec.cfg.nginx-ssl-protocols | `ssl_protocols` containing `SSLv3|TLSv1 |TLSv1.1` | CWE-327; A04 | M | lo | R |
| labsec.cfg.nginx-weak-ciphers | `ssl_ciphers` with `RC4|3DES|NULL|aNULL|MD5|EXPORT` | CWE-327 | M | lo | R |
| labsec.cfg.nginx-autoindex | `autoindex on;` | CWE-548 | M | lo | R |
| labsec.cfg.nginx-cors-wildcard | `add_header Access-Control-Allow-Origin *` together with `Allow-Credentials true`, or `$http_origin` reflected without a map | CWE-942 | H | lo | R |
| labsec.cfg.nginx-http-only | `listen 80` with no redirect to https | CWE-319 | L | hi | R |
| labsec.cfg.nginx-proxy-xff | `proxy_set_header X-Forwarded-For` missing, or `proxy_set_header Host` unset | CWE-348 | L | hi | R (optional) |
| labsec.cfg.nginx-no-limit | No `limit_req`/`client_max_body_size` | CWE-770 | L | hi | R (optional) |
| labsec.cfg.nginx-alias-traversal | `location /x { alias /y/; }` with no trailing slash on the location | CWE-22 | M | lo | R |
| labsec.cfg.pkg-lifecycle-scripts | `preinstall|postinstall|install` scripts fetching URLs (`curl`, `wget`, `node -e`) | CWE-829; CWE-506; A03 | H | lo | R/JSON |
| labsec.cfg.pkg-wildcard-version | Dependencies pinned to `*`, `latest`, or a git/http URL | CWE-1104; CWE-829; A03 | M | lo | R/JSON |
| labsec.cfg.pkg-http-registry | An `http://` registry or `.npmrc` with an `_authToken` literal or `strict-ssl=false` | CWE-319; CWE-798 | H | lo | R (.npmrc) |
| labsec.cfg.pkg-lockfile-missing | `package.json` with no `package-lock.json` | CWE-1104 | L | lo | project-level, NOT a code pattern |
| labsec.cfg.pkg-known-vuln | `npm audit` and NuGet vulnerability findings | CWE-1395; A03 | varies | – | NOT an Opengrep rule (Trivy/SCA) |
| labsec.cfg.csproj-nowarn-sec | `<NoWarn>` including `CA5350;CA5351;CA5359;CA5386;CA2300;CA2301;CA2302;CA3075` (security analyzer suppressions) | CWE-1164 | M | lo | R (XML) |
| labsec.cfg.csproj-lockmode | `<TreatWarningsAsErrors>` off / `NuGetAudit` disabled | A03 | L | med | R (optional) |
| labsec.cfg.launchsettings-prod | `ASPNETCORE_ENVIRONMENT: Development` in Dockerfile/compose for deploy targets | CWE-489; CWE-215 | M | med | R |

## 4. Not statically detectable, or needs DAST (ZAP) or project-level analysis

- **Runtime headers.** The effective CSP, HSTS, X-Frame-Options, Referrer-Policy and Permissions-Policy are only visible in real responses (CS:HTTP_Headers, CS:Content_Security_Policy). nginx `add_header` inheritance, CDN edits and the ASP.NET middleware order all change the result.
- **CSP quality.** Whether `'unsafe-inline'`, `'unsafe-eval'` or wildcard sources are present, whether Trusted Types is enforced (NG-SEC section "Trusted Types"), and whether a nonce is applied.
- **Missing authorization.** Minimal API endpoints without `RequireAuthorization` are only meaningful with group, fallback and policy context. Opengrep can emit a hint at best, and ZAP or a route enumeration with and without a token confirms it.
- **IDOR and BOLA.** Ownership checks need data-model and business-logic context (A01; CS:Insecure_Direct_Object_Reference_Prevention).
- **Cookie flags as served.** Secure, HttpOnly and SameSite, as the browser receives them behind a proxy.
- **CORS behavior.** The runtime preflight and reflected-origin behavior.
- **TLS posture.** The cipher suite and protocol the server actually negotiates (testssl, ZAP).
- **Rate limiting and brute-force protection.** The actual effectiveness of limits.
- **Session lifecycle.** Logout, refresh token rotation and reuse detection, Keycloak realm settings (token lifespan, brute-force detection, required PKCE). These are realm configuration, not code. Audit the realm export JSON separately.
- **Business-logic flaws.** The ASVS V2 areas such as race conditions and workflow bypass.
- **Secrets in git history.** This is Gitleaks territory.
- **Dependency CVEs.** This is Trivy/SCA (CWE-1395, A03).
- **Container runtime posture.** Effective capabilities and the actual user, as opposed to what the Dockerfile says.
- **Error information leaks** in real error pages (ZAP active scan).
- **Real SSRF reachability, SQLi exploitability and XSS reflection.** Opengrep gives a candidate and ZAP confirms it.

## 5. Suggested rollout priority

1. Critical/High, low FP, pure patterns: the JWT validation toggles, `BinaryFormatter`, `TypeNameHandling`, TLS validation off, `FromSqlRaw` taint, `bypassSecurityTrust*`, `innerHTML` DOM sinks, `privileged: true`, `curl | sh`, Npgsql SSL, hardcoded passwords.
2. Taint rules: SQL, command, path, redirect, SSRF and XSS, with shared minimal-API sources (`[FromQuery]`, `[FromRoute]`, `[FromBody]`, `HttpRequest`) and Angular sources (`ActivatedRoute`, `location.*`).
3. Config regexes: appsettings, Dockerfile, compose, nginx.
4. Opt-in or noisy checks: `nativeElement`, `JSON.parse`, `Random`, `AllowedHosts`, `target=_blank`.

I can pull the live pages to confirm ASVS 5.0 IDs and replace the UNVERIFIED tags if you want. It would be a separate fetch pass.