# JavaScript/TypeScript ecosystem security standards (research input for T12)

Source: read-only research task mwkwkb4x-9-z5ap, 2026-11-17 (pages fetched live). UNVERIFIED items are checked by the parent below or by T12.

# JS/TS security guidance → static checks (research pass, 2026-11-17)

React (Meta), Node.js (OpenJS Foundation), npm (GitHub/Microsoft) and pnpm (independent) are not Google products. I included them as requested. Only Angular and web.dev are Google.

**Verification rule.** Each page below was fetched live with `fetch_and_extract` and read. Anything I could not read is marked **UNVERIFIED**. I did not cite anything from memory.

## Page status

| Page | Status |
|---|---|
| angular.dev/best-practices/security | Fetched. The middle of the extract (CSP and Trusted Types section) was truncated, so I cite only what I saw: XSS, `bypassSecurityTrust*`, XSRF, SSRF `allowedHosts`. |
| angular.dev/reference/configs/workspace-config | Fetched. |
| nodejs.org security-best-practices | Fetched. |
| nodejs.org/api/permissions.html | Fetched. |
| pnpm.io/supply-chain-security | Fetched. |
| pnpm.io/settings | Fetched. Setting names only, no per-setting descriptions. |
| OWASP Nodejs cheat sheet | Fetched. The middle was truncated. Note the real URL is `Nodejs_Security_Cheat_Sheet.html`; `NodeJS_…` returns 404. |
| OWASP NPM cheat sheet | Fetched. The middle (audit, tokens) was truncated. |
| OpenSSF `npm.md` | Fetched from github.com/ossf/package-manager-best-practices. |
| web.dev strict-csp, trusted-types, coop-coep, samesite-cookies-explained | Fetched. |
| react.dev `components/common` | Fetched. |
| react.dev `rsc/server-functions` | Fetched. It has no security text. |
| ossf/scorecard README | Fetched. |
| lockfile-lint README | Fetched. |
| eslint-plugin-security README | Fetched. |
| docs.npmjs.com npm-audit, config, generating-provenance-statements | Only the table of contents was extracted. I know the options exist, not their semantics. |

**Not verified at all:**
- React 19 blocking `javascript:` URLs.
- React "use server" security notes.
- Google safevalues/Closure/google-security-research docs.
- OpenJS Foundation guidance beyond the Node page.
- Yarn.
- OpenSSF `slsa.dev`.
- The Scorecard and eslint-plugin-security licenses.
- Socket CLI free tier.

## A. Source code (ts/tsx/js/html)

All rule forms are Opengrep unless noted.

| ID | Pattern to detect | Reference (URL + section) | CWE / Sev / FP | Form |
|---|---|---|---|---|
| labsec.react.dangerous-html | `dangerouslySetInnerHTML={{__html: $X}}` where `$X` is not a literal | react.dev/reference/react-dom/components/common, "Dangerously setting the inner HTML". It says to create the `{__html}` object close to the HTML generator and not inline. | 79 / High / medium (sanitized values) | taint, sanitizers DOMPurify/sanitize-html |
| labsec.react.dangerous-html-inline | `dangerouslySetInnerHTML={{...}}` inline object (style rule) | Same page, "not recommended to create the object inline". | 79 / Low / high | pattern |
| labsec.react.trustedhtml-policy | `__html` fed from a `trustedTypes.createPolicy` whose `createHTML` returns its input unchanged | Same page, "Your policy must still ensure…"; web.dev trusted-types, "Create a Trusted Type policy". | 79 / Med / low | pattern |
| labsec.ts.innerhtml-sink | `$E.innerHTML = $X`, `outerHTML`, `insertAdjacentHTML`, `document.write(ln)`, `iframe.srcdoc`, `DOMParser.parseFromString` with non-literal | web.dev/articles/trusted-types, "API introduction" (sink list). | 79 / High / medium | taint |
| labsec.ts.eval-family | `eval(`, `new Function(`, `setTimeout("str")`, `setInterval("str")` with non-literal | web.dev trusted-types (sinks); web.dev strict-csp, "Remove eval()". | 95 / High / low | pattern |
| labsec.ts.script-src-sink | `script.src = $X`, `script.text = $X`, `createElement('script')` with tainted value | web.dev trusted-types, "Script manipulation". | 79 / High / low | taint |
| labsec.html.inline-handler | `onclick=`/`on*=` attributes or `href="javascript:` in html/templates | web.dev/articles/strict-csp, Step 3 "Refactor HTML templates". | 79 / Low / medium | regex |
| labsec.html.script-no-nonce | `<script>` inline without `nonce=` in a project that sets nonce-CSP (cross-file) | web.dev strict-csp, "Add a nonce attribute". | n/a / Low / high | regex, project-level |
| labsec.ts.csp-weak | CSP string or helmet config containing `'unsafe-inline'` or `'unsafe-eval'` in `script-src`, or lacking `object-src 'none'` and `base-uri 'none'` | web.dev strict-csp, "Strict CSP structure". It also says host-allowlist CSPs are bypassable. | 693 / Med / medium. The documented `https: 'unsafe-inline'` fallback is ignored by browsers when a nonce is present, so allow it when `'nonce-'` is also present. | regex or json |
| labsec.ts.csp-meta-prod | CSP set only via `<meta http-equiv="Content-Security-Policy">` | web.dev strict-csp, Step 2: "recommend setting it as an HTTP header" in production. | 693 / Low / high | regex |
| labsec.ts.csp-nonce-static | A nonce constant or one not from `crypto.randomBytes`/`randomUUID` (for example `nonce: "abc"`) | web.dev strict-csp, "Generate a nonce for CSP": 128+ bit, new per response. | 330 / High / low | pattern |
| labsec.node.no-trusted-types | No `require-trusted-types-for 'script'` anywhere (informational) | web.dev trusted-types, "Switch to enforcing CSP". Angular's page also strongly encourages it. | n/a / Info / high | project-level |
| labsec.node.coop-coep | Headers `Cross-Origin-Opener-Policy`/`Cross-Origin-Embedder-Policy` absent while `SharedArrayBuffer` is used | web.dev/articles/coop-coep, intro. | n/a / Info / high | pattern |
| labsec.node.cookie-samesite | `Set-Cookie`/`res.cookie(`/`cookie-session` without `sameSite` | web.dev/articles/samesite-cookies-explained: declare it explicitly; `None` requires `Secure`. | 1275 / Med / medium | pattern |
| labsec.node.cookie-none-nosecure | `sameSite: 'none'` without `secure: true` | Same page, "SameSite=None must be secure". | 614 / Med / low | pattern |
| labsec.node.exec-template | `child_process.exec/execSync(` with a template literal, concatenation or non-literal | OWASP Node cheat sheet, "Do not use dangerous functions": `exec` "acts as a bash interpreter". | 78 / High / low | taint |
| labsec.node.spawn-shell | `spawn(..., {shell: true})` with a tainted argument | Same section. This one is my extrapolation, not stated on the page. | 78 / High / medium | pattern |
| labsec.node.vm-untrusted | `vm.runInNewContext/runInContext/Script` | OWASP Node cheat sheet: "`node:vm` … is not a security mechanism". | 94 / Med / medium | pattern |
| labsec.node.non-literal-require | `require($VAR)` | eslint-plugin-security README: `detect-non-literal-require`. | 829 / Med / high | pattern |
| labsec.node.non-literal-fs | `fs.*($VAR)` with a request-derived path | OWASP Node cheat sheet: user input into `fs` → traversal. Also `detect-non-literal-fs-filename`. | 22 / High / high (use taint) | taint |
| labsec.node.regexp-nonliteral | `new RegExp($VAR)` with tainted input; known-bad nested quantifiers | OWASP: "Stay away from evil regexes"; Node page "Denial of Service (CWE-400)". | 1333 / Med / high | taint + regex |
| labsec.node.timing-compare | `===` between a secret/token/hash and input (names `token`, `secret`, `hmac`, `password`) | Node page, "Timing Attacks (CWE-208)": use `crypto.timingSafeEqual`. | 208 / Med / high | pattern with name heuristics |
| labsec.node.proto-pollution | Recursive merge or `Object.assign` with a `JSON.parse`/`req.body` source; `obj[k][j] = v` with tainted keys | Node page, "Prototype Pollution (CWE-1321)". Mitigations: avoid recursive merge, `Object.hasOwn`, `Object.create(null)`. | 1321 / High / high | taint |
| labsec.node.insecure-http-parser | `insecureHTTPParser: true` | Node page, "HTTP Request Smuggling": do not use that option. | 444 / High / low | pattern |
| labsec.node.inspect-prod | `--inspect` or `--inspect=0.0.0.0` in Dockerfile/scripts/systemd | Node page, "DNS Rebinding (CWE-346)": do not run the inspector in production. | 346 / Med / medium | regex |
| labsec.node.net-no-error-handler | `net.createServer(` whose socket has no `.on('error'`; `http.Server` with no timeouts configured | Node page, "Denial of Service of HTTP server". | 400 / Low / high | pattern-not-inside |
| labsec.node.body-limit | `express.json()`/`urlencoded()` without `limit` | OWASP Node cheat sheet, "Set request size limits". | 770 / Low / medium (Express's default limit is 100kb, so check the version) | pattern |
| labsec.node.redirect-open | `res.redirect(req.query.*/req.body.*/req.params.*)` | Not covered by the pages I read, so treat the source as OWASP generic. UNVERIFIED for these specific pages. | 601 / Med / medium | taint |
| labsec.node.x-powered-by | Express app with no `helmet()`/`app.disable('x-powered-by')` | OWASP Node cheat sheet, helmet section: `hidePoweredBy`, `noSniff`, `frameguard`, CSP. | 200 / Low / high | project-level pattern |
| labsec.node.helmet-xss-auditor | `X-XSS-Protection` set to anything but `0` | OWASP Node cheat sheet: set it to `0`, because the header is deprecated. | 693 / Low / low | regex |
| labsec.node.rate-limit | Login/reset routes with no `express-rate-limit` or equivalent | OWASP Node cheat sheet, "Take precautions against brute-forcing". | 307 / Low / high | route heuristic |
| labsec.node.worker-permission | Run script lacks `node --permission` or `permission` in `node.config.json`, or has `--allow-fs-read=*`/`--allow-fs-write=*`/`--allow-child-process` | nodejs.org/api/permissions.html. Stable since v23.5/v22.13. It is a "seat belt", not a sandbox against malicious code. | n/a / Info / high | json and regex on `package.json` scripts and config |
| labsec.node.permission-audit | `--permission-audit` in production | Same page: audit mode logs but does not deny access. | n/a / Low / low | regex |
| labsec.ts.angular-bypass | `bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl(` with a non-literal | angular.dev/best-practices/security, "Trusting safe values". The page marks them security-sensitive. | 79 / High / medium | taint |
| labsec.ts.angular-template-concat | Template string built from user data (`template:` with a `${}` or `+`); `ɵ`/JIT compile in production | angular.dev security: "Never create templates by concatenating user input"; use AOT in production. | 94 / High / medium | pattern |
| labsec.ts.angular-elementref | `ElementRef.nativeElement.innerHTML =`, `document.write` in Angular components | angular.dev security, "Direct use of the DOM APIs". | 79 / Med / medium | pattern |
| labsec.ts.angular-xsrf-off | `withNoXsrfProtection()` or `HttpClientXsrfModule.disable()` | angular.dev security, "Disabling XSRF protection". The page documents `withNoXsrfProtection()`. `HttpClientXsrfModule.disable()` is **UNVERIFIED**. | 352 / Med / medium | pattern |
| labsec.ts.angular-xsrf-names | `withXsrfConfiguration` with default-colliding names (informational) | Same page: the backend must verify the header, or the default protection is ineffective. | 352 / Info / high | pattern, review only |
| labsec.ts.angular-xssi | A JSON API that does not emit the `)]}',\n` prefix (informational) | angular.dev security, XSSI. | 829 / Info / high | skip, backend check |
| labsec.ts.angular-trust-proxy | `trustProxyHeaders: true`, or `NG_TRUST_PROXY_HEADERS` set to everything | angular.dev security, "Configuring trusted proxy headers": only behind a trusted proxy. | 918 / High / medium | pattern and regex |
| labsec.ts.angular-allowed-hosts-wildcard | `allowedHosts` containing `"*"` (in `angular.json`, `new AngularAppEngine({allowedHosts:['*']})`, or `NG_ALLOWED_HOSTS=*`) | angular.dev security, "Configuring allowed hosts": `*` "presents a security risk". | 918 / High / low | json and pattern |

## B. Config files

| ID | File | Detect | Reference | Sev / FP / form |
|---|---|---|---|---|
| labsec.ts.angular-no-autocsp | `angular.json` | `security.autoCsp` absent or false on the build target. The option exists: "Generates a hash-based CSP when set to true, or `{unsafeEval:true}`" (workspace-config, "Security configuration"). | Info/Low; FP high, because a server-sent CSP may exist. json check |
| labsec.ts.angular-autocsp-unsafeeval | `angular.json` | `autoCsp.unsafeEval: true`. Same page. | Low; FP low. json check |
| labsec.ts.angular-sourcemap-prod | `angular.json` | `sourceMap` true, or `scripts:true` with `hidden` unset, in the production configuration. The page says `scripts`/`styles`/`sourcesContent` default to true and `hidden` to false. Hidden maps must also not be deployed; `sourcesContent:false` protects source. CWE-540. | Low; FP medium. json check |
| labsec.ts.angular-allowedCommonJs | `angular.json` | `allowedCommonJsDependencies`: **no security reference found**. This is a quality/bundle-size item, so I dropped it from the security set. | n/a |
| labsec.ts.tsconfig-strict | `tsconfig*.json` | `"strict": false`. No official security text in the fetched pages. It is a quality item. | Info; FP high. json check |
| labsec.npm.npmrc-ignore-scripts | `.npmrc` | `ignore-scripts=true` is absent. OWASP NPM cheat sheet §3: "Consider adding `ignore-scripts=true` to your `.npmrc`". Node page lists `--ignore-scripts`. CWE-829. | Low; FP high. regex, absence check |
| labsec.npm.min-release-age | `.npmrc` | `min-release-age` is absent. Node page (supply-chain section): `--min-release-age` since npm v11.10.0, in days, example `min-release-age = 1`. The option name is in the npm config TOC. | Low. regex, absence check |
| labsec.npm.dep-git-http | `package.json` | A dependency value matching `git+http://`, `git://`, `http://…tgz`, or a bare `user/repo` GitHub shorthand. OWASP NPM §3 says to check for git URLs, tarball URLs and `file:` paths. Node page says pin to an immutable source, not a mutable one. | CWE-829/494; Med; FP low. json + regex |
| labsec.npm.dep-range-star | `package.json` | A dependency of `*`, `latest`, empty, or `x`, and also `>=`. Node page: "Pin dependency versions to a specific immutable version, not a range or a mutable source". | Med for `*`/`latest`; Low for `^`/`~` (high FP). json check |
| labsec.npm.no-lockfile | repo | `package.json` exists with no `package-lock.json`/`pnpm-lock.yaml`/`yarn.lock`/`npm-shrinkwrap.json`. OpenSSF `npm.md` ("Use a Lockfile"): applications should commit a lockfile. CWE-1357. | Med; FP medium for libraries (OpenSSF says libraries differ). file-exists check |
| labsec.npm.ci-install | CI yml / Dockerfile | `npm install`/`npm i`/`yarn install` without `--frozen-lockfile` in CI; `npm ci` is the read-only form. OpenSSF "Lockfiles and commands" lists `npm ci` as read-only and `npm install` as updating the lockfile; OWASP NPM §2. | Low; FP medium. regex |
| labsec.npm.lockfile-http | lockfile | `resolved` URLs over `http://`, or non-registry hosts. This is what `lockfile-lint --allowed-hosts --validate-https` checks. | CWE-829; Med; FP low. regex or lockfile-lint |
| labsec.npm.lockfile-no-integrity | `package-lock.json` | A `resolved` entry without `integrity`. OpenSSF "package-lock.json": the lockfile installation patches the lockfile if the integrity field is absent. | Med; FP low. json check |
| labsec.npm.scoped-registry | `.npmrc` | Private-looking package names with no `@scope:registry=` line. OpenSSF "Scopes"/"Private packages" and OWASP NPM §12 on dependency confusion. | Med; FP high. heuristic review |
| labsec.npm.npmrc-secrets | `.npmrc` | `_authToken=` with a literal token in a committed file. OpenSSF: "Do not commit this file `~/.npmrc` with credentials". | CWE-798; High; FP low. regex |
| labsec.npm.publish-files | `package.json` | A publishable package (no `"private": true`) without a `files` allowlist. OWASP NPM §1 and the Node page ("Exposure of Sensitive Information (CWE-552)"). | CWE-552; Low; FP medium. json check |
| labsec.npm.publish-no-provenance | CI publish workflow | `npm publish` without `--provenance`, or without `id-token: write`/trusted publishing. OWASP NPM §11 (trusted publishing generates provenance). The docs page exists, but I did not read its body. | Low; FP medium. regex |
| labsec.npm.ci-token | CI yml | `NPM_TOKEN` as a long-lived secret on publish steps. OWASP NPM §11 prefers OIDC. | Low. regex |
| labsec.pnpm.allowBuilds | `pnpm-workspace.yaml` | `dangerouslyAllowAllBuilds: true`, or `strictDepBuilds: false`. pnpm.io/supply-chain-security, "Block risky postinstall scripts": build scripts are blocked unless listed in `allowBuilds`, and `strictDepBuilds` is on by default. | High / Med; FP low. yaml check |
| labsec.pnpm.min-release-age | `pnpm-workspace.yaml` | `minimumReleaseAge: 0`. The same page says the default is 1440 minutes (1 day) and opting out means setting 0. A missing key is therefore **not** a finding on current pnpm. It does matter if the `packageManager` field pins an older pnpm (**UNVERIFIED**; I did not find the version where this default began). | Med; FP low. yaml check |
| labsec.pnpm.blockExotic | `pnpm-workspace.yaml` | `blockExoticSubdeps: false`. Same page: on by default, it blocks git and tarball-URL transitive dependencies. | Med; FP low. yaml check |
| labsec.pnpm.trust-policy | `pnpm-workspace.yaml` | `trustPolicy` absent (informational), or a large `trustPolicyExclude`. Same page documents `no-downgrade`, `trustPolicyExclude` and `trustPolicyIgnoreAfter`. | Info. yaml check |
| labsec.pnpm.verify-store | `pnpm-workspace.yaml` | `verifyStoreIntegrity: false`. The setting name is in pnpm.io/settings "Store settings". **Its semantics are UNVERIFIED.** | Low. yaml check |
| labsec.pnpm.dynamic-registry | `pnpm-workspace.yaml` | `${...}` placeholders in `registry`/`registries`/`namedRegistries` values or keys, or in `userAgent`. pnpm.io/settings warns it can leak secrets via a malicious repo; this is rejected or ignored on recent versions. | CWE-200; Med; FP low. regex |
| labsec.pnpm.lockfile-scan | repo/CI | An SBOM or SCA tool that reads only the first document of `pnpm-lock.yaml`. pnpm.io/supply-chain-security, "Use a lockfile". | Info. tool check |
| labsec.pnpm.named-registry | `pnpm-workspace.yaml` | Multiple `registries` without `namedRegistries` aliases. Same page, "Pin dependencies to the registry they come from". | Low. yaml check |

## C. Free tools (what I could confirm)

| Tool | License | Offline? | Notes |
|---|---|---|---|
| `npm audit` | npm CLI; license not fetched | No, it queries the registry | The `audit signatures` subcommand is in the npm-audit TOC under "Audit Signatures". OpenSSF `npm.md` says it needs npm ≥ 8.15.0. `include-attestations` is an npm-audit config option. |
| `npm audit signatures` | same | No | Verifies registry ECDSA signatures. OpenSSF notes npm has no user-level signatures. |
| OpenSSF Scorecard CLI | Apache-2.0 (**UNVERIFIED**; the README does not say) | No, it needs a GitHub token and calls the API | Has `--npm=<pkg>` and `--checks`. Pinned-Dependencies, Vulnerabilities (OSV), Token-Permissions and Dangerous-Workflow checks apply here. It is a heuristic score, and the README says it is "not one-size-fits-all". |
| `lockfile-lint` | Apache-2.0 (README) | Yes, it reads local lockfiles | Handles npm and yarn lockfiles. The README says pnpm lockfiles carry no tarball source, so it has nothing to check there. It is not a vulnerability scanner. Whether it is maintained is **UNVERIFIED**. |
| `eslint-plugin-security` (eslint-community) | **UNVERIFIED** | Yes | Rules: `detect-child-process`, `detect-eval-with-expression`, `detect-non-literal-fs-filename`, `detect-non-literal-require`, `detect-non-literal-regexp`, `detect-unsafe-regex`, `detect-possible-timing-attacks`, `detect-object-injection`, `detect-bidi-characters`. The README warns of many false positives. |
| `eslint-plugin-node-security`, `@lavamoat/allow-scripts` | **UNVERIFIED** | n/a | Both are only named in the OWASP cheat sheets. |
| Retire.js, OWASP Dependency-Check | **UNVERIFIED** | n/a | Named in the OWASP Node cheat sheet. |
| CSP Evaluator, Lighthouse | **UNVERIFIED** | n/a | web.dev strict-csp recommends Lighthouse ≥ 7.3.0 with `--preset=experimental`, and CSP Evaluator. |
| Socket, Snyk | **UNVERIFIED** | n/a | The Node page says Socket does static analysis of packages. I did not check pricing or a free tier. |

## Suggested follow-ups (my inferences, not from the sources)
1. Ship section B first. The config checks have the lowest false-positive rate and need only json/yaml/regex.
2. Treat `labsec.node.redirect-open`, `labsec.node.spawn-shell` and the Angular `HttpClientXsrfModule.disable()` rule as provisional until each has a verified reference.
3. Re-fetch the npm docs (`config`, `audit`, provenance), the React 19 notes, safevalues/Closure and Yarn before building any rule that depends on their semantics.
## Parent verification (2026-11-17)

- npm docs (v11): `npm audit signatures` and `--audit-level` present in commands/npm-audit; `ignore-scripts` and `min-release-age` present in using-npm/config; `--provenance` and `id-token` present in generating-provenance-statements. Rules labsec.npm.npmrc-ignore-scripts, labsec.npm.min-release-age and labsec.npm.publish-no-provenance are now backed by the official npm docs.
- Angular source (`packages/common/http/src/module.ts`, main): `HttpClientXsrfModule.disable()` exists (deprecated, maps to `withNoXsrfProtection()`) -> labsec.ts.angular-xsrf-off covers both. NEW: JSONP is `@deprecated 22.1 ... as it can cause XSS vulnerabilities` -> add rule labsec.ts.angular-jsonp (`withJsonpSupport()` / `HttpClientJsonpModule` / `jsonp(`), CWE-79, Medium.
- React 19 blocking `javascript:` URLs: NOT found on react.dev/blog/2024/12/05/react-19 nor on react-dom/components/common -> claim dropped; keep labsec.html.inline-handler (`href="javascript:"`) from web.dev strict-csp only.
- react.dev/reference/rsc/use-server mentions security and untrusted input ("security" x12, "untrusted" x4): T12 must read it and derive a rule for Server Functions arguments treated as untrusted.
- Licenses: ossf/scorecard Apache-2.0 (pushed 2026-11-16), lirantal/lockfile-lint Apache-2.0 (pushed 2026-11-04), eslint-community/eslint-plugin-security Apache-2.0 (pushed 2026-10-30). None archived.
- google/safevalues: Apache-2.0 repository confirmed; its docs did not mention TrustedHTML in the README text extracted, so no rule derived from it.
